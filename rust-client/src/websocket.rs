//! 极简 WebSocket 客户端（RFC 6455）+ TLS，仅覆盖本协议所需：
//!
//! - 握手：标准 HTTP Upgrade，子协议固定 `v1.0.0`，校验 `Sec-WebSocket-Accept`；
//! - 客户端帧**必须掩码**（FIN=1、Binary/Text、MASK=1）；服务端下行帧不掩码；
//! - 支持分片重组与 16/64 位长度；ping 自动回 pong；close 帧上报调用方。
//!
//! TLS 走 rustls（纯 Rust 实现，默认校验 webpki 根证书；可用 `TlsOptions` 附加私有 CA，
//! 或仅在测试场景下跳过校验——Go 侧曾写死 `InsecureSkipVerify`（issue #33），本库默认
//! 安全）。`ws://`（不加密）仅用于本地测试代理，对应 `HikConfig::use_tls = false`。
//!
//! 与 `php-client/src/WebSocket.php` 同取向：握手 / 掩码 / 重组都自己实现，不引第三方
//! WebSocket 库；TLS 用 rustls 而非 openssl 绑定。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};

use crate::base64;
use crate::config::TlsOptions;
use crate::error::Error;

/// WebSocket 子协议（协议文档「握手」：固定 `v1.0.0`）。
pub const SUBPROTOCOL: &str = "v1.0.0";

/// RFC 6455 的 Accept 魔数。
const WS_ACCEPT_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// 拨号与握手的超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// WebSocket 消息（重组分片后的一条完整消息）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(Vec<u8>),
    Binary(Vec<u8>),
}

/// WebSocket 层错误。
#[derive(Debug)]
pub enum WsError {
    /// 传输 I/O 错误。
    Io(std::io::Error),
    /// 读超时（调用方据此走看门狗 / keepalive 逻辑）。
    Timeout,
    /// 对端关闭（EOF 或 close 帧）。
    Closed,
    /// 握手失败。
    Handshake(String),
    /// 帧畸形。
    Frame(String),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::Io(e) => write!(f, "{e}"),
            WsError::Timeout => write!(f, "read timeout"),
            WsError::Closed => write!(f, "connection closed"),
            WsError::Handshake(s) => write!(f, "websocket handshake failed: {s}"),
            WsError::Frame(s) => write!(f, "websocket protocol error: {s}"),
        }
    }
}

impl From<WsError> for Error {
    fn from(e: WsError) -> Self {
        match e {
            WsError::Io(e) => Error::Io(e),
            WsError::Timeout => Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "read timeout",
            )),
            WsError::Closed => Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed by peer",
            )),
            WsError::Handshake(s) => Error::WebSocket(format!("handshake: {s}")),
            WsError::Frame(s) => Error::WebSocket(format!("frame: {s}")),
        }
    }
}

/// 可设置读超时的流（TcpStream 支持，测试用的内存流默认不支持）。
pub trait WsIo: Read + Write {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        let _ = dur;
        Ok(())
    }
}

/// 生产流：明文 TCP 或 rustls TLS。
///
/// TLS 变体大得多，但每个会话只建一条连接，枚举尺寸无关紧要；
/// 装箱反而给每次读/写加一层间接。
#[allow(clippy::large_enum_variant)]
pub enum Stream {
    Plain(TcpStream),
    Tls(StreamOwned<ClientConnection, TcpStream>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

impl WsIo for Stream {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.set_read_timeout(dur),
            // TLS 流包装的是同一个 socket，超时设在底层 TCP 上即可。
            Stream::Tls(s) => s.get_ref().set_read_timeout(dur),
        }
    }
}

/// WebSocket 连接。泛型在流类型上：生产用 [`Stream`]，测试可用任意 `Read + Write`。
pub struct WebSocket<S: WsIo> {
    stream: S,
    /// 已读未消费的字节（握手响应剩余 + 半帧）。
    rbuf: Vec<u8>,
    pos: usize,
}

impl WebSocket<Stream> {
    /// 建立连接并完成 WebSocket 握手。返回连接与一个克隆的底层 TCP 句柄
    /// （调用方可用它实现"停止"：shutdown 会立刻解开阻塞的读）。
    pub fn connect(
        host: &str,
        port: u16,
        path: &str,
        use_tls: bool,
        opts: &TlsOptions,
    ) -> Result<(Self, TcpStream), Error> {
        let host_bare = host.trim_start_matches('[').trim_end_matches(']');
        let addrs: Vec<SocketAddr> = (host_bare, port)
            .to_socket_addrs()
            .map_err(Error::Io)?
            .collect();
        let mut last_err: Option<std::io::Error> = None;
        let mut sock = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(s) => {
                    sock = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let sock = sock.ok_or_else(|| {
            Error::Io(last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no address to connect")
            }))
        })?;
        let stop_sock = sock.try_clone()?;

        let stream = if use_tls {
            Stream::Tls(tls_connect(host_bare, sock, opts)?)
        } else {
            Stream::Plain(sock)
        };
        let ws = WebSocket::from_stream(stream, host, port, path)?;
        Ok((ws, stop_sock))
    }
}

impl<S: WsIo> WebSocket<S> {
    /// 在已建立的流上完成 WebSocket 握手。
    pub fn from_stream(mut stream: S, host: &str, port: u16, path: &str) -> Result<Self, Error> {
        // 握手读也要有界：接受连接但始终不应答的代理会 otherwise 挂死会话。
        stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;

        let mut key = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        let sec_key = base64::encode(&key);
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}:{port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {sec_key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\
             \r\n"
        );
        write_all(&mut stream, request.as_bytes())
            .map_err(|e| Error::WebSocket(format!("handshake write: {e}")))?;

        // 读 HTTP 响应头（\r\n\r\n 结束），响应后可能已带上帧数据。
        let mut header: Vec<u8> = Vec::with_capacity(1024);
        let split = loop {
            let mut chunk = [0u8; 4096];
            let n = match stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(Error::WebSocket(
                        "connection closed during handshake".into(),
                    ))
                }
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(Error::WebSocket(format!("handshake read: {e}")));
                }
            };
            header.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_subslice(&header, b"\r\n\r\n") {
                break pos;
            }
            if header.len() > 64 * 1024 {
                return Err(Error::WebSocket("handshake response too large".into()));
            }
        };

        let head = std::str::from_utf8(&header[..split])
            .map_err(|_| Error::WebSocket("handshake response is not UTF-8".into()))?;
        let leftover = header[split + 4..].to_vec();

        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        if !(status_line.starts_with("HTTP/1.1 101") || status_line.starts_with("HTTP/1.0 101")) {
            return Err(Error::WebSocket(format!("upgrade failed: {status_line}")));
        }

        // 校验 Sec-WebSocket-Accept（gorilla/websocket 同样强制）。
        let expected = {
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update(sec_key.as_bytes());
            h.update(WS_ACCEPT_MAGIC.as_bytes());
            base64::encode(&h.finalize())
        };
        let mut got_accept: Option<&str> = None;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("sec-websocket-accept") {
                    got_accept = Some(value.trim());
                }
            }
        }
        match got_accept {
            Some(v) if v == expected => {}
            _ => {
                return Err(Error::WebSocket(
                    "missing or invalid Sec-WebSocket-Accept".into(),
                ))
            }
        }

        Ok(Self {
            stream,
            rbuf: leftover,
            pos: 0,
        })
    }

    /// 设置底层读超时。`None` = 阻塞读。
    pub fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(dur)
    }

    /// 读一条完整消息（分片已重组；ping 已自动回 pong）。
    pub fn read_message(&mut self) -> Result<Message, WsError> {
        let mut frag_opcode: Option<u8> = None;
        let mut frag_buf: Vec<u8> = Vec::new();
        loop {
            let (fin, opcode, payload) = self.read_frame()?;
            match opcode {
                0x0 => {
                    // continuation
                    if frag_opcode.is_none() {
                        return Err(WsError::Frame(
                            "continuation frame without a preceding data frame".into(),
                        ));
                    }
                    frag_buf.extend_from_slice(&payload);
                    if fin {
                        let op = frag_opcode.take().unwrap();
                        return Ok(finish_message(op, frag_buf));
                    }
                }
                0x1 | 0x2 => {
                    if fin {
                        return Ok(finish_message(opcode, payload));
                    }
                    frag_opcode = Some(opcode);
                    frag_buf = payload;
                }
                0x8 => return Err(WsError::Closed),
                0x9 => self.send_frame(0xA, &payload)?, // ping → pong
                0xA => {}                               // pong → 忽略
                _ => {}                                 // 未知 opcode → 忽略该帧
            }
        }
    }

    /// 发送一条文本消息（客户端帧必须掩码）。
    pub fn send_text(&mut self, data: &[u8]) -> Result<(), WsError> {
        self.send_frame(0x1, data)
    }

    /// 发送一条二进制消息。
    pub fn send_binary(&mut self, data: &[u8]) -> Result<(), WsError> {
        self.send_frame(0x2, data)
    }

    /// 发送 keepalive ping。
    pub fn send_ping(&mut self) -> Result<(), WsError> {
        self.send_frame(0x9, &[])
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), WsError> {
        let len = payload.len();
        let mut frame = Vec::with_capacity(14 + len);
        frame.push(0x80 | opcode);
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mut mask = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut mask);
        frame.extend_from_slice(&mask);
        let mask_start = frame.len();
        frame.extend_from_slice(payload);
        for (i, b) in frame[mask_start..].iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
        write_all(&mut self.stream, &frame)
    }

    /// 读一个帧。返回 (FIN, opcode, payload)。
    fn read_frame(&mut self) -> Result<(bool, u8, Vec<u8>), WsError> {
        let head = self.read_exact(2).map_err(map_read_err)?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        let len: u64 = match head[1] & 0x7F {
            126 => {
                let e = self.read_exact(2).map_err(map_read_err)?;
                u16::from_be_bytes([e[0], e[1]]) as u64
            }
            127 => {
                let e = self.read_exact(8).map_err(map_read_err)?;
                let v = u64::from_be_bytes(e.try_into().unwrap());
                if v >> 63 != 0 {
                    return Err(WsError::Frame("64-bit length with the high bit set".into()));
                }
                v
            }
            n => n as u64,
        };
        let mut mask = [0u8; 4];
        if masked {
            let m = self.read_exact(4).map_err(map_read_err)?;
            mask.copy_from_slice(&m);
        }
        let mut payload = self.read_exact(len as usize).map_err(map_read_err)?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
        }
        Ok((fin, opcode, payload))
    }

    /// 读到至少 `n` 字节可用并取出前 `n` 字节。
    ///
    /// 按声明长度预分配是危险的（谎报的 64 位长度会直接引爆内存），所以增量读入。
    fn read_exact(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        while self.rbuf.len() - self.pos < n {
            self.maybe_compact();
            let mut chunk = [0u8; 16384];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "eof",
                    ))
                }
                Ok(k) => self.rbuf.extend_from_slice(&chunk[..k]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        let out = self.rbuf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    /// 缓冲 compaction：全消费完时清零，pos 过大时前移。
    fn maybe_compact(&mut self) {
        if self.pos == 0 {
            return;
        }
        if self.pos == self.rbuf.len() {
            self.rbuf.clear();
            self.pos = 0;
        } else if self.pos >= 65536 {
            self.rbuf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

/// 读错误的分类：超时与 EOF 要与普通 I/O 错误区分开。
fn map_read_err(e: std::io::Error) -> WsError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => WsError::Timeout,
        std::io::ErrorKind::UnexpectedEof => WsError::Closed,
        _ => WsError::Io(e),
    }
}

fn finish_message(opcode: u8, payload: Vec<u8>) -> Message {
    if opcode == 0x1 {
        Message::Text(payload)
    } else {
        Message::Binary(payload)
    }
}

fn write_all<S: WsIo>(stream: &mut S, data: &[u8]) -> Result<(), WsError> {
    let mut off = 0;
    while off < data.len() {
        match stream.write(&data[off..]) {
            Ok(0) => {
                return Err(WsError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "wrote 0 bytes",
                )))
            }
            Ok(k) => off += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(WsError::Io(e)),
        }
    }
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 建立 rustls TLS 连接。
fn tls_connect(
    host: &str,
    sock: TcpStream,
    opts: &TlsOptions,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Error> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for der in &opts.extra_root_certs_der {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| Error::Tls(format!("invalid root certificate: {e}")))?;
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if opts.danger_accept_invalid_certs {
        // 仅用于自签测试代理：对应 Go 的 InsecureSkipVerify:true。
        config
            .dangerous()
            .set_certificate_verifier(std::sync::Arc::new(NoCertVerifier));
    }
    let server_name = ServerName::try_from(host)
        .map_err(|_| Error::Tls(format!("invalid server name: {host}")))?
        .to_owned();
    let conn = ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok(StreamOwned::new(conn, sock))
}

/// 跳过证书校验的 verifier（`TlsOptions::danger_accept_invalid_certs`）。
#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read, Write};
    use std::sync::{Arc, Condvar, Mutex};

    /// 一对交叉连接的内存流（测试 WebSocket 帧编解码，不起 socket）。
    /// read 阻塞直到有数据（带 5s 上限，避免测试挂死）。
    #[derive(Clone, Default)]
    struct Duplex {
        inbox: Arc<(Mutex<Vec<u8>>, Condvar)>,
        outbox: Arc<(Mutex<Vec<u8>>, Condvar)>,
    }

    impl Duplex {
        fn pair() -> (Self, Self) {
            let a_out = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
            let b_out = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
            (
                Duplex {
                    inbox: b_out.clone(),
                    outbox: a_out.clone(),
                },
                Duplex {
                    inbox: a_out,
                    outbox: b_out,
                },
            )
        }

        /// 推数据给对端读。
        fn peer_write(&self, data: &[u8]) {
            let (lock, cvar) = &*self.outbox;
            lock.lock().unwrap().extend_from_slice(data);
            cvar.notify_all();
        }

        /// 取走对端写来的全部数据（不阻塞）。
        fn peer_read_all(&self) -> Vec<u8> {
            std::mem::take(&mut *self.inbox.0.lock().unwrap())
        }

        /// 轮询等待对端写来数据（测试用，最多等 `ms` 毫秒）。
        fn await_peer(&self, ms: u64) -> Vec<u8> {
            for _ in 0..(ms / 5).max(1) {
                let got = self.peer_read_all();
                if !got.is_empty() {
                    return got;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("peer did not send anything within {ms}ms");
        }
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let (lock, cvar) = &*self.inbox;
            let mut inbox = lock.lock().unwrap();
            let mut waited = Duration::ZERO;
            while inbox.is_empty() {
                if waited >= Duration::from_millis(750) {
                    return Err(std::io::Error::new(ErrorKind::WouldBlock, "empty"));
                }
                let (guard, _) = cvar.wait_timeout(inbox, Duration::from_millis(50)).unwrap();
                inbox = guard;
                waited += Duration::from_millis(50);
            }
            let n = inbox.len().min(buf.len());
            buf[..n].copy_from_slice(&inbox[..n]);
            inbox.drain(..n);
            Ok(n)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let (lock, cvar) = &*self.outbox;
            lock.lock().unwrap().extend_from_slice(buf);
            cvar.notify_all();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl WsIo for Duplex {}

    /// 服务端帧写入 helper（服务端下行帧不掩码）。`fin=false` 用于分片首帧。
    fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        server_frame_fin(opcode, payload, true)
    }

    fn server_frame_fin(opcode: u8, payload: &[u8], fin: bool) -> Vec<u8> {
        let mut f = vec![(if fin { 0x80 } else { 0 }) | opcode];
        if payload.len() < 126 {
            f.push(payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            f.push(126);
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            f.push(127);
            f.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        f.extend_from_slice(payload);
        f
    }

    fn accept_for(key: &str) -> String {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(key.as_bytes());
        h.update(WS_ACCEPT_MAGIC.as_bytes());
        base64::encode(&h.finalize())
    }

    /// 握手 + 基本收发（服务端逻辑在线程里驱动，主线程驱动客户端）。
    #[test]
    fn handshake_and_frame_exchange() {
        let (client_io, server_io) = Duplex::pair();
        let server = std::thread::spawn(move || {
            let req = String::from_utf8(server_io.await_peer(2000)).unwrap();
            assert!(req.starts_with("GET /media?version=0.1"), "req: {req}");
            assert!(req.contains("Upgrade: websocket"));
            assert!(req.contains("Sec-WebSocket-Protocol: v1.0.0"));
            let key = req
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap()
                .to_string();
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                accept_for(&key)
            );
            server_io.peer_write(resp.as_bytes());
            // 分片 binary：首帧 FIN=0，续帧 FIN=1
            server_io.peer_write(&server_frame_fin(0x2, b"wo", false));
            server_io.peer_write(&server_frame(0x0, b"rld"));
        });

        let mut ws = WebSocket::from_stream(client_io, "h", 1, "/media?version=0.1").unwrap();
        assert_eq!(
            ws.read_message().unwrap(),
            Message::Binary(b"world".to_vec()),
            "fragmented binary must be reassembled"
        );
        server.join().unwrap();
    }

    /// 客户端帧必须掩码；服务端分片 / 16 位长度 / ping 自动回 pong / close。
    #[test]
    fn frame_codec() {
        let (client_io, server_io) = Duplex::pair();
        let mut ws = WebSocket {
            stream: client_io,
            rbuf: Vec::new(),
            pos: 0,
        };

        // 客户端发送：FIN=1、opcode=0x2、MASK=1。
        ws.send_binary(b"hello").unwrap();
        let got = server_io.peer_read_all();
        assert_eq!(got[0], 0x82, "FIN + binary opcode");
        assert_eq!(got[1] & 0x80, 0x80, "client frames must be masked");
        assert_eq!(got[1] & 0x7F, 5);
        let mask = &got[2..6];
        let payload: Vec<u8> = got[6..]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i & 3])
            .collect();
        assert_eq!(payload, b"hello");

        // 分片 text：首帧 FIN=0，续帧 FIN=1 → "te" + "xt" = "text"。
        server_io.peer_write(&server_frame_fin(0x1, b"te", false));
        server_io.peer_write(&server_frame(0x0, b"xt"));
        assert_eq!(
            ws.read_message().unwrap(),
            Message::Text(b"text".to_vec()),
            "fragmented text must be reassembled"
        );

        // ping → 自动 pong（pong 在客户端处理 ping 时发出，随后照常返回数据帧）。
        server_io.peer_write(&server_frame(0x9, b""));
        server_io.peer_write(&server_frame(0x2, b"after-ping"));
        assert_eq!(
            ws.read_message().unwrap(),
            Message::Binary(b"after-ping".to_vec())
        );
        let pong = server_io.peer_read_all();
        assert_eq!(pong[0], 0x8A, "pong opcode");

        // 16 位扩展长度（300 字节）。
        let big = vec![0x5Au8; 300];
        server_io.peer_write(&server_frame(0x2, &big));
        assert_eq!(ws.read_message().unwrap(), Message::Binary(big));

        // close 帧 → WsError::Closed。
        server_io.peer_write(&server_frame(0x8, b""));
        assert!(matches!(ws.read_message(), Err(WsError::Closed)));
    }

    #[test]
    fn handshake_rejects_bad_status() {
        let (client_io, server_io) = Duplex::pair();
        // 响应可预置：客户端写请求后读到的就是它。
        server_io.peer_write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        match WebSocket::from_stream(client_io, "h", 1, "/media") {
            Err(Error::WebSocket(s)) => assert!(s.contains("upgrade failed"), "{s}"),
            Err(other) => panic!("want upgrade failure, got {other:?}"),
            Ok(_) => panic!("want upgrade failure, got Ok"),
        }
    }

    #[test]
    fn handshake_rejects_bad_accept() {
        let (client_io, server_io) = Duplex::pair();
        server_io
            .peer_write(b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: bogus\r\n\r\n");
        match WebSocket::from_stream(client_io, "h", 1, "/media") {
            Err(Error::WebSocket(s)) => assert!(s.contains("Sec-WebSocket-Accept"), "{s}"),
            Err(other) => panic!("want accept failure, got {other:?}"),
            Ok(_) => panic!("want accept failure, got Ok"),
        }
    }

    #[test]
    fn timeout_surfaces_as_ws_error() {
        // 底层 read 返回 WouldBlock → WsError::Timeout（调用方据此走看门狗）。
        let (client_io, _server_io) = Duplex::pair();
        let mut ws = WebSocket {
            stream: client_io,
            rbuf: Vec::new(),
            pos: 0,
        };
        assert!(matches!(ws.read_message(), Err(WsError::Timeout)));
    }
}
