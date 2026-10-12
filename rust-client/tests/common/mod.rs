//! 集成测试公共设施：一个进程内的 WebSocket mock 代理（明文 TCP 回环，对应 Go 侧
//! `startMock` + gorilla/websocket 的 httptest 服务器）。
//!
//! mock 只实现本协议用到的 WS 子集：读客户端的掩码帧、写不掩码的服务端帧、分片不需要
//! （服务端到客户端不掩码，与真代理一致）。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use hik_ws_client::HikConfig;

/// 测试用 SDP（与 Go 侧 `testSDP` 相同）：H264/90000 + sprop-parameter-sets。
pub const TEST_SDP: &str = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=Session streamed by Hikvision\n\
     m=video 0 RTP/AVP 96\na=rtpmap:96 H264/90000\n\
     a=fmtp:96 packetization-mode=1;profile-level-id=42001f;\
     sprop-parameter-sets=Z2QAH6zZQFAFuhAAAAMAEAAAAwPI8YMZYA==,aM7A8g==\n";

/// H.264 IDR 帧（Annex-B）。
pub fn idr_frame() -> Vec<u8> {
    vec![0, 0, 0, 1, 0x65, 0x88, 0x84, 0x21]
}

/// H.264 P 帧（Annex-B）。
pub fn p_frame() -> Vec<u8> {
    vec![0, 0, 0, 1, 0x41, 0x9a, 0x00]
}

/// 无协议信封的裸 Annex-B 帧（服务端 raw-binary 路径）。
pub fn raw_frame() -> Vec<u8> {
    vec![0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33, 0x44]
}

/// 指向 mock 服务器的客户端配置（`ws://`，不加密）。
pub fn mock_config(addr: std::net::SocketAddr) -> HikConfig {
    HikConfig {
        proxy_host: "127.0.0.1".into(),
        proxy_port: addr.port(),
        device_ip: "127.0.0.1".into(),
        device_port: 559,
        username: "admin".into(),
        password: "token123".into(),
        version: "0.1".into(),
        cipher_suites: 0,
        verbose: false,
        max_reconnects: 0,
        use_tls: false, // mock 是明文 TCP 回环
        ..Default::default()
    }
}

/// 进程内 mock 代理。`scenario` 对**每个**连接执行一次（重连测试按连接序号分支）。
pub struct MockServer {
    pub addr: std::net::SocketAddr,
    pub conns: Arc<AtomicUsize>,
    _handle: JoinHandle<()>,
}

impl MockServer {
    pub fn start<F>(scenario: F) -> Self
    where
        F: FnMut(MockConn, usize) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let conns = Arc::new(AtomicUsize::new(0));
        let conns_thread = conns.clone();
        // 每个连接一线程；scenario 需要 FnMut，用 Mutex 包一下。
        let scenario = Arc::new(std::sync::Mutex::new(scenario));
        let handle = thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(sock) = sock else { break };
                let n = conns_thread.fetch_add(1, Ordering::SeqCst);
                let scenario = scenario.clone();
                thread::spawn(move || {
                    let conn = MockConn::new(sock);
                    (scenario.lock().unwrap())(conn, n);
                });
            }
        });
        Self {
            addr,
            conns,
            _handle: handle,
        }
    }
}

/// mock 侧的一条连接。
pub struct MockConn {
    sock: TcpStream,
    rbuf: Vec<u8>,
}

impl MockConn {
    fn new(sock: TcpStream) -> Self {
        Self {
            sock,
            rbuf: Vec::new(),
        }
    }

    /// 读客户端握手请求并回 101（带正确的 Sec-WebSocket-Accept）。返回请求文本。
    pub fn accept_handshake(&mut self) -> String {
        let req = self.read_until(b"\r\n\r\n");
        let req = String::from_utf8_lossy(&req).to_string();
        let key = req
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .expect("Sec-WebSocket-Key")
            .to_string();
        // accept = base64(sha1(key + magic))，与 websocket.rs 的算法一致。
        let accept = ws_accept(&key);
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: v1.0.0\r\n\r\n"
        );
        self.sock.write_all(resp.as_bytes()).expect("write 101");
        req
    }

    /// 读一条客户端消息（客户端帧必须掩码；这里解掩码）。返回 (opcode, payload)。
    pub fn read_client_message(&mut self) -> (u8, Vec<u8>) {
        let head = self.read_exact(2);
        let opcode = head[0] & 0x0F;
        assert_ne!(opcode, 0x0, "unexpected continuation frame from client");
        assert_eq!(head[1] & 0x80, 0x80, "client frames must be masked");
        let len = match head[1] & 0x7F {
            126 => {
                let e = self.read_exact(2);
                u16::from_be_bytes([e[0], e[1]]) as usize
            }
            127 => {
                let e = self.read_exact(8);
                u64::from_be_bytes(e.try_into().unwrap()) as usize
            }
            n => n as usize,
        };
        let mask = self.read_exact(4);
        let mut payload = self.read_exact(len);
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
        (opcode, payload)
    }

    /// 带超时地尝试读一条客户端消息；超时返回 `None`（keepalive 测试用）。
    pub fn try_read_client_message(&mut self, timeout: Duration) -> Option<(u8, Vec<u8>)> {
        self.sock.set_read_timeout(Some(timeout)).ok()?;
        let head = self.read_exact_opt(2)?;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        let len = match head[1] & 0x7F {
            126 => {
                let e = self.read_exact_opt(2)?;
                u16::from_be_bytes([e[0], e[1]]) as usize
            }
            127 => {
                let e = self.read_exact_opt(8)?;
                u64::from_be_bytes(e.try_into().unwrap()) as usize
            }
            n => n as usize,
        };
        let mask = if masked {
            self.read_exact_opt(4)?
        } else {
            vec![0; 4]
        };
        let mut payload = self.read_exact_opt(len)?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
        }
        Some((opcode, payload))
    }

    /// 发送文本消息（服务端帧不掩码）。
    pub fn send_text(&mut self, s: &str) {
        self.send_frame(0x1, s.as_bytes()).expect("mock write");
    }

    /// 发送二进制消息。
    pub fn send_binary(&mut self, data: &[u8]) {
        self.send_frame(0x2, data).expect("mock write");
    }

    /// 发送二进制消息；对端已断开时返回 Err（不断言）。
    pub fn send_binary_checked(&mut self, data: &[u8]) -> Result<(), ()> {
        self.send_frame(0x2, data).map_err(|_| ())
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let mut f = vec![0x80 | opcode];
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
        self.sock.write_all(&f)
    }

    fn read_until(&mut self, delim: &[u8]) -> Vec<u8> {
        loop {
            if let Some(pos) = find(&self.rbuf, delim) {
                let out: Vec<u8> = self.rbuf.drain(..pos + delim.len()).collect();
                return out;
            }
            let mut chunk = [0u8; 4096];
            let n = self.sock.read(&mut chunk).expect("mock read");
            if n == 0 {
                panic!("mock: connection closed while reading");
            }
            self.rbuf.extend_from_slice(&chunk[..n]);
        }
    }

    fn read_exact(&mut self, n: usize) -> Vec<u8> {
        while self.rbuf.len() < n {
            let mut chunk = [0u8; 4096];
            let read = self.sock.read(&mut chunk).expect("mock read");
            if read == 0 {
                panic!("mock: connection closed mid-frame");
            }
            self.rbuf.extend_from_slice(&chunk[..read]);
        }
        self.rbuf.drain(..n).collect()
    }

    /// `read_exact` 的超时友好版：读不够返回 `None`（调用方需先设过读超时）。
    fn read_exact_opt(&mut self, n: usize) -> Option<Vec<u8>> {
        while self.rbuf.len() < n {
            let mut chunk = [0u8; 4096];
            match self.sock.read(&mut chunk) {
                Ok(0) => return None,
                Ok(read) => self.rbuf.extend_from_slice(&chunk[..read]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return None
                }
                Err(e) => panic!("mock read: {e}"),
            }
        }
        Some(self.rbuf.drain(..n).collect())
    }
}

/// 服务端侧的 PKD/rand 推送（对应 Go 的 `sendAuth`）。
pub fn send_auth(conn: &mut MockConn) {
    conn.send_text(
        r#"{"errorCode":0,"PKD":"00aabb","rand":"1234","cipherSuite":0,"version":"0.1"}"#,
    );
}

/// 服务端侧读 realplay 请求并断言关键字段（对应 Go 的 `expectRealplay`）。
pub fn expect_realplay(conn: &mut MockConn) {
    let (opcode, payload) = conn.read_client_message();
    assert_eq!(opcode, 0x1, "realplay request must be a text message");
    let req: serde_json::Value = serde_json::from_slice(&payload).expect("realplay JSON");
    assert_eq!(req["cmd"], "realplay");
    assert_eq!(req["url"], "ws://127.0.0.1:559/openUrl/token123");
    // 默认空 key/authorization/token（ADR-0004：服务端据此不下发加密流）。
    assert_eq!(req["key"], "");
    assert_eq!(req["authorization"], "");
    assert_eq!(req["token"], "");
}

fn ws_accept(key: &str) -> String {
    // 不引 sha1/base64 crate：手算一份与实现等价的 accept（测试独立于实现的编解码）。
    let mut input = String::with_capacity(key.len() + 36);
    input.push_str(key);
    input.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = sha1_hex(&input);
    base64_encode(&digest)
}

/// 极简 SHA-1（测试用；正确性由 FIPS 180 向量在调用处间接覆盖——
/// 实际上由"客户端接受我们的 101"反向验证：accept 算错握手直接失败）。
fn sha1_hex(s: &str) -> Vec<u8> {
    // 直接内嵌一个微型实现，避免在测试里再引一个 crate。
    // 输入是 ASCII，输出 20 字节。
    fn left_rotate(n: u32, d: u32) -> u32 {
        n.rotate_left(d)
    }
    let mut msg = s.as_bytes().to_vec();
    let ml = (msg.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = left_rotate(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = Vec::with_capacity(20);
    for v in h {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

/// 极简 Base64 编码（测试用）。
fn base64_encode(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 0x3F) as usize] as char);
        out.push(A[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 握手 accept 依赖手写 SHA-1 的正确性：算错时所有集成用例都会以
    // "invalid Sec-WebSocket-Accept" 失败。先用 FIPS 180 向量钉住它。
    #[test]
    fn sha1_fips_vector() {
        assert_eq!(
            base64_encode(&sha1_hex("abc")),
            "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
        );
    }
}
