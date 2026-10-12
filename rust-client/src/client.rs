//! 客户端接线：会话生命周期 + 媒体链路。对应 `go-client/client.go`（行为基准）与
//! `php-client/src/HikMediaClient.php`。
//!
//! 传输层（WebSocket、鉴权、封包、重连）与媒体解析层（RTP、PS、SPS、SDP）分离
//! （ADR-0001）：本模块只做接线，解析逻辑在 `rtp` / `psdemux` / `sps` / `sdp` 里。

use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::HikConfig;
use crate::crypto;
use crate::error::{Error, ServerError};
use crate::media::{analyze_frame, sniff_codec};
use crate::media_info::{FrameMeta, MediaInfo};
use crate::protocol::{
    self, MSG_TYPE_AUDIO_DATA, MSG_TYPE_KEEPALIVE, MSG_TYPE_SESSION_ERROR, MSG_TYPE_VIDEO_DATA,
};
use crate::psdemux::PsDemuxer;
use crate::rtp::RtpDetector;
use crate::sdp::parse_sdp;
use crate::sps::recover_resolution;
use crate::websocket::{Message, WebSocket, WsError};

/// 视频帧回调：逐帧元数据 + Annex-B 负载。
pub type OnVideoFrame = Box<dyn FnMut(&FrameMeta, &[u8]) + Send>;
/// 视频负载回调（向后兼容的旧入口）。
pub type OnVideoData = Box<dyn FnMut(&[u8]) + Send>;
/// 原始容器负载回调（解复用前，诊断用）。
pub type OnRawVideo = Box<dyn FnMut(&[u8]) + Send>;
/// 音频负载回调。
pub type OnAudioData = Box<dyn FnMut(&[u8]) + Send>;
/// 流描述回调。
pub type OnMediaInfo = Box<dyn FnMut(&MediaInfo) + Send>;
/// SPS NAL 回调（归档用）。
pub type OnSps = Box<dyn FnMut(&[u8]) + Send>;
/// 错误回调。
pub type OnError = Box<dyn FnMut(&Error) + Send>;

/// 回调集合。字段与 Go 侧 `HikMediaClient` 的回调一一对应。
pub struct Callbacks {
    /// 逐帧元数据 + Annex-B 负载（优先于 `on_video_data`）。
    pub on_video_frame: Option<OnVideoFrame>,
    /// 已解复用的 Annex-B 访问单元（向后兼容）。
    pub on_video_data: Option<OnVideoData>,
    /// 解复用**前**的原始容器负载（诊断 / 抓包归档用）。
    pub on_raw_video: Option<OnRawVideo>,
    /// 音频负载原样下发（不解 PES、不解码，ADR-0004）。
    pub on_audio_data: Option<OnAudioData>,
    /// realplay 返回 SDP 解析出的流描述。
    ///
    /// 收到的是 **SDP 时刻的快照**；容器 / 编码 / 分辨率在码流内恢复后的最新值通过
    /// [`HikMediaClient::media_info`] 与每帧的 `FrameMeta` 读取（Go 侧回调指针可见
    /// 同一对象的后续写回，Rust 的所有权模型下以快照 + 访问器等价呈现）。
    pub on_media_info: Option<OnMediaInfo>,
    /// 码流内首个 SPS NAL（含起始码），归档用。
    pub on_sps: Option<OnSps>,
    /// 传输 / 会话错误。
    pub on_error: Option<OnError>,
}

/// `Box<dyn FnMut(..)>` 没有 Default 实现，无法 derive——每个字段显式置 None。
#[allow(clippy::derivable_impls)]
impl Default for Callbacks {
    fn default() -> Self {
        Self {
            on_video_frame: None,
            on_video_data: None,
            on_raw_video: None,
            on_audio_data: None,
            on_media_info: None,
            on_sps: None,
            on_error: None,
        }
    }
}

/// 停止句柄：调用 `stop()` 后 `stream()` 会在当前消息处理后干净退出，
/// 阻塞中的读会因底层 socket 被 shutdown 立即返回。
#[derive(Clone)]
pub struct StopHandle {
    flag: Arc<AtomicBool>,
    sock: Arc<Mutex<Option<TcpStream>>>,
}

impl StopHandle {
    /// 请求停止。
    pub fn stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
        // shutdown 会解开阻塞的 read（停止前无需等 stall 超时）。
        if let Some(s) = self.sock.lock().unwrap().as_ref() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }

    /// 是否已请求停止。
    pub fn is_stopped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// 海康威视取流客户端。
pub struct HikMediaClient {
    config: HikConfig,
    callbacks: Callbacks,
    ws: Option<WebSocket<crate::websocket::Stream>>,
    /// 鉴权阶段服务端下发的参数。
    server_pkd: String,
    server_rand: String,

    // ---- 媒体链路状态（与 Go 侧一一对应）----
    media_info: Option<MediaInfo>,
    /// MPEG-PS 解复用器。第一条负载上才分配；其余容器路径下保持 None。
    ps: Option<PsDemuxer>,
    container_known: bool,
    /// RTP 判定：会话级，先于容器判定。
    rtp: RtpDetector,
    frame_count: u64,
    start_time: Option<Instant>,
    last_activity: Instant,
    last_ping: Instant,

    stop_flag: Arc<AtomicBool>,
    stop_sock: Arc<Mutex<Option<TcpStream>>>,
}

impl HikMediaClient {
    pub fn new(config: HikConfig) -> Self {
        Self {
            config,
            callbacks: Callbacks::default(),
            ws: None,
            server_pkd: String::new(),
            server_rand: String::new(),
            media_info: None,
            ps: None,
            container_known: false,
            rtp: RtpDetector::new(),
            frame_count: 0,
            start_time: None,
            last_activity: Instant::now(),
            last_ping: Instant::now(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            stop_sock: Arc::new(Mutex::new(None)),
        }
    }

    /// 回调集合（链式设置）。
    pub fn callbacks(&mut self) -> &mut Callbacks {
        &mut self.callbacks
    }

    /// 取停止句柄（`stream()` 开始前就能拿）。
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle {
            flag: self.stop_flag.clone(),
            sock: self.stop_sock.clone(),
        }
    }

    /// 当前 media info（若有）。
    pub fn media_info(&self) -> Option<&MediaInfo> {
        self.media_info.as_ref()
    }

    /// 已交付的帧数。
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    /// 建立 WebSocket 连接（TLS 默认校验证书，见 `HikConfig::tls_options`）。
    pub fn connect(&mut self) -> Result<(), Error> {
        let (ws, sock) = crate::websocket::WebSocket::connect(
            &self.config.proxy_host,
            self.config.proxy_port,
            &media_path(&self.config),
            self.config.use_tls,
            &self.config.tls_options,
        )?;
        *self.stop_sock.lock().unwrap() = Some(sock);
        self.ws = Some(ws);
        Ok(())
    }

    /// 关闭连接。
    pub fn close(&mut self) {
        self.ws = None;
    }

    /// 读取服务端下发的 PKD / rand（无需主动发认证请求）。
    pub fn authenticate(&mut self) -> Result<(), Error> {
        let ws = self.ws.as_mut().ok_or(Error::NotConnected)?;
        // 给握手读加界：接受连接但始终不应答的代理会 otherwise 挂死会话。
        if let Some(d) = self.config.stall_timeout {
            ws.set_read_timeout(Some(d))?;
        }
        let msg = ws.read_message()?;
        let payload = match msg {
            Message::Text(p) => p,
            Message::Binary(_) => {
                return Err(Error::Protocol(
                    "expected text message for auth, got binary".into(),
                ))
            }
        };
        let resp: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|e| Error::Protocol(format!("auth response is not JSON: {e}")))?;

        if let Some(code) = resp.get("errorCode").and_then(|v| v.as_f64()) {
            if code != 0.0 {
                let msg = resp
                    .get("errorMsg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Err(Error::Server(ServerError::new(code as i32, msg)));
            }
        }
        if let Some(pkd) = resp.get("PKD").and_then(|v| v.as_str()) {
            self.server_pkd = pkd.to_string();
        }
        if let Some(rand) = resp.get("rand").and_then(|v| v.as_str()) {
            self.server_rand = rand.to_string();
        }
        Ok(())
    }

    /// 发送 realplay 请求，启动取流。
    ///
    /// 默认以**空 `key` / `authorization` / `token`** 请求（与 Go / Python / PHP 一致，
    /// 服务端据此不下发加密流，媒体载荷本身不加密，ADR-0004）。代理要求严格鉴权时
    /// （`HikConfig::use_realplay_auth`）用 `crypto` 填实这三个字段。
    pub fn realplay(&mut self) -> Result<(), Error> {
        let device_url = self.config.device_url();
        let mut req = serde_json::json!({
            "sequence": 0,
            "cmd": "realplay",
            "url": device_url,
            "key": "",
            "authorization": "",
            "token": "",
        });
        if self.config.use_realplay_auth && !self.server_pkd.is_empty() {
            let (iv, key) = crypto::generate_client_iv_key();
            req["key"] = crypto::generate_realplay_key(&iv, &key, &self.server_pkd)?.into();
            req["authorization"] = crypto::generate_authorization(
                &self.server_rand,
                &self.config.password,
                &key,
                &iv,
            )?
            .into();
            req["token"] = crypto::generate_token(&device_url, &key, &iv)?.into();
        }
        let body = serde_json::to_vec(&req)
            .map_err(|e| Error::Protocol(format!("realplay request encode: {e}")))?;
        let ws = self.ws.as_mut().ok_or(Error::NotConnected)?;
        ws.send_text(&body)?;
        self.log("realplay request sent");
        Ok(())
    }

    /// 处理一条视频负载。RTP 判定器会扣住开头几条直到能定性，一次喂入可能放出 0/1/多条。
    pub fn feed_video(&mut self, data: &[u8]) {
        for p in self.rtp.feed(data) {
            self.feed_container(&p);
        }
    }

    /// 处理一条已去封装的负载。MPEG-PS 先解复用，其余容器原样下发。
    pub fn feed_container(&mut self, data: &[u8]) {
        if let Some(cb) = self.callbacks.on_raw_video.as_mut() {
            cb(data);
        }
        // 容器只在会话第一条负载上判一次（ADR-0002）：MEDIAINFO 头只是提示，HVAG 系设备
        // 的头解不出来、container 为空但负载明明是 MPEG-PS，只能靠嗅探定性；且只能在第一条
        // 上嗅，后续消息都是从 pack 中段续传的。
        if !self.container_known {
            self.container_known = true;
            let want_ps = match self.media_info.as_ref() {
                Some(info) => info.container == "PS",
                None => PsDemuxer::is_ps_data(data),
            };
            if want_ps {
                self.ps = Some(PsDemuxer::new());
                // 嗅探结论写回 MediaInfo：对 HVAG 那类设备这是容器的唯一来源，隐含的 90kHz
                // PS 时钟又是 PTS 能换算成帧率的前提。
                if let Some(info) = self.media_info.as_mut() {
                    if info.container.is_empty() {
                        info.container = "PS".into();
                        info.clock_rate = 90000;
                    }
                }
            }
        }

        if let Some(ps) = self.ps.as_mut() {
            for f in ps.feed(data) {
                self.deliver_frame(&f.data, f.pts, f.has_pts);
            }
        } else {
            self.deliver_frame(data, 0, false);
        }
    }

    /// 流结束时把还压在手里的东西放出去：先 RTP 判定器扣住的负载，再解复用器的最后一个
    /// 访问单元。顺序不能反——扣住的负载得先进解复用器。
    pub fn flush_media(&mut self) {
        for p in self.rtp.flush() {
            self.feed_container(&p);
        }
        if let Some(ps) = self.ps.as_mut() {
            for f in ps.flush() {
                self.deliver_frame(&f.data, f.pts, f.has_pts);
            }
        }
    }

    /// 主循环：消费消息直到连接关闭、出错或被停止。
    ///
    /// 与 Go 侧 `Run` / Python 侧 `run` 同语义：每帧循环解包，本帧内所有协议消息都要
    /// 交付；解不出来则把剩余整段当原始视频。
    pub fn run(&mut self) -> Result<(), Error> {
        let result = self.run_loop();
        // 流结束必须 flush：一个 pack 关闭上一帧，最后一帧只有在这里才完成。
        self.flush_media();
        result
    }

    fn run_loop(&mut self) -> Result<(), Error> {
        self.reset_media_state();
        loop {
            // 读超时 = min(看门狗窗口, keepalive 间隔)：到点即唤醒，该ping 的 ping、
            // 该判卡死的判卡死。无看门狗时也按 keepalive 间隔醒。
            let timeout = match (self.config.stall_timeout, self.config.keepalive_interval) {
                (Some(s), k) => Some(s.min(k)),
                (None, k) => Some(k),
            };
            if let Some(ws) = self.ws.as_mut() {
                ws.set_read_timeout(timeout)?;
            }
            let msg = match self.ws.as_mut() {
                Some(ws) => ws.read_message(),
                None => return Err(Error::NotConnected),
            };
            match msg {
                Ok(Message::Text(payload)) => {
                    self.last_activity = Instant::now();
                    self.handle_text(&payload)?;
                }
                Ok(Message::Binary(payload)) => {
                    self.last_activity = Instant::now();
                    self.handle_binary(&payload)?;
                }
                Err(WsError::Timeout) => {
                    // 看门狗：窗口内没有任何消息到达 → 卡死。socket 还开着但设备停流时，
                    // 这是唯一能发现的信号。
                    if let Some(st) = self.config.stall_timeout {
                        if self.last_activity.elapsed() >= st {
                            let err = Error::Stalled;
                            self.emit_error(&err);
                            return Err(err);
                        }
                    }
                    if self.last_ping.elapsed() >= self.config.keepalive_interval {
                        if let Some(ws) = self.ws.as_mut() {
                            let _ = ws.send_ping(); // 写失败由下一次读暴露
                        }
                        self.last_ping = Instant::now();
                    }
                }
                Err(other) => {
                    // 停止请求把 socket shutdown 掉，读会立刻返回——这不是错误。
                    if self.stop_flag.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    let err: Error = other.into();
                    self.emit_error(&err);
                    return Err(err);
                }
            }
            if self.stop_flag.load(Ordering::SeqCst) {
                return Ok(());
            }
        }
    }

    /// 服务端 TEXT JSON 响应：realplay 成功即附 SDP；错误则终态返回 `ServerError`。
    fn handle_text(&mut self, payload: &[u8]) -> Result<(), Error> {
        let resp: serde_json::Value = match serde_json::from_slice(payload) {
            Ok(v) => v,
            Err(_) => {
                self.log(format!("Text msg (not JSON): {} bytes", payload.len()));
                return Ok(());
            }
        };
        let code = resp
            .get("errorCode")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if code != 0.0 {
            let msg = resp
                .get("errorMsg")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let srv = ServerError::new(code as i32, msg);
            self.log(format!("{srv}"));
            self.emit_error(&Error::Server(srv.clone()));
            return Err(Error::Server(srv));
        }
        if let Some(sdp) = resp.get("sdp").and_then(|v| v.as_str()) {
            if !sdp.is_empty() {
                self.log(format!("realplay OK, SDP length={}", sdp.len()));
                let info = parse_sdp(sdp);
                self.media_info = Some(info.clone());
                if let Some(cb) = self.callbacks.on_media_info.as_mut() {
                    cb(&info);
                }
            }
        } else if self.config.verbose {
            // 仍然丢弃——但静默丢弃就没法回答"代理在云台转动时推过别的东西吗"。
            // 只记键集合与大小：这个通道上的值可能带会话凭据，形状才是答案。
            let mut keys: Vec<&str> = resp
                .as_object()
                .map(|m| m.keys().map(|k| k.as_str()).collect())
                .unwrap_or_default();
            keys.sort_unstable();
            self.log(format!(
                "Text msg (no errorCode/sdp): {} bytes keys={:?}",
                payload.len(),
                keys
            ));
        }
        Ok(())
    }

    /// 二进制帧：循环解包到尾；解不出来 → 剩余整段当原始视频。
    fn handle_binary(&mut self, payload: &[u8]) -> Result<(), Error> {
        let mut rest: &[u8] = payload;
        while !rest.is_empty() {
            let msg = match protocol::unpack(rest) {
                Ok(msg) => msg,
                Err(_) => {
                    // 头部不完整 / 载荷截断 → 原始视频数据。
                    self.log(format!("Raw video frame: {} bytes", rest.len()));
                    self.feed_video(rest);
                    break;
                }
            };
            match msg.msg_type {
                MSG_TYPE_VIDEO_DATA => self.feed_video(msg.payload),
                MSG_TYPE_AUDIO_DATA => {
                    if let Some(cb) = self.callbacks.on_audio_data.as_mut() {
                        cb(msg.payload);
                    }
                }
                MSG_TYPE_SESSION_ERROR => {
                    let err = Error::Protocol(format!(
                        "session error: {}",
                        String::from_utf8_lossy(msg.payload)
                    ));
                    self.emit_error(&err);
                    return Err(err);
                }
                MSG_TYPE_KEEPALIVE => {
                    self.log(format!(
                        "Protocol msg 0x06 keepalive: {} bytes",
                        msg.payload.len()
                    ));
                }
                other => {
                    if self.config.verbose {
                        let head = &msg.payload[..msg.payload.len().min(16)];
                        self.log(format!(
                            "Protocol msg 0x{other:02x}: {} bytes (discarded) head={}",
                            msg.payload.len(),
                            hex_head(head)
                        ));
                    }
                }
            }
            rest = msg.remaining;
        }
        Ok(())
    }

    /// 补齐单帧元信息后交给调用方。`on_video_frame` 优先于 `on_video_data`，避免重复下发。
    fn deliver_frame(&mut self, data: &[u8], pts: i64, has_pts: bool) {
        if self.callbacks.on_video_frame.is_none() && self.callbacks.on_video_data.is_none() {
            return;
        }
        let start = *self.start_time.get_or_insert_with(Instant::now);
        self.frame_count += 1;

        let mut codec = self
            .media_info
            .as_ref()
            .map(|i| i.codec.clone())
            .unwrap_or_default();
        // 同理：解不出的 MEDIAINFO 头会让编码为空，没编码就判不了关键帧、也还原不了分辨率。
        // 码流自己说得清是哪种编码。
        if codec.is_empty() {
            codec = sniff_codec(data).to_string();
            if !codec.is_empty() {
                if let Some(info) = self.media_info.as_mut() {
                    info.codec = codec.clone();
                }
            }
        }
        // 分辨率只能从码流内 SPS 还原（MEDIAINFO 头不带），PS 流在第一个关键帧上补齐。
        let need_resolution = self
            .media_info
            .as_ref()
            .map(|i| i.width == 0)
            .unwrap_or(true);
        if !codec.is_empty() && need_resolution {
            if let Some((w, h, sps)) = recover_resolution(data, &codec) {
                if let Some(info) = self.media_info.as_mut() {
                    info.width = w;
                    info.height = h;
                }
                if let Some(cb) = self.callbacks.on_sps.as_mut() {
                    cb(&sps);
                }
            }
        }

        let elapsed = start.elapsed();
        let clock_rate = self.media_info.as_ref().map(|i| i.clock_rate).unwrap_or(0);
        let (width, height) = self
            .media_info
            .as_ref()
            .map(|i| (i.width, i.height))
            .unwrap_or((0, 0));
        let meta = FrameMeta {
            frame_index: self.frame_count,
            is_key_frame: analyze_frame(data, &codec),
            codec,
            width,
            height,
            pts: if has_pts {
                pts
            } else if clock_rate > 0 {
                (elapsed.as_secs_f64() * clock_rate as f64) as i64
            } else {
                0
            },
            has_pts,
            timestamp_ms: elapsed.as_millis() as i64,
        };
        if self.config.verbose {
            self.log(format!(
                "Video frame #{}: {} bytes (key={}, codec={})",
                meta.frame_index,
                data.len(),
                meta.is_key_frame,
                meta.codec
            ));
        }

        if let Some(cb) = self.callbacks.on_video_frame.as_mut() {
            cb(&meta, data);
            return;
        }
        if let Some(cb) = self.callbacks.on_video_data.as_mut() {
            cb(data);
        }
    }

    /// 拥有整个会话生命周期：连接、鉴权、realplay、接收；传输失败后按 `max_reconnects`
    /// 重建。`ServerError` 为终态，立即停止重连——盲目重试只会烧掉本就很短的 token
    /// 时间窗。
    pub fn stream(&mut self) -> Result<(), Error> {
        let wait = if self.config.reconnect_wait.is_zero() {
            Duration::from_secs(2)
        } else {
            self.config.reconnect_wait
        };
        for attempt in 0u32.. {
            if self.stop_flag.load(Ordering::SeqCst) {
                return Ok(());
            }
            let result = self.session();
            if self.stop_flag.load(Ordering::SeqCst) {
                return Ok(());
            }
            match result {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // 服务端错误永不重试；attempt 从 0 起，max_reconnects=0 即不重连。
                    if matches!(e, Error::Server(_)) || attempt >= self.config.max_reconnects {
                        return Err(e);
                    }
                    let backoff = wait * (attempt + 1);
                    self.log(format!("session failed ({e}), reconnecting in {backoff:?}"));
                    if self.sleep_interruptible(backoff) {
                        return Ok(());
                    }
                }
            }
        }
        unreachable!()
    }

    /// 一次 connect → receive 会话，总是以关闭连接结束。
    fn session(&mut self) -> Result<(), Error> {
        self.close();
        self.reset_media_state();
        self.connect()?;
        self.authenticate()?;
        self.realplay()?;
        self.run()
    }

    /// 可被停止请求打断的睡眠。
    fn sleep_interruptible(&self, dur: Duration) -> bool {
        let step = Duration::from_millis(50);
        let mut remaining = dur;
        while remaining > Duration::ZERO {
            if self.stop_flag.load(Ordering::SeqCst) {
                return true;
            }
            let s = step.min(remaining);
            std::thread::sleep(s);
            remaining -= s;
        }
        self.stop_flag.load(Ordering::SeqCst)
    }

    /// 新会话带来新 SDP 和崭新的容器：死连接上解了一半的东西不能带进来。
    fn reset_media_state(&mut self) {
        self.rtp = RtpDetector::new();
        self.ps = None;
        self.container_known = false;
        self.media_info = None;
        self.frame_count = 0;
        self.start_time = None;
        self.last_activity = Instant::now();
        self.last_ping = Instant::now();
    }

    fn emit_error(&mut self, err: &Error) {
        if let Some(cb) = self.callbacks.on_error.as_mut() {
            cb(err);
        }
    }

    fn log(&self, msg: impl AsRef<str>) {
        if self.config.verbose {
            log::info!("[hik-ws] {}", msg.as_ref());
        }
    }
}

/// 媒体端点路径（对应 Go 侧 `buildMediaURL` 的 path+query）。
fn media_path(config: &HikConfig) -> String {
    format!(
        "/media?version={}&cipherSuites={}&sessionID=&proxy={}:{}",
        config.version, config.cipher_suites, config.device_ip, config.device_port
    )
}

/// 调试日志里的十六进制头（未知协议类型）。
fn hex_head(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
