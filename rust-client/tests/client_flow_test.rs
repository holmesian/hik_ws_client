//! 客户端全流程集成测试：mock 代理 + 真实 TCP 回环，移植 `go-client/client_test.go` 与
//! `go-client/resilience_test.go` 的用例（行为基准）。
//!
//! 覆盖：SDP/media info、协议帧消费到尾、裸载荷回退、加密标志帧、ServerError 终态、
//! 丢弃消息不脱轨、鉴权失败、停止句柄、keepalive、PS/H.265 全链路、重连、看门狗。

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::{
    expect_realplay, idr_frame, mock_config, p_frame, raw_frame, send_auth, MockConn, MockServer,
    TEST_SDP,
};
use hik_ws_client::protocol::{
    pack_message, MSG_TYPE_AUDIO_DATA, MSG_TYPE_KEEPALIVE, MSG_TYPE_SESSION_ERROR,
    MSG_TYPE_VIDEO_DATA,
};
use hik_ws_client::{Error, HikMediaClient, ServerError};

/// 帧收集器（回调线程 → 测试线程）。
pub struct FrameSink {
    metas: Mutex<Vec<hik_ws_client::FrameMeta>>,
    sizes: Mutex<Vec<usize>>,
    payloads: Mutex<Vec<Vec<u8>>>,
    audio: Mutex<Vec<Vec<u8>>>,
    errors: Mutex<Vec<String>>,
    info: Mutex<Option<hik_ws_client::MediaInfo>>,
    enough: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl FrameSink {
    const fn empty() -> Self {
        Self {
            metas: Mutex::new(Vec::new()),
            sizes: Mutex::new(Vec::new()),
            payloads: Mutex::new(Vec::new()),
            audio: Mutex::new(Vec::new()),
            errors: Mutex::new(Vec::new()),
            info: Mutex::new(None),
            enough: Mutex::new(None),
        }
    }

    fn install(&'static self, client: &mut HikMediaClient) {
        client.callbacks().on_media_info = Some(Box::new(move |info| {
            *self.info.lock().unwrap() = Some(info.clone());
        }));
        client.callbacks().on_video_frame = Some(Box::new(move |meta, data| {
            self.metas.lock().unwrap().push(meta.clone());
            self.sizes.lock().unwrap().push(data.len());
            self.payloads.lock().unwrap().push(data.to_vec());
            self.signal();
        }));
        client.callbacks().on_video_data = Some(Box::new(move |data| {
            self.payloads.lock().unwrap().push(data.to_vec());
            self.signal();
        }));
        client.callbacks().on_audio_data = Some(Box::new(move |data| {
            self.audio.lock().unwrap().push(data.to_vec());
        }));
        client.callbacks().on_error = Some(Box::new(move |e| {
            self.errors.lock().unwrap().push(e.to_string());
        }));
    }

    fn set_enough(&'static self, tx: std::sync::mpsc::Sender<()>) {
        *self.enough.lock().unwrap() = Some(tx);
    }

    fn signal(&'static self) {
        if let Some(tx) = self.enough.lock().unwrap().as_ref() {
            let _ = tx.send(());
        }
    }
}

/// 完整收流路径一个会话里全走一遍：SDP/media info、单条协议视频帧、一帧里批量
/// （视频+音频+keepalive+未知类型）、加密标志帧、无协议信封的裸帧、会话错误。
#[test]
fn full_stream_flow() {
    let mock = MockServer::start(|mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(
            r#"{{"errorCode":0,"sdp":{}}}"#,
            json_str(TEST_SDP)
        ));

        // 1. 单条协议视频消息（关键帧）
        conn.send_binary(&pack_message(MSG_TYPE_VIDEO_DATA, &idr_frame()));
        // 2. 一帧里视频 + 音频 + keepalive + 未知类型
        let mut batch = pack_message(MSG_TYPE_VIDEO_DATA, &p_frame());
        batch.extend_from_slice(&pack_message(MSG_TYPE_AUDIO_DATA, b"audio-pcm"));
        batch.extend_from_slice(&pack_message(MSG_TYPE_KEEPALIVE, b""));
        batch.extend_from_slice(&pack_message(0x07, b"unknown"));
        conn.send_binary(&batch);
        // 3. 加密标志位的视频消息（仅暴露，不据此解密）
        conn.send_binary(&pack_message(MSG_TYPE_VIDEO_DATA | 0x80, &p_frame()));
        // 4. 无协议头的裸视频
        conn.send_binary(&raw_frame());
        // 5. 会话错误终止
        conn.send_binary(&pack_message(MSG_TYPE_SESSION_ERROR, b"stream closed"));
        thread::sleep(Duration::from_millis(300));
    });

    static SINK: FrameSink = FrameSink::empty();
    let config = mock_config(mock.addr);
    let mut client = HikMediaClient::new(config);
    SINK.install(&mut client);

    connect_and_play(&mut client);
    let handle = thread::spawn(move || {
        let _ = client.run();
    });
    handle.join().unwrap();

    let info = SINK
        .info
        .lock()
        .unwrap()
        .clone()
        .expect("OnMediaInfo never fired");
    assert_eq!(info.codec, "H264");
    assert_eq!(info.clock_rate, 90000);
    assert_eq!(info.width, 1280);
    assert!(
        (720..=736).contains(&info.height),
        "height = {}",
        info.height
    );

    // 视频：idr、p、加密 p、raw
    let metas = SINK.metas.lock().unwrap();
    let sizes = SINK.sizes.lock().unwrap();
    assert_eq!(
        metas.len(),
        4,
        "video frames = {}, want 4 (idr, p, encrypted, raw)",
        metas.len()
    );
    let want = [
        (true, idr_frame().len()),
        (false, p_frame().len()),
        (false, p_frame().len()),
        (true, raw_frame().len()),
    ];
    for (i, (key, size)) in want.iter().enumerate() {
        assert_eq!(metas[i].is_key_frame, *key, "frame {i}: key");
        assert_eq!(sizes[i], *size, "frame {i}: payload size");
        assert_eq!(metas[i].frame_index, i as u64 + 1, "frame {i}: index");
        assert_eq!(metas[i].codec, "H264", "frame {i}: codec");
        assert_eq!(metas[i].width, 1280, "frame {i}: width");
        if i > 0 {
            assert!(
                metas[i].timestamp_ms >= metas[i - 1].timestamp_ms,
                "frame {i}: timestamp went backwards"
            );
        }
    }

    let audio = SINK.audio.lock().unwrap();
    assert_eq!(audio.len(), 1);
    assert_eq!(audio[0], b"audio-pcm");

    let errors = SINK.errors.lock().unwrap();
    assert_eq!(
        errors.len(),
        1,
        "errors = {errors:?}, want the session error only"
    );
    assert_eq!(errors[0], "session error: stream closed");
}

/// 只注册 `on_video_data` 的调用方也必须收到每条净荷（协议帧与裸帧都算）。
#[test]
fn on_video_data_only() {
    let mock = MockServer::start(|mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(
            r#"{{"errorCode":0,"sdp":{}}}"#,
            json_str(TEST_SDP)
        ));
        conn.send_binary(&pack_message(MSG_TYPE_VIDEO_DATA, &idr_frame()));
        conn.send_binary(&raw_frame());
        conn.send_binary(&pack_message(MSG_TYPE_SESSION_ERROR, b"bye"));
        thread::sleep(Duration::from_millis(300));
    });

    static SINK: FrameSink = FrameSink::empty();
    let mut client = HikMediaClient::new(mock_config(mock.addr));
    client.callbacks().on_video_data = Some(Box::new(move |data| {
        SINK.payloads.lock().unwrap().push(data.to_vec());
    }));
    client.callbacks().on_error = Some(Box::new(|_| {}));

    connect_and_play(&mut client);
    thread::spawn(move || {
        let _ = client.run();
    })
    .join()
    .unwrap();

    let payloads = SINK.payloads.lock().unwrap();
    assert_eq!(payloads.len(), 2, "payloads = {}, want 2", payloads.len());
    assert_eq!(payloads[0], idr_frame());
    assert_eq!(payloads[1], raw_frame());
}

/// 一条二进制帧可能载着多条协议消息，读循环必须解包到尾——只解第一条会静默丢帧。
/// 尾部解不出来（声明长度超过剩余字节）时必须按裸视频按序交付。
#[test]
fn batched_frame_consumed_to_tail() {
    let mock = MockServer::start(|mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(
            r#"{{"errorCode":0,"sdp":{}}}"#,
            json_str(TEST_SDP)
        ));

        let mut batch = pack_message(MSG_TYPE_VIDEO_DATA, &idr_frame());
        batch.extend_from_slice(&pack_message(MSG_TYPE_VIDEO_DATA, &p_frame()));
        batch.extend_from_slice(&raw_frame());
        conn.send_binary(&batch);
        conn.send_binary(&pack_message(MSG_TYPE_SESSION_ERROR, b"bye"));
        thread::sleep(Duration::from_millis(300));
    });

    static SINK: FrameSink = FrameSink::empty();
    let mut client = HikMediaClient::new(mock_config(mock.addr));
    client.callbacks().on_video_data = Some(Box::new(move |data| {
        SINK.payloads.lock().unwrap().push(data.to_vec());
    }));
    client.callbacks().on_error = Some(Box::new(|_| {}));

    connect_and_play(&mut client);
    thread::spawn(move || {
        let _ = client.run();
    })
    .join()
    .unwrap();

    let payloads = SINK.payloads.lock().unwrap();
    let want = [idr_frame(), p_frame(), raw_frame()];
    assert_eq!(payloads.len(), want.len(), "frame not consumed to the tail");
    for (i, w) in want.iter().enumerate() {
        assert_eq!(&payloads[i], w, "payload {i}");
    }
}

/// realplay 失败路径：TEXT 里 errorCode != 0 → ServerError（终态，不重连）。
#[test]
fn server_error_text() {
    let mock = MockServer::start(|mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(r#"{"errorCode":28316423,"errorMsg":"url expired"}"#);
        thread::sleep(Duration::from_millis(300));
    });

    static SINK: FrameSink = FrameSink::empty();
    let mut client = HikMediaClient::new(mock_config(mock.addr));
    client.callbacks().on_error = Some(Box::new(move |e| {
        SINK.errors.lock().unwrap().push(e.to_string());
    }));

    connect_and_play(&mut client);
    thread::spawn(move || {
        let _ = client.run();
    })
    .join()
    .unwrap();

    let errors = SINK.errors.lock().unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0], "server error code=28316423 msg=url expired");
}

/// 鉴权阶段服务端报错：Authenticate 必须拒绝，不能带着空 PKD/rand 继续。
#[test]
fn authenticate_server_error() {
    let mock = MockServer::start(|mut conn: MockConn, _| {
        conn.accept_handshake();
        conn.send_text(r#"{"errorCode":65559,"errorMsg":"auth failed"}"#);
        thread::sleep(Duration::from_millis(200));
    });

    let mut client = HikMediaClient::new(mock_config(mock.addr));
    client.connect().expect("connect");
    let err = client.authenticate();
    assert!(
        err.is_err(),
        "Authenticate accepted an errorCode != 0 response"
    );
    match err.unwrap_err() {
        Error::Server(ServerError { code, .. }) => assert_eq!(code, 65559),
        other => panic!("want ServerError, got {other:?}"),
    }
}

/// 被丢弃的消息（无 errorCode/sdp 的 TEXT、非 JSON TEXT、未知二进制类型）必须进 Verbose
/// 日志、且不得脱轨其后协议消息的解析、不得漏进媒体路径。
#[test]
fn discarded_messages_logged_not_parsed() {
    let mock = MockServer::start(|mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(
            r#"{{"errorCode":0,"sdp":{}}}"#,
            json_str(TEST_SDP)
        ));
        // 客户端没有 handler 的 TEXT 帧。
        conn.send_text(r#"{"cmd":"ptzStatus","pan":1200}"#);
        // 根本不是 JSON 的 TEXT。
        conn.send_text("not json");
        // 未知二进制类型，随后跟一个真帧：未知类型不得让解析脱轨。
        conn.send_binary(&pack_message(0x07, b"\x01\x02\x03status"));
        conn.send_binary(&pack_message(MSG_TYPE_VIDEO_DATA, &idr_frame()));
        thread::sleep(Duration::from_millis(400));
    });

    // 捕获 log crate 的输出（只有本用例开 Verbose，日志行不会互相污染）。
    static LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    struct Capture;
    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            LOGS.lock().unwrap().push(format!("{}", record.args()));
        }
        fn flush(&self) {}
    }
    static CAPTURE: Capture = Capture;
    let _ = log::set_logger(&CAPTURE);
    log::set_max_level(log::LevelFilter::Info);

    static SINK: FrameSink = FrameSink::empty();
    let mut config = mock_config(mock.addr);
    config.verbose = true;
    let mut client = HikMediaClient::new(config);
    client.callbacks().on_video_data = Some(Box::new(move |data| {
        SINK.payloads.lock().unwrap().push(data.to_vec());
    }));
    client.callbacks().on_error = Some(Box::new(move |e| {
        SINK.errors.lock().unwrap().push(e.to_string());
    }));

    connect_and_play(&mut client);
    thread::spawn(move || {
        let _ = client.run();
    })
    .join()
    .unwrap();

    let payloads = SINK.payloads.lock().unwrap();
    assert_eq!(
        payloads.len(),
        1,
        "discarded messages leaked into the media path"
    );
    assert_eq!(
        payloads[0],
        idr_frame(),
        "frame after the discarded messages"
    );

    // mock 发完帧后关闭连接：唯一的错误应是这次 EOF，不是别的。
    let errors = SINK.errors.lock().unwrap();
    assert_eq!(errors.len(), 1, "errors = {errors:?}");
    assert!(
        errors[0].contains("connection closed"),
        "errors = {errors:?}"
    );

    let logs = LOGS.lock().unwrap();
    let joined = logs.join("\n");
    assert!(
        joined.contains("Text msg (no errorCode/sdp)"),
        "missing no-errorCode log:\n{joined}"
    );
    assert!(
        joined.contains("keys=[\"cmd\", \"pan\"]"),
        "missing keys log:\n{joined}"
    );
    assert!(
        joined.contains("Text msg (not JSON): 8 bytes"),
        "missing not-JSON log:\n{joined}"
    );
    assert!(
        joined.contains("Protocol msg 0x07"),
        "missing unknown-type log:\n{joined}"
    );
    assert!(
        joined.contains("head=010203737461747573"),
        "missing head hex log:\n{joined}"
    );
}

/// 整条 PS/H.265 恢复路径：MEDIAINFO 头（IMKH，PS+H265）只在 SDP 里声明容器与编码，
/// 分辨率只能从码流内 SPS 还原。断言解复用、SPS 分辨率、关键帧/PTS/帧数，且交付的是
/// 解复用后的基本流而不是原始 PS 字节。
#[test]
fn ps_h265_full_path() {
    // IMKH 头：container=PS(2), codec=H265(5)。
    let mut hdr = vec![0u8; 40];
    hdr[..4].copy_from_slice(b"IMKH");
    hdr[8] = 2;
    hdr[10] = 5;
    let sdp = format!(
        "v=0\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\na=Media_header:MEDIAINFO={};\n",
        hex_encode(&hdr)
    );

    const FRAMES: usize = 10;
    const WIDTH: u32 = 1280;
    const HEIGHT: u32 = 720;
    let sps = hevc_sps(WIDTH as u64, HEIGHT as u64);
    let vps = vec![0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x00];
    let pps = vec![0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0x00];

    let mut chunks = Vec::new();
    for i in 0..FRAMES {
        let mut au = vps.clone();
        au.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        au.extend_from_slice(&sps);
        au.extend_from_slice(&pps);
        if i == 0 {
            au.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x26, 0x01, 0x02]); // IDR_W_DLP
        } else {
            au.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x03]); // TRAIL_R
        }
        // 25fps @ 90kHz → 每帧 3600 tick。
        let pts = (i * 3600) as i64;
        let mut chunk = ps_pack();
        chunk.extend_from_slice(&ps_video_pes(&au, pts));
        chunks.push(chunk);
    }

    let mock = MockServer::start(move |mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(r#"{{"errorCode":0,"sdp":{}}}"#, json_str(&sdp)));
        for chunk in &chunks {
            conn.send_binary(&pack_message(MSG_TYPE_VIDEO_DATA, chunk));
        }
        conn.send_binary(&pack_message(MSG_TYPE_SESSION_ERROR, b"done"));
        thread::sleep(Duration::from_millis(300));
    });

    static SINK: FrameSink = FrameSink::empty();
    let client = std::sync::Arc::new(std::sync::Mutex::new(HikMediaClient::new(mock_config(
        mock.addr,
    ))));
    {
        let mut c = client.lock().unwrap();
        SINK.install(&mut c);
        connect_and_play(&mut c);
    }
    let runner = client.clone();
    thread::spawn(move || {
        let _ = runner.lock().unwrap().run();
    })
    .join()
    .unwrap();

    // on_media_info 收到的是 SDP 时刻的快照；容器/编码/时钟在那一刻已定。
    let snapshot = SINK
        .info
        .lock()
        .unwrap()
        .clone()
        .expect("OnMediaInfo never fired");
    assert_eq!(snapshot.container, "PS");
    assert_eq!(snapshot.codec, "H265");
    assert_eq!(snapshot.clock_rate, 90000);
    // 分辨率不在 MEDIAINFO 头里，必须从码流内 SPS 还原（写回客户端持有的 media_info，
    // 对应 Go 侧回调指针可见的同一对象）。
    let live = client
        .lock()
        .unwrap()
        .media_info()
        .cloned()
        .expect("media_info");
    assert_eq!((live.width, live.height), (WIDTH, HEIGHT));

    let metas = SINK.metas.lock().unwrap();
    let sizes = SINK.sizes.lock().unwrap();
    assert_eq!(
        metas.len(),
        FRAMES,
        "frames = {}, want {FRAMES}",
        metas.len()
    );
    let mut keys = 0;
    let mut pts_list = Vec::new();
    for (i, m) in metas.iter().enumerate() {
        if m.is_key_frame {
            keys += 1;
        }
        assert_eq!(m.codec, "H265", "frame {i}: codec");
        assert_eq!((m.width, m.height), (WIDTH, HEIGHT), "frame {i}: dims");
        assert!(m.has_pts, "frame {i}: HasPTS");
        pts_list.push(m.pts);
        assert!(sizes[i] >= 7, "frame {i}: implausibly small payload");
    }
    assert_eq!(keys, 1, "keyframes = {keys}, want 1 (only the IDR)");

    // PTS 必须是真实容器 PTS，每帧递增 3600。
    for i in 1..pts_list.len() {
        assert_eq!(pts_list[i] - pts_list[i - 1], 3600, "PTS delta at {i}");
    }

    let errors = SINK.errors.lock().unwrap();
    assert_eq!(
        errors.len(),
        1,
        "errors = {errors:?}, want the single session error"
    );
}

/// 代理在流中间掉线是常见现场故障：Stream 必须重建会话并继续交付，调用方无感。
#[test]
fn stream_reconnects_after_drop() {
    let mock = MockServer::start(|mut conn: MockConn, n| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(
            r#"{{"errorCode":0,"sdp":{}}}"#,
            json_str(TEST_SDP)
        ));
        if n == 0 {
            // 一帧，然后不做关闭握手直接消失。
            conn.send_binary(&pack_message(MSG_TYPE_VIDEO_DATA, &idr_frame()));
            return;
        }
        for _ in 0..50 {
            if conn
                .send_binary_checked(&pack_message(MSG_TYPE_VIDEO_DATA, &p_frame()))
                .is_err()
            {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    static SINK: FrameSink = FrameSink::empty();
    let (tx, rx) = std::sync::mpsc::channel();
    SINK.set_enough(tx);

    let mut config = mock_config(mock.addr);
    config.max_reconnects = 3;
    config.reconnect_wait = Duration::from_millis(20);
    let mut client = HikMediaClient::new(config);
    client.callbacks().on_video_data = Some(Box::new(move |_| SINK.signal()));
    client.callbacks().on_error = Some(Box::new(|_| {}));
    let stop = client.stop_handle();

    let handle = thread::spawn(move || client.stream());

    // 收到 3 帧就够证明重连后仍在交付（第 1 帧来自坠掉的连接，其余来自重连）。
    let mut count = 0;
    while count < 3 {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => count += 1,
            Err(_) => break,
        }
    }
    assert!(count >= 3, "only {count} frames after reconnect");
    stop.stop();
    let result = handle.join().unwrap();
    assert!(
        result.is_ok(),
        "stream returned {result:?}, want Ok on stop"
    );
    let conns = mock.conns.load(Ordering::SeqCst);
    assert!(
        conns >= 2,
        "connections = {conns}, want >= 2 (no reconnect happened)"
    );
}

/// openUrl token 一次性：服务端错误用同一 URL 重试只会拿到同样的码。Stream 必须在
/// 第一个服务端错误后放弃。
#[test]
fn stream_server_error_not_retried() {
    let mock = MockServer::start(|mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(r#"{"errorCode":28316423,"errorMsg":"url expired"}"#);
        thread::sleep(Duration::from_millis(300));
    });

    let mut config = mock_config(mock.addr);
    config.max_reconnects = 3;
    config.reconnect_wait = Duration::from_millis(10);
    let mut client = HikMediaClient::new(config);
    client.callbacks().on_error = Some(Box::new(|_| {}));

    let err = thread::spawn(move || client.stream()).join().unwrap();
    match err {
        Err(Error::Server(ServerError { code, .. })) => assert_eq!(code, 28316423),
        other => panic!("want ServerError, got {other:?}"),
    }
    assert_eq!(
        mock.conns.load(Ordering::SeqCst),
        1,
        "a server error must not be retried"
    );
}

/// 静默掉流：socket 健康但相机停发。没有看门狗客户端会永远阻塞在读上。
#[test]
fn stream_stall_timeout() {
    let mock = MockServer::start(|mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(
            r#"{{"errorCode":0,"sdp":{}}}"#,
            json_str(TEST_SDP)
        ));
        thread::sleep(Duration::from_secs(3)); // 从此静默
    });

    let mut config = mock_config(mock.addr);
    config.stall_timeout = Some(Duration::from_millis(150));
    let mut client = HikMediaClient::new(config);
    client.callbacks().on_error = Some(Box::new(|_| {}));

    let start = std::time::Instant::now();
    let err = thread::spawn(move || client.stream()).join().unwrap();
    assert!(
        matches!(err, Err(Error::Stalled)),
        "want ErrStalled, got {err:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "stall detected after {:?}",
        start.elapsed()
    );
}

/// 卡死的流要被恢复，不只是上报。
#[test]
fn stream_stall_timeout_reconnects() {
    let mock = MockServer::start(|mut conn: MockConn, n| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(
            r#"{{"errorCode":0,"sdp":{}}}"#,
            json_str(TEST_SDP)
        ));
        if n == 0 {
            thread::sleep(Duration::from_secs(2)); // 卡死
            return;
        }
        for _ in 0..50 {
            if conn
                .send_binary_checked(&pack_message(MSG_TYPE_VIDEO_DATA, &p_frame()))
                .is_err()
            {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    static SINK: FrameSink = FrameSink::empty();
    let (tx, rx) = std::sync::mpsc::channel();
    SINK.set_enough(tx);

    let mut config = mock_config(mock.addr);
    config.stall_timeout = Some(Duration::from_millis(150));
    config.max_reconnects = 2;
    config.reconnect_wait = Duration::from_millis(10);
    let mut client = HikMediaClient::new(config);
    client.callbacks().on_video_data = Some(Box::new(move |_| SINK.signal()));
    client.callbacks().on_error = Some(Box::new(|_| {}));
    let stop = client.stop_handle();

    let handle = thread::spawn(move || client.stream());
    let got = rx.recv_timeout(Duration::from_secs(5));
    assert!(got.is_ok(), "no frame after stall recovery");
    stop.stop();
    handle.join().unwrap().unwrap();
}

/// keepalive：流空闲期间周期性 WebSocket ping 要到达服务端。
#[test]
fn keepalive_pings() {
    let pinged = Arc::new(AtomicUsize::new(0));
    let pinged_server = pinged.clone();
    let mock = MockServer::start(move |mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(
            r#"{{"errorCode":0,"sdp":{}}}"#,
            json_str(TEST_SDP)
        ));
        // 持续读客户端帧：ping（opcode 0x9）计数。
        loop {
            match conn.try_read_client_message(Duration::from_millis(100)) {
                Some((0x9, _)) => pinged_server.fetch_add(1, Ordering::SeqCst),
                Some(_) => continue,
                None => break,
            };
        }
    });

    let mut config = mock_config(mock.addr);
    config.keepalive_interval = Duration::from_millis(50);
    let mut client = HikMediaClient::new(config);
    client.callbacks().on_error = Some(Box::new(|_| {}));

    let stop = client.stop_handle();
    let handle = thread::spawn(move || client.stream());
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while pinged.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        pinged.load(Ordering::SeqCst) > 0,
        "no keepalive ping received"
    );
    stop.stop();
    handle.join().unwrap().unwrap();
}

/// 停止句柄：stop() 之后 stream() 必须及时返回，且是干净退出（Ok）。
#[test]
fn stop_handle_returns_promptly() {
    let mock = MockServer::start(|mut conn: MockConn, _| {
        conn.accept_handshake();
        send_auth(&mut conn);
        expect_realplay(&mut conn);
        conn.send_text(&format!(
            r#"{{"errorCode":0,"sdp":{}}}"#,
            json_str(TEST_SDP)
        ));
        thread::sleep(Duration::from_secs(3)); // 保持静默
    });

    let mut client = HikMediaClient::new(mock_config(mock.addr));
    client.callbacks().on_error = Some(Box::new(|e| panic!("unexpected error on stop: {e}")));
    let stop = client.stop_handle();

    let handle = thread::spawn(move || client.stream());
    thread::sleep(Duration::from_millis(200));
    stop.stop();

    let result = handle.join().unwrap();
    assert!(
        result.is_ok(),
        "stream returned {result:?}, want Ok on stop"
    );
}

// ---------- 测试辅助 ----------

/// 握手三步（对应 Go 侧 `connectAndPlay`）：connect → authenticate → realplay。
fn connect_and_play(client: &mut HikMediaClient) {
    client.connect().expect("connect");
    client.authenticate().expect("authenticate");
    client.realplay().expect("realplay");
}

/// JSON 字符串字面量。
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

/// 小写 hex 编码。
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 最小 14 字节 MPEG-PS pack 头（pack_stuffing_length=0）。
fn ps_pack() -> Vec<u8> {
    let mut v = vec![0x00, 0x00, 0x01, 0xBA];
    v.extend_from_slice(&[0; 10]);
    v
}

/// 视频 PES（stream_id 0xE0）：3 字节 MPEG-2 PES 可选头 + PTS。
fn ps_video_pes(payload: &[u8], pts: i64) -> Vec<u8> {
    let mut body = vec![0x80, 0x80, 0x05];
    body.extend_from_slice(&encode_pts(pts as u64));
    body.extend_from_slice(payload);
    let mut pes = vec![0x00, 0x00, 0x01, 0xE0];
    pes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    pes.extend_from_slice(&body);
    pes
}

fn encode_pts(pts: u64) -> [u8; 5] {
    [
        (0x20 | ((pts >> 30) & 0x07) << 1 | 0x01) as u8,
        ((pts >> 22) & 0xFF) as u8,
        (((pts >> 15) & 0x7F) << 1 | 0x01) as u8,
        ((pts >> 7) & 0xFF) as u8,
        ((pts & 0x7F) << 1 | 0x01) as u8,
    ]
}

/// 手搓一个合法 HEVC SPS NAL（2 字节 NAL 头 + RBSP）。
fn hevc_sps(w: u64, h: u64) -> Vec<u8> {
    struct BitWriter {
        buf: Vec<u8>,
        nbits: usize,
    }
    impl BitWriter {
        fn put_bit(&mut self, b: u32) {
            let idx = self.nbits / 8;
            if idx >= self.buf.len() {
                self.buf.push(0);
            }
            if b == 1 {
                self.buf[idx] |= 1 << (7 - (self.nbits % 8));
            }
            self.nbits += 1;
        }
        fn put_bits(&mut self, v: u64, n: usize) {
            for i in (0..n).rev() {
                self.put_bit(((v >> i) & 1) as u32);
            }
        }
        fn put_ue(&mut self, v: u64) {
            let val = v + 1;
            let bits = 64 - val.leading_zeros() as usize;
            for _ in 0..bits - 1 {
                self.put_bit(0);
            }
            for i in (0..bits).rev() {
                self.put_bit(((val >> i) & 1) as u32);
            }
        }
    }
    let mut tw = BitWriter {
        buf: Vec::new(),
        nbits: 0,
    };
    tw.put_bits(0x42, 8); // NAL 头字节 0（type 33 = SPS_NUT）
    tw.put_bits(0x01, 8); // NAL 头字节 1
    tw.put_bits(0, 4); // sps_video_parameter_set_id
    tw.put_bits(0, 3); // sps_max_sub_layers_minus1
    tw.put_bits(1, 1); // sps_temporal_id_nesting_flag
    tw.put_bits(0, 2); // general_profile_space
    tw.put_bits(0, 1); // general_tier_flag
    tw.put_bits(1, 5); // general_profile_idc
    tw.put_bits(0, 32); // general_profile_compatibility_flag
    tw.put_bits(0, 48); // general_constraint_indicator_flag
    tw.put_bits(93, 8); // general_level_idc
    tw.put_ue(0); // sps_seq_parameter_set_id
    tw.put_ue(1); // chroma_format_idc
    tw.put_ue(w); // pic_width_in_luma_samples
    tw.put_ue(h); // pic_height_in_luma_samples
    tw.put_bits(1, 1); // conformance_window_flag
    tw.put_ue(0);
    tw.put_ue(0);
    tw.put_ue(0);
    tw.put_ue(0);
    tw.buf
}
