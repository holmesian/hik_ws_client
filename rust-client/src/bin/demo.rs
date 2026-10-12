//! 取流 Demo：连上代理，把解复用后的 Annex-B 访问单元写到标准输出，帧元信息写到 stderr。
//!
//! 用法：
//!
//! ```bash
//! cargo run --bin demo -- 'wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token'
//! cargo run --bin demo -- 'wss://...' -- -dur 10s    # 10 秒后自动停
//! ```
//!
//! openUrl token 一次性、分钟级过期：取到后必须立刻用，且不要为同一个链接跑两次。

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use hik_ws_client::{HikConfig, HikMediaClient};

fn main() -> ExitCode {
    // 极简 stderr logger（不引 env_logger）。
    struct StderrLogger;
    impl log::Log for StderrLogger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            let _ = writeln!(std::io::stderr(), "{}", record.args());
        }
        fn flush(&self) {}
    }
    static LOGGER: StderrLogger = StderrLogger;
    log::set_logger(&LOGGER).ok();
    log::set_max_level(log::LevelFilter::Info);

    let mut args = std::env::args().skip(1);
    let url = match args.next() {
        Some(u) => u,
        None => {
            eprintln!("usage: demo <wss://proxy/.../openUrl/<token>> [-dur 10s]");
            return ExitCode::from(2);
        }
    };
    let mut dur: Option<Duration> = None;
    while let Some(arg) = args.next() {
        if arg == "-dur" {
            if let Some(v) = args.next() {
                match humantime_lite(&v) {
                    Some(d) => dur = Some(d),
                    None => {
                        eprintln!("invalid -dur value: {v}");
                        return ExitCode::from(2);
                    }
                }
            }
        }
    }

    let mut config = match HikConfig::from_proxy_url(&url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[error] {e}");
            return ExitCode::from(2);
        }
    };
    config.verbose = true;
    config.max_reconnects = 3;

    let mut client = HikMediaClient::new(config);
    client.callbacks().on_media_info = Some(Box::new(|info| {
        eprintln!(
            "[sdp] container={} codec={} clockRate={}",
            if info.container.is_empty() {
                "(unknown)"
            } else {
                &info.container
            },
            if info.codec.is_empty() {
                "(unknown)"
            } else {
                &info.codec
            },
            info.clock_rate
        );
    }));
    client.callbacks().on_video_frame = Some(Box::new(|meta, data| {
        eprintln!(
            "[frame] #{} {} bytes key={} codec={} {}x{} pts={}",
            meta.frame_index,
            data.len(),
            if meta.is_key_frame { "yes" } else { "no" },
            if meta.codec.is_empty() {
                "?"
            } else {
                &meta.codec
            },
            meta.width,
            meta.height,
            meta.pts
        );
        let _ = std::io::stdout().write_all(data);
        let _ = std::io::stdout().flush();
    }));
    client.callbacks().on_error = Some(Box::new(|e| {
        eprintln!("[error] {e}");
    }));

    let stop = client.stop_handle();
    let result = if let Some(dur) = dur {
        // 定时停止：另起线程等时长后置停止位。
        let stopper = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(dur);
            stopper.stop();
        });
        client.stream()
    } else {
        client.stream()
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[error] stream ended: {e}");
            ExitCode::FAILURE
        }
    }
}

/// 极简时长解析：`10s` / `500ms` / `1m`（不引 humantime）。
fn humantime_lite(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        return ms.parse::<u64>().ok().map(Duration::from_millis);
    }
    if let Some(sec) = s.strip_suffix('s') {
        return sec.parse::<u64>().ok().map(Duration::from_secs);
    }
    if let Some(min) = s.strip_suffix('m') {
        return min.parse::<u64>().ok().map(Duration::from_secs);
    }
    s.parse::<u64>().ok().map(Duration::from_secs)
}
