//! hik_ws_client —— 海康威视 Web 私有 WebSocket 协议的取流客户端库（Rust 实现）。
//!
//! 连上代理、鉴权、取流，把设备下发的传输字节还原成**可直接喂解码器的 Annex-B 访问单元**。
//! 调用方不需要再自行判定格式、剥 RTP 头、拼起始码。
//!
//! 本库与 `go-client/`、`python-client/`、`nodejs-client/`、`php-client/` 并列，是同一套
//! 解析逻辑的第五个实现，**以 `go-client/` 为行为基准**（ADR-0001 多实现等价对齐、
//! ADR-0005 仓库布局）：解析行为的任何修改必须各侧同时改，且必须回放 `samples/` 断言
//! **同一组**帧数 / 关键帧数 / 分辨率。
//!
//! # 结构（传输层 / 媒体解析层分离）
//!
//! | 模块 | 层 | 职责 |
//! | --- | --- | --- |
//! | [`config`] | 传输 | 连接配置；`parse_proxy_url` 解析代理 URL |
//! | [`protocol`] | 传输 | 5 字节协议封包 / 解包；一帧多消息循环消费 |
//! | [`crypto`] | 传输 | 会话鉴权密钥派生、AES-CBC、RSA（魔改 PKCS#1 v1.5） |
//! | [`websocket`] | 传输 | RFC 6455 客户端（握手、掩码、分片重组） over rustls |
//! | [`client`] | 接线 | 会话生命周期 + 媒体链路接线（对应 `go-client/client.go`） |
//! | [`rtp`] | 媒体 | RTP 判定（会话级、跨消息互证）+ 剥离 |
//! | [`psdemux`] | 媒体 | MPEG-PS 解复用，重组访问单元，恢复 33 位 PTS |
//! | [`sps`] | 媒体 | H.264 / H.265 SPS 位解析，从码流内 SPS 还原分辨率 |
//! | [`sdp`] | 媒体 | realplay SDP / MEDIAINFO 头解析 |
//! | [`media`] | 媒体 | 编码嗅探 / 关键帧识别 / PS 嗅探 |
//! | [`media_info`] | 媒体 | `MediaInfo` / `FrameMeta` 类型 |
//!
//! 媒体层**不依赖任何第三方 crate**（与 Python 侧 `hik_media.py`、PHP 侧媒体层一致），
//! 可在任何环境直接单测。
//!
//! # 快速开始
//!
//! ```no_run
//! use hik_ws_client::{HikConfig, HikMediaClient};
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = HikConfig::from_proxy_url(
//!     "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token",
//! )?;
//! let mut client = HikMediaClient::new(config);
//!
//! client.callbacks().on_media_info = Some(Box::new(|info| {
//!     println!("container={} codec={} clock={}", info.container, info.codec, info.clock_rate);
//! }));
//! client.callbacks().on_video_frame = Some(Box::new(|meta, data| {
//!     // data 是可直接喂解码器的 Annex-B 访问单元
//!     println!("#{} {} bytes key={} pts={}", meta.frame_index, data.len(), meta.is_key_frame, meta.pts);
//! }));
//!
//! // 含重连；ServerError 为终态，立即停止
//! client.stream()?;
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod media;
pub mod media_info;
pub mod protocol;
pub mod psdemux;
pub mod rtp;
pub mod sdp;
pub mod sps;
pub mod websocket;

mod base64;
mod hex;

pub use client::{Callbacks, HikMediaClient, StopHandle};
pub use config::{HikConfig, TlsOptions};
pub use error::{Error, ServerError};
pub use media::{analyze_frame, sniff_codec};
pub use media_info::{FrameMeta, MediaInfo};
pub use protocol::{pack_message, unpack, ProtocolError, ProtocolMessage};
pub use sdp::parse_sdp;
pub use sps::{parse_h264_sps, parse_h265_sps, recover_resolution, strip_emulation_prevention};
