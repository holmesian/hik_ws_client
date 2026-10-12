# rust-client

海康威视 Web 私有 WebSocket 协议的 **Rust 取流客户端库**：连上代理、鉴权、取流，把设备下发的
传输字节还原成**可直接喂解码器的 Annex-B 访问单元**。

与 `go-client/`、`python-client/`、`nodejs-client/`、`php-client/` 并列，是同一套解析逻辑的
第五个实现；**以 `go-client/` 为行为基准**（[ADR-0001](../.codebuddy/adr/ADR-0001-transport-media-split-and-dual-implementation.md)
多实现等价对齐、[ADR-0005](../.codebuddy/adr/ADR-0005-repository-layout-and-component-independence.md)
组件独立）。

## 目录结构

传输层与媒体解析层分离（ADR-0001）：解析逻辑不依赖网络、不依赖第三方 crate，可对字节直接单测。

| 文件 | 层 | 职责 |
| --- | --- | --- |
| `src/config.rs` | 传输 | `HikConfig` / `TlsOptions`；`from_proxy_url` 解析代理 URL |
| `src/protocol.rs` | 传输 | 5 字节协议封包 / 解包；一帧多消息循环消费 |
| `src/crypto.rs` | 传输 | 密钥派生、AES-256-CBC、RSA（魔改 PKCS#1 v1.5） |
| `src/websocket.rs` | 传输 | RFC 6455 客户端（握手、掩码、分片重组） over rustls |
| `src/client.rs` | 接线 | 会话生命周期 + 媒体链路接线（对应 `go-client/client.go`） |
| `src/rtp.rs` | 媒体 | RTP 判定（会话级、跨消息互证）+ 剥离 |
| `src/psdemux.rs` | 媒体 | MPEG-PS 解复用，重组访问单元，恢复 33 位 PTS |
| `src/sps.rs` | 媒体 | H.264 / H.265 SPS 位解析，从码流内 SPS 还原分辨率 |
| `src/sdp.rs` | 媒体 | realplay SDP / MEDIAINFO 头解析 |
| `src/media.rs` | 媒体 | 编码嗅探 / 关键帧识别 |
| `src/media_info.rs` | 媒体 | `MediaInfo` / `FrameMeta` 类型 |
| `src/hex.rs` / `src/base64.rs` | 媒体 | 零依赖小编解码器（保持媒体层无第三方 crate） |
| `src/bin/demo.rs` | 工具 | 取流 demo：Annex-B 写 stdout，帧元信息写 stderr |

## 依赖

- **媒体解析层零第三方 crate**（`rtp` / `psdemux` / `sps` / `sdp` / `media` / `media_info`），
  与 Python 侧 `hik_media.py`、PHP 侧媒体层一致，任何环境可直接单测。
- 传输层：`rustls`（纯 Rust TLS，默认校验证书）+ `webpki-roots` + `sha2` / `md-5` / `aes` /
  `cbc`（RustCrypto）+ `num-bigint`（RSA modexp）+ `rand` + `serde_json` + `log`。
- **没有**第三方 WebSocket 库：握手 / 掩码 / 分片重组自己实现（与 `php-client/src/WebSocket.php`
  同取向），帧编解码有独立单测。

## 快速开始

```bash
cd rust-client
cargo build
cargo run --bin demo -- 'wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token'
cargo run --bin demo -- 'wss://…' -- -dur 10s        # 10 秒后自动停
```

作为库使用：

```rust
use hik_ws_client::{HikConfig, HikMediaClient};

let config = HikConfig::from_proxy_url(url)?;
let mut client = HikMediaClient::new(config);

client.callbacks().on_media_info = Some(Box::new(|info| {
    println!("container={} codec={} clock={}", info.container, info.codec, info.clock_rate);
});
client.callbacks().on_video_frame = Some(Box::new(|meta, data| {
    // data 是可直接喂解码器的 Annex-B 访问单元
    // meta: frame_index / is_key_frame / codec / width / height / pts / has_pts / timestamp_ms
});
client.callbacks().on_error = Some(Box::new(|e| eprintln!("error: {e}")));

let stop = client.stop_handle();   // 另一个线程里 stop.stop() 可干净结束 stream()
client.stream()?;                  // 含重连；ServerError 为终态，立即停止
```

> `on_media_info` 收到的是 **SDP 时刻的快照**；容器 / 编码 / 分辨率在码流内恢复后的最新值
> 通过 `client.media_info()` 与每帧 `FrameMeta` 读取（Go 侧回调指针可见同一对象的后续写回，
> Rust 所有权模型下以快照 + 访问器等价呈现）。

### 回调

| 回调 | 参数 | 说明 |
| --- | --- | --- |
| `on_video_frame` | `(&FrameMeta, &[u8])` | 逐帧元数据 + Annex-B 负载（优先于 `on_video_data`） |
| `on_video_data` | `(&[u8])` | 已解复用的 Annex-B 负载（向后兼容） |
| `on_raw_video` | `(&[u8])` | 解复用前的原始容器负载（诊断） |
| `on_audio_data` | `(&[u8])` | 音频负载原样下发（不解 PES、不解码，ADR-0004） |
| `on_media_info` | `(&MediaInfo)` | realplay 返回 SDP 解析出的流描述（快照） |
| `on_sps` | `(&[u8])` | 码流内首个 SPS NAL（含起始码），归档用 |
| `on_error` | `(&Error)` | 传输 / 会话错误 |

### 配置要点（`HikConfig`）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `use_tls` | `true` | `wss`。`false` 仅用于 `ws://` 测试代理 |
| `tls_options` | 默认校验证书 | `extra_root_certs_der` 附加私有 CA；`danger_accept_invalid_certs` 仅测试用（对应 Go 侧已移除的写死 `InsecureSkipVerify`，issue #33） |
| `max_reconnects` / `reconnect_wait` | 0 / 2s | 传输失败重连；`ServerError` 永不重试 |
| `stall_timeout` | `None` | 看门狗：窗口内无消息即判卡死（代理保活 socket 但设备停流时唯一的发现手段） |
| `keepalive_interval` | 20s | WebSocket ping 间隔 |
| `use_realplay_auth` | `false` | 默认空 `key`/`authorization`/`token` 请求（服务端据此不下发加密流，ADR-0004）；代理要求严格鉴权时打开 |

## 行为对齐

解析行为与 Go / Python / Node.js / PHP 逐条对齐，真机撞出来的每个缺陷都带着修复一起移植：

- **RTP 判定会话级、跨消息互证**（`rtp.rs`）：逐条判定会把裸 PS 续传消息（1/4 概率高两位
  是 `0b10`）误判成 RTP、静默砍掉 12 字节头；两条不要求相邻，容忍首包被拆成 8192 + 12。
- **剥 RTP 头连 CSRC / 扩展头 / 尾部 padding**，长度不合理时原样返回。
- **MPEG-PS 嗅探接受任意起始码（`>= 0xB9`）**：直播从流中间接入，首条可能落在音频 PES 上。
- **跳过 `0xBD` private_stream_1**：它自带 PTS，当视频处理会污染码流与时间戳（ADR-0004）。
- **一个 pack 对应一个访问单元**，流结束必须 `flush`；见到第一个 pack 头之前不收 PES。
- **PES 可选头是 3 字节**：长度当第 2 字节读会砍掉每个 PES 前 128 字节。
- **SPS 先剥防竞争字节，`scaling_list()` 用状态机读**：否则 High profile 设备分辨率恒为 0x0。
- **长度字段先扩宽再做边界检查**：`u32` 下 `5 + 0xFFFFFFFB` 回绕成 0 能骗过检查、随后越界。
- **容器 / 编码 / 分辨率都有码流兜底，SDP 只是提示**；PS 时钟恒为 90kHz，不采信 rtpmap。

与 Go 侧的差异只有**工程设施**（按 ADR-0001 属单侧自由项，不改变交付字节）：

- 同步 API（无 Go 的 `AsyncDelivery` 流水线；Node.js 侧的异步投递队列同理未移植）。
- `ws://` 明文入口（`HikConfig::use_tls = false`）供本地测试代理使用，生产仍是 `wss`。
- `StopHandle` 对应 Go 的 `context` 取消。

## 测试

```bash
cd rust-client
cargo test              # 单测 + 集成 + 样本回放
cargo clippy --all-targets
cargo fmt --check
```

- **单测**（`src/*.rs` 内 `#[cfg(test)]`）：协议封包（含溢出长度）、RTP 判定/剥离、PS 解复用
  （手写线格式字节，PES 布局 / DTS / 私有流 / 残帧丢弃）、SPS（EPB、scaling_list、真机
  High profile SPS）、SDP（IMKH / HVAG / rtpmap 音频时钟）、编解码 helper、WebSocket 帧编解码、
  鉴权向量（与 Go 基准同一组期望值，含 RSA 填充布局的私钥解密校验）。
- **集成测试**（`tests/client_flow_test.rs`）：进程内 mock 代理 + TCP 回环，移植 Go 侧
  `client_test.go` / `resilience_test.go` 的用例（全流程、批量帧、裸载荷、ServerError、
  丢弃消息、鉴权失败、PS/H.265 全链路、重连、看门狗、keepalive、停止句柄）。
- **样本回放**（`tests/sample_replay_test.rs`）：回放 `samples/` 四份真机采集，断言**与
  go-client / python-client / php-client 同一组**帧数 / 关键帧数 / 分辨率，外加严格结构
  走查（不允许 resync）与**交付字节 sha256 与 Go 基准逐位相同**的比对。

样本走 Git LFS，未拉取时回放用例 skip——**skip 等于没跑回归**：

```bash
git lfs install && git lfs pull     # 仓库根执行
```

| 样本 | 帧数 | 关键帧 | 分辨率 |
| --- | --- | --- | --- |
| `ps_h265_720p` | 611 | 25 | 1280x720 |
| `ps_h265_1080p` | 614 | 13 | 1920x1080 |
| `ps_h264_720p` | 655 | 26 | 1280x720 |
| `ps_h264_1080p` | 199 | 8 | 1920x1080 |

> 帧数、fps、分辨率全对**不代表码流是对的**——已修复的每个解析缺陷都能让这些数字看起来
> 正常。回放用例因此还断言每个访问单元以起始码开头、PTS 单调、SPS 还原正确，并与 Go 基准
> 逐字节比对，见 `.codebuddy/rules/testing.md`。
