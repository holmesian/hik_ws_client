# php-client

海康威视 Web 私有 WebSocket 协议的 **PHP 取流客户端库**：连上代理、鉴权、取流，把设备下发
的传输字节还原成**可直接喂解码器的 Annex-B 访问单元**。

与 `go-client/`、`python-client/`、`nodejs-client/` 并列，是同一套解析逻辑的第四个实现；
**以 `go-client/` 为行为基准**（[ADR-0001](../.codebuddy/adr/ADR-0001-transport-media-split-and-dual-implementation.md)
双实现等价对齐、[ADR-0005](../.codebuddy/adr/ADR-0005-repository-layout-and-component-independence.md)
组件独立）。

**要求 PHP 8.4+**（`readonly` 提升属性、`never` 返回类型、`str_*` 系列函数）。

## 目录结构

传输层与媒体解析层分离（ADR-0001）：解析逻辑不依赖网络，可对字节直接单测。

| 文件 | 层 | 职责 |
| --- | --- | --- |
| `src/Protocol.php` | 传输 | 5 字节协议封包 / 解包；一帧多消息循环消费 |
| `src/HikConfig.php` | 传输 | 连接配置；`fromProxyUrl` 解析代理 URL |
| `src/WebSocket.php` | 传输 | RFC 6455 客户端：握手、掩码、分片重组 |
| `src/Crypto.php` | 传输 | 会话鉴权密钥派生与 RSA 加密（可选） |
| `src/HikMediaClient.php` | 接线 | 会话生命周期 + 媒体链路接线（对应 `go-client/client.go`） |
| `src/PsDemuxer.php` | 媒体 | MPEG-PS 解复用，重组访问单元，恢复 33 位 PTS |
| `src/RtpDetector.php` | 媒体 | RTP 判定（会话级）+ 剥离 |
| `src/SpsParser.php` | 媒体 | H.264 / H.265 SPS 位解析，从码流内 SPS 还原分辨率 |
| `src/SdpParser.php` | 媒体 | realplay SDP / MEDIAINFO 头解析 |
| `src/MediaInfo.php` | 媒体 | `MediaInfo` / `FrameMeta` 类型 |
| `src/Media.php` | 媒体 | `sniffCodec` 编码判定 / `analyzeFrame` 关键帧识别 |

## 依赖

- **媒体解析层（`PsDemuxer` / `RtpDetector` / `SpsParser` / `SdpParser` / `Media`）只依赖标准库**，
  与 Python 侧 `hik_media.py` 一致，可在任何环境直接单测。
- 传输层需要 `ext-openssl`（TLS / AES）；`Crypto` 的 RSA 需要 `ext-gmp`。见 `composer.json`。

## 快速开始

```bash
# 取流（把解复用后的 Annex-B 写到 stdout，帧元数据写到 stderr）
php8.4 demo.php 'wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token'
```

作为库使用：

```php
require __DIR__ . '/php-client/src/index.php';

use HikWs\HikConfig;
use HikWs\HikMediaClient;

$client = new HikMediaClient(HikConfig::fromProxyUrl($url));

$client->onMediaInfo = fn($info) => printf("codec=%s %dx%d\n", $info->codec, $info->width, $info->height);

$client->onVideoFrame = function ($meta, string $data) {
    // $data 是可直接喂解码器的 Annex-B 访问单元
    // $meta: frameIndex / isKeyFrame / codec / width / height / pts / hasPts / timestampMs
};

$client->stream();   // 含重连；ServerError 为终态，立即停止
```

### 回调

| 回调 | 参数 | 说明 |
| --- | --- | --- |
| `onVideoFrame` | `(FrameMeta, string)` | 逐帧元数据 + Annex-B 负载（优先于 `onVideoData`） |
| `onVideoData` | `(string)` | 已解复用的 Annex-B 负载（向后兼容） |
| `onRawVideo` | `(string)` | 解复用前的原始容器负载（诊断） |
| `onAudioData` | `(string)` | 音频负载原样下发（不解 PES、不解码，ADR-0004） |
| `onMediaInfo` | `(MediaInfo)` | realplay 返回 SDP 解析出的流描述 |
| `onSps` | `(string)` | 码流内首个 SPS NAL（含起始码），归档用 |
| `onError` | `(\Throwable)` | 传输 / 会话错误 |

## 行为对齐

解析行为与 Go / Python 逐条对齐，真机撞出来的每个缺陷都带着修复一起移植：

- **RTP 判定会话级、跨消息互证**（`RtpDetector`）：逐条判定会把裸 PS 续传消息（1/4 概率高两位
  是 `0b10`）误判成 RTP，静默砍掉 12 字节头；两条不要求相邻，容忍首包被拆成 8192 + 12。
- **MPEG-PS 嗅探接受任意起始码（`>= 0xB9`）**：直播从流中间接入，首条可能落在音频 PES 上。
- **跳过 `0xBD` private_stream_1**：它自带 PTS，当视频处理会污染码流与时间戳（ADR-0004）。
- **PES 可选头是 3 字节**：长度当第 2 字节读会砍掉每个 PES 前 128 字节。
- **首个 pack 头之前的 PES 丢弃**：那是接入时未见头的访问单元尾巴。
- **SPS 先剥防竞争字节，`scaling_list()` 用状态机读**：否则 High profile 设备分辨率恒为 0x0。
- **PS 时钟恒为 90kHz**：不采信 SDP 的 rtpmap。
- **长度字段先扩宽再检查**：PHP 整数任意精度，天然无 Go 的 uint32 回绕，但超长声明仍拒绝。

`realplay` 默认以**空 `key` / `authorization` / `token`** 请求（与 go-client / python-client 一致，
服务端据此不下发加密流，媒体载荷本身不加密，ADR-0004）。代理要求严格鉴权时，构造客户端时传
`useRealplayAuth: true` 用 `Crypto` 填实这三个字段。

## 测试

```bash
git lfs install && git lfs pull     # 样本回放需要；不拉会 skip
php8.4 tests/run.php
```

不引 PHPUnit：媒体层只依赖标准库，测试也该在裸环境直接跑（与 Python 侧用 stdlib `unittest`
的取向一致）。测试回放 `samples/` 里的四份真机采集，断言**与 go-client / python-client 同一组**
帧数 / 关键帧数 / 分辨率：

| 样本 | 帧数 | 关键帧 | 分辨率 |
| --- | --- | --- | --- |
| `ps_h265_720p` | 611 | 25 | 1280x720 |
| `ps_h265_1080p` | 614 | 13 | 1920x1080 |
| `ps_h264_720p` | 655 | 26 | 1280x720 |
| `ps_h264_1080p` | 199 | 8 | 1920x1080 |

> 帧数、fps、分辨率全对**不代表码流是对的**——已修复的每个解析缺陷都能让这些数字看起来正常。
> 回放用例还断言每个访问单元以起始码开头、PTS 单调、SPS 还原正确，见 `.codebuddy/rules/testing.md`。

样本走 Git LFS，未拉取时用例 skip——**skip 等于没跑回归**。
