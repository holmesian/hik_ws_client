# go-client

海康 WebSocket 取流的 Go 实现，也是生产路径上使用的那一套，并且是两套实现的行为基准
（[ADR-0001](../.codebuddy/adr/ADR-0001-transport-media-split-and-dual-implementation.md)）。
交付给调用方的是**解复用后的 Annex-B 访问单元**，调用方不需要再做 RTP 解包或容器解析。

协议细节见 [../docs/protocol.md](../docs/protocol.md)，字节级管线见
[../docs/media-pipeline.md](../docs/media-pipeline.md)。

## 引入

```go
import hikws "github.com/holmesian/hik_ws_client/go-client"
```

## 用法

```go
package main

import (
	"context"
	"log"
	"time"

	hikws "github.com/holmesian/hik_ws_client/go-client"
)

func main() {
	ctx := context.Background()

	config, err := hikws.ParseProxyURL("wss://<host>:<port>/proxy/<device>/openUrl/<token>")
	if err != nil {
		log.Fatal(err)
	}

	// 健壮性与并发选项，零值即关闭
	config.MaxReconnects = 3               // 掉线后最多重建 3 次会话
	config.ReconnectWait = 2 * time.Second // 退避基数，第 N 次等待 N*base
	config.StallTimeout = 10 * time.Second // 连接还在但不来数据 = 断流
	config.AsyncDelivery = 64              // 解析/回调移出读循环，队列深度

	client := hikws.NewHikMediaClient(config)
	defer client.Close()

	client.OnVideoFrame = func(meta *hikws.FrameMeta, data []byte) {
		// data 是一个完整访问单元，可直接写进解码器 / ffmpeg stdin
		_ = meta.IsKeyFrame
	}

	// 阻塞事件循环：连接 → 鉴权 → realplay → 收流，掉线自动重建
	if err := client.Stream(ctx); err != nil {
		log.Fatal(err)
	}
}
```

`Stream` 接管整条会话生命周期。若要自己掌控握手，仍可按
`Connect` → `Authenticate` → `Realplay` → `Run` 逐步调用，此时重连由调用方负责。

## 回调

| 回调 | 参数 | 说明 |
| --- | --- | --- |
| `OnVideoFrame` | `(*FrameMeta, []byte)` | 访问单元 + 元信息（推荐） |
| `OnVideoData` | `([]byte)` | 同样是访问单元，不带元信息；注册了 `OnVideoFrame` 时不再触发 |
| `OnMediaInfo` | `(*MediaInfo)` | 容器 / 编码 / 时钟 / 参数集（含码流嗅探写回的结论） |
| `OnSPS` | `([]byte)` | 首个命中的 SPS NAL |
| `OnRawVideo` | `([]byte)` | 解复用**前**的容器字节，抓包归档用 |
| `OnAudioData` | `([]byte)` | 音频消息原样下发 |
| `OnError` | | 会话错误 |

`FrameMeta`：`FrameIndex / IsKeyFrame / Codec / Width / Height / PTS / HasPTS / TimestampMs`。
`HasPTS=true` 时 `PTS` 是容器里的真实 90kHz 时间戳（不从 0 开始）；否则是按到达时间合成的
单调递增值。`Width`/`Height` 由库从码流内 SPS 还原——`MEDIAINFO` 头从不携带分辨率。

## 异常与并发

| 场景 | 机制 |
| --- | --- |
| 连接被断开 | `Stream` 按 `MaxReconnects` / `ReconnectWait` 线性退避重建会话 |
| 断流（socket 还在但不来数据） | `StallTimeout` 读看门狗，超时判 `ErrStalled` 并重连 |
| 网络不佳 | 握手 10s 超时、写控制帧带 deadline、20s 周期 Ping 保活 |
| 服务端报错（token 过期等） | 返回 `*ServerError` 并**立即停止**重连——同一 URL 重试只会拿到同样的错误码 |
| 消费端慢 | `AsyncDelivery` 把解复用与回调放到独立 worker 与读 socket 流水线并行；队列满时反压，不丢帧 |

## 文件

| 文件 | 职责 |
| --- | --- |
| `config.go` | 配置与 URL 解析 |
| `crypto.go` | AES / RSA（海康魔改 PKCS#1 v1.5 填充） |
| `protocol.go` | 5 字节封包头解析 |
| `client.go` | WebSocket 会话、重连、看门狗、投递 |
| `rtp.go` | RTP 判定（会话级两条互证）与剥离 |
| `psdemux.go` | MPEG-PS 解复用，跨 PES 重组访问单元 |
| `media.go` | SDP / MEDIAINFO 解析、编码嗅探、H.264/H.265 SPS 分辨率还原 |
| `screenshot.go` | `VideoSaver`：经外部 ffmpeg 定时抓图（可选） |
| `examples/main.go` | 多路并发取流示例 |
| `e2e/probe/main.go` | 实链路探针：一次连接同时产出分析摘要与归档样本 |

## 实链路测试

```bash
go run ./e2e/probe -url 'wss://<host>:<port>/proxy/[<ip>]:<port>/openUrl/<token>' -dur 20s
```

批量摸底、从设备平台自动取链接、结果怎么读，见
[../.codebuddy/skills/hik-stream-debug/SKILL.md](../.codebuddy/skills/hik-stream-debug/SKILL.md)。

```bash
go build ./... && go vet ./... && go test -count=1 -race ./...
```
