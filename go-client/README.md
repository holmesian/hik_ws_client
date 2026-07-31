# Hikvision WebSocket Client (Golang 版)

这是一个将海康威视（Hikvision）Web私有协议流媒体反向代理连接功能从 Python 迁移重写至 Golang 环境的高性能库。相较于 Python 脚本，本库支持更好的高并发特性以实现多路路视频同时取流并在底层优化了资源消耗。

## 特性

- **无缝移植**：100% 涵盖了协议握手、RSA 魔改填充加密及 AES/CBC 解密传输逻辑。
- **并发与多例（Multi-Stream）**：采用 Goroutine 与 Channel 机制，您可以同时发起数十乃至上百个拉流请求，所有客户端结构相互独立，没有全局锁带来的并行瓶颈。
- **内置截图截流功能（Snapshot）**：我们附带了一个 `VideoSaver` 装饰结构用于直接挂载在回调函数中。只要您系统装有 FFMPEG，便能做到**按需频率截图**和**视频直接切片储存**。

---

## 快速运行与测试

进入 `examples` 文件夹，您可以运行示例同时拉取多路视频并且定时抓图：

```bash
cd ./examples

# 编译 demo
go build -o hik_ws_demo main.go

# 运行两路并发测试（需要替换下面具体的脱敏 URL 到您目前临时有效的代理地址）
./hik_ws_demo -url1="wss://example.com:6014/proxy/[1111::1111]:559/openUrl/tokenA" -url2="wss://example.com:6014/proxy/[1111::2222]:559/openUrl/tokenB"
```

---

## 作为依赖整合到您自己的项目中

您可以通过 `go get` 直接将此模块引入（或者放置在您 monorepo 的子模块中直接引用）：

```go
import (
	hikws "github.com/holmesian/hik_ws_client/go-client"
)
```

### 开发示例: 单流播放与截图

```go
package main

import (
	"context"
	"log"

	hikws "github.com/holmesian/hik_ws_client/go-client"
)

func main() {
    ctx := context.Background()

    // 1. 解析 Proxy 链接配置
    config, err := hikws.ParseProxyURL("wss://<proxy_host>:<port>/proxy/<device>/openUrl/<password>")
    if err != nil {
        log.Fatal(err)
    }

    // 2. 健壮性与并发选项（可选，零值即关闭）
    config.MaxReconnects = 3                // 掉线后最多重建 3 次会话
    config.ReconnectWait = 2 * time.Second  // 退避基数，第 N 次等待 N*base
    config.StallTimeout = 10 * time.Second  // 连接还在但不再来数据 = 断流
    config.AsyncDelivery = 64               // 解析/回调移出读循环，队列深度

    // 3. 初始化客户端实例
    client := hikws.NewHikMediaClient(config)
    defer client.Close()

    // 4. (可选功能) 配置按需存图，每秒抓一张报错到 ./snapshots 目录
    saver, err := hikws.NewVideoSaver(ctx, "./snapshots", "cam01", 1)
    if err == nil {
        defer saver.Close()
    }

    // 5. 挂载收流回调
    client.OnVideoData = func(data []byte) {
        // 如果注册了截屏组件，将底层数据流入组件
        if saver != nil {
            saver.Write(data)
        }
        // ... 或在此直接把 []byte 输送给您的解码器、AI 识别模块
    }

    // 6. 开启阻塞事件循环：连接 → 鉴权 → realplay → 收流，掉线自动重建
    if err := client.Stream(ctx); err != nil {
        log.Fatal(err)
    }
}
```

`Stream` 负责整条会话生命周期。若只想自己掌控握手，仍可按
`Connect` → `Authenticate` → `Realplay` → `Run` 的旧方式逐步调用，
此时重连由调用方负责。

## 目录结构

* `config.go`: 配置定义与 URL 参数提取逻辑
* `crypto.go`: 根据 Python 代码无缝移植的 AES & RSA 算法填充
* `protocol.go`: 封装定义底层 5-Bytes 海康封包头的分离
* `client.go`: WebSocket Core (依赖了可靠的 `github.com/gorilla/websocket` 来自动处理 Ping/Pong 及 WSS 掩码)
* `psdemux.go`: MPEG-PS 解复用，把 PES 还原成访问单元（设备实际下发的容器）
* `media.go`: SDP / MEDIAINFO 解析、H.264/H.265 SPS 分辨率还原
* `screenshot.go`: 用 FFMPEG `io.Pipe()` 执行帧捕获截取的封装结构
* `examples/main.go`: 并发能力和工具验证用例
* `e2e/probe/main.go`: 实链路探针，一次连接同时产出分析摘要与归档样本

---
**注意**: 生成的图片或数据会直接落地至 `NewVideoSaver()` 第二个参数指定的目录。确保运行路径有着读写文件夹子层权限。

---

## 帧元信息与 SDP

`realplay` 成功后，服务端会在返回文本中附带一段 SDP。库会解析它并通过
`OnMediaInfo(*MediaInfo)` 回调暴露给调用方，包含 `Codec`（`H264`/`H265`）、
`Container`（`PS` 等）、`ClockRate`（通常 90000）。

实测设备下发的是 **MPEG-PS 容器包裹的 H.265**，容器与编码只写在
`a=Media_header:MEDIAINFO=` 的 40 字节 IMKH 头里，**分辨率不在其中**：
`Width`/`Height` 由库从码流内的 SPS 还原（H.264 与 H.265 均支持）。

`OnVideoFrame(*FrameMeta, []byte)` 交付的是解复用后的 annex-b 基本流
（与 `screenshot.go` / `play.py` 喂给 ffmpeg 的格式一致），逐帧元信息：

- `IsKeyFrame`：是否含 IDR/IRAP（关键帧）
- `Codec`：来自 SDP，未携带时回退为 H.264
- `Width`/`Height`：来自 `MediaInfo`
- `PTS` / `HasPTS`：`HasPTS=true` 表示这是容器里的真实 90kHz PTS；
  裸码流路径没有 PTS，此时退回按到达时间合成的单调递增时间戳
- `TimestampMs`：相对首帧的到达时间

注册 `OnVideoFrame` 时不再触发 `OnVideoData`（避免同帧重复投递）；只注册
`OnVideoData` 的既有调用方行为不变。诊断用回调：`OnRawVideo` 给出解复用**前**
的容器原始字节，`OnSPS` 给出首个命中的 SPS NAL。

## 异常与并发

| 场景 | 机制 |
| --- | --- |
| 连接被断开 | `Stream` 按 `MaxReconnects` / `ReconnectWait` 线性退避重建会话 |
| 断流（socket 还在但不来数据） | `StallTimeout` 读看门狗，超时判定 `ErrStalled` 并触发重连 |
| 网络不佳 | 握手 10s 超时、写控制帧带 deadline、20s 周期 Ping 保活 |
| 服务端报错（token 过期等） | 返回 `*ServerError` 并**立即停止**重连——同一 URL 重试只会拿到同样的错误码 |
| 消费端慢 | `AsyncDelivery` 把解复用与回调放到独立 worker，与读 socket 流水线并行；队列满时反压，不丢帧 |

## 实链路探针与样本归档

```bash
go run ./e2e/probe -url 'wss://<host>:<port>/proxy/[<ip>]:<port>/openUrl/<token>' -dur 20s
```

一次连接同时完成「播放分析」与「原始样本归档」。之所以合成一个工具：代理下发的
openUrl token 是一次性的且约一分钟内失效，分两次运行的话第二次必然拿到
`errorCode 28316423`。样本按容器与编码分目录落到 `../samples/<container>_<codec>/`，
详见 [samples/README.md](../samples/README.md)。
