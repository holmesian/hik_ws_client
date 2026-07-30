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

    // 2. 初始化客户端实例
    client := hikws.NewHikMediaClient(config)
    defer client.Close()

    // 3. 开始连接并验证
    if err := client.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    if err := client.Authenticate(); err != nil {
        log.Fatal(err)
    }
    if err := client.Realplay(); err != nil {
        log.Fatal(err)
    }

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

    // 6. 开启阻塞事件循环
    client.Run(ctx)
}
```

## 目录结构

* `config.go`: 配置定义与 URL 参数提取逻辑
* `crypto.go`: 根据 Python 代码无缝移植的 AES & RSA 算法填充
* `protocol.go`: 封装定义底层 5-Bytes 海康封包头的分离
* `client.go`: WebSocket Core (依赖了可靠的 `github.com/gorilla/websocket` 来自动处理 Ping/Pong 及 WSS 掩码)
* `screenshot.go`: 用 FFMPEG `io.Pipe()` 执行帧捕获截取的封装结构
* `examples/main.go`: 并发能力和工具验证用例

---
**注意**: 生成的图片或数据会直接落地至 `NewVideoSaver()` 第二个参数指定的目录。确保运行路径有着读写文件夹子层权限。

---

## 帧元信息与 SDP

`realplay` 成功后，服务端会在返回文本中附带一段 SDP。库会解析它并通过
`OnMediaInfo(*MediaInfo)` 回调暴露给调用方，包含 `Codec`（如 `H264`/`H265`）、
`ClockRate`（通常 90000）、以及从 `sprop-parameter-sets` 的 SPS 中还原的
`Width`/`Height`（当前支持 H.264，H.265 高度暂留 0）。这相当于把 h5player
拿到的 SDP 以结构化形式直接交给调用方。

同时，由于底层交付的是裸 H.264/H.265 annex-b 码流（与 `screenshot.go` /
`play.py` 直接喂给 ffmpeg 的格式一致），库会对每个视频帧做 NAL 扫描，
通过 `OnVideoFrame(*FrameMeta, []byte)` 回调给出逐帧元信息：

- `IsKeyFrame`：是否含 IDR（关键帧）
- `Codec`：来自 SDP，未携带时回退为 H.264
- `Width`/`Height`：来自 `MediaInfo`
- `PTS` / `TimestampMs`：码流本身不带 DTS/PTS，这里按到达时间以时钟
  速率（或毫秒）合成的单调递增时间戳，供调用方排序使用

注册 `OnVideoFrame` 时不再触发 `OnVideoData`（避免同帧重复投递）；只注册
`OnVideoData` 的既有调用方行为不变。
