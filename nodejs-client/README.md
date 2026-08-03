# Node.js 海康威视 WebSocket 视频流转发服务

基于本项目 Python/Go 实现移植的 Node.js 版本，支持海康威视私有 WebSocket 协议的视频流接收和转发。
目录原名 `nodejs-hik-ws`，已按仓库命名规范统一为 **`nodejs-client`**（与 `go-client` / `python-client` 并列）。

本实现以 **`go-client/` 为行为基准**（[ADR-0001](../../.codebuddy/adr/ADR-0001-transport-media-split-and-dual-implementation.md) 双实现等价对齐、
[ADR-0005](../../.codebuddy/adr/ADR-0005-repository-layout-and-component-independence.md) 组件独立）。

## 特性

- 完整的私有 WebSocket 协议实现（握手、认证、密钥交换、视频流接收）
- **MPEG-PS 解复用**（`psdemux.js`，移植自 `go-client/psdemux.go`）：重组被拆到多个 PES 包里的访问单元，恢复 33 位 PTS
- **RTP 判定与剥离**（`rtp.js`，移植自 `go-client/rtp.go`）：每个会话一次性决定媒体是否被 RTP 包裹，按对（SSRC + 连续序号）判定，剥离 12 字节固定头 + CSRC + 扩展 + 填充
- **媒体管线元数据**（`media.js`，移植自 `go-client/media.go`）：`sniffCodec` 编码判定、`analyzeFrame` 关键帧识别、`clone` 安全拷贝
- `realplay` 鉴权字段接线（`buildRealplayRequest` + `crypto.js` 的 `generateRealplayKey / generateAuthorization / generateToken`）
- **传输层健壮性**：keepalive（20s ping）、stall 看门狗、对端上报错误以 `ServerError` 终态结束（停止而非重连）
- **异步投递队列**（`asyncDelivery`）：慢消费者不阻塞读循环
- 支持 WebSocket 转发服务器模式（多客户端、多会话管理）
- 支持 H.264/H.265 视频流和音频流接收
- SDP 解析（提取 SPS/PPS、编解码信息等）
- 支持 IPv4/IPv6 设备地址
- 基于 `ws` 库实现，兼容 Node.js 18+

## 关于 realplay 鉴权字段（重要）

协议约定（`docs/protocol.md` + [ADR-0004](../../.codebuddy/adr/ADR-0004-component-scope-boundary.md)）：`realplay` 以 **空 `key`** 请求，
服务端据此不下发加密流，媒体载荷本身不加密，密钥交换只用于会话鉴权——`go-client` / `python-client` 皆如此。因此
**默认 `key/authorization/token` 为空，与二者对齐**。

当代理要求严格鉴权时，可在 config 中开启 `useRealplayAuth: true`；客户端会用 `crypto.js` 已有的三个函数填实这三个字段。
该路径默认关闭，以避免违背上述协议约定：

```javascript
const client = new HikMediaClient({ ...config, useRealplayAuth: true });
```

## 安装

```bash
cd nodejs-client
npm install
```

## 使用方式

### 方式一：直接运行客户端 Demo

```bash
node demo.js "wss://proxy.example.com:6014/proxy/[fd00:0:2c0:9::10c]:559/openUrl/auth_token"
```

### 方式二：启动转发服务器

```bash
# 默认监听 8080 端口
npm start

# 或指定端口
PORT=9000 node src/index.js
```

客户端通过 WebSocket 连接到转发服务器：

```javascript
const ws = new WebSocket('ws://localhost:8080?url=wss://proxy.example.com/...');
ws.onmessage = (e) => {
  if (e.data instanceof Blob) {
    // 视频二进制数据
  } else {
    // JSON 控制消息 (status, sdp, error)
    const msg = JSON.parse(e.data);
  }
};
```

### 方式三：作为模块使用

```javascript
import { HikMediaClient, parseProxyURL } from './src/index.js';

const config = parseProxyURL('wss://...');
const client = new HikMediaClient(config);

client.on('video', (data) => {
  // 解复用后的 Annex-B 访问单元（主输出，对齐 go-client OnVideoData）
});

client.on('videoFrame', (data, meta) => {
  // 同一份数据，附带帧元数据 { codec, isKeyFrame, pts, hasPTS }
});

client.on('sdp', (sdpInfo) => {
  console.log(sdpInfo.videoCodec); // H264
});

await client.run();
```

## 文件结构

```
nodejs-client/
├── src/
│   ├── index.js      # 对外导出入口
│   ├── client.js     # 海康 WS 客户端（握手/鉴权/媒体管线/健壮性）
│   ├── relay.js      # 转发服务器
│   ├── config.js     # URL 解析 / 配置
│   ├── crypto.js     # AES/RSA 加密（含 generateRealplayKey/Authorization/Token）
│   ├── protocol.js   # 协议打包/解包
│   ├── sdp.js        # SDP 解析
│   ├── psdemux.js    # MPEG-PS 解复用（新增，对齐 go-client）
│   ├── rtp.js        # RTP 判定与剥离（新增，对齐 go-client）
│   └── media.js      # 编码判定/关键帧识别/拷贝（新增，对齐 go-client）
├── test/
│   ├── crypto.test.js
│   ├── protocol.test.js
│   ├── config.test.js
│   ├── sdp.test.js
│   ├── registry.test.js
│   ├── media.test.js       # sniffCodec / analyzeFrame / clone（新增）
│   ├── psdemux.test.js     # PS 解复用（新增）
│   ├── rtp.test.js         # RTP 判定与剥离（新增）
│   └── client.test.js      # 鉴权接线 / ServerError / 媒体管线 / 看门狗 / 异步投递（新增）
├── demo.js           # 客户端演示
└── package.json
```

## 协议流程

1. 连接 `wss://proxy/media?version=0.1&cipherSuites=0&sessionID=&proxy=<device>`
2. 接收服务器下发的 `PKD`（RSA 公钥）和 `rand`（随机数）
3. 生成客户端 `iv`/`key`，发送 `realplay` 请求（默认空 `key`，见上文）
4. 接收 SDP 信息
5. 接收二进制视频/音频流数据，按会话判定 PS / RTP，重组为 Annex-B 访问单元

## API

### HikMediaClient 事件

| 事件名        | 参数                  | 说明                                                        |
| ------------- | --------------------- | ----------------------------------------------------------- |
| `connected`   | -                     | WebSocket 已连接                                            |
| `authenticated` | `{pkd, rand}`       | 认证完成                                                    |
| `sdp`         | `SDPInfo`             | 收到 SDP                                                    |
| `video`       | `Buffer`              | 解复用后的 Annex-B 访问单元（主输出）                      |
| `videoFrame`  | `Buffer, meta`        | 同一份数据 + 帧元数据 `{ codec, isKeyFrame, pts, hasPTS }` |
| `rawVideo`    | `Buffer`              | 解复用前的原始容器字节（诊断用）                            |
| `audio`       | `Buffer`              | 音频数据                                                    |
| `json`        | `object`              | JSON 控制消息                                               |
| `error`       | `Error`               | 错误；对端上报错误带 `isServerError` 标志，为终态           |
| `close`       | -                     | 连接关闭                                                    |

### HikRelayServer

```javascript
const server = new HikRelayServer({ port: 8080 });
server.start();
// server.stop();
```

转发服务器对 `ServerError` 终态以 `1008` 优雅关断对端连接（而非 `1011` 内部错误），与 go-client 终态语义对齐。

### 配置项（HikMediaClientConfig）

| 字段           | 默认     | 说明                                              |
| -------------- | -------- | ------------------------------------------------- |
| `keepaliveInterval` | `20000` | 心跳间隔（ms），`<=`0 关闭                         |
| `stallTimeout` | `0`      | 看门狗：超过该毫秒数无数据则判定掉线（0 = 关闭）  |
| `asyncDelivery` | `0`     | 异步投递缓冲区大小（条），`0` = 同步投递           |
| `useRealplayAuth` | `false` | 开启 `realplay` 鉴权字段接线                       |

## 测试

```bash
npm test
```

覆盖：协议/加密/SDP/注册表，以及本次对齐 go-client 新增的鉴权接线、PS 解复用、RTP 判定、媒体管线、
`ServerError` 终态、看门狗、keepalive、异步投递队列。

## 依赖

- [ws](https://github.com/websockets/ws) - WebSocket 客户端/服务器
- Node.js >= 18 (原生支持 `node:test`, `crypto`)

## 合规

本目录为仓库顶层独立组件，不引入任何调用方项目名/路径/治理编号（[ADR-0005](../../.codebuddy/adr/ADR-0005-repository-layout-and-component-independence.md)）。
`go-client/`、`python-client/`、`docs/`、`.codebuddy/` 不在本目录范围内，改动不得触碰。
