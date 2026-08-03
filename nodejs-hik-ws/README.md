# Node.js 海康威视 WebSocket 视频流转发服务

基于本项目 Python/Go 实现移植的 Node.js 版本，支持海康威视私有 WebSocket 协议的视频流接收和转发。

## 特性

- 完整的私有 WebSocket 协议实现（握手、认证、密钥交换、视频流接收）
- 支持 WebSocket 转发服务器模式（多客户端、多会话管理）
- 支持 H.264/H.265 视频流和音频流接收
- SDP 解析（提取 SPS/PPS、编解码信息等）
- 支持 IPv4/IPv6 设备地址
- 基于 `ws` 库实现，兼容 Node.js 18+

## 安装

```bash
cd nodejs-hik-ws
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
  // 处理视频帧
});

client.on('sdp', (sdpInfo) => {
  console.log(sdpInfo.videoCodec); // H264
});

await client.run();
```

## 文件结构

```
nodejs-hik-ws/
├── src/
│   ├── index.js      # 服务器入口
│   ├── client.js     # 海康 WS 客户端
│   ├── relay.js      # 转发服务器
│   ├── config.js     # URL 解析 / 配置
│   ├── crypto.js     # AES/RSA 加密
│   ├── protocol.js   # 协议打包/解包
│   └── sdp.js        # SDP 解析
├── test/
│   ├── crypto.test.js
│   ├── protocol.test.js
│   ├── config.test.js
│   └── sdp.test.js
├── demo.js           # 客户端演示
└── package.json
```

## 协议流程

1. 连接 `wss://proxy/media?version=0.1&cipherSuites=0&sessionID=&proxy=<device>`
2. 接收服务器下发的 `PKD`（RSA 公钥）和 `rand`（随机数）
3. 生成客户端 `iv`/`key`，发送 `realplay` 请求
4. 接收 SDP 信息
5. 接收二进制视频/音频流数据

## API

### HikMediaClient 事件

| 事件名       | 参数           | 说明               |
| ------------ | -------------- | ------------------ |
| `connected`  | -              | WebSocket 已连接   |
| `authenticated` | `{pkd, rand}` | 认证完成           |
| `sdp`        | `SDPInfo`      | 收到 SDP           |
| `video`      | `Buffer`       | 视频帧数据         |
| `audio`      | `Buffer`       | 音频数据           |
| `json`       | `object`       | JSON 控制消息      |
| `error`      | `Error`        | 错误               |
| `close`      | -              | 连接关闭           |

### HikRelayServer

```javascript
const server = new HikRelayServer({ port: 8080 });
server.start();
// server.stop();
```

## 测试

```bash
npm test
```

## 依赖

- [ws](https://github.com/websockets/ws) - WebSocket 客户端/服务器
- Node.js >= 18 (原生支持 `node:test`, `crypto`)
