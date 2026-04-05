# 海康威视私有 WebSocket 协议分析文档

## 概述

本文档记录了对海康威视私有 WebSocket 协议栈的逆向分析过程，以及基于分析结果实现的 Python 客户端。

## 协议架构

### 连接模式

海康威视的 Web 视频流使用两层 WebSocket 连接：

```
┌──────────────┐          ┌─────────────────┐          ┌──────────────┐
│   Browser    │ ──WS──▶  │  Proxy Server   │ ──TCP──▶ │   Camera     │
│ (h5player)   │ ◀──WS─── │ (cloud relay)   │ ◀─RTSP─ │  (device)    │
└──────────────┘          └─────────────────┘          └──────────────┘
```

### URL 格式

代理 URL 格式：

```
wss://<proxy_host>:<proxy_port>/proxy/<device_ip>:<device_port>/openUrl/<auth>
```

示例：

```
wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token
```

媒体端点 URL：

```
wss://<proxy_host>:<proxy_port>/media?version=0.1&cipherSuites=0&sessionID=&proxy=<device>
```

## 协议流程

### 1. WebSocket 握手

客户端发送标准 HTTP Upgrade 请求：

```
GET /media?version=0.1&cipherSuites=0&sessionID=&proxy=[ipv6]:559 HTTP/1.1
Host: example.com:6014
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64_key>
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: v1.0.0
```

服务器响应：

```
HTTP/1.1 101 Switching Protocols
Sec-WebSocket-Protocol: v1.0.0
```

### 2. 认证请求 (MSG_TYPE_AUTH_REQUEST = 0x02)

发送 JSON 格式的认证信息：

```json
{
  "username": "admin",
  "password": "",
  "clientType": "web3.0",
  "keyVersion": "v1",
  "random": "uuid-without-dashes"
}
```

### 3. 密钥交换 (MSG_TYPE_KEY_EXCHANGE = 0x04)

服务器响应认证后，下发密钥参数：

```json
{
  "PKD": "服务器下发的公钥数据",
  "rand": "随机数",
  "type": "keyExchange"
}
```

### 4. 密钥生成算法

基于 `h5player.min.js` 和 `Decoder.js` 逆向分析：

```
1. password_md5 = MD5(password)
2. salt_data = SHA256(password_md5 + "rtsp" + username)
3. auth_data = SHA256(PKD + rand)
4. combined = SHA256(salt_data + auth_data + salt_data)
5. secret_key = hex(combined)
```

Python 实现：

```python
def generate_secret_key(PKD: str, rand: str, username: str, password: str) -> str:
    password_md5 = hashlib.md5(password.encode()).digest()
    salt_input = password_md5 + b"rtsp" + username.encode()
    salt_data = hashlib.sha256(salt_input).digest()
    auth_input = PKD.encode() + rand.encode()
    auth_data = hashlib.sha256(auth_input).digest()
    combined_input = salt_data + auth_data + salt_data
    combined = hashlib.sha256(combined_input).digest()
    return combined.hex()
```

### 5. 视频数据 (MSG_TYPE_VIDEO_DATA = 0x40)

服务器发送加密的视频帧：

- 帧头包含时间戳、帧类型、长度等信息
- 视频数据使用 AES-CBC 加密
- 密钥是之前生成的 secret_key

### 6. 帧格式

```
┌─────────────────────────────────────────────────────┐
│  0x24 0x34  │ 0x00 0x00  │ [4B length] │ ...      │
│  固定头     │ 保留        │ 数据长度     │ 负载数据  │
└─────────────────────────────────────────────────────┘
```

- **帧类型判断**：检查数据第5个字节的最低位
  - `0x01`：关键帧 (I-Frame)
  - `0x02`：P-Frame

## 协议消息类型

| 类型 | 名称                   | 描述           |
| ---- | ---------------------- | -------------- |
| 0x01 | MSG_TYPE_HELLO         | 握手           |
| 0x02 | MSG_TYPE_AUTH_REQUEST  | 认证请求       |
| 0x03 | MSG_TYPE_AUTH_RESPONSE | 认证响应       |
| 0x04 | MSG_TYPE_KEY_EXCHANGE  | 密钥交换       |
| 0x05 | MSG_TYPE_SESSION_ERROR | 会话错误       |
| 0x06 | MSG_TYPE_KEEPALIVE     | 心跳           |
| 0x20 | 开始预览               | 开始媒体流预览 |
| 0x40 | MSG_TYPE_VIDEO_DATA    | 视频数据       |
| 0x41 | MSG_TYPE_AUDIO_DATA    | 音频数据       |

## 消息格式

所有消息使用以下格式：

```
┌──────────┬────────────┬─────────────────────────────┐
│ 1 Byte   │ 4 Bytes    │ N Bytes                      │
│ Type     │ Length     │ Payload                       │
└──────────┴────────────┴─────────────────────────────┘
```

## WebSocket 帧

客户端发送到服务器的帧必须使用掩码：

- FIN = 1
- Opcode = 0x02 (Binary)
- MASK = 1
- Payload = 协议消息

服务器发送到客户端的帧：

- FIN = 1
- Opcode = 0x02 (Binary)
- MASK = 0
- Payload = 协议消息

## 使用方法

### 快速开始

```bash
# 进入项目目录
cd hik_ws_client

# 运行演示程序
python3 demo.py "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token"

python3 demo.py "wss://example.com:6014/proxy/[1111::3333]:559/openUrl/auth_token_b"

# 指定用户名密码
python3 demo.py "wss://..." --username admin --password yourpassword

# 启用详细输出
python3 demo.py "wss://..." -v
```

### API 使用

```python
import asyncio
from hik_ws_client import HikMediaClient, HikConfig, parse_proxy_url

async def main():
    # 方式1: 从 URL 解析配置
    config = parse_proxy_url("wss://host:port/proxy/ip:port/openUrl/auth")

    # 方式2: 直接创建配置
    config = HikConfig(
        proxy_host="host.com",
        proxy_port=6014,
        proxy_path="/proxy/ip:port",
        device_ip="192.168.1.64",
        device_port=8000,
        username="admin",
        password=""
    )

    # 创建客户端
    client = HikMediaClient(config)

    # 设置回调
    def on_video(data):
        print(f"Video: {len(data)} bytes")

    client.on_video_data = on_video

    # 运行
    await client.run()

asyncio.run(main())
```

### 保存视频帧

```python
# 使用 --save-frames 选项保存原始帧数据
python3 demo.py "wss://..." --save-frames --output-dir ./frames
```

## 已知问题

1. **IPv6 支持**：代码已支持 IPv6 设备地址，但需要完整测试
2. **视频解码**：当前只保存原始帧数据，未实现 H.264/H.265 解码
3. **音频处理**：音频流未完整解析

## 文件结构

```
hik_ws_client/
├── hik_ws_client.py    # 核心协议实现
├── demo.py             # 演示程序
├── README.md           # 本文档
└── output/             # 视频帧输出目录
```

## 依赖

### Python 环境

- Python 3.8+ (推荐 Python 3.14)
- 虚拟环境 (推荐)

### 必需依赖

```bash
# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install pycryptodome
```

### 完整依赖列表

| 包名             | 用途         | 版本要求    |
| ---------------- | ------------ | ----------- |
| pycryptodome     | AES/RSA 加密 | >= 3.23.0   |
| (标准库) asyncio | 异步IO       | Python 3.8+ |
| (标准库) json    | JSON解析     | Python 3.8+ |
| (标准库) hashlib | MD5/SHA计算  | Python 3.8+ |
| (标准库) hmac    | HMAC计算     | Python 3.8+ |
| (标准库) base64  | Base64编码   | Python 3.8+ |
| (标准库) struct  | 二进制打包   | Python 3.8+ |
| (标准库) socket  | 网络通信     | Python 3.8+ |

### 快速安装

```bash
# 方法1: 使用虚拟环境
cd /path/to/hik_ws_client
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```

## 视频帧显示和处理

### 当前状态

当前版本实现了视频流的**接收和原始数据保存**，但**未包含视频解码**。获取的原始数据是 RTP 打包的 G.711 音频和视频编码数据（如 H.264/H.265）。

### 显示视频的方法

#### 方法1: 使用 demo.py 保存帧（推荐用于调试）

```bash
# 保存原始帧数据到文件
python3 demo.py "wss://..." --save-frames --output-dir ./frames
```

保存的原始帧可用于后续解码分析。

#### 方法2: 使用回调函数处理视频数据

```python
import asyncio
from hik_ws_client import HikMediaClient, HikConfig, parse_proxy_url

async def main():
    url = "wss://..."
    config = parse_proxy_url(url)
    client = HikMediaClient(config)

    # 设置视频帧回调
    def on_video_frame(data: bytes):
        # data 是原始视频帧数据
        print(f"Received video frame: {len(data)} bytes")
        # 在这里可以实现解码和显示

    client.on_video_data = on_video_frame

    # 运行
    await client.run()

asyncio.run(main())
```

#### 方法3: 集成 OpenCV 显示（需要额外解码）

完整的视频显示需要：

1. 解析 RTP 头获取视频数据
2. 解码 H.264/H.265
3. 使用 OpenCV/PyGame 显示

示例框架：

```python
import cv2
import numpy as np

def display_frame(encoded_data: bytes):
    """
    需要实现:
    1. RTP 解包
    2. H.264/H.265 解码 (可使用 ffmpeg-python 或 decord)
    3. OpenCV 显示
    """
    # 这是一个框架，需要根据实际编码格式实现
    pass
```

### 后续工作

1. 实现完整的视频解码（H.264/H.265）
2. 添加音频解码支持
3. 实现播放控制（暂停、恢复、seek）
4. 添加 PTZ 云台控制
5. 完善错误处理和重连机制

---

## 参考资料

- `h5player.min.js`：海康威视 Web 播放器核心代码
- `Decoder.js`：WebAssembly 解码器 JavaScript 接口
- `DecodeWorker.js`：解码器 Web Worker
- `hik.txt`：协议流程分析记录

## 后续工作

1. 实现完整的视频解码（H.264/H.265）
2. 添加音频解码支持
3. 实现播放控制（暂停、恢复、seek）
4. 添加 PTZ 云台控制
5. 完善错误处理和重连机制
