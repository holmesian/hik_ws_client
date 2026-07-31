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

媒体负载**不加密**（密钥交换只用于会话鉴权）。代理下发的是容器字节，123 台真机摸底
实测共三种形态：

| 形态           | 表现                                    | 处理                                   |
| -------------- | --------------------------------------- | -------------------------------------- |
| 裸 MPEG-PS     | 消息以 `00 00 01 XX` 起始码开头          | 直接解复用                             |
| RTP 包裹的 PS  | 每个包 12 字节 RTP 头，SSRC 恒定、序号 +1 | 先剥 RTP 头，再解复用                  |
| 首包被拆       | 首个 RTP 包被拆成 8192 + 12 两条消息      | 判定窗口取前 4 条，找一对互证的包       |

**判定必须是会话级的**：逐条消息判 RTP 会把裸 PS 的续传消息（任意字节有 1/4 概率高
两位是 `0b10`）误判成 RTP，静默砍掉 12 字节，而帧数、关键帧数、分辨率全都正常。

### 6. MPEG-PS 容器

一个 pack 承载一个访问单元，`00 00 01 BA` 的 pack 头关掉上一帧——因此天然有一帧延迟，
流结束必须 flush，否则丢最后一帧。

| 起始码        | 内容                | 处理                                    |
| ------------- | ------------------- | --------------------------------------- |
| `00 00 01 BA` | pack 头             | 关闭上一个访问单元                      |
| `00 00 01 BC` | PSM                 | 跳过                                    |
| `00 00 01 E0` | 视频 PES            | 去掉 3 字节可选头后拼进当前访问单元      |
| `00 00 01 C0` | 音频 PES            | 跳过                                    |
| `00 00 01 BD` | private_stream_1    | **跳过**（见下）                        |

**`0xBD` 私有流不含云台信息。** 94 台设备的全量普查：82 台每秒发一条 96 字节
`00020017` 记录（ECB 加密，无设备密钥无法验证内容），12 台发 24 字节常量记录，另有
两台各自的私有记录。没有任何一类携带坐标、角度或定位数据。它自带 PTS，当视频处理会
把密文拼进码流、并把帧时间戳取成私有包的——所以解复用器只跳过它，不解析、不外露。

### 7. 分辨率与编码

`a=Media_header:MEDIAINFO=<hex>` 头给出容器和编码，但**不含分辨率**；且有一类设备的
头 magic 是 `HVAG` 而非 `IMKH`，本客户端解不出来。因此容器靠嗅探兜底、编码靠 NAL 头
嗅探兜底、分辨率一律从码流内的 SPS 还原。

PS 的时间戳恒为 90kHz，**不能采信 SDP 的 rtpmap**：有设备在 video m-line 上写
`a=rtpmap:8 PCMA/8000`，照抄会把 25fps 的流算成 2.22fps。

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

# 断线自动重连
python3 demo.py "wss://..." --reconnect
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
    def on_frame(meta, data):
        # data 是一个完整的 annex-b 访问单元，可直接喂解码器
        print(f"#{meta.frame_index} {meta.codec} {meta.width}x{meta.height} "
              f"key={meta.is_key_frame} pts={meta.pts} {len(data)} bytes")

    client.on_frame = on_frame

    # 运行
    await client.run()

asyncio.run(main())
```

### 回调

| 回调             | 参数                  | 说明                                                        |
| ---------------- | --------------------- | ----------------------------------------------------------- |
| `on_frame`       | `(FrameMeta, bytes)`  | 单个访问单元 + 元信息（编码/分辨率/关键帧/PTS）              |
| `on_video_data`  | `(bytes,)`            | 同样是解复用后的访问单元，只是不带元信息；设了 `on_frame` 时不再触发 |
| `on_media_info`  | `(MediaInfo,)`        | SDP 解析结果（容器、编码、时钟、SPS）                        |
| `on_sps`         | `(bytes,)`            | 从码流里还原出的 SPS NAL（含起始码）                         |
| `on_raw_video`   | `(bytes,)`            | 去掉 RTP 封装、进解复用器之前的容器字节，用于抓流存档        |
| `on_audio_data`  | `(bytes,)`            | 音频消息原样下发                                             |
| `on_error`       | `(str,)`              | 会话错误                                                     |

`FrameMeta`：`frame_index / is_key_frame / codec / width / height / pts / has_pts /
timestamp_ms`。`has_pts` 为真时 `pts` 是容器给的 90kHz 时间戳，否则是按到达时间合成的。

### 保存视频帧

```python
# 使用 --save-frames 选项保存原始帧数据
python3 demo.py "wss://..." --save-frames --output-dir ./frames
```

## 测试

```bash
# Python 媒体解析层（只依赖标准库，无需装任何东西）
python3 -m unittest test_hik_media -v

# Go 客户端
cd go-client && go test -race ./...
```

两套测试都会回放 `samples/` 里的真机采集并断言同一组帧数、关键帧数和分辨率——任一侧
的解析改坏了，回放数字就会对不上。样本由 Git LFS 管理，跑之前先 `git lfs pull`
（没拉取时用例会跳过并提示，不会误报失败）。

## 文件结构

```
hik_ws_client/
├── hik_ws_client.py     # 传输层：WebSocket、鉴权、协议封包、重连
├── hik_media.py         # 媒体解析层：RTP 判定/剥离、PS 解复用、SPS、SDP（仅标准库）
├── test_hik_media.py    # 媒体层回归测试 + 真机样本回放
├── demo.py              # 演示程序
├── play.py              # FFmpeg + OpenCV 实时播放
├── go-client/           # Go 实现（同一套解析逻辑，含 e2e 探针）
├── samples/             # 真机 MPEG-PS 采集（Git LFS），见 samples/README.md
└── README.md            # 本文档
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

## 播放与解码

客户端交付的是完整的 annex-b 访问单元，可直接喂给解码器；本仓库不内置解码。

```bash
# FFmpeg 解码 + OpenCV 实时显示
python3 play.py "wss://..."
```

`play.py` 把 `on_video_data` 收到的访问单元写进 ffmpeg 的 stdin，读回 MJPEG 显示。
自己接解码器时同理：`on_frame` 的 `data` 直接写管道即可，不需要再做 RTP 解包或
容器解析。

## 已知限制

1. **音频**：音频消息原样下发（`on_audio_data`），未解析 PES、未解码。
2. **云台**：码流里没有云台信息。94 台设备全量普查确认 `0xBD` 私有流不含坐标/角度，
   PTZ 需要走设备的独立控制接口，不在本客户端范围内。
3. **加密的私有流**：`0xBD` 记录为 ECB 加密，无设备密钥，内容无法验证。

---

## 参考资料

- `h5player.min.js`：海康威视 Web 播放器核心代码
- `Decoder.js`：WebAssembly 解码器 JavaScript 接口
- `DecodeWorker.js`：解码器 Web Worker
- `hik_ws.txt`：协议流程分析记录
- `samples/README.md`：真机采集样本与全量摸底结论
5. 完善错误处理和重连机制
