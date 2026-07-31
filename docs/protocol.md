# 传输层协议

海康威视 Web 私有 WebSocket 协议的逆向分析结果：连接模型、握手、鉴权、封包格式。
媒体载荷的解析在 [media-pipeline.md](./media-pipeline.md)。

## 连接模型

```
┌──────────────┐          ┌─────────────────┐          ┌──────────────┐
│   Browser    │ ──WS──▶  │  Proxy Server   │ ──TCP──▶ │   Camera     │
│ (h5player)   │ ◀──WS─── │  (cloud relay)  │ ◀─RTSP── │  (device)    │
└──────────────┘          └─────────────────┘          └──────────────┘
```

浏览器不直连设备，所有流量经代理中转。

## URL 格式

代理 URL（业务平台下发的 `play_url` 就是这种）：

```
wss://<proxy_host>:<proxy_port>/proxy/<device_ip>:<device_port>/openUrl/<auth>
wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token
```

客户端据此拼出实际连接的媒体端点：

```
wss://<proxy_host>:<proxy_port>/media?version=0.1&cipherSuites=0&sessionID=&proxy=<device>
```

`<auth>`（openUrl token）**一次性、分钟级过期**，取到后必须立刻建连，且不能为同一个链接
跑两次程序。这一条约束了所有调试工具的设计，见 `.codebuddy/skills/hik-stream-debug/`。

## 握手

标准 HTTP Upgrade，子协议固定 `v1.0.0`：

```
GET /media?version=0.1&cipherSuites=0&sessionID=&proxy=[ipv6]:559 HTTP/1.1
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: v1.0.0
```

服务端回 `101 Switching Protocols` 并带回同一子协议。客户端发出的帧必须掩码
（FIN=1、Opcode=0x02 Binary、MASK=1）；服务端下行帧不掩码。

## 消息类型

| 类型 | 名称 | 说明 |
| ---- | ---- | ---- |
| 0x01 | `MSG_TYPE_HELLO` | 握手 |
| 0x02 | `MSG_TYPE_AUTH_REQUEST` | 认证请求 |
| 0x03 | `MSG_TYPE_AUTH_RESPONSE` | 认证响应 |
| 0x04 | `MSG_TYPE_KEY_EXCHANGE` | 密钥交换 |
| 0x05 | `MSG_TYPE_SESSION_ERROR` | 会话错误 |
| 0x06 | `MSG_TYPE_KEEPALIVE` | 心跳 |
| 0x20 | 开始预览（realplay） | 请求媒体流 |
| 0x40 | `MSG_TYPE_VIDEO_DATA` | 视频数据 |
| 0x41 | `MSG_TYPE_AUDIO_DATA` | 音频数据 |

## 封包格式

```
┌──────────┬────────────┬─────────────────────────────┐
│ 1 Byte   │ 4 Bytes    │ N Bytes                     │
│ Type     │ Length(BE) │ Payload                     │
└──────────┴────────────┴─────────────────────────────┘
```

- 一个 WebSocket 消息里可能连着多条协议消息，必须循环消费到尾，否则静默丢帧。
- 也存在**没有协议信封**的裸载荷消息，需要回退处理。
- `Length` 来自网络：**做加法前先扩成宽整数**。`uint32` 下 `5 + 0xFFFFFFFB` 回绕成 0，
  能骗过任何边界检查，随后越界读直接打死进程——这是真机摸底撞出来的，不是理论风险。
- `EncryptFlag`(0x80) 仅解析暴露，不据此解密：realplay 以空 key 请求，服务端不下发加密流，
  **媒体载荷本身不加密**（密钥交换只用于会话鉴权）。见 ADR-0004。

## 认证与密钥派生

认证请求（JSON）：

```json
{
  "username": "admin",
  "password": "",
  "clientType": "web3.0",
  "keyVersion": "v1",
  "random": "uuid-without-dashes"
}
```

服务端下发密钥参数：

```json
{ "PKD": "<服务器公钥数据>", "rand": "<随机数>", "type": "keyExchange" }
```

密钥派生（对照 `h5player.min.js` / `Decoder.js` 逆向所得）：

```
1. password_md5 = MD5(password)
2. salt_data    = SHA256(password_md5 + "rtsp" + username)
3. auth_data    = SHA256(PKD + rand)
4. combined     = SHA256(salt_data + auth_data + salt_data)
5. secret_key   = hex(combined)
```

```python
def generate_secret_key(PKD: str, rand: str, username: str, password: str) -> str:
    password_md5 = hashlib.md5(password.encode()).digest()
    salt_data = hashlib.sha256(password_md5 + b"rtsp" + username.encode()).digest()
    auth_data = hashlib.sha256(PKD.encode() + rand.encode()).digest()
    return hashlib.sha256(salt_data + auth_data + salt_data).digest().hex()
```

realplay 请求里的 key 用 RSA 加密，填充是海康**魔改的 PKCS#1 v1.5**（Go 侧
`crypto.go`、Python 侧同名实现，两侧有用私钥解密校验填充的单测）。

## realplay 响应与 SDP

realplay 成功后服务端在返回文本里附一段 SDP，其中
`a=Media_header:MEDIAINFO=<hex>` 声明容器与编码。**它只是提示**：magic 不一定可解、
从不携带分辨率、rtpmap 可能是错的。处理方式见 [media-pipeline.md](./media-pipeline.md)
与 ADR-0002。

## 错误码

| 错误码 | 含义 | 客户端应对 |
| --- | --- | --- |
| `28316423` | URL 已失效（token 过期或已被用过） | 重新取链接；**不要重连**，同一 URL 重试只会拿到同样的码 |
| `26214462` | 服务端取流失败（设备 `is_online=1` 也可能出现） | 换设备；客户端正常上报并结束会话即可 |
| `26214475` / `26214476` | 同上，服务端侧失败 | 同上 |

这些码不在 `h5player.min.js` 的已知错误表里，属服务端侧状态。客户端遇到 `MSG_TYPE_SESSION_ERROR`
一律返回 `*ServerError` 并**立即停止重连**——盲目重试只会烧掉本来就很短的 token 时间窗。
