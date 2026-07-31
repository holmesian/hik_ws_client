# Python 客户端

Python 侧是**分析与研究工具**；生产取流用 [go-client](../go-client/README.md)。两套实现共用
同一套解析逻辑，Go 为行为基准（ADR-0001）。

- `hik_ws_client.py`：传输层（WebSocket、鉴权、封包、重连）
- `hik_media.py`：媒体解析层，**仅依赖标准库**

## 安装

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt      # 只有 pycryptodome（AES/RSA），媒体层不需要
```

Python 3.8+。

## 命令行

```bash
python3 demo.py "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token"
python3 demo.py "wss://..." --username admin --password yourpassword
python3 demo.py "wss://..." -v                       # 详细输出
python3 demo.py "wss://..." --reconnect               # 断线自动重连
python3 demo.py "wss://..." --save-frames --output-dir ./frames
python3 play.py "wss://..."                           # FFmpeg 解码 + OpenCV 实时显示
```

## API

```python
import asyncio
from hik_ws_client import HikMediaClient, HikConfig, parse_proxy_url

async def main():
    config = parse_proxy_url("wss://host:port/proxy/ip:port/openUrl/auth")
    # 或手动构造：HikConfig(proxy_host=..., proxy_port=..., proxy_path=...,
    #                      device_ip=..., device_port=..., username="admin", password="")

    client = HikMediaClient(config)

    def on_frame(meta, data):
        # data 是一个完整的 Annex-B 访问单元，可直接喂解码器
        print(f"#{meta.frame_index} {meta.codec} {meta.width}x{meta.height} "
              f"key={meta.is_key_frame} pts={meta.pts} {len(data)} bytes")

    client.on_frame = on_frame
    await client.run()

asyncio.run(main())
```

### 回调

| 回调 | 参数 | 说明 |
| --- | --- | --- |
| `on_frame` | `(FrameMeta, bytes)` | 单个访问单元 + 元信息 |
| `on_video_data` | `(bytes,)` | 同样是访问单元，不带元信息；设了 `on_frame` 时不再触发 |
| `on_media_info` | `(MediaInfo,)` | SDP 解析结果（容器、编码、时钟、参数集） |
| `on_sps` | `(bytes,)` | 从码流还原出的 SPS NAL（含起始码） |
| `on_raw_video` | `(bytes,)` | 去 RTP 封装、进解复用器**之前**的容器字节，抓流存档用 |
| `on_audio_data` | `(bytes,)` | 音频消息原样下发（未解 PES、未解码） |
| `on_error` | `(str,)` | 会话错误 |

`FrameMeta`：`frame_index / is_key_frame / codec / width / height / pts / has_pts /
timestamp_ms`。`has_pts` 为真时 `pts` 是容器给的 90kHz 时间戳，否则是按到达时间合成的。

## 播放与解码

客户端交付的是完整的 Annex-B 访问单元，可直接喂解码器；本仓库不内置解码（ADR-0004）。
`play.py` 就是把 `on_video_data` 收到的访问单元写进 ffmpeg 的 stdin、读回 MJPEG 显示——
自己接解码器时同理，不需要再做 RTP 解包或容器解析。

## 测试

```bash
python3 -m unittest test_hik_media -v
```

回放 `samples/` 的真机采集并断言与 Go 侧**同一组**帧数、关键帧数、分辨率。先
`git lfs pull`，否则用例 skip（skip 等于没跑回归）。
