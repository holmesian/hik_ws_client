# hik_ws_client

海康威视 Web 私有 WebSocket 协议的取流客户端库：连上代理、鉴权、取流，把设备下发的传输字节
还原成**可直接喂解码器的 Annex-B 访问单元**。

Go 与 Python 两套实现共用同一套解析逻辑（Go 为行为基准）。它是 DataStation 生态里字节级解析的
唯一权威实现——下游不再自行判定格式、剥 RTP 头、拼起始码。

## 快速开始

```bash
git clone https://cnb.cool/holmesian/hik_ws_client.git && cd hik_ws_client
git lfs install && git lfs pull        # 真机样本，跑回放测试需要
```

**Go**（生产使用）：

```bash
cd go-client && go build ./...
go run ./e2e/probe -url 'wss://<host>:<port>/proxy/[<ip>]:<port>/openUrl/<token>' -dur 10s
```

**Python**（分析工具）：

```bash
pip install -r requirements.txt
python3 demo.py "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token"
```

> 取流链接（openUrl token）**一次性、分钟级过期**，取到后必须立刻使用，且不要为同一个链接
> 跑两次程序。

## 测试

```bash
cd go-client && go build ./... && go vet ./... && go test -count=1 -race ./...
python3 -m unittest test_hik_media
```

两套测试都会回放 `samples/` 里的真机采集并断言**同一组**帧数、关键帧数和分辨率——任一侧改坏了
解析，回放数字就对不上。样本走 Git LFS，没 `git lfs pull` 时用例会 skip（skip 等于没跑回归）。

**注意**：帧数、fps、分辨率全对**不代表码流是对的**——已修复的每个解析缺陷都能让这些数字看起来
完全正常。正确性判据见 `.codebuddy/rules/testing.md`。

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/protocol.md](./docs/protocol.md) | 传输层协议：连接模型、握手、鉴权与密钥派生、封包格式、错误码 |
| [docs/media-pipeline.md](./docs/media-pipeline.md) | 媒体管线：RTP 判定与剥离 → PS 解复用 → 访问单元 → 元信息恢复 |
| [docs/ptz-stream-observability.md](./docs/ptz-stream-observability.md) | 云台转动时码流里能不能看出来：4 台设备 64 次转动的受控差分实测 |
| [docs/python-api.md](./docs/python-api.md) | Python 客户端用法与回调 |
| [go-client/README.md](./go-client/README.md) | Go 客户端 API、健壮性与并发选项 |
| [go-client/e2e/bench/README.md](./go-client/e2e/bench/README.md) | 多路并发压测与内存复用优化实测：并发梯度、单路资源基线、上限判据 |
| [samples/README.md](./samples/README.md) | 真机采集样本与全量摸底实测结论（证据都在这里） |
| [.codebuddy/skills/hik-stream-debug/](./.codebuddy/skills/hik-stream-debug/SKILL.md) | 测试与调试方法：给一条链接或一份 OA curl 就能跑 |
| [.codebuddy/adr/INDEX.md](./.codebuddy/adr/INDEX.md) | 架构决策记录 |
| [.codebuddy/rules/](./.codebuddy/rules/) | 开发规范（解析硬约束、验证要求、脱敏红线） |

## 文件结构

```
hik_ws_client/
├── hik_ws_client.py     # Python 传输层：WebSocket、鉴权、封包、重连
├── hik_media.py         # Python 媒体解析层（仅标准库）
├── test_hik_media.py    # Python 回归测试 + 样本回放
├── demo.py / play.py    # 演示程序 / FFmpeg + OpenCV 实时播放
├── go-client/           # Go 实现（生产路径），含 e2e/probe 单路探针与 e2e/bench 并发压测
├── samples/             # 真机 MPEG-PS 采集（Git LFS）与实测结论
├── docs/                # 技术细节文档
└── .codebuddy/          # 规范、架构决策、调试 skill
```

## 已知限制

1. **音频**原样下发，未解 PES、未解码。
2. **码流里没有云台信息**——94 台设备普查确认 `0xBD` 私有流不含坐标/角度；**转动过程中**同样
   没有（4 台设备 64 次转动的受控差分，见
   [docs/ptz-stream-observability.md](./docs/ptz-stream-observability.md)）。PTZ 需走设备独立
   控制接口。
3. **`0xBD` 私有记录为 ECB 加密**，无设备密钥，内容无法验证。

边界的完整表述见 [ADR-0004](./.codebuddy/adr/ADR-0004-component-scope-boundary.md)。

## 参考资料

- `h5player.min.js` / `Decoder.js` / `DecodeWorker.js`：海康 Web 播放器与 WASM 解码器（逆向对象）
- `hik_ws.txt`：早期协议流程分析记录
