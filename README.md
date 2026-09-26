# hik_ws_client

海康威视 Web 私有 WebSocket 协议的取流客户端库：连上代理、鉴权、取流，把设备下发的传输字节
还原成**可直接喂解码器的 Annex-B 访问单元**。调用方不需要再自行判定格式、剥 RTP 头、拼起始码。

这是一个**独立组件**，不承载任何调用方项目的业务上下文（[ADR-0005](./.codebuddy/adr/ADR-0005-repository-layout-and-component-independence.md)）。

## 四个并列的实现

| 库 | 定位 | 入口 |
| --- | --- | --- |
| [`go-client/`](./go-client/README.md) | Go 实现，生产取流用这套，也是行为基准 | `import hikws "github.com/holmesian/hik_ws_client/go-client"` |
| [`python-client/`](./python-client/README.md) | Python 实现，分析与研究工具 | `from hik_ws_client import HikMediaClient` |
| [`nodejs-client/`](./nodejs-client/README.md) | Node.js 实现，WebSocket 转发服务器与客户端 | `import { HikMediaClient, HikRelayServer } from 'nodejs-client'` |
| [`php-client/`](./php-client/README.md) | PHP 实现（要求 PHP 8.4+），媒体解析层仅标准库 | `require 'php-client/src/index.php'` |

四套实现共用同一套解析逻辑、回放同一份样本、断言同一组数字（[ADR-0001](./.codebuddy/adr/ADR-0001-transport-media-split-and-dual-implementation.md)、
[ADR-0005](./.codebuddy/adr/ADR-0005-repository-layout-and-component-independence.md)）。
各库之外的目录都是**各侧共享**的资产：`samples/`（真机样本与实测结论）、`docs/`（与语言无关的
协议与管线文档）、`.codebuddy/`（规范、架构决策、调试 skill）。

## 快速开始

```bash
git clone https://cnb.cool/holmesian/hik_ws_client.git && cd hik_ws_client
git lfs install && git lfs pull        # 真机样本，跑回放测试需要
```

**Go**：

```bash
cd go-client && go build ./...
go run ./e2e/probe -url 'wss://<host>:<port>/proxy/[<ip>]:<port>/openUrl/<token>' -dur 10s
```

**Python**：

```bash
cd python-client && pip install -r requirements.txt
python3 demo.py "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token"
```

**Node.js**（WebSocket 转发服务器 / 客户端，需 Node.js ≥ 18）：

```bash
cd nodejs-client && npm install
node demo.js "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token"   # 直连客户端
npm start                                                                           # 转发服务器（默认 8080）
```

**PHP**（要求 PHP 8.4+，需 `ext-openssl` / `ext-gmp`）：

```bash
cd php-client && php8.4 demo.php "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token"
```

> 取流链接（openUrl token）**一次性、分钟级过期**，取到后必须立刻使用，且不要为同一个链接
> 跑两次程序。

## 测试

仓库根执行：

```bash
(cd go-client && go build ./... && go vet ./... && go test -count=1 -race ./...)
(cd python-client && python3 -m unittest test_hik_media)
(cd nodejs-client && npm install && npm test)
(cd php-client && php8.4 tests/run.php)
```

Go / Python / PHP 三套测试都会回放 `samples/` 里的真机采集并断言**同一组**帧数、关键帧数和分辨率——
任一侧改坏了解析，回放数字就对不上。样本走 Git LFS，没 `git lfs pull` 时用例会 skip（skip 等于没跑
回归）。
Node.js 这边带的是协议/加密/SDP/注册表单测，以及对齐 go-client 新增的鉴权（`buildRealplayRequest`
空 key 默认 / `useRealplayAuth` 接线）、PS 解复用、RTP 判定与剥离、媒体管线（sniffCodec / analyzeFrame /
clone）、`ServerError` 终态、看门狗、keepalive、异步投递队列等单测（`node --test`）。真机回放需真实设备。
PHP 这边带协议封包 / RTP / PS 解复用 / SPS / SDP / 客户端接线单测 + 四份真机样本回放（`php8.4 tests/run.php`，
不引 PHPUnit）。

**注意**：帧数、fps、分辨率全对**不代表码流是对的**——已修复的每个解析缺陷都能让这些数字看起来
完全正常。正确性判据见 `.codebuddy/rules/testing.md`。

## 目录结构

```
hik_ws_client/
├── go-client/           # Go 库（生产路径），含 e2e/probe 单路探针与 e2e/bench 并发压测
├── python-client/       # Python 库（分析工具），含 demo.py / play.py
├── nodejs-client/       # Node.js 库，WebSocket 转发服务器与客户端，含单测
├── php-client/          # PHP 库（PHP 8.4+），含 demo.php 与测试
├── samples/             # 各侧共享：真机 MPEG-PS 采集（Git LFS）与实测结论
├── docs/                # 各侧共享：与语言无关的技术文档
└── .codebuddy/          # 规范、架构决策、调试 skill
```

## 文档

| 文档 | 内容 |
| --- | --- |
| [go-client/README.md](./go-client/README.md) | Go 库 API、健壮性与并发选项 |
| [python-client/README.md](./python-client/README.md) | Python 库用法与回调 |
| [nodejs-client/README.md](./nodejs-client/README.md) | Node.js 库 API、转发服务器与单测 |
| [php-client/README.md](./php-client/README.md) | PHP 库 API、回调与测试 |
| [docs/protocol.md](./docs/protocol.md) | 传输层协议：连接模型、握手、鉴权与密钥派生、封包格式、错误码 |
| [docs/media-pipeline.md](./docs/media-pipeline.md) | 媒体管线：RTP 判定与剥离 → PS 解复用 → 访问单元 → 元信息恢复 |
| [docs/ptz-stream-observability.md](./docs/ptz-stream-observability.md) | 云台转动时码流里能不能看出来：4 台设备 64 次转动的受控差分实测 |
| [go-client/e2e/bench/README.md](./go-client/e2e/bench/README.md) | 多路并发压测与内存复用优化实测：并发梯度、单路资源基线、上限判据 |
| [samples/README.md](./samples/README.md) | 真机采集样本与全量摸底实测结论（证据都在这里） |
| [.codebuddy/skills/hik-stream-debug/](./.codebuddy/skills/hik-stream-debug/SKILL.md) | 测试与调试方法：给一条链接或一份 OA curl 就能跑 |
| [.codebuddy/adr/INDEX.md](./.codebuddy/adr/INDEX.md) | 架构决策记录 |
| [.codebuddy/rules/](./.codebuddy/rules/) | 开发规范（解析硬约束、验证要求、脱敏红线） |

## 已知限制

1. **音频**原样下发，未解 PES、未解码。
2. **码流里没有云台信息**——94 台设备普查确认 `0xBD` 私有流不含坐标/角度；**转动过程中**同样
   没有（4 台设备 64 次转动的受控差分，见
   [docs/ptz-stream-observability.md](./docs/ptz-stream-observability.md)）。PTZ 需走设备独立
   控制接口。
3. **`0xBD` 私有记录为 ECB 加密**，无设备密钥，内容无法验证。

边界的完整表述见 [ADR-0004](./.codebuddy/adr/ADR-0004-component-scope-boundary.md)。

## 参考资料

`h5player.min.js` / `Decoder.js` / `DecodeWorker.js`：海康 Web 播放器与 WASM 解码器，本库的
逆向对象。逆向结论已全部整理进 [docs/protocol.md](./docs/protocol.md) 与
[docs/media-pipeline.md](./docs/media-pipeline.md)。
