---
description: hik_ws_client 项目总规范（定位、目录职责、双实现对齐、文档结构、脱敏红线）
alwaysApply: true
---

## 这个仓库是什么

海康威视 Web 私有 WebSocket 协议的**取流客户端库**：连上代理、鉴权、取流，把设备下发的
传输字节还原成可直接喂解码器的 Annex-B 访问单元。

它是一个**独立组件**，可被任意项目引用，仓库里不写任何具体调用方的业务上下文、内部路径或
治理编号（`ADR-0005`）。调用方不应自研 RTP / 容器 / 起始码解析——本仓库的解析缺陷会直接
变成调用方的画面损坏，改这里的代码要按"库"的标准要求自己，不是按脚本。

## 目录职责

顶层是**两个并列的库** + 三类共享资产（`ADR-0005`）。

| 路径 | 职责 | 约束 |
| --- | --- | --- |
| `go-client/` | Go 库（传输 + 媒体），生产使用的就是它，也是行为基准 | 见 `media-parsing.md`；目录名是 import path 的一部分，不改 |
| `go-client/e2e/probe/` | 单路实链路探针：一次连接完成分析 + 归档 | 语义单一，别往里堆功能 |
| `python-client/` | Python 库（分析与研究工具） | 与 Go 等价对齐，见下 |
| `python-client/hik_ws_client.py` | Python 传输层：WebSocket、鉴权、封包、重连 | 不做媒体解析 |
| `python-client/hik_media.py` | Python 媒体解析层 | **仅标准库**，不引入第三方依赖 |
| `samples/` | 两侧共享：真机采集样本（Git LFS）与实测结论 | 见 `samples/README.md` |
| `docs/` | 两侧共享：与语言无关的技术文档 | 语言相关的 API 文档进各自库的 README |
| `.codebuddy/adr/` | 架构决策记录（宪法层） | 变更须经 owner 确认 |

## 双实现对齐

Go 与 Python 是**同一套解析逻辑的两个实现，Go 为准**。

- 解析行为的任何修改（判定规则、字段布局、边界处理）必须**两边同时改**，否则两边对同一
  份样本会给出不同结果——这种分歧一旦留下，下次排查时无法判断哪边是对的。
- 两边都必须回放 `samples/` 并断言**同一组**帧数、关键帧数、分辨率。这是唯一能证明"行为
  一致"的东西，其它形式的对齐（读代码、看注释）都不算。
- 只在一侧修的例外只有一种：该侧独有的工程设施（如 Go 的 `AsyncDelivery`）。这类改动不得
  改变交付给调用方的字节。
- **内存/分配策略属于这类工程设施，不是解析行为。** Go 侧两处缓冲复用（`closeAU` 精确尺寸
  拷贝 + 累加器保留容量、读循环复用 `bytes.Buffer` + 净荷 `clone`）已核验与 Python 侧
  （`hik_media.py._close_au`、`hik_ws_client.py._parse_ws_frame`/`receive_message`）交付字节
  逐位相同，**不要把它们"同步"到 Python**——CPython 的 `bytearray` 不保留容量、扩容因子只有
  1.125，照抄换不来收益。依据与复现方法见 `docs/media-pipeline.md`。

## 文档结构

- 根 `README.md` 是**仓库入口**：项目是什么、两个库各是什么、怎么跑起来、去哪看细节。不放
  协议字段表、不放字节级分析过程、不放某一侧的 API 细节。
- 各库的 API 与用法进各自的 README：`go-client/README.md`、`python-client/README.md`。
- 与语言无关的技术细节进 `docs/`：协议见 `docs/protocol.md`，媒体管线见
  `docs/media-pipeline.md`。
- **实测结论只写在 `samples/README.md`**，且必须标明是哪一轮摸底、多少台设备测出来的。
  推测与实测在这个项目里必须可区分——大量早期结论后来被真机推翻过。
- 新增文档要在 README 的文档索引里登记，否则等于不存在。

## 脱敏红线

提交进仓库的任何内容（代码、注释、示例、测试、文档、样本、摘要）**不得包含**：

- 代理主机名、设备内网地址（IPv4 / IPv6）；
- openUrl token、Bearer token、Cookie、会话 ID；
- 设备名称、部门名称等运营信息；
- 调用方项目的名称、内部路径与治理编号（`ADR-0005`）。

示例一律用 `example.com` / `[1111::2222]` / `auth_token`。提交前自查：

```bash
git diff --cached | grep -Ei 'coolmitech|holmesian\.org|openUrl/[A-Za-z0-9]{5,}|Bearer [0-9a-f]{16,}'
```

`probe` 的摘要**完全不记录源 URL**——它对分析码流没有价值，却是提交后擦不掉的东西。

## 提交与 PR

- 根因驱动、最小改动，不堆防御性代码（见 `.codebuddy/skills/` 与项目开发规范）。
- 推送前 `git pull --rebase` 确认与 `main` 无冲突。
- 每个修复都要带一条能复现该缺陷的回归用例；没有用例的修复视为未完成。
- 涉及解析行为、组件边界、依赖或目录职责的变更，先看 `.codebuddy/adr/INDEX.md`，
  与既有 `Accepted` 决策冲突时新开 ADR，经 owner 确认后再动代码。
