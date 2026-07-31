# hik_ws_client 架构决策记录（ADR）索引

本目录记录本仓库已拍板、不可随意违反的架构决策（"宪法层"），位于自动加载的
`.codebuddy/rules/` 之上。新增或修改决策须经项目 owner 确认后方可置 `Accepted`。

**状态图例**：✅ Accepted（已生效）｜⚠️ Proposed（待 owner 确认）｜⬜ Deprecated（已废弃）｜↩ Superseded（已被取代）

## 决策一览

| 编号 | 标题 | 状态 | 关联规则 |
|------|------|------|----------|
| [ADR-0001](./ADR-0001-transport-media-split-and-dual-implementation.md) | 传输层与媒体解析层分离，Go 为权威实现、Python 等价对齐 | ⚠️ Proposed | `project.md`, `testing.md` |
| [ADR-0002](./ADR-0002-stream-is-the-source-of-truth.md) | 线格式以码流为准，SDP 仅作提示；一次性判定必须跨消息互证 | ⚠️ Proposed | `media-parsing.md` |
| [ADR-0003](./ADR-0003-real-device-samples-as-regression-baseline.md) | 真机样本库（Git LFS）+ 严格结构走查作为验收基线 | ⚠️ Proposed | `testing.md` |
| [ADR-0004](./ADR-0004-component-scope-boundary.md) | 组件边界：只做取流与解复用，不解码/解密/私有流/PTZ | ⚠️ Proposed | `project.md`, `media-parsing.md` |

> 本批四条记录的都是**已落地并经真机验证的既成行为**，不是新提议——它们是把 123 台设备
> 摸底换来的结论固化成约束，确认后置 `Accepted` 即可，不需要额外改代码。

## 与 DataStation 的关系

本仓库是 DataStation 生态里视频流字节级解析的唯一权威实现，对应 DataStation
`ADR-0030`（视频流字节级解析收敛至 hik_ws_client 客户端库，已 Accepted）：下游
`wails-video-ai/internal/stream/` 不得自研 RTP / 容器 / 起始码解析。

因此**本仓库的解析缺陷会直接变成下游的画面损坏**。ADR-0002 与 ADR-0003 是这条依赖成立
的前提：前者保证解析结论建立在码流事实上，后者保证改动有真机基线兜底。

## 使用方式

1. **改代码前**：先查本索引与 `.codebuddy/rules/`，确认不违反 `Accepted` 决策。
2. **提出新决策**：复制 `template.md` → `ADR-<下一编号>-<slug>.md`，状态填 `Proposed`，
   在本表登记。
3. **决策生效**：经 owner 确认后状态改为 `Accepted`，同步本表。
4. **决策被取代**：原 ADR 标注 `Superseded by ADR-00XX`，不删除历史。
