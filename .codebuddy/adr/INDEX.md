# hik_ws_client 架构决策记录（ADR）索引

本目录记录本仓库已拍板、不可随意违反的架构决策（"宪法层"），位于自动加载的
`.codebuddy/rules/` 之上。新增或修改决策须经项目 owner 确认后方可置 `Accepted`。

**状态图例**：✅ Accepted（已生效）｜⚠️ Proposed（待 owner 确认）｜⬜ Deprecated（已废弃）｜↩ Superseded（已被取代）

## 决策一览

| 编号 | 标题 | 状态 | 关联规则 |
|------|------|------|----------|
| [ADR-0001](./ADR-0001-transport-media-split-and-dual-implementation.md) | 传输层与媒体解析层分离，Go 为权威实现、其余语言实现等价对齐 | ✅ Accepted | `project.md`, `testing.md` |
| [ADR-0002](./ADR-0002-stream-is-the-source-of-truth.md) | 线格式以码流为准，SDP 仅作提示；一次性判定必须跨消息互证 | ✅ Accepted | `media-parsing.md` |
| [ADR-0003](./ADR-0003-real-device-samples-as-regression-baseline.md) | 真机样本库（Git LFS）+ 严格结构走查作为验收基线 | ✅ Accepted | `testing.md` |
| [ADR-0004](./ADR-0004-component-scope-boundary.md) | 组件边界：只做取流与解复用，不解码/解密/私有流/PTZ | ✅ Accepted | `project.md`, `media-parsing.md` |
| [ADR-0005](./ADR-0005-repository-layout-and-component-independence.md) | 仓库布局：各语言实现并列为独立库；不承载调用方项目上下文 | ✅ Accepted | `project.md` |

> ADR-0001 ~ 0004 记录的都是**已落地并经真机验证的既成行为**——把 123 台设备摸底换来的结论
> 固化成约束，2026-08-01 经项目 owner 确认转为 `Accepted`，没有随之改动任何代码。
> ADR-0001 与 ADR-0005 于 2026-09-26 追加"修订记录"，把"多实现等价对齐 / 各语言各占一个顶层
> 目录"的原则扩展到其后新增的 `nodejs-client`、`php-client`（决策正文与日期不改）。

## 组件定位

本仓库是一个**独立组件**：把海康 Web 私有 WebSocket 协议的传输字节还原成可直接喂解码器的
Annex-B 访问单元。调用方可以是任何项目，本仓库不记录、不依赖任何具体调用方的业务上下文与
治理编号（ADR-0005）。

对调用方的唯一期待是：**不要自研 RTP / 容器 / 起始码解析**。本仓库的解析缺陷会直接变成调用方
的画面损坏，而这些缺陷全都不报错——ADR-0002 与 ADR-0003 就是为此立的：前者保证解析结论建立在
码流事实上，后者保证改动有真机基线兜底。

## 使用方式

1. **改代码前**：先查本索引与 `.codebuddy/rules/`，确认不违反 `Accepted` 决策。
2. **提出新决策**：复制 `template.md` → `ADR-<下一编号>-<slug>.md`，状态填 `Proposed`，
   在本表登记。
3. **决策生效**：经 owner 确认后状态改为 `Accepted`，同步本表并在文件里记下确认日期。
4. **决策被取代**：原 ADR 标注 `Superseded by ADR-00XX`，不删除历史。
