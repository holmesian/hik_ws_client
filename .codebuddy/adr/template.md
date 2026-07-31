---
adr: 0000
title: <ADR 标题>
status: template
date: YYYY-MM-DD
deciders: <决策者/角色>
related_rules: <关联规则文件，如 media-parsing.md>
related_docs: <关联文档（仓库内相对路径）>
---

# ADR-0000 <标题>

> MADR 风格模板。复制本文件为 `ADR-<编号>-<slug>.md` 后填写，并在 `INDEX.md` 登记。

## 状态（Status）

- `Accepted`：已拍板并落地
- `Proposed`：已提出，待 owner 确认
- `Deprecated`：已废弃
- `Superseded by ADR-00XX`：被某 ADR 取代

## 背景与问题（Context）

为什么要做这个决策？面临什么问题、约束或权衡？**引用实测证据**（哪一轮摸底、多少台设备、
什么现象），不要写推测。

## 决策（Decision）

我们决定：<一句话决策>。

具体约定：
- <要点 1>
- <要点 2>

## 后果（Consequences）

**正面**：<好处>
**负面 / 风险**：<代价与限制>
**合规要求**：<谁必须遵守，违反时如何处理>

## 备注（Notes）

- 关联规则：`.codebuddy/rules/<file>`
- 关联文档：`<path>`
- 评审记录：<日期 + 结论>
