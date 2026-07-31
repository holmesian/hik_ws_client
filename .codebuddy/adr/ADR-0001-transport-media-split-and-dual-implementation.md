---
adr: 0001
title: 传输层与媒体解析层分离，Go 为权威实现、Python 等价对齐
status: Proposed
date: 2026-07-31
deciders: DataStation 架构师；待项目 owner 确认
related_rules: project.md, testing.md
related_docs: go-client/, hik_media.py, docs/media-pipeline.md
---

# ADR-0001 传输层与媒体解析层分离，Go 为权威实现、Python 等价对齐

## 状态（Status）

`Proposed`——记录的是**已落地并经真机验证**的既成结构（`hik_media.py` 已从
`hik_ws_client.py` 拆出，Go 侧 `client.go` / `psdemux.go` / `media.go` / `rtp.go` 同构）。
确认后置 `Accepted`，不需要额外改代码。

## 背景与问题（Context）

本仓库同时存在 Python 与 Go 两套实现。早期媒体解析散在客户端回调里，两侧各写各的，结果是
**同一份样本两边给出不同结果**：Python 侧要么少帧、要么把分辨率还原成 0x0、要么把裸 PS 的
续传字节误判成 RTP 而静默截断。分歧一旦出现，排查时无法判断哪边是对的。

同时下游 `wails-video-ai` 按 DataStation `ADR-0030` 已把字节级解析全部收敛到本仓库的
`go-client`——生产路径只有 Go 一条，Python 是分析与研究工具。

## 决策（Decision）

我们决定：**传输层与媒体解析层分离；Go 实现为行为基准，Python 实现与之等价对齐。**

- 传输层（WebSocket、鉴权、封包、重连）与媒体解析层（RTP 判定/剥离、PS 解复用、SPS、SDP）
  分属不同文件，解析层不依赖网络、可对字节直接单测。
- Python 媒体层（`hik_media.py`）**仅依赖标准库**，保证任何环境下都能跑分析。
- 解析行为的任何修改**两侧同时改**；两侧都回放 `samples/` 并断言同一组帧数、关键帧数、
  分辨率。这是唯一能证明"行为一致"的手段。
- 允许单侧存在的只有工程设施（如 Go 的 `AsyncDelivery` 流水线），且不得改变交付字节。

## 后果（Consequences）

**正面**：下游只需信任一个实现；两侧对同一样本给出同一组数字，分歧即刻暴露；解析层可脱离
网络测试，缺陷能用归档字节离线复现。

**负面 / 风险**：每次解析修改的成本翻倍（两侧 + 两套用例）。这是刻意付出的代价——上一次
放任分歧的结果是 Python 侧的结论完全不可用。

**合规要求**：只改一侧解析行为的 PR 不予合入，除非属于上述工程设施例外并在 PR 中说明。

## 备注（Notes）

- 关联规则：`.codebuddy/rules/project.md`、`.codebuddy/rules/testing.md`
- 下游约束：DataStation `ADR-0030`（`internal/stream/` 不得自研 RTP / 容器 / 起始码解析）
