---
adr: 0001
title: 传输层与媒体解析层分离，Go 为权威实现、Python 等价对齐
status: Accepted
date: 2026-07-31
accepted: 2026-08-01
deciders: 项目 owner
related_rules: project.md, testing.md
related_docs: go-client/, python-client/hik_media.py, docs/media-pipeline.md
---

# ADR-0001 传输层与媒体解析层分离，Go 为权威实现、Python 等价对齐

## 状态（Status）

`Accepted`（2026-08-01 由项目 owner 确认）——记录的是**已落地并经真机验证**的既成结构
（`hik_media.py` 已从 `hik_ws_client.py` 拆出，Go 侧 `client.go` / `psdemux.go` / `media.go` /
`rtp.go` 同构）。

## 背景与问题（Context）

本仓库同时存在 Python 与 Go 两套实现。早期媒体解析散在客户端回调里，两侧各写各的，结果是
**同一份样本两边给出不同结果**：Python 侧要么少帧、要么把分辨率还原成 0x0、要么把裸 PS 的
续传字节误判成 RTP 而静默截断。分歧一旦出现，排查时无法判断哪边是对的。

同时生产取流只走 `go-client` 一条路径，Python 是分析与研究工具。

## 决策（Decision）

我们决定：**传输层与媒体解析层分离；Go 实现为行为基准，Python 实现与之等价对齐。**

- 传输层（WebSocket、鉴权、封包、重连）与媒体解析层（RTP 判定/剥离、PS 解复用、SPS、SDP）
  分属不同文件，解析层不依赖网络、可对字节直接单测。
- Python 媒体层（`python-client/hik_media.py`）**仅依赖标准库**，保证任何环境下都能跑分析。
- 解析行为的任何修改**两侧同时改**；两侧都回放 `samples/` 并断言同一组帧数、关键帧数、
  分辨率。这是唯一能证明"行为一致"的手段。
- 允许单侧存在的只有工程设施（如 Go 的 `AsyncDelivery` 流水线），且不得改变交付字节。

## 后果（Consequences）

**正面**：调用方只需信任一个实现；两侧对同一样本给出同一组数字，分歧即刻暴露；解析层可脱离
网络测试，缺陷能用归档字节离线复现。

**负面 / 风险**：每次解析修改的成本翻倍（两侧 + 两套用例）。这是刻意付出的代价——上一次
放任分歧的结果是 Python 侧的结论完全不可用。

**合规要求**：只改一侧解析行为的 PR 不予合入，除非属于上述工程设施例外并在 PR 中说明。

## 备注（Notes）

- 关联规则：`.codebuddy/rules/project.md`、`.codebuddy/rules/testing.md`
- 目录布局：`ADR-0005`（各语言实现并列为独立库，`samples/` / `docs/` 各侧共享）

## 修订记录（Amendments）

- **2026-09-26**：本决策的"多实现等价对齐"原则**同样适用于后续新增的语言实现**，不限于原文的
  Go / Python 两侧。新增实现须满足同一约束：传输与解析分层、回放 `samples/` 并断言与 Go **同一组**
  帧数 / 关键帧数 / 分辨率。已按此落地的实现：`nodejs-client/`（部分对齐：协议/加密/RTP/PS/媒体管线，
  未含码流内 SPS 分辨率还原与样本回放）、`php-client/`（完整对齐：回放 `samples/` 四份真机采集，
  断言同一组数字，见 `php-client/tests/HikMediaTest.php`）。决策正文与日期不改，仅此追加。
