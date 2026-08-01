---
adr: 0003
title: 真机样本库（Git LFS）+ 严格结构走查作为验收基线
status: Accepted
date: 2026-07-31
accepted: 2026-08-01
deciders: 项目 owner
related_rules: testing.md
related_docs: samples/README.md, go-client/sample_replay_test.go, python-client/test_hik_media.py
---

# ADR-0003 真机样本库（Git LFS）+ 严格结构走查作为验收基线

## 状态（Status）

`Accepted`（2026-08-01 由项目 owner 确认）——记录的是已落地的既成做法（4 份样本已入 LFS，
两侧回放测试已存在）。

## 背景与问题（Context）

这个项目里"测试全绿"反复被证明不等于"解析正确"：

- 三份样本全绿的同一份代码，在 42 台真机队列上 **39/39 采集损坏**；
- 42 台全绿的那一版，扩到 123 台又撞出 5 个缺陷，其中一个能被远端字节直接打死进程；
- 单元测试的构造 helper 与实现犯同一个错误（PES 头长度取错位置），全套用例照样绿。

同时，线上测试链接（openUrl token）**一次性、分钟级过期**，同一个现场拿不到第二次。缺陷
能否复现，完全取决于当时有没有把原始字节存下来。

## 决策（Decision）

我们决定：**真机采集样本进仓库（Git LFS）并作为回归基线；正确性判据是严格结构走查，不是
计数。**

- 每遇到一种新形态（新容器 / 新编码 / 新分辨率 / 新封装）**当场采集归档**，目录按
  `samples/<容器>_<编码>_<分辨率>/` 分类，内容与脱敏要求见 `samples/README.md`。
- 归档的是**解复用前的容器原始字节**——唯一不可再生的材料；派生产物不入库。
- `*.ps` / `*.bin` 由 Git LFS 管理；回放用例在样本未拉取时 skip，**CI 必须显式 `git lfs pull`**。
- 正确性判据：不允许 resync 的严格 PS 结构走查、基本流 sha256 比对、或喂解码器。帧数 /
  关键帧数 / 分辨率 / fps **一律不作为正确性证明**。
- 涉及线格式的断言手写字节，不复用实现里的构造 helper。

## 后果（Consequences）

**正面**：解析缺陷可离线复现；Go 与 Python 有共同的对齐基准；"数字正常但码流损坏"这类
缺陷有了能抓住它的判据。

**负面 / 风险**：仓库体积随样本增长（现 4 份约 14MB，走 LFS）；clone 后不拉 LFS 会静默
跳过回归，属已知取舍——用例会打印 skip 提示。样本采集依赖临时凭证，无法在 CI 里自动获取。

**合规要求**：改动解析逻辑（含性能优化）的 PR 必须附样本回放结果；新形态设备的采集不得
遗漏归档；归档内容不得含主机名、内网地址、token、设备名。

## 备注（Notes）

- 关联规则：`.codebuddy/rules/testing.md`
- 采集方法：`.codebuddy/skills/hik-stream-debug/`、`go-client/e2e/probe/`
