---
adr: 0005
title: 仓库布局——Go 与 Python 并列为两个独立库；组件不承载调用方项目上下文
status: Accepted
date: 2026-08-01
accepted: 2026-08-01
deciders: 项目 owner
related_rules: project.md
related_docs: README.md, go-client/README.md, python-client/README.md
---

# ADR-0005 仓库布局——Go 与 Python 并列为两个独立库；组件不承载调用方项目上下文

## 状态（Status）

`Accepted`（2026-08-01 由项目 owner 指示并确认）。

## 背景与问题（Context）

改造前的布局是**不对称**的：Go 实现收在 `go-client/`，Python 实现的 6 个文件
（`hik_ws_client.py` / `hik_media.py` / `test_hik_media.py` / `demo.py` / `play.py` /
`requirements.txt`）散在仓库根，`docs/python-api.md` 又把 Python 的 API 文档放在两侧共享的
`docs/` 里。后果有三个：

- 根目录看不出这是"两套等价实现"，看起来像"一个 Python 项目额外带了个 go-client"；
- 两库各自的依赖清单、测试入口、文档入口不在同一层级，`.cnb` 流水线的 `ifModify` 也只能按
  单个文件名盯 `requirements.txt`；
- ADR-0001 要求两侧等价对齐，但目录形态本身没有体现这层对称性。

另一个问题是**上下文外溢**：README、`go-client/README.md`、`docs/media-pipeline.md`、
`.codebuddy/rules/project.md` 与 ADR-0001 里都写着某个具体调用方项目的名字、它的内部模块路径，
以及它那边的 ADR 编号。本仓库是可被任意项目引用的独立组件，把某一个调用方的治理编号写进自己的
约束里，会让其他调用方读到无法核实的引用，也会让本仓库的约束看起来依附于外部项目。

## 决策（Decision）

我们决定：**两套实现各占一个顶层目录、并列为两个独立库；两库之外的顶层目录一律是两侧共享的
资产；仓库内不出现任何调用方项目的名称、路径或治理编号。**

- `go-client/` 与 `python-client/` 是两个并列的库，各自持有自己的源码、依赖清单、测试入口与
  `README.md`。
- 共享资产只有三类：`samples/`（真机样本与实测结论）、`docs/`（与语言无关的协议与管线文档）、
  `.codebuddy/`（规范、ADR、调试 skill）。**语言相关的 API 文档进各自库的 `README.md`，不进
  `docs/`。**
- `go-client/` 的目录名**不改**：它是 Go 的 import path（`github.com/holmesian/hik_ws_client/go-client`）
  的一部分，改名会打断所有已有调用方的引用，收益仅是命名对称，不值这个代价。
- 样本库留在仓库根：两侧回放同一份样本、断言同一组数字是 ADR-0001/0003 的执行手段，放进任一
  语言目录都会制造归属错觉。
- 谈及使用方一律用中性表述（"调用方""下游"）。确需说明某个具体集成时，写在那个项目自己的
  仓库里，不写进这里。

## 后果（Consequences）

**正面**：根目录一眼看出两套并列实现；两库的依赖与测试入口对称，流水线可按目录粒度触发；
本组件可以被任何项目引用而不携带无关上下文。

**负面 / 风险**：Python 侧的导入路径变了——原先在仓库根 `python3 -m unittest test_hik_media`，
现在要 `cd python-client`；引用了根级 `hik_ws_client.py` 的外部脚本需要改路径。这是一次性代价，
换取长期的结构对称。`go-client` 与 `python-client` 命名不完全对仗，是为保住 Go import path
稳定而刻意接受的不一致。

**合规要求**：新增语言实现按同样形态开顶层目录，不得再把源码放回仓库根。提交内容里出现调用方
项目名称、内部路径或其治理编号的，不予合入。

## 备注（Notes）

- 关联规则：`.codebuddy/rules/project.md`（目录职责、文档结构）
- 关联决策：`ADR-0001`（多实现等价对齐——本决策是它在目录形态上的落实）

## 修订记录（Amendments）

- **2026-09-26**：决策正文里的"两个并列的库"应读作"**每个语言实现各占一个顶层目录、并列**"。
  原文以 Go / Python 两库为例陈述，其后 `nodejs-client/`、`php-client/` 均按本决策第 2 条
  （"新增语言实现按同样形态开顶层目录"）落地：各自持有源码、依赖清单、测试入口与 `README.md`，
  语言相关的 API 文档进各自库的 README。决策正文与日期不改，仅此追加。
- **2026-10-12**：`rust-client/` 按同一形态落地（2026-10-12 经 owner 确认）：持有 `Cargo.toml` /
  `Cargo.lock`、`src/`、`tests/`、`src/bin/demo.rs` 与 `README.md`；开发镜像与 `.cnb.yml` 的
  `ifModify` 同步纳入 Rust 工具链与依赖清单。决策正文与日期不改，仅此追加。
