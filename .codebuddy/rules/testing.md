---
description: 验证规范——什么算证明解析正确，样本回放与真机摸底的使用方式
alwaysApply: false
globs:
  - "**/*_test.go"
  - "python-client/test_hik_media.py"
  - "rust-client/tests/**"
  - "rust-client/src/**/*.rs"
  - "go-client/e2e/**"
  - "samples/**"
---

## 第一条：计数不算验证

帧数、关键帧数、分辨率、fps 全对，**不代表码流是对的**。已修复的每一个解析缺陷都能让这四个
数字看起来完全正常：RTP 头没剥的那一版跑出 655 帧 / 26 关键帧 / 1280x720，和正确结果一模一样，
只有画面是坏的。

要证明解析正确，用下面三种之一：

- **严格结构走查**：按规范逐个 pack / system / PSM / PES 前进，**不允许任何 resync**，每个元素
  必须紧接上一个元素结束处开始。起点取第一个起始码（不是 offset 0），末尾容忍最后一个元素被
  采集时长截断——否则会把"从流中间接入"和"采集到时间就停"误判成损坏。
- **字节比对**：对基本流做 sha256，与已知正确的输出对照。
- **喂解码器**：`ffprobe` / `ffmpeg` 读得出且画面正常。

## 第二条：构造用例时手写线格式字节

不要复用实现里的构造 helper。测试与实现同源时，实现把字段布局摆错了，测试会跟着认——PES 头
长度取错位置这个缺陷就是这么躲过全套单元测试的。涉及线格式的断言一律手写字节。

## 第三条：样本回放是回归底线

`samples/`（Git LFS）里的四份真机采集覆盖 `{H.264, H.265} × {720p, 1080p}`，即全量摸底中 94 台
出流设备的全部形态。

- Go：`go-client/sample_replay_test.go`；Python：`python-client/test_hik_media.py`；
  Rust：`rust-client/tests/sample_replay_test.rs`（另加交付字节 sha256 与 Go 基准的逐位比对）。
  各侧断言**同一组**数值。
- 跑之前 `git lfs install && git lfs pull`。未拉取时用例会 skip——**skip 等于没跑回归**，CI 必须
  显式拉取。
- 改任何解析逻辑（包括性能优化）后必须重跑，数值对不上就是改坏了。

## 第四条：样本证明不了没见过的设备

同一份代码：三份样本全绿，扩到 42 台真机 39/39 损坏；42 台全绿的那版，扩到 123 台又撞出 5 个
缺陷（其中一个直接 panic）。覆盖面每扩一档就会遇到一档新形态。

因此：

- 解析层的重要改动，除单测外还要跑一轮真机队列（方法见 `.codebuddy/skills/hik-stream-debug/`）；
- 每拿到一个新形态的设备就**当场采集归档**——token 一次性、分钟级过期，拿不到第二次；
- "跑过一轮真机"不是一劳永逸的结论，别把它当成免测理由。

## 第五条：否定结论要有阳性对照

"没变化""没出现""0 条"不是结论，除非你先证明了度量手段**能**测出非零。否定结果最危险的
失败模式是度量器本身坏了——数出来永远是 0，看着像干净确认。

- **零结果配阳性对照**：云台可观测性实测里，①② 两层"转动期间 0 条额外消息"的统计依赖 logTap
  的正则匹配 `client.go` 的日志格式；正则一旦漂移就恒为 0。先写一版契约测试断言 logTap 能命中
  库真实打印的每一行，再信那个 0（见 `go-client/e2e/ptztap/tap_test.go`）。
- **差分要有对照组**：判断"X 是转动导致的"，必须有一组"完全不转、其余一致"的采集来量 X 的
  自然发生率。第 ⑤ 层编码器信号正是被对照组否掉的——静置对照 54.5x > 真实转动最强 38.6x，
  证明它测的是场景变化不是云台（见 `docs/ptz-stream-observability.md`）。
- **skip / 静默丢弃 = 没测**：缺依赖就 skip 的用例、把剩余字节静默丢弃的分支，都会让"通过"
  和"没跑"长得一样。第三条已就 LFS skip 立过规矩，同理适用于任何条件跳过与静默丢弃。

## 第六条：常规命令

```bash
# 仓库根执行
# Go：竞态检测必须开
(cd go-client && go build ./... && go vet ./... && go test -count=1 -race ./...)

# Python：媒体层仅标准库
(cd python-client && python3 -m unittest test_hik_media -v)

# Rust：clippy 零警告、fmt 干净
(cd rust-client && cargo test && cargo clippy --all-targets && cargo fmt --check)
```

新修复必须附带能复现该缺陷的回归用例；只改代码不加用例的修复视为未完成。
