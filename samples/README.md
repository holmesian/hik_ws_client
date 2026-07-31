# 码流样本库

用于 `hik_ws_client` 组件的离线调试与研究。线上测试链接是一次性的、分钟级过期，
拿不到第二次；每次拿到新链接都必须**当场采集并归档**，样本才是可复现问题的唯一依据。

## 采集

```bash
cd go-client
go run ./e2e/probe -url 'wss://<host>:<port>/proxy/[<ip>]:<port>/openUrl/<token>' -dur 20s
```

`probe` 一次连接内同时完成分析与归档，不要拆成两次运行——第二次必然
`errorCode 28316423`（URL 已失效）。

## 目录约定

按**容器 + 编码**分类，一种组合一个目录，例如 `ps_h265/`、`ps_h264/`、`raw_h264/`。
目录名由 `probe` 从 MEDIAINFO 自动推导，也可用 `-name` 覆盖。

每个目录内：

| 文件 | 内容 |
| --- | --- |
| `stream.ps` / `stream.bin` | 解复用**前**的容器原始字节，最有价值的复现材料 |
| `stream.h265` / `stream.h264` | 解复用后的 annex-b 基本流，可直接 `ffprobe` / `ffplay` |
| `stream.sdp` | realplay 返回的 SDP 原文（含 MEDIAINFO 头） |
| `sps.bin` | 命中的第一个 SPS NAL，分辨率解析回归用 |
| `summary.txt` | 该次采集的容器/编码/分辨率/帧数/关键帧/PTS/fps 摘要 |

验证样本：

```bash
ffprobe -v error -show_streams samples/ps_h265/stream.h265
```

## 已知码流特征（实测结论，非文档推测）

- **容器是 MPEG-PS，不是裸 annex-b。** 编码是 H.265。二者只声明在 SDP 的
  `a=Media_header:MEDIAINFO=<hex>` 里：40 字节 IMKH 头，offset 8-9 为容器
  （`02 00` = PS），offset 10-11 为编码（`05 00` = H265）。
- **MEDIAINFO 头里没有分辨率**，必须从码流内的 SPS 还原。
- **一个 PS pack 对应一个访问单元**，所以帧只能在下一个 pack 头到来时才判定结束，
  天然有一帧延迟；流结束时必须 flush，否则丢最后一帧。
- **单个 NAL 会被切开跨多个 PES 包**，因此绝不能对未解复用的 PS 字节做 annex-b
  起始码扫描——既会漏掉真 NAL，又会把 PES stream_id 误判成 NAL 头。
- **PES 可选头是 3 字节**（`flags1` / `PTS_DTS_flags` / `PES_header_data_length`）。
  把长度当成第 2 字节读，会把 `0x80` 的 PTS 标志当成 128 字节头长：每个 PES payload
  被砍掉前 128 字节、PTS 也早解一字节。症状极隐蔽——帧数、关键帧数、码率看着都正常。
- **H.265/H.264 SPS 必须先去除防竞争字节（EPB）再做位解析。** H.265 的
  `general_profile_compatibility_flag` 是 32 位常为 0 的字段，天然构成 `00 00 00 00`，
  在线上会被编码成 `00 00 03 00 ...`；不剥离就会导致后续所有字段错位，实测把
  1280x720 解析成 `2x1`。
- PTS 是 33 位、90kHz。

## 踩坑记录

- **自建 mock 要照着真实字节写。** 单元测试的构造 helper 一旦和实现犯同一个错误
  （PES 头长度取错位置），测试全绿而线上全错。涉及线格式的断言要手写字节，不要
  复用 helper。
- **"帧数对、关键帧对"不等于解析正确。** 上面的 PES 截断问题在摘要里完全看不出来，
  只有对照 `ffprobe` 或逐字节回放归档样本才能发现。这正是要留样本的原因。
