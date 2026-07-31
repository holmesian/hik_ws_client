---
name: hik-stream-debug
description: "测试与调试海康 WebSocket 视频流：给一条 play_url 或一份 OA 平台 curl（cookie/Bearer），即可取播放地址、拉流、判定容器/编码/分辨率/帧率、归档样本、批量摸底设备队列。用于验证 hik_ws_client 解析改动、排查某台摄像机不出流或画面异常。"
---

# 海康视频流测试与调试

## 什么时候用

- 拿到一条 `play_url` 或一份 OA 平台的 curl，要**验证组件能不能正确解出这路流**；
- 改了 `hik_ws_client` 的解析逻辑，要**跑一轮真机确认没改坏**；
- 某台摄像机不出流 / 画面花，要判断是**服务端问题还是解析问题**；
- 遇到新形态设备，要**当场采集样本**存进仓库。

## 唯一需要牢记的前提

**openUrl token 一次性、分钟级过期。** 取到链接后必须立刻建连——手工"取链接 → 粘贴 → 运行"
的间隔往往就够它失效，批量摸底更不可能先取一批再跑。所有工具因此都把「取链接」和「拉流」
放在同一个进程里紧挨着做；拿到 `errorCode 28316423` 基本就是这中间拖太久了。

同理，**不要为同一个链接跑两次程序**（比如先分析再抓包），第二次必然失败。`probe` 一次
连接内同时完成分析与归档就是为了这件事。

## 准备

```bash
git clone https://cnb.cool/holmesian/hik_ws_client.git && cd hik_ws_client
git lfs install && git lfs pull      # 样本回放需要；不拉的话回放用例会 skip
cd go-client && go build ./... && cd ..
```

`ffmpeg` 只有截图 / 播放才需要，纯解析验证不需要。

## 三种入口

### A. 只有一条 play_url

```bash
cd go-client
go run ./e2e/probe -url 'wss://<host>:<port>/proxy/[<ip>]:<port>/openUrl/<token>' -dur 10s
```

### B. 有 OA 平台的 curl（cookie / Bearer）

把浏览器里复制的整条 curl 存成文件（脚本自己从里面抠 base / Bearer / PHPSESSID）：

```bash
python3 .codebuddy/skills/hik-stream-debug/scripts/oa_stream.py --curl-file ./oa.curl list
python3 .codebuddy/skills/hik-stream-debug/scripts/oa_stream.py --curl-file ./oa.curl probe --ipc-id 306 --dur 10s
```

也可以走环境变量，不落文件：

```bash
export HIK_OA_BASE='https://<oa-host>/api.php' HIK_OA_TOKEN='<bearer>'
python3 .codebuddy/skills/hik-stream-debug/scripts/oa_stream.py probe --ipc-id 306 --dur 10s
```

**凭证和站点地址一律不写进仓库**（`.codebuddy/rules/project.md` 脱敏红线）。`oa.curl` 放在
仓库外或加进 `.gitignore`。

### C. 批量摸底整个设备队列

```bash
python3 .codebuddy/skills/hik-stream-debug/scripts/oa_stream.py --curl-file ./oa.curl \
    sweep --count 24 --dur 5s --out ./sweep.json
```

逐台「取链接 → 立刻 probe」，最后给出出流成功数与逐台形态。加 `--archive` 才会把样本落进
`samples/`（默认写临时目录，避免摸底把仓库塞满）；`--ipc-ids 306,462` 可只测指定几台。

## 怎么读结果

`probe` 的摘要块：

```
container : PS      codec : H265     resolution : 1280x720
frames    : 203     keyframes : 4    rawBytes : 877908
latency   : mediainfo=..ms firstByte=..ms firstFrame=..ms
errors    : 0 []
pts       : 203 frames, ...  => 25.00 fps
```

- **判据是 `frames`，不是进程退出码**——服务端报错时 probe 一样正常退出。
- `frames > 0` 且 `fps` 在 10~30、`resolution` 非 `0x0`，说明这一路解析链路是通的。
- `resolution` 为 `0x0` 而 frames 正常 → SPS 没解出来（换个编码分支的设备复现，多半是解析缺陷）。
- `container` 为空 → MEDIAINFO 解不出且嗅探也没写回，属组件缺陷。

## 出不了流时先分清是谁的问题

| 现象 | 含义 | 该做什么 |
| --- | --- | --- |
| `errorCode 28316423` | URL 已失效 | 重新取链接，缩短取链接到建连的间隔 |
| `errorCode 26214462` | 服务端取流失败（`is_online=1` 也可能出现） | 换设备。客户端已正常上报并结束会话，不是客户端问题 |
| `errorCode 26214475 / 26214476` | 同上，服务端侧 | 换设备 |
| `errors=0` 但 `frames=0` | 连上了但一直没数据 | 服务端建流慢或没建起来；`-dur` 调长复测一次即可判断 |
| 客户端 panic / 卡死 | **组件缺陷** | 必须修，并补回归用例 |

实测参照（2026-07-31，24 台在线设备）：**14 台出流 / 10 台服务端侧失败**（`26214462`×8、
`26214476`×1、无数据超时×1）。历史上一次全量 123 台是 94 台出流。**队列里两三成设备取不到流
是常态**，不要据此判定客户端有问题。

## 出了流但怀疑画面坏

这是这个项目最难发现的一类问题：**帧数、关键帧数、分辨率、fps 全对，码流却是坏的**。

- 计数正常**不能**证明解析正确；
- 判据只有三种：不允许 resync 的严格 PS 结构走查、基本流 sha256 比对、喂 `ffprobe`/`ffmpeg`；
- 详见 `.codebuddy/rules/testing.md` 与 `samples/README.md`（RTP 二次封装那一节就是"计数全对、
  145 个 RTP 头被写进图像数据"的实例）。

```bash
ffprobe -v error -show_streams samples/ps_h265_720p/stream.ps
```

## 采集样本

遇到新形态（新容器 / 新编码 / 新分辨率 / 新封装）就当场归档：

```bash
cd go-client && go run ./e2e/probe -url '<新链接>' -dur 20s        # 自动落到 ../samples/<容器>_<编码>_<分辨率>/
```

归档内容与脱敏要求见 `samples/README.md`。**样本里不得出现主机名、内网地址、token、设备名**；
`probe` 的摘要因此完全不记录源 URL。提交前自查：

```bash
grep -rIn -Ei '<你的域名>|openUrl/[A-Za-z0-9]{5,}' samples/ | head
```

## 改完解析代码的固定动作

```bash
cd go-client && go build ./... && go vet ./... && go test -count=1 -race ./...
python3 -m unittest test_hik_media                # 仓库根，Python 侧
```

两侧都会回放 `samples/` 并断言同一组帧数 / 关键帧数 / 分辨率。**样本全绿证明不了没见过的
设备**：三份样本全绿的代码曾在 42 台真机上 39/39 损坏。重要解析改动请再跑一轮 `sweep`。
