# 验证留档

各次改动在提交前实际跑出来的证据截图。放截图而不是只放结论，是因为这个项目的
"通过"和"没跑"长得很像（`testing.md` 第五条）：帧数 / 关键帧数 / 分辨率全对也不代表
码流是对的，只有真跑过的输出能分辨。

图片由真实命令输出渲染，非手工绘制。对应的命令写在每张图里。

## php-client（PHP 8.4.26）

| 图 | 命令 | 结论 |
| --- | --- | --- |
| [php-client-tests.png](./php-client-tests.png) | `php8.4 tests/run.php` | 44 passed / 0 failed / **0 skipped** |
| [php-client-sample-replay.png](./php-client-sample-replay.png) | 解复用 `samples/` 四份真机采集 | 帧数 / 关键帧 / 分辨率 / fps 与 Go、Python **同一组** |
| [php-client-ffprobe.png](./php-client-ffprobe.png) | `ffprobe -count_frames` | 解出的基本流可被独立解码器读出（判据三） |
| [php-client-e2e-tls.png](./php-client-e2e-tls.png) | 真 TLS WebSocket 端点回放 | 端到端 611 帧 / 25 关键帧 / 1280x720 / 24.93fps |

`skip` 计为 0 是有意强调的：LFS 未拉取、依赖缺失时的用例会 skip，而 skip 等于没跑回归。
