#!/usr/bin/env python3
"""OA 设备平台 → 取播放链接 → 跑 probe 的粘合脚本（仅标准库）。

存在的理由只有一个：openUrl token 一次性、分钟级过期。手工"先取链接再粘贴到 probe"
的间隔往往就够它失效，批量摸底更是不可能——所以取链接与建连必须在同一个进程里紧挨着做。

凭证与站点地址都从命令行/环境变量传入，绝不写进仓库。

用法见 ../SKILL.md。
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 20


def parse_curl(text):
    """从粘贴的 curl 命令里抠出 base、bearer、cookie。"""
    out = {}
    m = re.search(r"authorization:\s*Bearer\s+([A-Za-z0-9._-]+)", text, re.I)
    if m:
        out["token"] = m.group(1)
    m = re.search(r"PHPSESSID=([A-Za-z0-9._-]+)", text)
    if m:
        out["session"] = m.group(1)
    m = re.search(r"https?://[^/'\"\s]+/api\.php", text)
    if m:
        out["base"] = m.group(0)
    return out


def resolve_creds(args):
    creds = {}
    if args.curl_file:
        with open(args.curl_file, encoding="utf-8") as fh:
            creds.update(parse_curl(fh.read()))
    for key, val in (
        ("base", args.base or os.environ.get("HIK_OA_BASE")),
        ("token", args.token or os.environ.get("HIK_OA_TOKEN")),
        ("session", args.session or os.environ.get("HIK_OA_SESSION")),
    ):
        if val:
            creds[key] = val
    creds.setdefault("session", creds.get("token"))
    missing = [k for k in ("base", "token") if not creds.get(k)]
    if missing:
        sys.exit(
            "缺少 %s。用 --curl-file 粘贴一条浏览器 curl，或用 --base/--token，"
            "或设 HIK_OA_BASE/HIK_OA_TOKEN。" % "/".join(missing)
        )
    return creds


def api(creds, params):
    url = creds["base"] + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url,
        headers={
            "accept": "application/json, text/plain, */*",
            "authorization": "Bearer " + creds["token"],
            "cookie": "PHPSESSID=" + creds["session"],
            "user-agent": "hik-stream-debug/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_devices(creds, date, device_type="all", group_id=None):
    params = {"module": "ipc_device", "action": "list", "date": date, "device_type": device_type}
    if group_id:
        params["group_id"] = group_id
    body = api(creds, params)
    if not body.get("success"):
        sys.exit("设备列表接口失败: %s" % body.get("message"))
    return body.get("data") or []


def play_url(creds, ipc_id, protocol=7):
    body = api(
        creds,
        {"module": "ipc_device", "action": "getPlayUrl", "ipc_id": ipc_id, "protocol": protocol},
    )
    if not body.get("success"):
        return None, body.get("message", "unknown")
    return (body.get("data") or {}).get("play_url"), None


def run_probe(url, dur, go_dir, archive, extra):
    """跑 probe。返回 (returncode, 合并输出)。"""
    cmd = ["go", "run", "./e2e/probe", "-url", url, "-dur", dur]
    if not archive:
        # 不归档：把样本根指到临时目录之外没有意义，probe 总要写点东西，
        # 所以用 -samples 指到一个一次性目录，调用方自行清理。
        cmd += ["-samples", os.path.join(go_dir, ".probe-scratch")]
    cmd += extra
    proc = subprocess.run(
        cmd, cwd=go_dir, capture_output=True, text=True,
        timeout=_seconds(dur) + 120,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _seconds(dur):
    m = re.match(r"^(\d+(?:\.\d+)?)(ms|s|m)$", dur)
    if not m:
        return 60
    val, unit = float(m.group(1)), m.group(2)
    return int(val * {"ms": 0.001, "s": 1, "m": 60}[unit]) + 1


def parse_summary(output):
    """把 probe 的 `==== probe summary ====` 块解析成字典。"""
    fields = {}
    inside = False
    for line in output.splitlines():
        if line.startswith("==== probe summary"):
            inside = True
            continue
        if inside and line.startswith("======"):
            break
        if inside and ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip()] = v.strip()
    m = re.search(r"([\d.]+) fps", fields.get("pts", ""))
    if m:
        fields["fps"] = m.group(1)
    return fields


def digest(output):
    """一行结论：出流了就报形态，没出流就报原因。

    判据是 frames，不是进程退出码——probe 在服务端报错时同样正常退出。
    """
    f = parse_summary(output)
    if not f:
        tail = [l for l in output.strip().splitlines() if l.strip()][-1:]
        return False, "probe 无摘要输出: %s" % ("; ".join(tail) or "(空)")
    frames = int(f.get("frames", "0") or 0)
    if frames == 0:
        err = f.get("errors", "0")
        return False, "无出流 errors=%s" % err
    return True, "%s/%s %s frames=%s key=%s fps=%s raw=%sB" % (
        f.get("container", "?"), f.get("codec", "?"), f.get("resolution", "?"),
        frames, f.get("keyframes", "?"), f.get("fps", "?"), f.get("rawBytes", "?"),
    )


def cmd_list(args, creds):
    devices = list_devices(creds, args.date, args.device_type, args.group_id)
    online = [d for d in devices if str(d.get("is_online")) == "1"]
    print("设备总数 %d，在线 %d" % (len(devices), len(online)))
    if args.json:
        print(json.dumps([d.get("ipc_id") for d in online]))
    else:
        for d in online[: args.limit]:
            print("  ipc_id=%s group=%s" % (d.get("ipc_id"), d.get("group_id")))


def cmd_url(args, creds):
    url, err = play_url(creds, args.ipc_id, args.protocol)
    if err:
        sys.exit("取播放地址失败: %s" % err)
    print(url)


def cmd_probe(args, creds):
    url = args.url
    if not url:
        url, err = play_url(creds, args.ipc_id, args.protocol)
        if err:
            sys.exit("取播放地址失败: %s" % err)
    rc, out = run_probe(url, args.dur, args.go_dir, args.archive, args.probe_args)
    print(out)
    sys.exit(rc)


def cmd_sweep(args, creds):
    devices = list_devices(creds, args.date, args.device_type, args.group_id)
    online = [d for d in devices if str(d.get("is_online")) == "1"]
    if args.ipc_ids:
        wanted = {int(x) for x in args.ipc_ids.split(",")}
        online = [d for d in online if int(d.get("ipc_id")) in wanted]
    if args.count:
        online = online[: args.count]
    print("待测 %d 台（在线设备）" % len(online), flush=True)

    ok, failed = 0, []
    results = []
    for i, dev in enumerate(online, 1):
        ipc = dev.get("ipc_id")
        t0 = time.time()
        url, err = play_url(creds, ipc, args.protocol)
        if err or not url:
            failed.append((ipc, "no_play_url: %s" % err))
            print("[%d/%d] ipc=%s 取链接失败: %s" % (i, len(online), ipc, err), flush=True)
            continue
        rc, out = run_probe(url, args.dur, args.go_dir, args.archive, args.probe_args)
        good, line = digest(out)
        if good:
            ok += 1
        else:
            failed.append((ipc, line))
        results.append(
            {"ipc_id": ipc, "ok": good, "summary": line, "fields": parse_summary(out)}
        )
        print(
            "[%d/%d] ipc=%s %s (%.1fs) %s"
            % (i, len(online), ipc, "OK " if good else "FAIL", time.time() - t0, line),
            flush=True,
        )

    print("\n出流成功 %d / %d" % (ok, len(online)))
    for ipc, why in failed:
        print("  失败 ipc=%s %s" % (ipc, why))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, ensure_ascii=False, indent=2)
        print("明细写入 %s" % args.out)


def main():
    p = argparse.ArgumentParser(description="OA 取流链路调试脚本")
    p.add_argument("--curl-file", help="粘贴浏览器 curl 命令的文件，自动抠出 base/token/cookie")
    p.add_argument("--base", help="OA api.php 地址（也可用 HIK_OA_BASE）")
    p.add_argument("--token", help="Bearer token（也可用 HIK_OA_TOKEN）")
    p.add_argument("--session", help="PHPSESSID，默认与 token 相同")
    p.add_argument("--date", default=time.strftime("%Y-%m-%d"))
    p.add_argument("--device-type", default="all")
    p.add_argument("--group-id")
    p.add_argument("--protocol", type=int, default=7)
    p.add_argument("--go-dir", default="go-client", help="go-client 目录")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list", help="列出在线设备")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("url", help="取单台播放地址")
    s.add_argument("ipc_id")
    s.set_defaults(func=cmd_url)

    s = sub.add_parser("probe", help="取链接并立即 probe 一台")
    s.add_argument("--ipc-id")
    s.add_argument("--url", help="已有 play_url 时直接用它，跳过 OA 接口")
    s.add_argument("--dur", default="10s")
    s.add_argument("--archive", action="store_true", help="归档到 samples/（默认写临时目录）")
    s.add_argument("probe_args", nargs="*", help="透传给 probe 的额外参数")
    s.set_defaults(func=cmd_probe)

    s = sub.add_parser("sweep", help="逐台取链接并当场 probe")
    s.add_argument("--count", type=int, help="只测前 N 台")
    s.add_argument("--ipc-ids", help="逗号分隔，只测这些")
    s.add_argument("--dur", default="8s")
    s.add_argument("--archive", action="store_true")
    s.add_argument("--out", help="明细写入 JSON 文件")
    s.add_argument("probe_args", nargs="*")
    s.set_defaults(func=cmd_sweep)

    args = p.parse_args()
    need_creds = not (args.cmd == "probe" and getattr(args, "url", None))
    creds = resolve_creds(args) if need_creds else {}
    args.func(args, creds)


if __name__ == "__main__":
    main()
