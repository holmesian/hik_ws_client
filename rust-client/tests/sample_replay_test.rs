//! 真机样本回放：把 `samples/` 的四份采集重放进解复用器，断言**与 go-client /
//! python-client / php-client 同一组**帧数 / 关键帧数 / 分辨率（ADR-0001 / ADR-0003）。
//!
//! 样本走 Git LFS；未 `git lfs pull` 时文件是指针，用例 skip——**skip 等于没跑回归**
//! （`.codebuddy/rules/testing.md` 第三条）。
//!
//! 计数不算验证：每个已修复的解析缺陷都能让帧数/关键帧数/分辨率看起来完全正常。
//! 所以这里除 tally 外还做：严格结构走查（不允许 resync）、每个访问单元以起始码开头、
//! PTS 单调、SPS 是单个 NAL 且类型正确。

use hik_ws_client::psdemux::PsDemuxer;
use hik_ws_client::{analyze_frame, recover_resolution};
use sha2::{Digest, Sha256};

/// 归档的真机采集。数字为全量摸底实测值（`samples/README.md`）。
struct Sample {
    dir: &'static str,
    codec: &'static str,
    frames: usize,
    keys: usize,
    width: u32,
    height: u32,
    sps_nal: u8,
}

const SAMPLES: &[Sample] = &[
    Sample {
        dir: "ps_h265_720p",
        codec: "H265",
        frames: 611,
        keys: 25,
        width: 1280,
        height: 720,
        sps_nal: 33,
    },
    Sample {
        dir: "ps_h265_1080p",
        codec: "H265",
        frames: 614,
        keys: 13,
        width: 1920,
        height: 1080,
        sps_nal: 33,
    },
    Sample {
        dir: "ps_h264_720p",
        codec: "H264",
        frames: 655,
        keys: 26,
        width: 1280,
        height: 720,
        sps_nal: 7,
    },
    Sample {
        dir: "ps_h264_1080p",
        codec: "H264",
        frames: 199,
        keys: 8,
        width: 1920,
        height: 1080,
        sps_nal: 7,
    },
];

#[test]
fn replay_samples() {
    let mut replayed = 0;
    for s in SAMPLES {
        if replay_one(s) {
            replayed += 1;
        }
    }
    // 与 Go 侧一致：单份样本缺失时 skip。但一份都没跑起来必须响——
    // "skip 等于没跑回归"（.codebuddy/rules/testing.md 第三条）。
    assert!(
        replayed > 0,
        "no sample replayed: run `git lfs install && git lfs pull` in the repo root"
    );
}

/// 交付字节与 Go 侧**逐位相同**：对每个访问单元按 `PTS|HasPTS|len|字节` 串接取
/// sha256，与 go-client（行为基准）对同一样本、同一切分算出的摘要比对。
///
/// 这比各自断言帧数/关键帧数更强——本仓库撞过的每个解析缺陷都是"数字全对、字节是坏的"
/// （docs/media-pipeline.md）。摘要由 Go 侧临时用例实测产出（口径见下）；**解析行为合法
/// 变更时这组摘要会变，必须两侧同时重算并确认仍相同**。
///
/// 口径：每帧依次追加 —— PTS（u64 大端，8 字节）、HasPTS（1 字节）、len（u64 大端，
/// 8 字节）、帧字节；对整条串接取 sha256。
#[test]
fn delivery_bytes_match_go_baseline() {
    let digests: &[(&str, &str)] = &[
        (
            "ps_h265_720p",
            "817ee3c08e420a286acf09d5041cfebef9814ffbeb98eff77f78fefb80bb43e2",
        ),
        (
            "ps_h265_1080p",
            "2c8b6a92fc26cf13d51b6001c60e52ae6410a73523c22c5f179d9379ac074cf6",
        ),
        (
            "ps_h264_720p",
            "78ffb060bcc55ece69d7140b2bed34102be8a7e0c87073f1c9e3fb9b01eeaad1",
        ),
        (
            "ps_h264_1080p",
            "73e95a307797fdc22ca658a170820c7006361056b1583ca2392a593452724faf",
        ),
    ];
    let mut checked = 0;
    for (dir, want) in digests {
        let path = format!("../samples/{dir}/stream.ps");
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        if raw.starts_with(b"version https://git-lfs") {
            continue;
        }
        let mut d = PsDemuxer::new();
        let mut frames = Vec::new();
        let mut off = 0;
        while off < raw.len() {
            let end = (off + (16 << 10)).min(raw.len());
            frames.extend(d.feed(&raw[off..end]));
            off = end;
        }
        frames.extend(d.flush());

        let mut hasher = Sha256::new();
        for f in &frames {
            hasher.update((f.pts as u64).to_be_bytes());
            hasher.update([u8::from(f.has_pts)]);
            hasher.update((f.data.len() as u64).to_be_bytes());
            hasher.update(&f.data);
        }
        let got = hex_lower(&hasher.finalize());
        assert_eq!(
            &got, want,
            "{dir}: delivered bytes differ from the Go baseline"
        );
        checked += 1;
    }
    assert!(checked > 0, "no sample available for the digest comparison");
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 回放一份样本。返回 false = 跳过（缺失或 LFS 指针）。
fn replay_one(s: &Sample) -> bool {
    let path = format!("../samples/{}/stream.ps", s.dir);
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(_) => {
            eprintln!("SKIP {path}: sample not present (git lfs pull?)");
            return false;
        }
    };
    // LFS 未拉取时文件在但内容是指针：严格走查会在 offset 0 脱轨，给出看不懂的失败。
    if raw.starts_with(b"version https://git-lfs") {
        eprintln!("SKIP {path}: unfetched LFS pointer; run `git lfs pull`");
        return false;
    }

    // 结构先行。解复用器会在下一个 pack 头重同步，因此它乐于从一个被打了洞的流里
    // 产出正确的帧数——RTP 剥离子弹当初就是这么在两个方向上隐形的。严格走查不
    // resync：每个元素必须紧接上一个元素结束处开始。
    let (elements, derail) = strict_walk_ps(&raw);
    assert!(
        derail < 0,
        "{}: strict PS walk derailed at {}/{} after {} elements",
        s.dir,
        derail,
        raw.len(),
        elements
    );

    // 按 16KiB 分片喂入，让访问单元跨调用断裂，和 WebSocket 层的切分一样。
    let mut d = PsDemuxer::new();
    let mut frames = Vec::new();
    let mut off = 0;
    while off < raw.len() {
        let end = (off + (16 << 10)).min(raw.len());
        frames.extend(d.feed(&raw[off..end]));
        off = end;
    }
    frames.extend(d.flush());

    assert_eq!(frames.len(), s.frames, "{}: frames", s.dir);

    let mut keys = 0;
    let mut with_pts = 0;
    let mut prev_pts = 0i64;
    for (i, f) in frames.iter().enumerate() {
        if analyze_frame(&f.data, s.codec) {
            keys += 1;
        }
        if f.has_pts {
            with_pts += 1;
            if with_pts > 1 && f.pts < prev_pts {
                panic!(
                    "{}: frame {i}: PTS went backwards ({} < {})",
                    s.dir, f.pts, prev_pts
                );
            }
            prev_pts = f.pts;
        }
        // 每个访问单元必须以起始码开头。PES 头长度读错在这里第一个现形：
        // 负载会多一段垃圾前缀或丢掉头部字节。
        assert!(
            f.data.starts_with(&[0, 0, 0, 1]) || f.data.starts_with(&[0, 0, 1]),
            "{}: frame {i} does not start with a start code: {:02x?}",
            s.dir,
            &f.data[..f.data.len().min(8)]
        );
    }
    assert_eq!(keys, s.keys, "{}: keyframes", s.dir);
    assert_eq!(with_pts, s.frames, "{}: frames carrying PTS", s.dir);

    // 分辨率必须从码流内 SPS 出来。防竞争字节没剥的那一版会把 720p 解成 2x1。
    let mut got = (0u32, 0u32);
    let mut sps_len = 0usize;
    let mut sps_type = 0u8;
    for f in &frames {
        if let Some((w, h, sps)) = recover_resolution(&f.data, s.codec) {
            got = (w, h);
            sps_len = sps.len();
            // sps 从 3 字节起始码开始，NAL 头在 index 3，与起始码长度无关。
            sps_type = if s.codec == "H265" {
                sps[3] >> 1 & 0x3F
            } else {
                sps[3] & 0x1F
            };
            break;
        }
    }
    assert_eq!(got, (s.width, s.height), "{}: recovered resolution", s.dir);
    // 还原出的 SPS 必须是单个 NAL，不是关键帧的剩余部分。
    assert!(
        sps_len > 0 && sps_len <= 128,
        "{}: recovered SPS is {sps_len} bytes; expected a single SPS NAL",
        s.dir
    );
    assert_eq!(sps_type, s.sps_nal, "{}: recovered NAL type", s.dir);
    eprintln!(
        "OK {}: {} bytes, {} elements, {} frames / {} keys, {}x{} (pts on {with_pts})",
        s.dir,
        raw.len(),
        elements,
        frames.len(),
        keys,
        got.0,
        got.1
    );
    true
}

/// 严格结构走查：逐元素前进，**不允许任何 resync**。返回 (元素数, 脱轨偏移)，
/// 脱轨偏移为 -1 表示干净走到 buffer 末尾。
///
/// 故意比解复用器更严：解复用器靠扫下一个 pack 头对抗丢包，也让丢包不可见——
/// 只有不 resync 的走查能分辨一条完整的流和一条被打过洞的流。起点取第一个起始码
/// （不是 offset 0），末尾容忍最后一个元素被采集时长截断。
fn strict_walk_ps(b: &[u8]) -> (i64, i64) {
    // 从第一个起始码开始。
    let mut i = match b.windows(3).position(|w| w == [0x00, 0x00, 0x01]) {
        Some(p) => p,
        None => return (0, 0),
    };
    let mut n = 0i64;
    while i < b.len() {
        if i + 4 > b.len() || b[i] != 0 || b[i + 1] != 0 || b[i + 2] != 1 {
            return (n, i as i64);
        }
        let size = match b[i + 3] {
            0xBA => {
                // pack 头：14 字节 + stuffing。
                if i + 14 > b.len() {
                    return (n, i as i64);
                }
                14 + (b[i + 13] & 7) as usize
            }
            0xB9 => 4, // program end
            _ => {
                // system header / PSM / PES：都有 6 字节长度前缀。
                if i + 6 > b.len() {
                    return (n, i as i64);
                }
                6 + u16::from_be_bytes([b[i + 4], b[i + 5]]) as usize
            }
        };
        if i + size > b.len() {
            return (n, i as i64);
        }
        i += size;
        n += 1;
    }
    (n, -1)
}
