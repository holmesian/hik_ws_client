//! MPEG-PS 解复用。对应 `go-client/psdemux.go` 与 `docs/media-pipeline.md` ③。
//!
//! 设备会把**单个 NAL 切开放进多个 PES**（PES 头可能落在 VPS 中间），所以绝不能对未解
//! 复用的 PS 字节扫 Annex-B 起始码：既会漏真 NAL，又会把 PES stream_id 误判成 NAL 头，
//! 还会撞上图像数据里的伪起始码。
//!
//! 一个 PS pack 对应一个访问单元，pack 头关闭上一帧——天然一帧延迟，流结束必须 flush。

/// 起始码 ID（`00 00 01` 之后那个字节）。
const PS_END_CODE: u8 = 0xB9; // program end；容器用的最小 ID
const PS_PACK_START: u8 = 0xBA; // pack 头——开启新访问单元
const PS_SYSTEM_START: u8 = 0xBB; // system header；PSM / PES 都大于它
const PES_VIDEO_FIRST: u8 = 0xE0;
const PES_VIDEO_LAST: u8 = 0xEF;

/// 一个从 PS 容器恢复出来的视频访问单元。
#[derive(Debug, Clone)]
pub struct PsFrame {
    /// Annex-B 基本流字节（解复用后的访问单元）。
    pub data: Vec<u8>,
    /// 33 位容器 PTS（90kHz）；仅 `has_pts` 为真时有效。
    pub pts: i64,
    pub has_pts: bool,
}

/// PS 解复用器。跨 Feed 调用缓冲未完成的单元；缓冲最多持有**一个**不完整单元
/// （PES 有 64KiB 长度上限），不会无限增长。
pub struct PsDemuxer {
    buf: Vec<u8>,
    au: Vec<u8>,
    pts: i64,
    has_pts: bool,
    synced: bool, // 见过 pack 头；此前收到的是接入点之前的残帧
}

impl Default for PsDemuxer {
    fn default() -> Self {
        Self::new()
    }
}

impl PsDemuxer {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            au: Vec::new(),
            pts: 0,
            has_pts: false,
            synced: false,
        }
    }

    /// 喂入一段 PS 字节，返回完成的访问单元。分片可以落在任意位置，余量留到下次。
    pub fn feed(&mut self, data: &[u8]) -> Vec<PsFrame> {
        self.buf.extend_from_slice(data);

        let mut out = Vec::new();
        let mut off = 0;
        // buf 移出后再步进，避免 step(&mut self) 与 buf 的借用冲突。
        let mut buf = std::mem::take(&mut self.buf);
        while off < buf.len() {
            match self.step(&buf[off..]) {
                Some((n, frame)) => {
                    if let Some(f) = frame {
                        out.push(f);
                    }
                    off += n;
                }
                None => break,
            }
        }
        if off > 0 {
            buf.drain(..off);
        }
        self.buf = buf;
        out
    }

    /// 流结束时必须调用：一个 pack 关闭上一帧，最后一帧只有在这里才完成。
    pub fn flush(&mut self) -> Vec<PsFrame> {
        match self.close_au() {
            Some(f) => vec![f],
            None => Vec::new(),
        }
    }

    /// `b` 是否以 MPEG-PS 起始码开头——用于给解不出 MEDIAINFO 头的流定性。
    ///
    /// **任意**起始码都算，不只是 pack 头：直播从流中间接入，首条消息可能落在音频 PES
    /// （`00 00 01 c0`）上。下限 `0xB9` 足以挡掉裸 Annex-B（NAL 头最高位恒为 0）。
    pub fn is_ps_data(b: &[u8]) -> bool {
        b.len() >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] >= PS_END_CODE
    }

    /// 解析一个容器单元：返回 (消耗字节数, 该单元完成的访问单元)；需要更多数据时 `None`。
    fn step(&mut self, b: &[u8]) -> Option<(usize, Option<PsFrame>)> {
        if b.len() < 4 {
            return None;
        }

        if b[0] | b[1] != 0 || b[2] != 0x01 {
            // 不在起始码上——重同步。保留尾部 2 字节（可能是被切在两段之间的起始码头）。
            match find_start_code(b) {
                Some(idx) => return Some((idx, None)),
                None => return Some((b.len() - 2, None)),
            }
        }

        let sid = b[3];
        if sid == PS_PACK_START {
            // 14 字节 pack 头 + pack_stuffing_length（第 13 字节低 3 位）。
            if b.len() < 14 {
                return None;
            }
            let n = 14 + (b[13] & 0x07) as usize;
            if b.len() < n {
                return None;
            }
            let f = self.close_au();
            self.synced = true;
            return Some((n, f));
        }

        if sid >= PS_SYSTEM_START {
            // system header、program stream map 与所有 PES 共用 6 字节长度前缀形式。
            if b.len() < 6 {
                return None;
            }
            let n = 6 + u16::from_be_bytes([b[4], b[5]]) as usize;
            if b.len() < n {
                return None;
            }
            if (PES_VIDEO_FIRST..=PES_VIDEO_LAST).contains(&sid) {
                self.append_pes(&b[6..n]);
            }
            // 音频 PES（C0..DF）与 private_stream_1（BD）按长度跳过——后者自带 PTS，
            // 当视频处理会把密文拼进码流、还会把帧时间戳取错（ADR-0004）。
            return Some((n, None));
        }

        // 不是容器起始码（游离的 NAL 前缀）——跨过它。
        Some((3, None))
    }

    /// 交出累计至今的访问单元（如有）。帧拿到精确尺寸的副本，累加器保留容量给下一单元。
    fn close_au(&mut self) -> Option<PsFrame> {
        if self.au.is_empty() {
            return None;
        }
        // drain(..) 保留 self.au 的容量（对齐 Go 侧 closeAU 的复用策略，
        // 交付字节与一次性新建完全一致）。这里刻意不用 mem::take——那会丢掉容量，
        // 让每个访问单元重新从零长缓冲。
        #[allow(clippy::drain_collect)]
        let data: Vec<u8> = self.au.drain(..).collect();
        let f = PsFrame {
            data,
            pts: self.pts,
            has_pts: self.has_pts,
        };
        self.pts = 0;
        self.has_pts = false;
        Some(f)
    }

    /// 剥掉 PES 头，把净荷拼进当前访问单元，并从第一个带 PTS 的 PES 取帧 PTS。
    ///
    /// `b` 是 6 字节起始码/长度前缀之后的字节。MPEG-2 PES 可选头是**三字节**：
    ///
    /// ```text
    /// b[0] '10' 标记 + 加扰/优先级/对齐标志（典型 0x80）
    /// b[1] PTS_DTS_flags（7-6 位）+ ESCR/ES_rate/DSM/copy/CRC/ext 标志
    /// b[2] PES_header_data_length，覆盖 b[3:3+hlen]（PTS、DTS……）
    /// ```
    ///
    /// 把长度当第 2 字节读，会把 0x80 的 PTS 标志当成 128 字节头长，每个 payload 被砍掉
    /// 前 128 字节、PTS 早解一字节。实测 `PES_header_data_length` 分布在 2..10。
    fn append_pes(&mut self, b: &[u8]) {
        // 直播从任意位置接入：首个 pack 头之前到达的 PES，是接入前就已发出的访问单元
        // 尾巴。42 台实测 7 台如此开场，最极端的一台已收了 151KiB 的关键帧尾巴——
        // 放出去就是每条会话头部一个解不了的残帧，还会让首帧 PTS 偏早。
        if !self.synced {
            return;
        }
        if b.len() < 3 || b[0] & 0xC0 != 0x80 {
            return;
        }
        let hlen = b[2] as usize;
        if b.len() < 3 + hlen {
            return;
        }
        // PTS_DTS_flags 在 b[1] 的 7-6 位；0b10 = 仅 PTS，0b11 = PTS+DTS。
        if b[1] & 0x80 != 0 && hlen >= 5 && !self.has_pts {
            self.pts = read_pts(&b[3..8]);
            self.has_pts = true;
        }
        self.au.extend_from_slice(&b[3 + hlen..]);
    }
}

/// 在 `b` 中找下一个 `00 00 01` 起始码。
fn find_start_code(b: &[u8]) -> Option<usize> {
    b.windows(3).position(|w| w == [0x00, 0x00, 0x01])
}

/// 解 33 位 PTS（5 字节 PES 时间戳字段）。
fn read_pts(b: &[u8]) -> i64 {
    ((b[0] as i64 >> 1) & 0x07) << 30
        | (b[1] as i64) << 22
        | ((b[2] as i64 >> 1) & 0x7F) << 15
        | (b[3] as i64) << 7
        | (b[4] as i64 >> 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小 14 字节 pack 头（pack_stuffing_length=0）。
    fn ps_pack() -> Vec<u8> {
        let mut v = vec![0x00, 0x00, 0x01, PS_PACK_START];
        v.extend_from_slice(&[0; 10]);
        v
    }

    /// 视频 PES（stream_id 0xE0）：标准 3 字节 MPEG-2 PES 可选头；pts>=0 时带 PTS。
    fn ps_video_pes(payload: &[u8], pts: i64) -> Vec<u8> {
        let (flags, hdr_len, head) = if pts >= 0 {
            (0x80u8, 5u8, encode_pts(pts as u64).to_vec())
        } else {
            (0x00, 0, Vec::new())
        };
        let mut body = vec![0x80, flags, hdr_len];
        body.extend_from_slice(&head);
        body.extend_from_slice(payload);
        let mut pes = vec![0x00, 0x00, 0x01, PES_VIDEO_FIRST];
        pes.extend_from_slice(&(body.len() as u16).to_be_bytes());
        pes.extend_from_slice(&body);
        pes
    }

    /// 把 33 位 PTS 编进 5 字节 PES 时间戳字段。
    fn encode_pts(pts: u64) -> [u8; 5] {
        [
            (0x20 | ((pts >> 30) & 0x07) << 1 | 0x01) as u8,
            ((pts >> 22) & 0xFF) as u8,
            (((pts >> 15) & 0x7F) << 1 | 0x01) as u8,
            ((pts >> 7) & 0xFF) as u8,
            ((pts & 0x7F) << 1 | 0x01) as u8,
        ]
    }

    #[test]
    fn single_frame() {
        let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21]; // H264 IDR
        let mut d = PsDemuxer::new();
        let mut got = d.feed(&[ps_pack(), ps_video_pes(&idr, -1)].concat());
        got.extend(d.feed(&ps_pack())); // 收尾 pack 吐出缓冲的 AU
        got.extend(d.flush());

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, idr);
        assert!(!got[0].has_pts, "expected no PTS (none supplied)");
    }

    // 证明解复用器是必需的：切在两个 PES 里的 NAL 被重组成一个连续访问单元。
    // 直接对未解复用的 PS 字节扫起始码，只会在 PES 边界看到一个假 NAL 头。
    #[test]
    fn split_nal() {
        let nal = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21];
        let mut d = PsDemuxer::new();
        let mut got = d.feed(&[ps_pack(), ps_video_pes(&nal[..6], -1)].concat());
        got.extend(d.feed(&ps_video_pes(&nal[6..], -1)));
        got.extend(d.feed(&ps_pack()));
        got.extend(d.flush());

        assert_eq!(
            got.len(),
            1,
            "frames = {}, want 1 (NAL merged across PES)",
            got.len()
        );
        assert_eq!(got[0].data, nal);
    }

    #[test]
    fn pts_recovery() {
        let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x01];
        let want = 90_000i64; // 1s @ 90kHz
        let mut d = PsDemuxer::new();
        let mut got = d.feed(&[ps_pack(), ps_video_pes(&idr, want)].concat());
        got.extend(d.feed(&ps_pack()));
        got.extend(d.flush());

        assert_eq!(got.len(), 1);
        assert!(got[0].has_pts, "expected PTS flag set");
        assert_eq!(got[0].pts, want);
    }

    #[test]
    fn resync() {
        let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x01];
        let mut d = PsDemuxer::new();
        let junk = vec![0xAA, 0xBB, 0xCC];
        let mut got = d.feed(&[junk, ps_pack(), ps_video_pes(&idr, -1)].concat());
        got.extend(d.feed(&ps_pack()));
        got.extend(d.flush());

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, idr);
    }

    // 用手写线格式字节钉住 PES 布局，与实现里的 helper 无关：可选头是三字节，
    // 把长度当第 2 字节读会把 0x80 的 PTS 标志看成 128 字节头长，每个 payload 被砍掉
    // 前 128 字节、PTS 早解一字节。helper 与实现共犯时这个缺陷完全看不见。
    #[test]
    fn standard_pes_header() {
        let mut payload = vec![0x00, 0x00, 0x00, 0x01, 0x26, 0x01];
        payload.extend((6..200).map(|i| i as u8)); // 200 字节：足够让 128 字节误剥显现
        let want_pts = 3_600i64;

        let mut body = vec![0x80, 0x80, 0x05]; // 标记/标志, PTS_DTS_flags=0b10, hdrLen=5
        body.extend_from_slice(&encode_pts(want_pts as u64));
        body.extend_from_slice(&payload);
        let mut pes = vec![0x00, 0x00, 0x01, PES_VIDEO_FIRST];
        pes.extend_from_slice(&(body.len() as u16).to_be_bytes());
        pes.extend_from_slice(&body);

        let mut d = PsDemuxer::new();
        let mut got = d.feed(&[ps_pack(), pes].concat());
        got.extend(d.flush());

        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].data, payload,
            "payload truncated (PES header length misread)"
        );
        assert!(got[0].has_pts);
        assert_eq!(got[0].pts, want_pts);
    }

    // PTS+DTS 形式（PTS_DTS_flags=0b11，hlen=10）：帧 PTS 仍取 PTS 字段，
    // DTS 的字节不能漏进基本流。
    #[test]
    fn pes_with_dts() {
        let payload = vec![0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0xAB];
        let want_pts = 7_200i64;

        let mut body = vec![0x80, 0xC0, 0x0A];
        body.extend_from_slice(&encode_pts(want_pts as u64));
        body.extend_from_slice(&encode_pts((want_pts - 1800) as u64)); // DTS
        body.extend_from_slice(&payload);
        let mut pes = vec![0x00, 0x00, 0x01, PES_VIDEO_FIRST];
        pes.extend_from_slice(&(body.len() as u16).to_be_bytes());
        pes.extend_from_slice(&body);

        let mut d = PsDemuxer::new();
        let mut got = d.feed(&[ps_pack(), pes].concat());
        got.extend(d.flush());

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, payload, "DTS leaked into the ES");
        assert_eq!(got[0].pts, want_pts);
    }

    // 直播从帧中间接入是常态：首个 pack 头之前到达的 PES 是未见其头的访问单元尾巴，
    // 必须丢弃而不是作为一帧放出。42 台实测 7 台如此开场，一台带 151KiB 关键帧尾巴。
    #[test]
    fn drops_partial_leading_au() {
        let tail = vec![0x9A, 0x77, 0x01, 0x23]; // NAL 中段字节，无起始码
        let full = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x42];

        let mut d = PsDemuxer::new();
        let mut got = d.feed(&ps_video_pes(&tail, 3600)); // 从帧中接入
        got.extend(d.feed(&[ps_pack(), ps_video_pes(&full, 7200)].concat()));
        got.extend(d.flush());

        assert_eq!(got.len(), 1, "the partial leading AU must be dropped");
        assert_eq!(got[0].data, full);
        // 被丢弃的尾巴自带 PTS：取了它会把第一个真帧的时间戳提前 40ms。
        assert_eq!(got[0].pts, 7200, "PTS leaked from the dropped tail");
    }

    #[test]
    fn is_ps_data_cases() {
        let cases: Vec<(&str, Vec<u8>, bool)> = vec![
            ("pack header", vec![0x00, 0x00, 0x01, 0xba, 0x44], true),
            ("program end", vec![0x00, 0x00, 0x01, 0xb9], true),
            (
                "system header",
                vec![0x00, 0x00, 0x01, 0xbb, 0x00, 0x06],
                true,
            ),
            (
                "program stream map",
                vec![0x00, 0x00, 0x01, 0xbc, 0x00, 0x12],
                true,
            ),
            ("audio pes", vec![0x00, 0x00, 0x01, 0xc0, 0x00, 0xad], true),
            ("video pes", vec![0x00, 0x00, 0x01, 0xe0, 0x00, 0x9c], true),
            // annex-b NAL 头最高位恒为 0，永远到不了容器用的 stream ID。
            ("annex-b idr", vec![0x00, 0x00, 0x01, 0x65, 0x88], false),
            ("annex-b sps", vec![0x00, 0x00, 0x01, 0x67, 0x64], false),
            ("h265 vps", vec![0x00, 0x00, 0x01, 0x40, 0x01], false),
            ("not a start code", vec![0x80, 0x60, 0x18, 0x5c], false),
            ("too short", vec![0x00, 0x00, 0x01], false),
        ];
        for (name, input, want) in cases {
            assert_eq!(PsDemuxer::is_ps_data(&input), want, "case {name}");
        }
    }

    // 82/94 台设备的视频节目里每秒左右插一条 private_stream_1（0xBD）。其净荷不透明
    // （80 字节加密块）且自带 PTS：当视频处理既把垃圾缝进码流、又把帧时间戳取错——
    // 而帧数、关键帧数一切正常。下面的包是逐字节照抄的采集，不是 helper 造的。
    #[test]
    fn skips_private_stream() {
        let private = vec![
            0x00, 0x00, 0x01, 0xbd, 0x00, 0x6a, // 起始码 + 长度 106
            0x8c, 0x80, 0x07, 0x27, 0x9a, 0x07, 0xf7, 0x19, 0xff, 0xf8, // PES 头，带 PTS
            0x00, 0x02, 0x00, 0x17, 0x00, 0x01, 0x80, 0x00, 0x00, 0xff, 0x00, 0x00, 0xe0, 0xf1,
            0xf0, 0x50, 0x1d, 0x12, 0xf2, 0xf5, 0xee, 0xba, 0x71, 0xf3, 0xfc, 0xb6, 0x0f, 0x1b,
            0x73, 0x66, 0x65, 0xd9, 0x76, 0xb5, 0xff, 0xf7, 0x7a, 0xa5, 0xa1, 0xeb, 0xc7, 0xd4,
            0x92, 0x7d, 0x14, 0x51, 0xba, 0x3b, 0xfa, 0x5d, 0x69, 0x7f, 0xb6, 0x49, 0x3e, 0x9d,
            0xae, 0x71, 0x02, 0x48, 0x5f, 0x57, 0xfb, 0x40, 0xfa, 0x5d, 0x69, 0x7f, 0xb6, 0x49,
            0x3e, 0x9d, 0xae, 0x71, 0x02, 0x48, 0x5f, 0x57, 0xfb, 0x40, 0x79, 0x6f, 0xe1, 0xc9,
            0xa9, 0x21, 0xc7, 0xfa, 0x04, 0x72, 0xf7, 0x26, 0xdc, 0x2e, 0x97, 0xcf,
        ];
        let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21];

        let mut d = PsDemuxer::new();
        let mut got = d.feed(&ps_pack());
        got.extend(d.feed(&private));
        got.extend(d.feed(&ps_video_pes(&idr, 7200)));
        got.extend(d.flush());

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, idr, "private payload spliced into the ES");
        assert_eq!(got[0].pts, 7200, "PTS taken from the private packet");
    }
}
