//! RTP 判定（会话级、跨消息互证）与剥离。对应 `go-client/rtp.go`。
//!
//! **不是所有设备都发裸 PS**：有代理把每个 PS 分片再套一层 RTP（version 2、PT 96、
//! SSRC 恒定、大量带 padding）。判定必须整条会话只做一次：裸 PS 的续传消息从任意字节
//! 开始，任意字节有 1/4 概率高两位是 `0b10`——逐条消息判定会把续传消息当成 RTP、静默砍
//! 掉 12 字节（实测 39/39 采集损坏，而帧数/关键帧/分辨率全部正常）。

/// RTP 固定头长度。
const RTP_FIXED_HEADER: usize = 12;

/// 探针窗口：这么多条消息里找不到互证的一对，会话即判定为裸 PS。
const RTP_PROBE_MESSAGES: usize = 4;

/// 剥掉一条 RTP 封装的头部，返回媒体字节（借用的子切片）。
///
/// 调用方必须已确认整条会话是 RTP——逐包判定的理由见 [`RtpDetector`]。
/// 固定头、CSRC 列表、扩展头、**尾部 padding** 都要剥；任一段长度不合理时**原样返回**
/// 而不是返回空——裸 PS / 裸 Annex-B 才不会被误剥。
pub fn rtp_strip(b: &[u8]) -> &[u8] {
    if b.len() < RTP_FIXED_HEADER || b[0] >> 6 != 2 {
        return b;
    }
    let mut n = RTP_FIXED_HEADER + 4 * (b[0] & 0x0F) as usize; // CSRC 列表
    if b[0] & 0x10 != 0 {
        // 扩展头：2 字节 profile + 2 字节长度（以 32 位字计）。
        if b.len() < n + 4 {
            return b;
        }
        n += 4 + 4 * u16::from_be_bytes([b[n + 2], b[n + 3]]) as usize;
    }
    if n >= b.len() {
        return b;
    }
    let mut p = &b[n..];
    if b[0] & 0x20 != 0 {
        // padding：计数在最后一个字节，且含自身。
        let pad = p[p.len() - 1] as usize;
        if pad == 0 || pad > p.len() {
            return b;
        }
        p = &p[..p.len() - pad];
    }
    p
}

/// 会话级 RTP 判定器：判一次，整条会话套用。
///
/// 判据是**同一 SSRC + 序号递增**的一对消息；代理会把首个 RTP 包拆成 8192 + 12 两条
/// 消息，所以互证的两条**不要求相邻**——前若干条消息里找到一对即可。判定期间消息被扣住，
/// 定性后一起放出。
pub struct RtpDetector {
    decided: bool,
    is_rtp: bool,
    held: Vec<Vec<u8>>,
}

impl Default for RtpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RtpDetector {
    pub fn new() -> Self {
        Self {
            decided: false,
            is_rtp: false,
            held: Vec::new(),
        }
    }

    /// 是否已判定为 RTP 会话（测试与诊断用）。
    pub fn is_rtp(&self) -> bool {
        self.is_rtp
    }

    /// 喂入一条消息净荷，返回**现在就可以处理**的净荷列表：
    /// 判定期间返回空，定性后一次放出扣住的全部消息。
    pub fn feed(&mut self, b: &[u8]) -> Vec<Vec<u8>> {
        if self.decided {
            return vec![self.apply(b)];
        }
        if self.held.is_empty() && !rtp_header_plausible(b) {
            // 第一条消息就不可能是 RTP，当即定性——裸 PS 以 0x00 开头，这是常见情形。
            self.decided = true;
            return vec![b.to_vec()];
        }
        self.held.push(b.to_vec());
        self.is_rtp = rtp_pair_found(&self.held);
        if !self.is_rtp && self.held.len() < RTP_PROBE_MESSAGES {
            return Vec::new();
        }
        self.decided = true;
        self.release()
    }

    /// 会话在判定前结束：放出扣住的消息。没有互证的一对就无法确认序号，按非 RTP 放行——
    /// 原样放过最多得到可恢复的流，剥掉本不存在的头则不可恢复。
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.held.is_empty() {
            return Vec::new();
        }
        self.decided = true;
        self.release()
    }

    fn release(&mut self) -> Vec<Vec<u8>> {
        let held = std::mem::take(&mut self.held);
        let mut out = Vec::with_capacity(held.len());
        for h in held {
            out.push(self.apply(&h));
        }
        out
    }

    fn apply(&self, b: &[u8]) -> Vec<u8> {
        if self.is_rtp {
            rtp_strip(b).to_vec()
        } else {
            b.to_vec()
        }
    }
}

/// `b` 是否可能是 RTP 包。
fn rtp_header_plausible(b: &[u8]) -> bool {
    b.len() >= RTP_FIXED_HEADER && b[0] >> 6 == 2
}

/// 扣住的消息里是否存在同一条 RTP 流的一对包。过不了头校验的消息（包中段续传）直接跳过，
/// 所以两条**不要求相邻**。
fn rtp_pair_found(msgs: &[Vec<u8>]) -> bool {
    for i in 0..msgs.len() {
        if !rtp_header_plausible(&msgs[i]) {
            continue;
        }
        for j in i + 1..msgs.len() {
            if rtp_header_plausible(&msgs[j]) && rtp_consecutive(&msgs[i], &msgs[j]) {
                return true;
            }
        }
    }
    false
}

/// `b` 是否是 `a` 之后同一条流的包：SSRC 相同，序号领先但不超过探针窗口
/// （给被分帧藏起来的包留余量，同时把容器字节撞上这 48 位的概率挡在门外）。
fn rtp_consecutive(a: &[u8], b: &[u8]) -> bool {
    if a[8..12] != b[8..12] {
        return false;
    }
    let seq_a = u16::from_be_bytes([a[2], a[3]]);
    let seq_b = u16::from_be_bytes([b[2], b[3]]);
    let gap = seq_b.wrapping_sub(seq_a); // 与序号一样在 16 位处回绕
    gap >= 1 && gap as usize <= RTP_PROBE_MESSAGES
}

#[cfg(test)]
mod tests {
    use super::*;

    // 这里的 RTP 头逐字节手写，不经构造 helper：helper 与实现共享同一套字段布局时，
    // 实现摆错了测试会跟着认——PES 头长度取错位置这个缺陷当年就是这么躲过单测的。
    #[test]
    fn rtp_strip_cases() {
        let cases: Vec<(&str, &[u8], &[u8])> = vec![
            // V=2 P=0 X=0 CC=0, M=1 PT=96, seq, timestamp, SSRC。
            (
                "fixed header",
                &[
                    0x80, 0xe0, 0x18, 0x5c, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8, 0x00,
                    0x00, 0x01, 0xba, 0x44,
                ],
                &[0x00, 0x00, 0x01, 0xba, 0x44],
            ),
            // P=1：最后一个字节数 padding，且含自身。
            (
                "padding",
                &[
                    0xa0, 0xe0, 0x18, 0x5d, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8, 0x00,
                    0x00, 0x01, 0xe0, 0xff, 0xff, 0x03,
                ],
                &[0x00, 0x00, 0x01, 0xe0],
            ),
            // CC=2：固定头后跟两个 4 字节 CSRC。
            (
                "csrc list",
                &[
                    0x82, 0x60, 0x18, 0x5e, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x00, 0x00, 0x01, 0xba,
                ],
                &[0x00, 0x00, 0x01, 0xba],
            ),
            // X=1：2 字节 profile + 2 字节长度（32 位字），后面 1 个字。
            (
                "extension header",
                &[
                    0x90, 0x60, 0x18, 0x5f, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8, 0xbe,
                    0xde, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x01, 0xba,
                ],
                &[0x00, 0x00, 0x01, 0xba],
            ),
            (
                "bare mpeg-ps is not rtp",
                &[
                    0x00, 0x00, 0x01, 0xba, 0x44, 0x88, 0x2d, 0x42, 0x54, 0x01, 0x00, 0x00, 0x03,
                ],
                &[
                    0x00, 0x00, 0x01, 0xba, 0x44, 0x88, 0x2d, 0x42, 0x54, 0x01, 0x00, 0x00, 0x03,
                ],
            ),
            (
                "bare annex-b is not rtp",
                &[
                    0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x29, 0x8d, 0x8d, 0x40, 0x28, 0x02,
                ],
                &[
                    0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x29, 0x8d, 0x8d, 0x40, 0x28, 0x02,
                ],
            ),
            // 不可能兑现的 padding 计数：原样返回胜过返回空。
            (
                "impossible padding count",
                &[
                    0xa0, 0xe0, 0x18, 0x60, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8, 0x00,
                    0x00, 0xff,
                ],
                &[
                    0xa0, 0xe0, 0x18, 0x60, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8, 0x00,
                    0x00, 0xff,
                ],
            ),
            ("short message", &[0x80, 0xe0, 0x18], &[0x80, 0xe0, 0x18]),
        ];
        for (name, input, want) in cases {
            assert_eq!(rtp_strip(input), want, "case {name}");
        }
    }

    // 两个连续 RTP 包：SSRC 72 58 3c c8，序号 0x185c / 0x185d。
    fn rtp1() -> Vec<u8> {
        vec![
            0x80, 0xe0, 0x18, 0x5c, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8, 0x00, 0x00,
            0x01, 0xba, 0x11,
        ]
    }
    fn rtp2() -> Vec<u8> {
        vec![
            0x80, 0xe0, 0x18, 0x5d, 0x00, 0x00, 0x2a, 0x64, 0x72, 0x58, 0x3c, 0xc8, 0x22, 0x33,
            0x44, 0x55, 0x66,
        ]
    }
    // 恰好以 0b10xxxxxx 开头的裸 PS 续传消息——每 4 个任意字节就有 1 个长这样，
    // 逐条判定正是这样损坏了 39 台真机。
    fn cont1() -> Vec<u8> {
        vec![
            0x8c, 0x80, 0x08, 0x23, 0xc7, 0xdd, 0xc4, 0x69, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00,
            0x01, 0x40, 0x01,
        ]
    }
    fn cont2() -> Vec<u8> {
        vec![
            0xa5, 0x1f, 0x36, 0x26, 0xb1, 0x73, 0xbf, 0x6d, 0xc3, 0x46, 0x6f, 0x85, 0xb3, 0x36,
            0x4b, 0x56, 0x26,
        ]
    }

    #[test]
    fn rtp_detector() {
        let rtp_session: Vec<Vec<u8>> = vec![rtp1(), rtp2()];
        let bare_ps: Vec<Vec<u8>> = vec![
            vec![
                0x00, 0x00, 0x01, 0xba, 0x44, 0x88, 0x2d, 0x42, 0x54, 0x01, 0x00, 0x00,
            ],
            cont1(),
        ];
        let lookalike: Vec<Vec<u8>> = vec![cont1(), cont2()];
        // 同 SSRC 但序号不递增的一对
        let same_ssrc_wrong_seq: Vec<Vec<u8>> = {
            let mut v = rtp1();
            v[2] = 0x99;
            v[3] = 0x99;
            vec![rtp1(), v]
        };

        // 用例表：(名字, 喂入序列, 期望放行序列, 是否 RTP)
        #[allow(clippy::type_complexity)]
        let cases: Vec<(&str, Vec<Vec<u8>>, Vec<Vec<u8>>, bool)> = vec![
            (
                "rtp session strips every packet",
                rtp_session.clone(),
                vec![
                    vec![0x00, 0x00, 0x01, 0xba, 0x11],
                    vec![0x22, 0x33, 0x44, 0x55, 0x66],
                ],
                true,
            ),
            // 第一条消息即定性，什么都不扣。
            (
                "bare ps decides on the first message",
                bare_ps.clone(),
                bare_ps.clone(),
                false,
            ),
            // 两条都像 RTP，但 SSRC 不同——什么都别剥。
            (
                "continuations that look like rtp are passed through",
                lookalike.clone(),
                lookalike,
                false,
            ),
            (
                "matching ssrc but wrong sequence is not rtp",
                same_ssrc_wrong_seq.clone(),
                same_ssrc_wrong_seq,
                false,
            ),
        ];
        for (name, feed, want, is_rtp) in cases {
            let mut d = RtpDetector::new();
            let mut got = Vec::new();
            for m in &feed {
                got.extend(d.feed(m));
            }
            got.extend(d.flush());
            assert_eq!(got.len(), want.len(), "case {name}: payload count");
            for (i, w) in want.iter().enumerate() {
                assert_eq!(&got[i], w, "case {name}: payload {i}");
            }
            assert_eq!(d.is_rtp(), is_rtp, "case {name}: is_rtp");
        }
    }

    // WebSocket 消息边界不是 RTP 包边界：HVAG 系设备把第一个 8204 字节的包拆成
    // 8192 + 12 两条消息下发，第二条是包中段。要求两条相邻会把真正的 RTP 会话锁死在
    // 裸路径上，把每个 12 字节头缝进码流。
    #[test]
    fn detector_survives_fragmented_first_packet() {
        let head = vec![
            0x80, 0x60, 0x2c, 0x25, 0x00, 0x00, 0x00, 0x00, 0x69, 0x54, 0xd8, 0x56, 0x00, 0x00,
            0x01, 0xba, 0x11,
        ];
        // 同一个包的剩余部分，单独成消息：它是净荷，必须逐字节到达解复用器。
        let tail = vec![
            0x4d, 0x2a, 0xf7, 0x5b, 0x5d, 0xf9, 0xcd, 0x32, 0x70, 0x85, 0x02, 0x6b,
        ];
        let next = vec![
            0x80, 0x60, 0x2c, 0x26, 0x00, 0x00, 0x00, 0x00, 0x69, 0x54, 0xd8, 0x56, 0x22, 0x33,
            0x44,
        ];

        let mut d = RtpDetector::new();
        let mut got = Vec::new();
        for m in [&head, &tail, &next] {
            got.extend(d.feed(m));
        }
        got.extend(d.flush());

        assert!(
            d.is_rtp(),
            "fragmented first packet must still classify as RTP"
        );
        let want: Vec<Vec<u8>> = vec![
            vec![0x00, 0x00, 0x01, 0xba, 0x11],
            tail,
            vec![0x22, 0x33, 0x44],
        ];
        assert_eq!(got.len(), want.len());
        for (i, w) in want.iter().enumerate() {
            assert_eq!(&got[i], w, "payload {i}");
        }
    }

    // 会话在唯一一条"像 RTP"的消息后结束：没有第二包可证序号，丢弃唯一净荷比
    // 原样放过更糟。
    #[test]
    fn detector_flushes_held_message() {
        let only = vec![
            0x80, 0xe0, 0x18, 0x5c, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8, 0x00, 0x00,
            0x01, 0xba,
        ];
        let mut d = RtpDetector::new();
        assert!(d.feed(&only).is_empty(), "first message released early");
        let got = d.flush();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], only, "flush must release the held message verbatim");
        assert!(
            d.flush().is_empty(),
            "second flush released a payload again"
        );
    }
}
