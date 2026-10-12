//! realplay SDP 与 MEDIAINFO 头解析。对应 `go-client/media.go` 的 `ParseSDP` /
//! `applyMediaHeader`。
//!
//! `a=Media_header:MEDIAINFO=<hex>` 声明容器与编码，**它只是提示**：magic 不一定是
//! `IMKH`（有设备发 `HVAG`，字段布局不同），且该头**从不携带分辨率**。容器靠嗅探、
//! 编码靠 NAL 头嗅探、分辨率一律从码流内 SPS 还原；嗅探结论要**写回 `MediaInfo`**，
//! 否则调用方看到的是空容器。PS 的时钟恒为 90kHz，**不要采信 SDP 的 rtpmap**（有设备在
//! video m-line 上写 `a=rtpmap:8 PCMA/8000`，照抄把 25fps 算成 2.22fps）。

use crate::base64;
use crate::hex;
use crate::media_info::MediaInfo;
use crate::sps::parse_h264_sps;

/// 从 realplay SDP 字符串提取 `MediaInfo`。字段判不出也返回非空结构，调用方总能读到
/// 已恢复的部分。
pub fn parse_sdp(sdp: &str) -> MediaInfo {
    let mut info = MediaInfo {
        sdp: sdp.to_string(),
        ..Default::default()
    };
    let mut media_header = String::new();

    for line in sdp.split('\n') {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("a=Media_header:MEDIAINFO=") {
            media_header = rest.strip_suffix(';').unwrap_or(rest).to_string();
        } else if let Some(rest) = line.strip_prefix("a=rtpmap:") {
            // a=rtpmap:96 H264/90000——相机会发 "a=rtpmap:0 /0"，指名不了任何编码，
            // 只取确实存在的字段。
            if let Some((_, spec)) = rest.split_once(' ') {
                let mut parts = spec.splitn(2, '/');
                if let Some(name) = parts.next() {
                    if !name.is_empty() {
                        info.codec = name.to_uppercase();
                    }
                }
                if let Some(rate) = parts.next() {
                    if let Ok(r) = rate.parse::<i64>() {
                        info.clock_rate = r;
                    }
                }
            }
        } else if let Some(rest) = line.strip_prefix("a=fmtp:") {
            // a=fmtp:96 packetization-mode=1;profile-level-id=...;sprop-parameter-sets=Z0...,aM...
            if let Some(idx) = rest.find("sprop-parameter-sets=") {
                let mut value = &rest[idx + "sprop-parameter-sets=".len()..];
                if let Some(semi) = value.find(';') {
                    value = &value[..semi];
                }
                for ps in value.split(',') {
                    let ps = ps.trim();
                    if !ps.is_empty() {
                        info.parameter_sets.push(ps.to_string());
                    }
                }
                if info.codec == "H264" && !info.parameter_sets.is_empty() {
                    if let Ok(raw) = base64::decode(&info.parameter_sets[0]) {
                        if let Ok((w, h)) = parse_h264_sps(&raw) {
                            info.width = w;
                            info.height = h;
                        }
                    }
                }
            }
        }
    }

    // MEDIAINFO 头对容器与编码是权威的，覆盖 rtpmap（相机把后者留空）。
    apply_media_header(&mut info, &media_header);
    if info.container == "PS" {
        // PS 时间戳按定义就是 90kHz，rtpmap 说什么都不算。有设备把 video m-line 描述成
        // "a=rtpmap:8 PCMA/8000"（音频时钟），照字面读会把每个 PTS 推导的帧率变成
        // 胡说（25fps 变 2.22fps）。
        info.clock_rate = 90000;
    }
    info
}

/// 解码 `a=Media_header:MEDIAINFO=<hex>` 里那 40 字节海康 "IMKH" 头。只读容器与编码
/// 字段——该头不带分辨率（h5player 也从解码器取），音频字段没有消费方。
///
/// 未知 magic（如 HVAG）或未知字段值**留空而不是猜**，随后靠码流嗅探兜底。
fn apply_media_header(info: &mut MediaInfo, hex_str: &str) {
    let raw = match hex::decode(hex_str.trim()) {
        Ok(raw) => raw,
        Err(()) => return,
    };
    if raw.len() < 12 || &raw[..4] != b"IMKH" {
        return;
    }
    // 字段值不识别时保持原状（此时通常还是空）。
    match [raw[8], raw[9]] {
        [1, 0] => info.container = "HIK".into(),
        [2, 0] => info.container = "PS".into(),
        [4, 0] => info.container = "RTP".into(),
        [8, 0] => info.container = "GB".into(),
        [16, 0] => info.container = "RAW".into(),
        _ => {}
    }
    match [raw[10], raw[11]] {
        [1, 0] | [0, 1] => info.codec = "H264".into(),
        [5, 0] => info.codec = "H265".into(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn parse_sdp_h264() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=Session streamed by Hikvision\n\
                   m=video 0 RTP/AVP 96\na=rtpmap:96 H264/90000\n\
                   a=fmtp:96 packetization-mode=1;profile-level-id=42001f;\
                   sprop-parameter-sets=Z2QAH6zZQFAFuhAAAAMAEAAAAwPI8YMZYA==,aM7A8g==\n";
        let info = parse_sdp(sdp);
        assert_eq!(info.codec, "H264");
        assert_eq!(info.clock_rate, 90000);
        assert_eq!(info.parameter_sets.len(), 2);
        assert_eq!(info.width, 1280);
        assert!(
            info.height >= 720 && info.height <= 736,
            "height = {}",
            info.height
        );
    }

    #[test]
    fn parse_sdp_no_sprop() {
        let info = parse_sdp("m=video 0 RTP/AVP 96\na=rtpmap:96 H265/90000\n");
        assert_eq!(info.codec, "H265");
        assert_eq!((info.width, info.height), (0, 0), "no sprop → 0x0");
    }

    // MEDIAINFO 头（a=Media_header:MEDIAINFO=<hex>）覆盖 rtpmap，设定容器与编码。
    // 相机发的是这个而不是 sprop-parameter-sets，分辨率在见到码流内 SPS 前保持 0。
    #[test]
    fn parse_sdp_media_info_header() {
        let mut hdr = vec![0u8; 40];
        hdr[..4].copy_from_slice(b"IMKH");
        hdr[8] = 2; // container = PS
        hdr[10] = 5; // codec = H265
        let sdp = format!(
            "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=Session streamed by Hikvision\n\
             m=video 0 RTP/AVP 0\na=rtpmap:0 /0\n\
             a=Media_header:MEDIAINFO={};\n",
            hex::encode(&hdr)
        );
        let info = parse_sdp(&sdp);
        assert_eq!(info.container, "PS");
        assert_eq!(info.codec, "H265");
        assert_eq!(info.clock_rate, 90000, "PS default clock");
        assert_eq!(
            (info.width, info.height),
            (0, 0),
            "MEDIAINFO has no resolution"
        );
    }

    // 一台真 H.264 相机发来的 SDP：MEDIAINFO 头 40 字节但 magic 是 "HVAG" 而非
    // "IMKH"，本客户端没有它的字段布局。容器与编码留空是正确的——猜字段比留空更糟——
    // 客户端随后从码流把两者都恢复出来。
    #[test]
    fn parse_sdp_unknown_media_header_magic() {
        let sdp = "v=0\ns=hikvision\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\n\
                   a=Media_header:MEDIAINFO=4856414701010000C400C001C00200000000000000000000\
                   6462333300000000000000000000000000000000;\n";
        let info = parse_sdp(sdp);
        assert_eq!(info.container, "");
        assert_eq!(info.codec, "");
    }

    // 一台真 1080p 相机发来的 SDP：video m-line 上 advertised PCMA/8000（音频时钟）。
    // PS 时间戳无论如何都是 90kHz，照字面读会把 25fps 的流报成 2.22fps。
    #[test]
    fn parse_sdp_ps_ignores_audio_clock() {
        let sdp = "v=0\ns=hikvision\nm=video 0 RTP/AVP 8\na=rtpmap:8 PCMA/8000\n\
                   a=Media_header:MEDIAINFO=494D4B48000000000200050011710110401F000000FA00\
                   0000000000000000000000000000000000;\n";
        let info = parse_sdp(sdp);
        assert_eq!(info.container, "PS");
        assert_eq!(info.codec, "H265");
        assert_eq!(
            info.clock_rate, 90000,
            "PS is 90kHz, not the rtpmap audio clock"
        );
    }
}
