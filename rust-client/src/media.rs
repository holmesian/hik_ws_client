//! 码流分析：编码嗅探、关键帧识别。对应 `go-client/media.go` 的 `sniffCodec` /
//! `AnalyzeFrame`。

/// 从一个 Annex-B 访问单元嗅探编码，用于 MEDIAINFO 头解不出来（magic 不是 `IMKH`，
/// 如 HVAG 系设备）的流。没有定论时返回空串——调用方在后续访问单元上继续试。
///
/// 判据是**参数集**的 NAL 头——两种编码都它在每个关键帧前重发，且这两个字节的两种读法
/// 在实践上不会碰撞：
///
/// - H.265 是两字节头 `forbidden_zero(1) type(6) layer(6) tid(3)`；VPS/SPS/PPS 是
///   type 32/33/34、layer 0，首字节读作 `0x40/0x42/0x44`。按 H.264 读它们是 type
///   0/2/4——"未指定"与两个片数据分区，没有相机会发；
/// - H.264 是一字节头 `forbidden_zero(1) ref_idc(2) type(5)`；SPS 是 type 7 且必然
///   带非零 ref_idc，读作 `0x27/0x47/0x67`。按 H.265 读是保留类型或非零 layer。
pub fn sniff_codec(data: &[u8]) -> &'static str {
    let mut i = 0;
    while i < data.len() {
        let idx = match find_start_code(&data[i..]) {
            Some(idx) => idx,
            None => break,
        };
        let nal_pos = i + idx + 3;
        if nal_pos >= data.len() {
            break;
        }
        let b = data[nal_pos];
        if b == 0x40 || b == 0x42 || b == 0x44 {
            return "H265";
        }
        if b & 0x9F == 7 && b & 0x60 != 0 {
            return "H264";
        }
        i = nal_pos + 1;
    }
    ""
}

/// 判断一个 Annex-B 访问单元是否含关键 NAL。
///
/// 必须知道编码：H.264 与 H.265 的 NAL type 字段重叠（H.264 SPS 字节按 H.265 读也是
/// 合法类型），用 SDP 恢复出的编码消歧。H.265 的 IRAP NAL（type 16–21）与 H.264 的
/// IDR（type 5）都算关键帧；**参数集本身不是帧**。
pub fn analyze_frame(data: &[u8], codec: &str) -> bool {
    let is_h265 = codec == "H265";
    let mut i = 0;
    while i < data.len() {
        let idx = match find_start_code(&data[i..]) {
            Some(idx) => idx,
            None => break,
        };
        let pos = i + idx;
        let nal_pos = pos + 3; // 起始码 01 在 pos+2，NAL 头紧随其后
        if nal_pos >= data.len() {
            break;
        }
        let b = data[nal_pos];
        if is_h265 {
            let t = (b >> 1) & 0x3F;
            if (16..=21).contains(&t) {
                return true;
            }
        } else if b & 0x1F == 5 {
            return true;
        }
        i = nal_pos + 1;
    }
    false
}

/// 在 `b` 中找下一个 `00 00 01` 起始码。
fn find_start_code(b: &[u8]) -> Option<usize> {
    b.windows(3).position(|w| w == [0x00, 0x00, 0x01])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_codec_cases() {
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "h264 sps",
                vec![0, 0, 0, 1, 0x67, 0x42, 0x00, 0x29, 0, 0, 0, 1, 0x68, 0xca],
                "H264",
            ),
            (
                "h264 sps ref_idc 1",
                vec![0, 0, 1, 0x27, 0x42, 0x00, 0x29],
                "H264",
            ),
            (
                "h265 vps",
                vec![0, 0, 0, 1, 0x40, 0x01, 0x0c, 0x01, 0, 0, 0, 1, 0x42, 0x01],
                "H265",
            ),
            (
                "h265 sps only",
                vec![0, 0, 1, 0x42, 0x01, 0x01, 0x01, 0x60],
                "H265",
            ),
            // 只有 slice 的访问单元判不出编码；调用方继续试。
            ("h264 non-idr slice", vec![0, 0, 0, 1, 0x41, 0x9a, 0x00], ""),
            ("no start code", vec![0x67, 0x42, 0x00, 0x29], ""),
            ("truncated after start code", vec![0, 0, 1], ""),
        ];
        for (name, data, want) in cases {
            assert_eq!(sniff_codec(&data), want, "case {name}");
        }
    }

    #[test]
    fn analyze_frame_cases() {
        // 00 00 00 01 + NAL 头 0x65（IDR slice）
        assert!(analyze_frame(
            &[0x00, 0x00, 0x00, 0x01, 0x65, 0x01, 0x02, 0x03],
            "H264"
        ));
        // SPS(0x67) + P slice(0x41)
        assert!(!analyze_frame(
            &[0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1f, 0x00, 0x00, 0x01, 0x41, 0x9a, 0x00],
            "H264"
        ));
        // 4 字节起始码 + H.265 IDR_W_DLP（type 19）：byte0 = (19<<1)|1 = 0x27
        assert!(analyze_frame(
            &[0x00, 0x00, 0x00, 0x01, 0x27, 0x01, 0x02],
            "H265"
        ));
        // H.265 TRAIL_R（type 1）：byte0 = 0x02
        assert!(!analyze_frame(
            &[0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x03],
            "H265"
        ));
    }
}
