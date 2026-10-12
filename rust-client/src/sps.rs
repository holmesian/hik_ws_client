//! H.264 / H.265 SPS 位解析：从码流内 SPS 还原分辨率。
//!
//! 对应 `go-client/media.go` 的 SPS 部分与 `docs/media-pipeline.md` ④。
//! SDP 的 `paramsets` 在 94/94 台设备上为 0，**从码流还原 SPS 不是兜底路径而是主路径**。
//!
//! 两条硬约束（都来自真机缺陷）：
//!
//! - **先剥防竞争字节（EPB）再做位解析**。H.265 的 `general_profile_compatibility_flag`
//!   是 32 位常年全 0，线上编码成 `00 00 03`，不剥就把 1280x720 解成 2x1；
//! - **`scaling_list()` 用 `lastScale/nextScale` 状态机读**，不能按固定长度读 se(v)：
//!   表可提前终止（`delta_scale` 为 0），越过 NAL 尾会让 High profile 设备分辨率恒为 0x0。

use crate::error::Error;

/// SPS 解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpsError {
    /// 位流在读完所需字段前结束。
    Truncated,
    /// 解析出的尺寸不可信。
    Implausible(u32, u32),
}

impl std::fmt::Display for SpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpsError::Truncated => write!(f, "sps truncated"),
            SpsError::Implausible(w, h) => write!(f, "implausible dimensions {w}x{h}"),
        }
    }
}

impl From<SpsError> for Error {
    fn from(e: SpsError) -> Self {
        Error::Protocol(e.to_string())
    }
}

/// 最小的大端位读取器。
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize, // 位偏移
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_bit(&mut self) -> Result<u32, SpsError> {
        let byte = self.data.get(self.pos / 8).ok_or(SpsError::Truncated)?;
        let bit = (byte >> (7 - (self.pos % 8))) & 1;
        self.pos += 1;
        Ok(bit as u32)
    }

    fn read_bits(&mut self, n: usize) -> Result<u64, SpsError> {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.read_bit()? as u64;
        }
        Ok(v)
    }

    fn read_ue(&mut self) -> Result<u64, SpsError> {
        let mut leading_zeros = 0usize;
        loop {
            if self.read_bit()? == 1 {
                break;
            }
            leading_zeros += 1;
            if leading_zeros > 31 {
                return Err(SpsError::Truncated); // ue(v) too long
            }
        }
        if leading_zeros == 0 {
            return Ok(0);
        }
        let val = self.read_bits(leading_zeros)?;
        Ok((1u64 << leading_zeros) - 1 + val)
    }

    fn read_se(&mut self) -> Result<i64, SpsError> {
        let ue = self.read_ue()?;
        if ue % 2 == 0 {
            Ok(-((ue + 1) as i64 / 2))
        } else {
            Ok((ue + 1) as i64 / 2)
        }
    }
}

/// 剥掉 H.264/H.265 NAL 的防竞争字节：`00 00` 之后的 `0x03` 必须去掉。
/// 编码器只在 `00 00` 后插 03，所以这个位置的 03 永远是 EPB，不是真实数据。
pub fn strip_emulation_prevention(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    for (i, &byte) in b.iter().enumerate() {
        if i >= 2 && byte == 3 && b[i - 1] == 0 && b[i - 2] == 0 {
            continue;
        }
        out.push(byte);
    }
    out
}

/// 消费一个 `scaling_list()`。表**不是**固定长度的一串 se(v)：`delta_scale` 为 0 时
/// 提前结束，剩余项是推断值而非编码值。按固定长度读会越过 NAL 尾——720p High profile
/// 真机上六个 16 项表各只编了 20 bit，解析器因此跑飞、整场会话报 0x0。
fn skip_scaling_list(br: &mut BitReader<'_>, size: usize) -> Result<(), SpsError> {
    let mut last_scale = 8i64;
    let mut next_scale = 8i64;
    for _ in 0..size {
        if next_scale != 0 {
            let delta = br.read_se()?;
            next_scale = (last_scale + delta + 256) % 256;
        }
        if next_scale != 0 {
            last_scale = next_scale;
        }
    }
    Ok(())
}

/// 解析 H.264 SPS NAL（含 1 字节 NAL 头）的宽高。
pub fn parse_h264_sps(raw: &[u8]) -> Result<(u32, u32), SpsError> {
    if raw.len() < 2 {
        return Err(SpsError::Truncated);
    }
    let stripped = strip_emulation_prevention(&raw[1..]);
    let mut br = BitReader::new(&stripped);

    let profile_idc = br.read_bits(8)?;
    let _ = br.read_bits(8)?; // constraint flags + reserved
    let _ = br.read_bits(8)?; // level_idc
    let _ = br.read_ue()?; // seq_parameter_set_id

    let mut chroma_format_idc = 1u64;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        chroma_format_idc = br.read_ue()?;
        if chroma_format_idc == 3 {
            let _ = br.read_bit()?; // separate_colour_plane_flag
        }
        let _ = br.read_ue()?; // bit_depth_luma_minus8
        let _ = br.read_ue()?; // bit_depth_chroma_minus8
        let _ = br.read_bit()?; // qpprime_y_zero_transform_bypass_flag
        if br.read_bit()? == 1 {
            // seq_scaling_matrix_present
            let count = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..count {
                if br.read_bit()? == 1 {
                    let size = if i >= 6 { 64 } else { 16 };
                    skip_scaling_list(&mut br, size)?;
                }
            }
        }
    }

    let _ = br.read_ue()?; // log2_max_frame_num_minus4
    let poc_type = br.read_ue()?;
    match poc_type {
        0 => {
            let _ = br.read_ue()?; // log2_max_pic_order_cnt_lsb_minus4
        }
        1 => {
            let _ = br.read_bit()?; // delta_pic_order_always_zero_flag
            let _ = br.read_se()?; // offset_for_non_ref_pic
            let _ = br.read_se()?; // offset_for_top_to_bottom_field
            let num = br.read_ue()?;
            for _ in 0..num {
                let _ = br.read_se()?;
            }
        }
        _ => {}
    }

    let _ = br.read_ue()?; // max_num_ref_frames
    let _ = br.read_bit()?; // gaps_in_frame_num_value_allowed_flag
    let pic_width_mbs_minus1 = br.read_ue()?;
    let pic_height_map_units_minus1 = br.read_ue()?;
    let frame_mbs_only_flag = br.read_bit()?;
    if frame_mbs_only_flag == 0 {
        let _ = br.read_bit()?; // mb_adaptive_frame_field_flag
    }
    let _ = br.read_bit()?; // direct_8x8_inference_flag
    let crop_flag = br.read_bit()?;
    let (mut crop_left, mut crop_right, mut crop_top, mut crop_bottom) = (0u64, 0u64, 0u64, 0u64);
    if crop_flag == 1 {
        crop_left = br.read_ue()?;
        crop_right = br.read_ue()?;
        crop_top = br.read_ue()?;
        crop_bottom = br.read_ue()?;
    }

    let mut width = (pic_width_mbs_minus1 + 1) * 16;
    let mut height = (2 - frame_mbs_only_flag as u64) * (pic_height_map_units_minus1 + 1) * 16;

    let (sub_wc, sub_hc) = match chroma_format_idc {
        1 => (2u64, 2u64),
        2 => (2, 1),
        _ => (1, 1),
    };
    width = width.saturating_sub((crop_left + crop_right) * sub_wc);
    height = height.saturating_sub((crop_top + crop_bottom) * sub_hc);

    if width == 0 || height == 0 || width > 8192 || height > 8192 {
        return Err(SpsError::Implausible(width as u32, height as u32));
    }
    Ok((width as u32, height as u32))
}

/// 解析 H.265 SPS NAL（含 2 字节 NAL 头）的宽高。只读到分辨率所需字段。
pub fn parse_h265_sps(raw: &[u8]) -> Result<(u32, u32), SpsError> {
    if raw.len() < 3 {
        return Err(SpsError::Truncated);
    }
    let stripped = strip_emulation_prevention(&raw[2..]);
    let mut br = BitReader::new(&stripped);

    let _ = br.read_bits(4)?; // sps_video_parameter_set_id
    let max_sub_layers_minus1 = br.read_bits(3)?;
    let _ = br.read_bit()?; // sps_temporal_id_nesting_flag

    // profile_tier_level(1, maxSubLayersMinus1)
    let _ = br.read_bits(8)?; // profile_space(2)+tier(1)+profile_idc(5)
    let _ = br.read_bits(32)?; // profile_compatibility flags
    let _ = br.read_bits(48)?; // constraint indicators
    let _ = br.read_bits(8)?; // general_level_idc
    if max_sub_layers_minus1 > 0 {
        let mut sub_profile = 0u64;
        let mut sub_level = 0u64;
        for _ in 0..max_sub_layers_minus1 {
            sub_profile = (sub_profile << 1) | br.read_bit()? as u64;
            sub_level = (sub_level << 1) | br.read_bit()? as u64;
        }
        // 剩余 sub-layer 的 reserved_zero_2bits
        let _ = br.read_bits(2 * (8 - max_sub_layers_minus1) as usize)?;
        for i in 0..max_sub_layers_minus1 {
            if (sub_profile >> (max_sub_layers_minus1 - 1 - i)) & 1 == 1 {
                let _ = br.read_bits(8 + 32 + 48 + 8)?;
            }
            if (sub_level >> (max_sub_layers_minus1 - 1 - i)) & 1 == 1 {
                let _ = br.read_bits(8)?;
            }
        }
    }

    let _ = br.read_ue()?; // sps_seq_parameter_set_id
    let chroma_format_idc = br.read_ue()?;
    if chroma_format_idc == 3 {
        let _ = br.read_bit()?; // separate_colour_plane_flag
    }
    let pic_width = br.read_ue()?;
    let pic_height = br.read_ue()?;
    let conf_win_flag = br.read_bit()?;
    let (mut crop_left, mut crop_right, mut crop_top, mut crop_bottom) = (0u64, 0u64, 0u64, 0u64);
    if conf_win_flag == 1 {
        crop_left = br.read_ue()?;
        crop_right = br.read_ue()?;
        crop_top = br.read_ue()?;
        crop_bottom = br.read_ue()?;
    }

    let (sub_wc, sub_hc) = match chroma_format_idc {
        1 => (2u64, 2u64),
        2 => (2, 1),
        _ => (1, 1),
    };
    let width = pic_width.saturating_sub((crop_left + crop_right) * sub_wc);
    let height = pic_height.saturating_sub((crop_top + crop_bottom) * sub_hc);
    if width == 0 || height == 0 || width > 8192 || height > 8192 {
        return Err(SpsError::Implausible(width as u32, height as u32));
    }
    Ok((width as u32, height as u32))
}

/// 在一个 Annex-B 访问单元里找 SPS NAL 并解出宽高。返回 `(宽, 高, SPS NAL)`。
/// 没有 SPS 或解析失败时返回 `None`。
///
/// SPS 必须在**下一个起始码处截断**：切到访问单元末尾虽然也能解析（位读取器会提前停），
/// 但交给调用方的就是整个关键帧而不是 SPS——归档出的 sps.bin 曾因此达到 ~89KB。
pub fn recover_resolution(data: &[u8], codec: &str) -> Option<(u32, u32, Vec<u8>)> {
    if codec.is_empty() {
        return None;
    }
    let is_h265 = codec == "H265";
    let sps_type = if is_h265 { 33u8 } else { 7u8 };
    let mut i = 0;
    while i < data.len() {
        let idx = find_start_code(&data[i..])?;
        let pos = i + idx;
        let nal_pos = pos + 3;
        if nal_pos >= data.len() {
            return None;
        }
        let b = data[nal_pos];
        let t = if is_h265 { (b >> 1) & 0x3F } else { b & 0x1F };
        if t == sps_type {
            // 在下一个起始码处截断这个 NAL。
            let mut end = data.len();
            if let Some(next) = find_start_code(&data[nal_pos..]) {
                end = nal_pos + next;
                // 4 字节起始码（00 00 00 01）会留一个拖尾的 0。
                if end > nal_pos && data[end - 1] == 0 {
                    end -= 1;
                }
            }
            let sps = data[pos..end].to_vec(); // 起始码 + NAL，归档的规范单元
            let parsed = if is_h265 {
                parse_h265_sps(&sps[3..])
            } else {
                parse_h264_sps(&sps[3..])
            };
            if let Ok((w, h)) = parsed {
                return Some((w, h, sps));
            }
        }
        i = nal_pos + 1;
    }
    None
}

/// 在 `b` 中找下一个 `00 00 01` 起始码。
fn find_start_code(b: &[u8]) -> Option<usize> {
    b.windows(3).position(|w| w == [0x00, 0x00, 0x01])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用位写入器（SPS 编码）。
    struct BitWriter {
        buf: Vec<u8>,
        nbits: usize,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                buf: Vec::new(),
                nbits: 0,
            }
        }

        fn put_bit(&mut self, b: u32) {
            let idx = self.nbits / 8;
            if idx >= self.buf.len() {
                self.buf.push(0);
            }
            if b == 1 {
                self.buf[idx] |= 1 << (7 - (self.nbits % 8));
            }
            self.nbits += 1;
        }

        fn put_bits(&mut self, v: u64, n: usize) {
            for i in (0..n).rev() {
                self.put_bit(((v >> i) & 1) as u32);
            }
        }

        fn put_ue(&mut self, v: u64) {
            let val = v + 1;
            let bits = 64 - val.leading_zeros() as usize;
            for _ in 0..bits - 1 {
                self.put_bit(0);
            }
            for i in (0..bits).rev() {
                self.put_bit(((val >> i) & 1) as u32);
            }
        }

        fn bytes(&self) -> Vec<u8> {
            self.buf.clone()
        }
    }

    /// 手搓一个合法 HEVC SPS NAL（2 字节 NAL 头 + RBSP）。
    fn hevc_sps(w: u64, h: u64) -> Vec<u8> {
        let mut tw = BitWriter::new();
        tw.put_bits(0x42, 8); // NAL 头字节 0（type 33 = SPS_NUT）
        tw.put_bits(0x01, 8); // NAL 头字节 1
        tw.put_bits(0, 4); // sps_video_parameter_set_id
        tw.put_bits(0, 3); // sps_max_sub_layers_minus1
        tw.put_bits(1, 1); // sps_temporal_id_nesting_flag
        tw.put_bits(0, 2); // general_profile_space
        tw.put_bits(0, 1); // general_tier_flag
        tw.put_bits(1, 5); // general_profile_idc
        tw.put_bits(0, 32); // general_profile_compatibility_flag
        tw.put_bits(0, 48); // general_constraint_indicator_flag
        tw.put_bits(93, 8); // general_level_idc
        tw.put_ue(0); // sps_seq_parameter_set_id
        tw.put_ue(1); // chroma_format_idc
        tw.put_ue(w); // pic_width_in_luma_samples
        tw.put_ue(h); // pic_height_in_luma_samples
        tw.put_bits(1, 1); // conformance_window_flag
        tw.put_ue(0);
        tw.put_ue(0);
        tw.put_ue(0);
        tw.put_ue(0);
        tw.bytes()
    }

    /// 模拟 H.265 编码器：写出会形成 `00 00 0x`（x<=3）的字节前，在两个 0 后插 0x03。
    fn escape_nal(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(b.len() + 4);
        for (i, &byte) in b.iter().enumerate() {
            if i >= 2 && out[out.len() - 1] == 0 && out[out.len() - 2] == 0 && byte <= 3 {
                out.push(0x03);
            }
            out.push(byte);
        }
        out
    }

    #[test]
    fn parse_h265_sps_cases() {
        let (w, h) = parse_h265_sps(&hevc_sps(1920, 1080)).unwrap();
        assert_eq!((w, h), (1920, 1080));
    }

    // 逐字节照抄真机 High profile 设备的 SPS：六个 scaling list 都提前终止
    // （各 20 bit 而非 16 个 se(v)）。按固定长度读会越过 NAL 尾，解析失败、
    // 整场会话分辨率恒为 0x0。
    #[test]
    fn parse_h264_sps_high_profile_scaling_lists() {
        let sps: Vec<u8> = vec![
            0x67, 0x64, 0x00, 0x1f, 0xad, 0x84, 0x01, 0x0c, 0x20, 0x08, 0x61, 0x00, 0x43, 0x08,
            0x02, 0x18, 0x40, 0x10, 0xc2, 0x00, 0x84, 0x3b, 0x70, 0x28, 0x02, 0xdd, 0x37, 0x01,
            0x01, 0x01, 0x40, 0x00, 0x00, 0x03, 0x00, 0x40, 0x00, 0x00, 0x0c, 0xa1, 0x00,
        ];
        let (w, h) = parse_h264_sps(&sps).unwrap();
        assert_eq!((w, h), (1280, 720));
    }

    #[test]
    fn recover_resolution_in_stream() {
        let sps = hevc_sps(1280, 720);
        // AU = SPS NAL（起始码 + NAL）+ 一个 slice NAL。
        let mut au = vec![0x00, 0x00, 0x00, 0x01];
        au.extend_from_slice(&sps);
        au.extend_from_slice(&[0x00, 0x00, 0x01, 0x26, 0x01]); // H265 TRAIL_R

        let (w, h, sps_nal) = recover_resolution(&au, "H265").expect("ok=false");
        assert_eq!((w, h), (1280, 720));
        // 交出的必须是单个 SPS NAL，不是关键帧的剩余部分。
        assert!(
            sps_nal.len() <= 128,
            "recovered SPS is {} bytes",
            sps_nal.len()
        );
        assert_eq!(sps_nal[3] >> 1 & 0x3F, 33, "NAL type must be SPS");
    }

    #[test]
    fn strip_emulation_prevention_cases() {
        let cases: Vec<(&[u8], &[u8])> = vec![
            (&[0x00, 0x00, 0x03, 0x00], &[0x00, 0x00, 0x00]),
            (&[0x00, 0x00, 0x03, 0x01], &[0x00, 0x00, 0x01]),
            (
                &[0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x03, 0x03],
                &[0x00, 0x00, 0x02, 0x00, 0x00, 0x03],
            ),
            (&[0x01, 0x02, 0x03], &[0x01, 0x02, 0x03]), // 无 00 00 前缀，原样
        ];
        for (input, want) in cases {
            assert_eq!(
                strip_emulation_prevention(input),
                want,
                "input {input:02x?}"
            );
        }
    }

    // 合法 SPS 的 RBSP 里天然含 `00 00 0x` 串（32 位 profile_compatibility 全零）：
    // 剥掉线格式的 EPB 之后必须仍然解出正确分辨率。不剥就会把字段整体错位，
    // 真机上表现为 1280x720 解成 2x1。
    #[test]
    fn parse_h265_sps_with_epb() {
        let nal = hevc_sps(1280, 720); // 合法 SPS，尚无 EPB
        let escaped = escape_nal(&nal); // 线格式（带 0x03 转义）
        assert_ne!(nal, escaped, "escape_nal must have inserted EPBs");
        let (w, h) = parse_h265_sps(&escaped).unwrap();
        assert_eq!((w, h), (1280, 720));
    }

    #[test]
    fn no_sps_no_resolution() {
        // 只有 slice 的访问单元：没有 SPS，返回 None。
        let au = vec![0x00, 0x00, 0x00, 0x01, 0x41, 0x9a, 0x00];
        assert!(recover_resolution(&au, "H264").is_none());
        // 空编码名同样不出结果。
        assert!(recover_resolution(&au, "").is_none());
    }
}
