//! `MediaInfo` / `FrameMeta` 类型。对应 `go-client/media.go`。

/// realplay SDP 解析出的流描述（SDP 级元信息）。
///
/// **SDP 只是提示，码流才是事实**（ADR-0002）：容器与编码以 MEDIAINFO 头为准（解不出时
/// 留空、靠嗅探兜底），分辨率一律从码流内 SPS 还原，PS 时钟恒为 90kHz（不采信 rtpmap）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaInfo {
    /// 服务端返回的 SDP 原文。
    pub sdp: String,
    /// 载荷封装：`PS`（MPEG program stream——相机实际发的）、`RTP`、`GB`、`HIK`、`RAW`。
    /// 空 = SDP 没带 MEDIAINFO 头（或解不出），按裸基本流处理。
    pub container: String,
    /// 编码：`H264` / `H265`。
    pub codec: String,
    /// 时间戳时钟频率（H.26x 为 90000）。
    pub clock_rate: i64,
    /// 宽 / 高，从码流内 SPS 还原。MEDIAINFO 头不带分辨率，PS 流在见到第一个 SPS 前为 0。
    pub width: u32,
    pub height: u32,
    /// `sprop-parameter-sets` 里的 base64 SPS/PPS（标准 RTP 式 SDP 才带）。
    pub parameter_sets: Vec<String>,
}

/// 单帧元信息。基本流不带 DTS/PTS：没有容器 PTS 时，PTS / TimestampMs 由到达时间与
/// SDP 时钟频率合成，给出单调、保序的时间戳。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameMeta {
    pub frame_index: u64,
    pub is_key_frame: bool,
    pub codec: String,
    pub width: u32,
    pub height: u32,
    /// 容器 PTS（90kHz，`has_pts` 为真时）；否则为按到达时间合成的值。
    pub pts: i64,
    /// PTS 来自容器还是合成。
    pub has_pts: bool,
    /// 取流开始以来的墙上时钟毫秒数。
    pub timestamp_ms: i64,
}
