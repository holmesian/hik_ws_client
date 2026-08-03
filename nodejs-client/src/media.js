// media.js — 媒体管线辅助（移植自 go-client/media.go 的 sniffCodec / AnalyzeFrame）
//
// 这些辅助把解复用出来的 annex-b 访问单元变成可调用的帧元数据：编码判定与关键帧识别。
// 分辨率恢复（从 SDP 之外的内联 SPS 做完整比特解析）不在本次对齐范围内——它依赖一份
// 庞大的 SPS 比特解析器，且非 owner 列出的关键能力。

// indexOfStartCode 在 buf 中从 from 起查找 annex-b 起始码 00 00 01，返回下标或 -1。
function indexOfStartCode(buf, from) {
  return buf.indexOf(Buffer.from([0x00, 0x00, 0x01]), from);
}

// sniffCodec 从 annex-b 访问单元的 NAL 头识别视频编码，用于 MEDIAINFO 头无法解码的流。
// 返回 "H264"、"H265"，或 "" （无任何结论时，调用方应在后续访问单元上继续尝试）。
//
// 它锁定参数集，因为两种编码在每个关键帧前都会重发它们，而这些 NAL 头的两种读法在
// 实践中不会撞车：
//   - H.265 两字节头：VPS/SPS/PPS 为类型 32/33/34、层 0，故首字节读成 0x40/0x42/0x44。
//     当作 H.264 读则是类型 0/2/4——"unspecified" 与两个 slice data partition，没有相机
//     配置会发。
//   - H.264 一字节头：SPS 是类型 7 且 ref_idc 恒非 0，故读成 0x27/0x47/0x67。当作 H.265
//     读则是保留或非零层类型。
export function sniffCodec(data) {
  let i = 0;
  while (i < data.length) {
    const idx = indexOfStartCode(data, i);
    if (idx < 0) break;
    const nalPos = idx + 3; // indexOf 返回绝对下标；NAL 头紧跟 3/4 字节起始码之后
    if (nalPos >= data.length) break;
    const b = data[nalPos];
    if (b === 0x40 || b === 0x42 || b === 0x44) return "H265";
    if ((b & 0x9f) === 7 && (b & 0x60) !== 0) return "H264";
    i = nalPos + 1;
  }
  return "";
}

// analyzeFrame 扫描 H.264/H.265 annex-b 帧里的 NAL 单元，报告它是否含关键 NAL。codec
// 必需，因为 H.264 与 H.265 的 NAL 类型字段重叠，所以用 SDP 恢复的 codec 来消歧：codec
// 为 "H265" 时任意 IRAP NAL（类型 16-21）标记关键帧，否则用 H.264 的 IDR 类型（5）。
// 假定数据以 NAL 开头（可选前置 00 00 00 01 或 00 00 01 起始码），这正是 PS 解复用与裸
// 基本流给出的载荷形态。
export function analyzeFrame(data, codec) {
  const isH265 = codec === "H265";
  let i = 0;
  while (i < data.length) {
    const idx = indexOfStartCode(data, i);
    if (idx < 0) break;
    const nalPos = idx + 3; // 起始码的 01 在 idx+2，NAL 头紧随其后
    if (nalPos >= data.length) break;
    const b = data[nalPos];
    if (isH265) {
      const t = (b >> 1) & 0x3f;
      // IRAP NAL 单元（IDR/CRA）无需先前帧即可解码。
      if (t >= 16 && t <= 21) return true;
    } else {
      if ((b & 0x1f) === 5) return true; // H.264 IDR
    }
    i = nalPos + 1;
  }
  return false;
}

// clone 复制一段缓冲区。每个离开读循环的载荷都必须复制：交给异步投递 worker 后它仍持有
// 这段缓冲，而 OnVideoData / OnRawVideo 的调用方有权保留交给他们的字节。
export function clone(b) {
  return Buffer.from(b);
}
