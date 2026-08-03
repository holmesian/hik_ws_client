// rtp.js — RTP 判定与剥离（移植自 go-client/rtp.go）
//
// 部分代理把容器塞进 RTP 而非裸传：一个 WebSocket 消息承载一个 RTP 包，携带一段
// MPEG-PS 流的分片。封装的两部分都必须剥离：
//   - 头部：12 字节固定 + CSRC 列表 + 可选扩展；
//   - 尾部填充：P 位置位时由最后一个字节计数（含它自己）。
// 任一处遗漏都是"静默破坏"而非"明显坏掉"：一个 PES 包按声明长度被消费，注入的字
// 节会挤掉真实载荷而不是平移它——帧数、关键帧数、NAL 普查甚至基本流长度都完全正确，
// 而切片数据已损坏。

const RTP_FIXED_HEADER = 12;

// rtpStrip 从单个包剥离 RTP 封装，返回媒体字节。假设调用方已经确定该会话是 RTP。
export function rtpStrip(b) {
  if (b.length < RTP_FIXED_HEADER || (b[0] >> 6) !== 2) return b;
  let n = RTP_FIXED_HEADER + 4 * (b[0] & 0x0f); // CSRC 列表
  if ((b[0] & 0x10) !== 0) {
    // 扩展：2 字节 profile，2 字节 以字为单位的 length
    if (b.length < n + 4) return b;
    n += 4 + 4 * b.readUInt16BE(n + 2);
  }
  if (n >= b.length) return b;
  let p = b.subarray(n);
  if ((b[0] & 0x20) !== 0) {
    // padding，由最后一个字节计数并包含它自己
    const pad = p[p.length - 1];
    if (pad === 0 || pad > p.length) return b;
    p = p.subarray(0, p.length - pad);
  }
  return p;
}

// rtpProbeMessages 限制持有量：这么多消息里仍未找到匹配对，则判定为裸流，原样释放。
const RTP_PROBE_MESSAGES = 4;

// RtpDetector 每个会话一次性决定媒体消息是否被 RTP 包裹，并把该决定套用到每条消息。
//
// 不能逐消息判定：裸 MPEG-PS 流只有第一帧以 pack 头开头，其后每条消息都是容器中间的
// 任意字节续传，而任意字节里有 1/4 的概率高位两位置为 0b10——一个完全合法的 RTP 版本
// 字段。逐消息判定因此会从裸 PS 部署的四分之一消息里切掉 12 字节头，外加最后一个字节
// 碰巧声称的填充。
//
// 所以判定来自"一对"消息：RTP 携带常量 SSRC 和递增 1 的序列号；容器字节在全部 48 位上
// 一致只是任何真实流都到不了的巧合。
//
// 这对消息不必相邻：WebSocket 消息边界不是 RTP 包边界——HVAG 相机家族里代理把第一个
// 8204 字节包拆成 8192 + 12 字节尾巴，所以第二条消息是包中间，过不了头部检查。要求相邻
// 会把一个真正 RTP 的会话整个锁在裸路径上。前几条消息改作持有，在这几条里找这对。
export class RtpDetector {
  constructor() {
    this.decided = false;
    this.isRTP = false;
    this.held = [];
  }

  // feed 返回待处理的载荷：持有期间为 none，会话分类后一次性全部返回。
  feed(b) {
    if (this.decided) return [this.apply(b)];
    if (this.held.length === 0 && !rtpHeaderPlausible(b)) {
      // 第一条消息不可能是 RTP 就立即定案——常见情形：裸 PS 以 0x00 开局。
      this.decided = true;
      return [b];
    }
    this.held.push(Buffer.from(b)); // 留存私有副本
    this.isRTP = rtpPairFound(this.held);
    if (!this.isRTP && this.held.length < RTP_PROBE_MESSAGES) return [];
    this.decided = true;
    return this.release();
  }

  // flush 在会话结束、判定器尚未定案前释放持有的消息。没有确认对就无从校验序列，
  // 因此按非 RTP 处理：把字节透传留下的是可恢复的流，而剥离一个从不存在的头则不是。
  flush() {
    if (this.held.length === 0) return [];
    this.decided = true;
    return this.release();
  }

  release() {
    const out = [];
    for (const h of this.held) out.push(this.apply(h));
    this.held = [];
    return out;
  }

  apply(b) {
    return this.isRTP ? rtpStrip(b) : b;
  }
}

// rtpHeaderPlausible 报告 b 是否可能是一个 RTP 包。
export function rtpHeaderPlausible(b) {
  return b.length >= RTP_FIXED_HEADER && (b[0] >> 6) === 2;
}

// rtpPairFound 报告持有的消息里是否包含同一流的两个 RTP 包。处于包中间的分片消息只是
// 过不了头部检查并被跳过，所以两个里只需较早的是包起点——这对不必在消息列表里相邻。
export function rtpPairFound(msgs) {
  for (let i = 0; i < msgs.length; i++) {
    if (!rtpHeaderPlausible(msgs[i])) continue;
    for (let j = i + 1; j < msgs.length; j++) {
      if (rtpHeaderPlausible(msgs[j]) && rtpConsecutive(msgs[i], msgs[j])) {
        return true;
      }
    }
  }
  return false;
}

// rtpConsecutive 报告 b 是否是 a 同一 RTP 流的后续包：相同 SSRC，序列号领先不超过探测窗口。
// 间隙允许消息分片藏在其间的包；对其设界让容器需要凑齐的 48 位巧合够不着。
export function rtpConsecutive(a, b) {
  if (!a.subarray(8, 12).equals(b.subarray(8, 12))) return false;
  const seqA = a.readUInt16BE(2);
  const seqB = b.readUInt16BE(2);
  // 16 位回绕，与序列号一致
  const gap = (seqB - seqA) & 0xffff;
  return gap >= 1 && gap <= RTP_PROBE_MESSAGES;
}
