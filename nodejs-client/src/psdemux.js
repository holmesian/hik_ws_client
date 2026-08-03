// psdemux.js — MPEG-PS 解复用（移植自 go-client/psdemux.go）
//
// 设备把单个 NAL 拆到多个 PES 包里（一个 PES 头可能落在某个 VPS 中间），所以
// 原始 PS 字节不能直接当 annex-b 扫描：start-code 扫描既会漏掉真正的 NAL，又会
// 把 PES 流 ID 误当成 NAL 头匹配上。必须先解 PS 容器、重组访问单元。
//
// 一个 PS pack 恰好承载一个访问单元，因此 pack 头会关闭上一帧。这带来一帧的
// 固有延迟——只有下一帧开始，上一帧才算完整。

// MPEG-PS 起始码后面的 ID 字节（00 00 01 之后的那个）。
const PS_END_CODE = 0xb9; // program end；容器用到的最小 ID
const PS_PACK_START = 0xba; // pack header —— 开启一个新访问单元
const PS_SYSTEM_START = 0xbb; // system header；PSM/PES 都在它之上
const PES_VIDEO_FIRST = 0xe0;
const PES_VIDEO_LAST = 0xef;

const START_CODE = Buffer.from([0x00, 0x00, 0x01]);

// PsFrame 是从 PS 容器里重组出的一个视频访问单元。
export class PsFrame {
  constructor() {
    this.data = Buffer.alloc(0);
    this.pts = 0;
    this.hasPTS = false;
  }
}

// PsDemuxer 从海康 MPEG-PS 容器里重组视频基本流。
export class PsDemuxer {
  constructor() {
    this.buf = Buffer.alloc(0); // 跨 Feed 调用缓冲的不完整单元
    this.au = Buffer.alloc(0); // 当前正在累积的访问单元
    this.pts = 0;
    this.hasPTS = false;
    this.synced = false; // 见过 pack 头之前都处于"帧中间"
  }

  // Feed 吞入一段 PS 字节，返回它完成的访问单元。分片可能在任意位置切断一个
  // pack；剩余部分缓冲到下一次调用。缓冲最多只保留一个不完整单元（PES 包按
  // 64KiB 长度界定），因此不会无限增长。
  feed(data) {
    this.buf = Buffer.concat([this.buf, data]);

    const out = [];
    let off = 0;
    while (off < this.buf.length) {
      const [n, frame, ok] = this.step(this.buf.subarray(off));
      if (!ok) break;
      if (frame) out.push(frame);
      off += n;
    }
    this.buf = this.buf.subarray(off);
    return out;
  }

  // step 解析一个容器单元。返回消耗的字节数、可能完成的访问单元，以及
  // ok=false 表示还需要更多数据。
  step(b) {
    if (b.length < 4) return [0, null, false];

    if ((b[0] | b[1]) !== 0 || b[2] !== 0x01) {
      // 不在起始码上——重新同步。保留末尾 2 字节，它们可能是被截断的起始码头。
      const idx = b.indexOf(START_CODE);
      if (idx >= 0) return [idx, null, true];
      return [b.length - 2, null, true];
    }

    const sid = b[3];
    if (sid === PS_PACK_START) {
      // 14 字节 pack 头 + pack_stuffing_length（第 13 字节低 3 位）。
      if (b.length < 14) return [0, null, false];
      const n = 14 + (b[13] & 0x07);
      if (b.length < n) return [0, null, false];
      const f = this.closeAU();
      this.synced = true;
      return [n, f, true];
    }

    if (sid >= PS_SYSTEM_START) {
      // system header、PSM 以及每个 PES 包共用 6 字节长度界定形式。
      if (b.length < 6) return [0, null, false];
      const n = 6 + b.readUInt16BE(4);
      if (b.length < n) return [0, null, false];
      if (sid >= PES_VIDEO_FIRST && sid <= PES_VIDEO_LAST) {
        this.appendPES(b.subarray(6, n));
      }
      return [n, null, true];
    }

    // 不是容器起始码（一个 stray NAL 前缀）——跳过它。
    return [3, null, true];
  }

  // Flush 发出仍缓冲的访问单元（如果有）。流结束时必须调用：因为一个 PS pack
  // 关闭上一帧，最后一帧只有在 Flush 时才完成（一帧延迟是容器固有的，这里必然回收）。
  flush() {
    const f = this.closeAU();
    return f ? [f] : [];
  }

  // closeAU 发出迄今累积的访问单元（如果有）。访问单元拿到自己恰好大小的副本，
  // 累加器保留容量供下一单元复用。调用方仍拿到私有切片，因此它们对帧做的任何
  // 事都不会互相影响。
  closeAU() {
    if (this.au.length === 0) return null;
    const data = Buffer.from(this.au); // 独立副本
    const f = new PsFrame();
    f.data = data;
    f.pts = this.pts;
    f.hasPTS = this.hasPTS;
    this.au = Buffer.alloc(0);
    this.pts = 0;
    this.hasPTS = false;
    return f;
  }

  // appendPES 剥离 PES 头并把载荷追加到当前访问单元，从第一个携带 PTS 的 PES 包
  // 取走帧 PTS。
  //
  // b 是 6 字节起始码/长度前缀之后的字节。其后的 MPEG-2 PES 可选头是 THREE 字节，
  // 不是两字节：
  //   b[0] '10' 标记 + scrambling/priority/alignment 标志（通常 0x80）
  //   b[1] PTS_DTS_flags（位 7-6）+ ESCR/ES_rate/DSM/copy/CRC/ext 标志
  //   b[2] PES_header_data_length，覆盖 b[3:3+hlen]（PTS、DTS……）
  appendPES(b) {
    // 实时流在任意点接入，所以第一个 pack 头之前的 PES 包是某个我们从未见其开头的
    // 访问单元的尾巴。实测 42 台相机里 7 台这样开局，有一次是 151KiB 的关键帧尾巴——
    // 直接发出会在每个此类会话开头产生一帧无 PTS、不可解码的帧。
    if (!this.synced) return;
    if (b.length < 3 || (b[0] & 0xc0) !== 0x80) return;
    const hlen = b[2];
    if (b.length < 3 + hlen) return;
    // PTS_DTS_flags 占据 b[1] 的位 7-6；0b10 = 仅 PTS，0b11 = PTS+DTS。
    if ((b[1] & 0x80) !== 0 && hlen >= 5 && !this.hasPTS) {
      this.pts = readPTS(b.subarray(3, 8));
      this.hasPTS = true;
    }
    this.au = Buffer.concat([this.au, b.subarray(3 + hlen)]);
  }
}

// readPTS 从 5 字节 PES 时间戳字段解码 33 位 PTS。
export function readPTS(b) {
  return (
    (BigInt((b[0] >> 1) & 0x07) << 30n) |
    (BigInt(b[1]) << 22n) |
    (BigInt((b[2] >> 1) & 0x7f) << 15n) |
    (BigInt(b[3]) << 7n) |
    (BigInt(b[4] >> 1))
  );
}

// isPSData 报告 b 是否以 MPEG-PS 起始码开头，用于分类未声明容器的流。
//
// 任意 PS 起始码都算，不只是 pack 头：实时流在任意点接入，所以它的第一帧可能开在
// 容器的任意包上。某台相机以音频 PES（00 00 01 c0）开局，被整会话判成非 PS 流，
// 把原始传输块当帧发出。
//
// 0xB9 下限把裸 annex-b 基本流挡在外面：NAL 头字节最高位永远为 0，所以永远到不了
// 容器使用的那些流 ID。
export function isPSData(b) {
  return (
    b.length >= 4 && b[0] === 0 && b[1] === 0 && b[2] === 1 && b[3] >= PS_END_CODE
  );
}
