import { describe, it } from 'node:test';
import assert from 'node:assert';
import { sniffCodec, analyzeFrame, clone } from '../src/media.js';

function annexb(nalType, payload = Buffer.from([0x01, 0x02, 0x03])) {
  // 构造一个 annex-b 访问单元：起始码 + 单 NAL
  return Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x01]), Buffer.from([nalType]), payload]);
}

describe('media sniffCodec', () => {
  it('detects H265 from VPS/SPS/PPS NAL header bytes', () => {
    // 0x40 / 0x42 / 0x44 是 H.265 两字节头的层0 参数集
    assert.strictEqual(sniffCodec(annexb(0x40)), 'H265');
    assert.strictEqual(sniffCodec(annexb(0x42)), 'H265');
    assert.strictEqual(sniffCodec(annexb(0x44)), 'H265');
  });

  it('detects H264 from SPS NAL (type 7, ref_idc non-zero)', () => {
    // 0x67 = 0b01100111 -> (b&0x9f)==7 且 (b&0x60)!=0
    assert.strictEqual(sniffCodec(annexb(0x67)), 'H264');
  });

  it('returns empty string when no parameter set is present', () => {
    // 仅 IDR slice（type 5）：不会被当作参数集识别
    assert.strictEqual(sniffCodec(annexb(0x65)), '');
  });
});

describe('media analyzeFrame', () => {
  it('flags H264 IDR (nal type 5) as keyframe', () => {
    const f = annexb(0x65);
    assert.strictEqual(analyzeFrame(f, 'H264'), true);
    assert.strictEqual(analyzeFrame(f, ''), true); // 空 codec 回退到 H264 判定
  });

  it('flags H265 IRAP (nal types 16-21) as keyframe', () => {
    // 0x28 = 0b00101000 -> (b>>1)&0x3f = 20 -> IRAP
    const f = annexb(0x28);
    assert.strictEqual(analyzeFrame(f, 'H265'), true);
  });

  it('does not flag a non-key H264 slice as keyframe', () => {
    // 0x61 = 0b01100001 -> type 1 (non-IDR)
    const f = annexb(0x61);
    assert.strictEqual(analyzeFrame(f, 'H264'), false);
  });

  it('disambiguates overlapping NAL types by codec', () => {
    // 0x42 作为 H.264 读是 type 2（data partition），但指定 H265 时它是 SPS 而非关键帧
    const f = annexb(0x42);
    // 0x42 在 H265 下不是 IRAP(16-21)，故不是关键帧
    assert.strictEqual(analyzeFrame(f, 'H265'), false);
  });
});

describe('media clone', () => {
  it('returns an independent copy', () => {
    const src = Buffer.from([1, 2, 3]);
    const c = clone(src);
    assert.notStrictEqual(c, src);
    assert.ok(c.equals(src));
    c[0] = 9;
    assert.strictEqual(src[0], 1);
  });
});
