import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  RtpDetector,
  rtpStrip,
  rtpHeaderPlausible,
  rtpConsecutive,
} from '../src/rtp.js';

// 构造一个 RTP 包：12 字节固定头（无 CSRC/扩展/填充），给定 seq 与 SSRC，后接媒体载荷。
function rtpPacket(seq, ssrc, payload) {
  const hdr = Buffer.alloc(12);
  hdr[0] = 0x80; // 版本 2
  hdr[1] = 96;   // payload type
  hdr.writeUInt16BE(seq, 2);
  hdr.writeUInt32BE(0, 4);
  hdr.writeUInt32BE(ssrc, 8);
  return Buffer.concat([hdr, payload]);
}

const SSRC = 0x12345678;
const A = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
const B = Buffer.from([0x01, 0x02, 0x03, 0x04]);

describe('rtp rtpStrip', () => {
  it('strips a 12-byte header from an RTP packet', () => {
    const pkt = rtpPacket(1, SSRC, A);
    assert.ok(rtpStrip(pkt).equals(A));
  });

  it('passes through a non-RTP buffer unchanged', () => {
    const raw = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67]);
    assert.ok(rtpStrip(raw).equals(raw));
  });
});

describe('rtp rtpHeaderPlausible / rtpConsecutive', () => {
  it('flags a plausible RTP header', () => {
    assert.strictEqual(rtpHeaderPlausible(rtpPacket(1, SSRC, A)), true);
    assert.strictEqual(rtpHeaderPlausible(Buffer.from([0x00, 0x00, 0x00, 0x01])), false);
  });

  it('detects consecutive sequence numbers with same SSRC (16-bit wrap)', () => {
    assert.strictEqual(rtpConsecutive(rtpPacket(0xfffe, SSRC, A), rtpPacket(0xffff, SSRC, B)), true);
    assert.strictEqual(rtpConsecutive(rtpPacket(1, SSRC, A), rtpPacket(1, SSRC, B)), false); // gap 0
    assert.strictEqual(rtpConsecutive(rtpPacket(1, SSRC, A), rtpPacket(2, 0x99999999, B)), false); // 不同 SSRC
  });
});

describe('RtpDetector', () => {
  it('classifies a RTP stream after a consecutive pair and strips both packets', () => {
    const d = new RtpDetector();
    const out1 = d.feed(rtpPacket(100, SSRC, A)); // 持有
    assert.strictEqual(out1.length, 0);
    assert.strictEqual(d.decided, false);
    const out2 = d.feed(rtpPacket(101, SSRC, B)); // 配对成功 -> 一次性放出两条
    assert.strictEqual(d.decided, true);
    assert.strictEqual(d.isRTP, true);
    assert.strictEqual(out2.length, 2);
    assert.ok(out2[0].equals(A));
    assert.ok(out2[1].equals(B));
  });

  it('classifies a raw annex-b stream immediately (first message not RTP)', () => {
    const d = new RtpDetector();
    const raw = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67, 0x42]);
    const out = d.feed(raw);
    assert.strictEqual(d.decided, true);
    assert.strictEqual(d.isRTP, false);
    assert.strictEqual(out.length, 1);
    assert.ok(out[0].equals(raw));
  });

  it('flushes held messages as raw when never paired', () => {
    // 单条 RTP 头但从不出现配对 -> 保持"裸流"判定，原样透传（不剥离不存在的头）
    const d = new RtpDetector();
    const pkt = rtpPacket(1, SSRC, A);
    const out = d.feed(pkt);
    assert.strictEqual(out.length, 0);
    const flushed = d.flush();
    assert.strictEqual(flushed.length, 1);
    assert.ok(flushed[0].equals(pkt)); // 透传完整包，不剥离
  });

  it('applies the decision to later messages', () => {
    const d = new RtpDetector();
    d.feed(Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67])); // 裸流定案
    const pkt = rtpPacket(5, SSRC, A);
    const out = d.feed(pkt);
    assert.strictEqual(d.isRTP, false);
    assert.ok(out[0].equals(pkt)); // 仍按裸流透传
  });
});
