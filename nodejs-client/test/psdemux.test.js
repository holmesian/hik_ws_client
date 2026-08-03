import { describe, it } from 'node:test';
import assert from 'node:assert';
import { PsDemuxer, isPSData } from '../src/psdemux.js';

// 构造一个最小可解的 MPEG-PS 访问单元：pack 头 + system header + 一个视频 PES 包。
// 流需要第二个 pack 头来关闭第一个访问单元（一帧延迟是 PS 容器固有）。
function buildPS(payload) {
  const start = Buffer.from([0x00, 0x00, 0x01]);

  // pack header: ba + 10 字节（stuffing=0 -> n=14）
  const pack = Buffer.concat([
    start,
    Buffer.from([0xba]),
    Buffer.alloc(10, 0x00),
  ]);

  // system header: bb + 2 字节长度（这里给 0）
  const sys = Buffer.concat([
    start,
    Buffer.from([0xbb]),
    Buffer.from([0x00, 0x00]),
  ]);

  // PES 视频包: e0 + 2 字节长度 + PES 可选头(0x80,0x80,0x05) + 5 字节 PTS + 载荷。
  // PTS 字节任取即可——本测试只验证 hasPTS 与载荷重组，不校验具体时间戳解码值。
  const pesHeader = Buffer.from([0x80, 0x80, 0x05]); // PTS 仅标志, hlen=5
  const ptsBytes = Buffer.from([0x21, 0x00, 0x01, 0x00, 0x02]);
  const pesPayload = Buffer.concat([pesHeader, ptsBytes, payload]);
  const pesLen = Buffer.from([(pesPayload.length >> 8) & 0xff, pesPayload.length & 0xff]);
  const pes = Buffer.concat([start, Buffer.from([0xe0]), pesLen, pesPayload]);

  return Buffer.concat([pack, sys, pes]);
}

const PAYLOAD = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x00, 0x00, 0x01, 0x65, 0x01]);

describe('psdemux isPSData', () => {
  it('accepts a PS stream starting with a pack header', () => {
    assert.strictEqual(isPSData(Buffer.from([0x00, 0x00, 0x01, 0xba, 0x00])), true);
  });

  it('accepts a PS stream starting with an audio PES (non-pack) start code', () => {
    // 实时流可能在任意包接入，首帧未必以 pack 头开头
    assert.strictEqual(isPSData(Buffer.from([0x00, 0x00, 0x01, 0xc0, 0x00])), true);
  });

  it('rejects raw annex-b elementary stream', () => {
    // NAL 头最高位恒为 0，到不了容器使用的流 ID（>= 0xb9）
    assert.strictEqual(isPSData(Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67])), false);
  });
});

describe('PsDemuxer', () => {
  it('reassembles a single access unit from a PS pack', () => {
    const ps = new PsDemuxer();
    // 第一个 pack 头关闭的是空 AU；再给第二个 pack 头来关闭第一个真正的 AU
    const secondPack = Buffer.concat([
      Buffer.from([0x00, 0x00, 0x01, 0xba]),
      Buffer.alloc(10, 0x00),
    ]);
    const stream = Buffer.concat([buildPS(PAYLOAD), secondPack]);
    const frames = ps.feed(stream);
    const flushed = ps.flush();
    const all = frames.concat(flushed);
    assert.strictEqual(all.length, 1);
    assert.ok(all[0].data.equals(PAYLOAD));
    assert.strictEqual(all[0].hasPTS, true);
    assert.ok(Number(all[0].pts) > 0);
  });

  it('buffers a partial pack across feeds', () => {
    const ps = new PsDemuxer();
    const full = Buffer.concat([buildPS(PAYLOAD), Buffer.from([0x00, 0x00, 0x01, 0xba]), Buffer.alloc(10, 0x00)]);
    const first = ps.feed(full.subarray(0, 20));
    assert.strictEqual(first.length, 0); // 不完整，无 AU
    const rest = ps.feed(full.subarray(20));
    const all = first.concat(rest).concat(ps.flush());
    assert.strictEqual(all.length, 1);
  });

  it('returns independent frame copies', () => {
    const ps = new PsDemuxer();
    const stream = Buffer.concat([buildPS(PAYLOAD), Buffer.from([0x00, 0x00, 0x01, 0xba]), Buffer.alloc(10, 0x00)]);
    const frames = ps.feed(stream).concat(ps.flush());
    assert.strictEqual(frames.length, 1);
    const copy = Buffer.from(frames[0].data);
    copy[0] = 0xff;
    assert.notStrictEqual(frames[0].data[0], 0xff);
  });
});
