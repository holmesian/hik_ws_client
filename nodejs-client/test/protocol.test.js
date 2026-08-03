import { describe, it } from 'node:test';
import assert from 'node:assert';
import { packMessage, unpackMessage, MsgTypeVideoData } from '../src/protocol.js';

describe('protocol', () => {
  it('packMessage creates correct buffer', () => {
    const payload = Buffer.from('hello');
    const packed = packMessage(MsgTypeVideoData, payload);
    assert.strictEqual(packed.length, 5 + payload.length);
    assert.strictEqual(packed[0], MsgTypeVideoData);
    assert.strictEqual(packed.readUInt32BE(1), payload.length);
    assert.deepStrictEqual(packed.subarray(5), payload);
  });

  it('unpackMessage extracts payload correctly', () => {
    const payload = Buffer.from('test data');
    const packed = packMessage(0x02, payload);
    const { msgType, payload: unpackedPayload, remaining } = unpackMessage(packed);
    assert.strictEqual(msgType, 0x02);
    assert.deepStrictEqual(unpackedPayload, payload);
    assert.deepStrictEqual(remaining, Buffer.alloc(0));
  });

  it('unpackMessage handles incomplete data', () => {
    const buf = Buffer.from([0x40, 0x00, 0x00]);
    const result = unpackMessage(buf);
    assert.strictEqual(result.msgType, null);
    assert.deepStrictEqual(result.remaining, buf);
  });

  it('unpackMessage handles remaining data', () => {
    const payload1 = Buffer.from('first');
    const payload2 = Buffer.from('second');
    const packed1 = packMessage(0x01, payload1);
    const packed2 = packMessage(0x02, payload2);
    const combined = Buffer.concat([packed1, packed2]);

    const result1 = unpackMessage(combined);
    assert.strictEqual(result1.msgType, 0x01);
    assert.deepStrictEqual(result1.payload, payload1);
    assert.ok(result1.remaining.length > 0);

    const result2 = unpackMessage(result1.remaining);
    assert.strictEqual(result2.msgType, 0x02);
    assert.deepStrictEqual(result2.payload, payload2);
  });
});
