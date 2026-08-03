// verify.mjs — 功能级实测验证（超出单测），覆盖本次移植的能力。
// 运行: node verify.mjs    （依赖已 npm install）
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import WebSocket from 'ws';
import { PsDemuxer, isPSData } from './src/psdemux.js';
import { RtpDetector, rtpStrip } from './src/rtp.js';
import { sniffCodec, analyzeFrame, clone } from './src/media.js';
import {
  HikMediaClient,
  ServerError,
  buildRealplayRequest,
} from './src/client.js';
import { generateClientIVKey } from './src/crypto.js';

const results = [];
function check(name, cond, detail = '') {
  const ok = !!cond;
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
}

const baseConfig = {
  deviceIP: '192.168.1.64', devicePort: 65001,
  proxyHost: 'proxy.example.com', proxyPort: 443,
  password: 'secret', version: '20210428', cipherSuites: 'all',
};

// 把一个 33 位 PTS 编码成 MPEG PES 5 字节时间戳（与 psdemux.readPTS 互逆）
function encodePTS(v) {
  return [
    ((v >> 30n) & 7n) << 1n,
    (v >> 22n) & 0xffn,
    ((v >> 15n) & 0x7fn) << 1n,
    (v >> 7n) & 0xffn,
    (v & 0x7fn) << 1n,
  ].map((x) => Number(x) & 0xff);
}

// ---- 1. PS 解复用：合成多 PES 包访问单元 ----
function psPack(payloads, pts) {
  const start = Buffer.from([0x00, 0x00, 0x01]);
  const pack = Buffer.concat([start, Buffer.from([0xba]), Buffer.alloc(10, 0x00)]);
  const sys = Buffer.concat([start, Buffer.from([0xbb]), Buffer.from([0x00, 0x00])]);
  const pesChunks = [];
  payloads.forEach((pl, i) => {
    const ptsBytes = i === 0 ? encodePTS(BigInt(pts)) : [0x80, 0x00, 0x00, 0x00, 0x00];
    const pesPayload = Buffer.concat([Buffer.from([0x80, 0x80, 0x05]), Buffer.from(ptsBytes), pl]);
    const pesLen = Buffer.from([(pesPayload.length >> 8) & 0xff, pesPayload.length & 0xff]);
    pesChunks.push(Buffer.concat([start, Buffer.from([0xe0]), pesLen, pesPayload]));
  });
  const secondPack = Buffer.concat([start, Buffer.from([0xba]), Buffer.alloc(10, 0x00)]);
  return Buffer.concat([pack, sys, ...pesChunks, secondPack]);
}

console.log('\n=== 1. PS 解复用（多 PES 包访问单元重组 + PTS 还原）===');
{
  const payload1 = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1e, 0x9a]);
  const payload2 = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x65, 0x01, 0x02, 0x03]);
  const stream = psPack([payload1, payload2], 123456);
  const ps = new PsDemuxer();
  // 分三段喂入，模拟网络分片
  const part = Math.floor(stream.length / 3);
  const f1 = ps.feed(stream.subarray(0, part));
  const f2 = ps.feed(stream.subarray(part, part * 2));
  const f3 = ps.feed(stream.subarray(part * 2));
  const frames = [...f1, ...f2, ...f3, ...ps.flush()];
  check('多 PES 包重组为 1 个访问单元', frames.length === 1, `frames=${frames.length}`);
  check('重组数据 = 两 PES 载荷拼接', frames[0] && frames[0].data.equals(Buffer.concat([payload1, payload2])),
    frames[0] ? `len=${frames[0].data.length}` : 'no frame');
  check('PTS 还原正确 (123456)', frames[0] && Number(frames[0].pts) === 123456,
    frames[0] ? `pts=${Number(frames[0].pts)}` : '');
  check('isPSData 识别 pack 头', isPSData(Buffer.from([0x00, 0x00, 0x01, 0xba, 0x00])) === true);
  check('isPSData 拒绝裸 annex-b', isPSData(Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67])) === false);
}

// ---- 2. RTP 判定与剥离（含扩展 + 填充）----
function rtpPacket(seq, ssrc, media, { ext = false, pad = 0 } = {}) {
  const hdr = Buffer.alloc(12);
  hdr[0] = 0x80 | (ext ? 0x10 : 0) | (pad ? 0x20 : 0); // 版本2
  hdr[1] = 96;
  hdr.writeUInt16BE(seq, 2);
  hdr.writeUInt32BE(0, 4);
  hdr.writeUInt32BE(ssrc, 8);
  let body = Buffer.from(media);
  if (ext) {
    const extData = Buffer.from([0xbe, 0xde, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd]); // 1 个 32-bit 字
    body = Buffer.concat([extData, body]);
  }
  if (pad) {
    const tail = Buffer.alloc(pad, 0x00);
    tail[pad - 1] = pad; // 最后字节 = 填充计数（含自身）
    body = Buffer.concat([body, tail]);
  }
  return Buffer.concat([hdr, body]);
}

console.log('\n=== 2. RTP 判定与剥离（12B 头 + 扩展 + 填充）===');
{
  const media = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);
  const pkt = rtpPacket(100, 0x12345678, media, { ext: true, pad: 3 });
  const stripped = rtpStrip(pkt);
  check('RTP 剥离 12B 头 + 扩展 + 填充', stripped.equals(media), `media=${stripped.toString('hex')}`);

  const d = new RtpDetector();
  const out1 = d.feed(rtpPacket(100, 0x12345678, Buffer.from([1, 2, 3]))); // 持有
  const out2 = d.feed(rtpPacket(101, 0x12345678, Buffer.from([4, 5, 6]))); // 配对
  check('RtpDetector 判定为 RTP（SSRC+连续序号）', d.decided && d.isRTP, `isRTP=${d.isRTP}`);
  check('两条消息均被剥离放行', out1.length === 0 && out2.length === 2 &&
    out2[0].equals(Buffer.from([1, 2, 3])) && out2[1].equals(Buffer.from([4, 5, 6])));

  const d2 = new RtpDetector();
  const raw = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67, 0x42]);
  const o = d2.feed(raw);
  check('裸 annex-b 立即判定为非 RTP 并透传', d2.decided && !d2.isRTP && o.length === 1 && o[0].equals(raw));
}

// ---- 3. 媒体管线 sniffCodec / analyzeFrame / clone ----
console.log('\n=== 3. 媒体管线（编码判定 / 关键帧 / 拷贝）===');
{
  const h264 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1e, 0x9a]),
    Buffer.from([0x00, 0x00, 0x00, 0x01, 0x65, 0x01, 0x02, 0x03])]);
  const h265 = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0c, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03]);
  check('sniffCodec 判定 H264', sniffCodec(h264) === 'H264');
  check('sniffCodec 判定 H265', sniffCodec(h265) === 'H265');
  check('analyzeFrame H264 IDR 关键帧', analyzeFrame(h264, 'H264') === true);
  check('analyzeFrame H264 非 IDR 非关键帧', analyzeFrame(Buffer.from([0x00, 0x00, 0x00, 0x01, 0x61]), 'H264') === false);
  check('analyzeFrame H265 IRAP 关键帧', analyzeFrame(Buffer.from([0x00, 0x00, 0x00, 0x01, 0x28]), 'H265') === true);
  const src = Buffer.from([9, 8, 7]);
  const c = clone(src);
  c[0] = 0;
  check('clone 返回独立副本', !c.equals(src) && src[0] === 9);
}

// ---- 4. keepalive / stall / ServerError / 异步投递 ----
console.log('\n=== 4. 传输层健壮性（心跳 / 看门狗 / 终态 / 异步投递）===');
{
  // keepalive：mock ws 记录 ping 调用
  const c = new HikMediaClient({ ...baseConfig, keepaliveInterval: 30 });
  let pings = 0;
  c.ws = { readyState: WebSocket.OPEN, ping() { pings++; }, close() {} };
  c._startKeepalive();
  await new Promise((r) => setTimeout(r, 80));
  c._clearTimers();
  check('keepalive 心跳按时发送 (>=2 次 / 30ms)', pings >= 2, `pings=${pings}`);

  // stall 看门狗：无数据 -> 终态掉线
  const c2 = new HikMediaClient({ ...baseConfig, stallTimeout: 20 });
  let stalled = null;
  c2.on('error', (e) => { if (e.isStalled) stalled = e; });
  c2._resetStall();
  await new Promise((r) => setTimeout(r, 60));
  check('stall 看门狗触发 isStalled 终态', stalled && stalled.isStalled === true);

  // ServerError 终态：模拟对端下发错误帧，确认停止而非重连
  let connectCount = 0;
  const c3 = new HikMediaClient({ ...baseConfig });
  c3.on('error', () => {}); // 防御：避免无监听时 EventEmitter 抛错
  const fakeWs = new EventEmitter();
  fakeWs.readyState = WebSocket.OPEN;
  fakeWs.ping = () => {};
  fakeWs.close = () => { fakeWs.emit('close', 1000); };
  fakeWs.send = () => {};
  c3.connect = function () {
    connectCount++;
    return new Promise((resolve) => {
      this.ws = fakeWs;
      fakeWs.on('open', () => { this.connected = true; this.emit('connected'); resolve(); });
      fakeWs.on('error', (e) => this.emit('error', e));
      fakeWs.on('close', () => { this.connected = false; this._clearTimers(); this.emit('close'); });
      fakeWs.on('message', (data, isBinary) => { this._resetStall(); this._handleMessage(data, isBinary); });
      process.nextTick(() => fakeWs.emit('open'));
    });
  };
  const runP = c3.run();
  await new Promise((r) => setTimeout(r, 10));
  fakeWs.emit('message', Buffer.from(JSON.stringify({ errorCode: 401, errorMsg: 'token expired' })), false);
  let terminal = null;
  try { await runP; } catch (e) { terminal = e; }
  check('ServerError 终态：run() 以 isServerError 拒绝', terminal && terminal.isServerError === true,
    terminal ? `code=${terminal.code}` : 'no error');
  check('ServerError 终态且不重连（connect 仅 1 次）', connectCount === 1, `connectCount=${connectCount}`);

  // 异步投递：慢消费者不阻塞读循环 + 顺序保真
  const c4 = new HikMediaClient({ ...baseConfig, asyncDelivery: 5 });
  const order = [];
  let syncReturned = true;
  c4.on('video', (b) => order.push(b[0]));
  const t0 = Date.now();
  for (let i = 0; i < 5; i++) {
    c4._onVideoData(Buffer.from([i, 0x00, 0x00, 0x00, 0x01, 0x67]));
  }
  syncReturned = Date.now() - t0 < 50; // 同步喂入应立即返回
  await new Promise((r) => setTimeout(r, 30));
  check('异步投递：5 帧全部送达', order.length === 5, `delivered=${order.length}`);
  check('异步投递：顺序保真', order.join(',') === '0,1,2,3,4', `order=${order.join(',')}`);
  check('异步投递：喂入不阻塞读循环（同步返回）', syncReturned);
}

// ---- 5. realplay 鉴权接线（useRealplayAuth，真实跑 crypto 路径）----
console.log('\n=== 5. realplay 鉴权接线（mock 协议交换，真实 crypto 路径）===');
{
  const c = new HikMediaClient({ ...baseConfig, useRealplayAuth: true });
  const fakeWs = new EventEmitter();
  fakeWs.readyState = WebSocket.OPEN;
  fakeWs.ping = () => {};
  fakeWs.close = () => {};
  let sentRealplay = null;
  fakeWs.send = (m) => { sentRealplay = JSON.parse(m); };
  c.connect = function () {
    return new Promise((resolve) => {
      this.ws = fakeWs;
      fakeWs.on('open', () => { this.connected = true; this.emit('connected'); resolve(); });
      fakeWs.on('error', (e) => this.emit('error', e));
      fakeWs.on('close', () => { this.connected = false; this._clearTimers(); this.emit('close'); });
      fakeWs.on('message', (data, isBinary) => {
        if (isBinary) return;
        const resp = JSON.parse(data.toString('utf-8'));
        if (resp.errorCode && resp.errorCode !== 0) { this.emit('error', new ServerError(resp.errorCode, resp.errorMsg)); return; }
        this.serverPKD = resp.PKD || '';
        this.serverRand = resp.rand || '';
        this._ivKey = generateClientIVKey();
        this.emit('authenticated', { pkd: this.serverPKD, rand: this.serverRand });
      });
      process.nextTick(() => fakeWs.emit('open'));
    });
  };
  // 模拟代理下发的 PKD/rand（真实鉴权交换）
  fakeWs.on('open', () => {
    setTimeout(() => fakeWs.emit('message', Buffer.from(JSON.stringify({ PKD: 'a1b2'.repeat(32), rand: 'rand-xyz' })), false), 0);
  });
  // 显式驱动真实握手路径：connect -> authenticate(拿到 PKD/rand 并派生 _ivKey) -> realplay(走 crypto)
  await c.connect();
  await c.authenticate();
  await c.realplay();
  c.close(); // 释放资源，使 run() 的 pending 承诺可结算（非终态）
  await new Promise((r) => setTimeout(r, 10));
  check('realplay 请求 key 被 crypto.generateRealplayKey 真实填充', sentRealplay && sentRealplay.key && sentRealplay.key.length > 0,
    sentRealplay ? `key.len=${sentRealplay.key.length}` : 'no request');
  check('realplay 请求 authorization 被真实填充', sentRealplay && sentRealplay.authorization && sentRealplay.authorization.length > 0);
  check('realplay 请求 token 被 generateToken 真实填充', sentRealplay && sentRealplay.token && sentRealplay.token.length > 0);

  // 对照：不开 useRealplayAuth 时保持空（协议约定，对齐 go-client）
  const reqEmpty = buildRealplayRequest(baseConfig);
  check('对照：默认空 key（协议对齐 go-client）', reqEmpty.key === '' && reqEmpty.authorization === '' && reqEmpty.token === '');
}

// ---- 汇总 ----
const failed = results.filter((r) => !r.ok);
console.log(`\n===== 功能级实测汇总: ${results.length - failed.length}/${results.length} PASS, ${failed.length} FAIL =====`);
if (failed.length) {
  console.log('失败项: ' + failed.map((f) => f.name).join('; '));
  process.exit(1);
}
console.log('全部功能实测正常。');
