import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import WebSocket from 'ws';
import {
  HikMediaClient,
  ServerError,
  buildRealplayRequest,
  KEEPALIVE_INTERVAL,
  STALL_DEFAULT,
} from '../src/client.js';
import { generateClientIVKey } from '../src/crypto.js';

const baseConfig = {
  deviceIP: '192.168.1.64',
  devicePort: 65001,
  proxyHost: 'proxy.example.com',
  proxyPort: 443,
  password: 'secret',
  version: '20210428',
  cipherSuites: 'all',
};

describe('buildRealplayRequest auth wiring', () => {
  it('sends empty key/authorization/token by default (matches go-client protocol)', () => {
    const req = buildRealplayRequest(baseConfig);
    assert.strictEqual(req.key, '');
    assert.strictEqual(req.authorization, '');
    assert.strictEqual(req.token, '');
    assert.strictEqual(req.cmd, 'realplay');
    assert.match(req.url, /^\w+:\/\//);
  });

  it('fills key/authorization/token when useRealplayAuth is set with iv/key/pkd/rand', () => {
    const { iv, key } = generateClientIVKey();
    const req = buildRealplayRequest(baseConfig, {
      useRealplayAuth: true,
      iv,
      key,
      pkd: 'a1b2'.repeat(32),
      rand: 'rand-123',
    });
    assert.ok(req.key.length > 0, 'key should be filled');
    assert.ok(req.authorization.length > 0, 'authorization should be filled');
    assert.ok(req.token.length > 0, 'token should be filled');
  });

  it('stays empty when useRealplayAuth lacks any required input', () => {
    const req = buildRealplayRequest(baseConfig, { useRealplayAuth: true });
    assert.strictEqual(req.key, '');
    assert.strictEqual(req.authorization, '');
    assert.strictEqual(req.token, '');
  });
});

describe('ServerError', () => {
  it('carries the server code and isServerError flag', () => {
    const err = new ServerError(401, 'token expired');
    assert.strictEqual(err.code, 401);
    assert.strictEqual(err.isServerError, true);
    assert.match(err.message, /401/);
  });
});

describe('exported resilience constants', () => {
  it('exposes keepalive/stall defaults', () => {
    assert.strictEqual(KEEPALIVE_INTERVAL, 20000);
    assert.strictEqual(STALL_DEFAULT, 0);
  });
});

describe('client media pipeline (no transport)', () => {
  function h264AU() {
    // SPS + IDR，便于 sniffCodec 判定 H264 且 analyzeFrame 标记关键帧
    return Buffer.concat([
      Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1e, 0x9a]),
      Buffer.from([0x00, 0x00, 0x00, 0x01, 0x65, 0x01, 0x02, 0x03]),
    ]);
  }

  it('emits rawVideo and demuxed video for a raw annex-b buffer (passthrough)', () => {
    const c = new HikMediaClient({ ...baseConfig });
    const raw = [];
    const video = [];
    c.on('rawVideo', (b) => raw.push(b));
    c.on('video', (b) => video.push(b));
    c._onVideoData(h264AU());
    assert.strictEqual(raw.length, 1);
    assert.strictEqual(video.length, 1);
    assert.ok(raw[0].equals(h264AU()));
    assert.ok(video[0].equals(h264AU()));
  });

  it('emits a videoFrame event with codec/isKeyFrame meta', () => {
    const c = new HikMediaClient({ ...baseConfig });
    let meta = null;
    c.on('videoFrame', (b, m) => { meta = m; });
    c._onVideoData(h264AU());
    assert.ok(meta);
    assert.strictEqual(meta.codec, 'H264');
    assert.strictEqual(meta.isKeyFrame, true);
  });
});

describe('async delivery queue', () => {
  it('delivers frames in order when asyncDelivery > 0', async () => {
    const c = new HikMediaClient({ ...baseConfig, asyncDelivery: 4 });
    const order = [];
    c.on('video', () => order.push('video'));
    c._onVideoData(Buffer.from([0x00, 0x00, 0x00, 0x01, 0x67, 0x42]));
    c._onVideoData(Buffer.from([0x00, 0x00, 0x00, 0x01, 0x65, 0x01]));
    // 让出事件循环，等 drain 处理完队列
    await new Promise((r) => setTimeout(r, 20));
    assert.strictEqual(order.length, 2);
  });
});

describe('stall watchdog', () => {
  it('emits a terminal isStalled error after stallTimeout with no data', async () => {
    const c = new HikMediaClient({ ...baseConfig, stallTimeout: 15 });
    let stalled = null;
    c.on('error', (err) => { if (err.isStalled) stalled = err; });
    c._resetStall(); // 没有后续数据喂入
    await new Promise((r) => setTimeout(r, 60));
    assert.ok(stalled);
    assert.strictEqual(stalled.isStalled, true);
  });
});

describe('keepalive timer lifecycle', () => {
  it('starts and clears the keepalive timer against a live socket', () => {
    const c = new HikMediaClient({ ...baseConfig, keepaliveInterval: 100 });
    c.ws = { readyState: WebSocket.OPEN, ping() {}, close() {} };
    c._startKeepalive();
    assert.ok(c._keepaliveTimer, 'keepalive timer should be set');
    c._clearTimers();
    assert.strictEqual(c._keepaliveTimer, null);
  });
});
