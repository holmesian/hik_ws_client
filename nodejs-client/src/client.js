import WebSocket from 'ws';
import { EventEmitter } from 'events';
import {
  MsgTypeVideoData,
  MsgTypeAudioData,
  MsgTypeSessionError,
  MsgTypeKeepAlive,
  unpackMessage,
} from './protocol.js';
import {
  generateClientIVKey,
  generateRealplayKey,
  generateAuthorization,
  generateToken,
} from './crypto.js';
import { parseSDP } from './sdp.js';
import { PsDemuxer, isPSData } from './psdemux.js';
import { RtpDetector } from './rtp.js';
import { sniffCodec, analyzeFrame, clone } from './media.js';

// 与 go-client 对齐的健壮性常量（可被单测缩短）。
export const KEEPALIVE_INTERVAL = 20 * 1000; // 每 20s 发一个 WebSocket ping
export const KEEPALIVE_WRITE_WAIT = 5 * 1000;
export const STALL_DEFAULT = 0; // 0 = 关闭看门狗

// ServerError 是代理在带内上报的错误（openUrl token 过期、凭据错误、设备不可达）。
// 它是终态：重试同一个 URL 只会拿到同一个码，因此应当停止而非重连。
export class ServerError extends Error {
  constructor(code, msg) {
    super(`server error code=${code} msg=${msg}`);
    this.name = 'ServerError';
    this.code = code;
    this.isServerError = true;
  }
}

// buildRealplayRequest 构造 realplay 请求体。
//
// 协议约定（docs/protocol.md + ADR-0004）realplay 以**空 key** 请求，服务端据此不下发
// 加密流、媒体载荷本身不加密，密钥交换只用于会话鉴权——go-client / python-client 皆如此。
// 因此默认 key/authorization/token 为空，与二者对齐。
//
// 但当 useRealplayAuth 为真（且已拿到服务端 PKD/rand 与本地 iv/key）时，按 crypto.js 已有
// 的 generateRealplayKey / generateAuthorization / generateToken 填实这三个字段，以适配
// 要求严格鉴权的代理。该路径默认关闭，避免违背上述协议约定。
export function buildRealplayRequest(config, opts = {}) {
  const deviceURL = `ws://${config.deviceIP}:${config.devicePort}/openUrl/${config.password}`;
  let key = '';
  let authorization = '';
  let token = '';
  if (opts.useRealplayAuth && opts.iv && opts.key && opts.pkd && opts.rand) {
    key = generateRealplayKey(opts.iv, opts.key, opts.pkd);
    authorization = generateAuthorization(opts.rand, config.password, opts.key, opts.iv);
    token = generateToken(deviceURL, opts.key, opts.iv);
  }
  return {
    sequence: 0,
    cmd: 'realplay',
    url: deviceURL,
    key,
    authorization,
    token,
  };
}

export class HikMediaClient extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.ws = null;
    this.sdp = '';
    this.sdpInfo = null;
    this.serverPKD = '';
    this.serverRand = '';
    this._ivKey = null;

    // 媒体管线状态（对齐 go-client）
    this.mediaInfo = null; // 由 SDP 恢复的流描述
    this.ps = null; // PS 解复用器，首个载荷时按需分配；裸基本流路径恒为 null
    this.containerKnown = false;
    this.rtp = new RtpDetector(); // RTP 判定（每个会话一次性决定）

    this.connected = false;
    this._closing = false;
    this._terminal = false; // ServerError 终态：停止而非重连

    // 看门狗 / 心跳
    this.keepaliveInterval = config.keepaliveInterval || KEEPALIVE_INTERVAL;
    this.stallTimeout = config.stallTimeout || STALL_DEFAULT;
    this._keepaliveTimer = null;
    this._stallTimer = null;

    // 异步投递队列（默认关闭：asyncDelivery=0 为同步投递）
    this.asyncDelivery = config.asyncDelivery || 0;
    this._queue = [];
    this._draining = false;
  }

  buildMediaURL() {
    const proxy = `${this.config.deviceIP}:${this.config.devicePort}`;
    return `wss://${this.config.proxyHost}:${this.config.proxyPort}/media?version=${this.config.version}&cipherSuites=${this.config.cipherSuites}&sessionID=&proxy=${proxy}`;
  }

  async connect() {
    const url = this.buildMediaURL();

    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(url, ['v1.0.0'], {
        rejectUnauthorized: false,
      });

      this.ws.on('open', () => {
        this.connected = true;
        this.emit('connected');
        resolve();
      });

      this.ws.on('error', (err) => {
        this.emit('error', err);
        if (!this.connected) reject(err);
      });

      this.ws.on('close', (code, reason) => {
        this.connected = false;
        this._clearTimers();
        this.emit('close', code, reason);
      });

      this.ws.on('message', (data, isBinary) => {
        this._resetStall();
        this._handleMessage(data, isBinary);
      });
    });
  }

  async authenticate() {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Authentication timeout'));
      }, 10000);

      const onMessage = (data, isBinary) => {
        if (isBinary) return;
        clearTimeout(timeout);
        this.ws.off('message', onMessage);

        try {
          const resp = JSON.parse(data.toString('utf-8'));

          if (resp.errorCode && resp.errorCode !== 0) {
            const err = new ServerError(resp.errorCode, resp.errorMsg || '');
            this.emit('error', err);
            reject(err);
            return;
          }

          this.serverPKD = resp.PKD || '';
          this.serverRand = resp.rand || '';
          if (this.config.useRealplayAuth) {
            // 仅在需要鉴权字段时派生本地 iv/key
            this._ivKey = generateClientIVKey();
          }
          this.emit('authenticated', { pkd: this.serverPKD, rand: this.serverRand });
          resolve(resp);
        } catch (err) {
          reject(err);
        }
      };

      this.ws.on('message', onMessage);
    });
  }

  async realplay() {
    const req = buildRealplayRequest(this.config, {
      useRealplayAuth: this.config.useRealplayAuth,
      iv: this._ivKey ? this._ivKey.iv : null,
      key: this._ivKey ? this._ivKey.key : null,
      pkd: this.serverPKD,
      rand: this.serverRand,
    });
    this.ws.send(JSON.stringify(req));
    this.emit('realplay_sent', req.url);
  }

  async run() {
    await this.connect();
    await this.authenticate();
    await this.realplay();
    // run() 在此持续接收，直到连接关闭或终态错误。
    return new Promise((resolve, reject) => {
      this._runResolve = resolve;
      this._runReject = reject;
      this._startKeepalive();
      this._resetStall();
    });
  }

  close() {
    this._closing = true;
    this.connected = false;
    this._clearTimers();
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        /* ignore */
      }
      this.ws = null;
    }
  }

  // ---- 传输层健壮性 ----

  _startKeepalive() {
    if (this.keepaliveInterval <= 0) return;
    this._keepaliveTimer = setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      try {
        this.ws.ping();
      } catch {
        /* 写失败：连接已坏，看门狗/close 会处理 */
      }
    }, this.keepaliveInterval);
    // 不阻止进程退出
    if (this._keepaliveTimer.unref) this._keepaliveTimer.unref();
  }

  _resetStall() {
    if (this.stallTimeout <= 0) return;
    if (this._stallTimer) clearTimeout(this._stallTimer);
    this._stallTimer = setTimeout(() => {
      const err = new Error(
        `stream stalled: no data within ${this.stallTimeout}ms`,
      );
      err.isStalled = true;
      this.emit('error', err);
      // 看门狗把"代理静默掉线但握着 socket"变成一次可观测的结束
      this.close();
      this._finish(err);
    }, this.stallTimeout);
    if (this._stallTimer.unref) this._stallTimer.unref();
  }

  _clearTimers() {
    if (this._keepaliveTimer) {
      clearInterval(this._keepaliveTimer);
      this._keepaliveTimer = null;
    }
    if (this._stallTimer) {
      clearTimeout(this._stallTimer);
      this._stallTimer = null;
    }
  }

  _finish(err) {
    if (this._runResolve) {
      // 终态错误（ServerError / stall）向上抛出；干净关闭则 resolve(null)
      if (err) {
        const r = this._runReject;
        this._runResolve = null;
        this._runReject = null;
        if (r) r(err);
      } else {
        const r = this._runResolve;
        this._runResolve = null;
        this._runReject = null;
        if (r) r(null);
      }
    }
  }

  // ---- 消息处理 ----

  _handleMessage(data, isBinary) {
    if (!isBinary) {
      try {
        const resp = JSON.parse(data.toString('utf-8'));
        const code = resp.errorCode || 0;

        if (code !== 0) {
          // ServerError 终态：代理随即将会话拆除，继续存活只会随后冒出一个
          // 令人困惑的 "close 1005"。停止而非重连。
          const err = new ServerError(
            code,
            resp.errorMsg || `Server error code=${code}`,
          );
          this.emit('error', err);
          this._terminal = true;
          this.close();
          this._finish(err);
          return;
        }

        if (resp.sdp) {
          this.sdp = resp.sdp;
          this.sdpInfo = parseSDP(resp.sdp);
          this._applyMediaInfo(this.sdpInfo);
          this.emit('sdp', this.sdpInfo);
        }

        this.emit('json', resp);
      } catch {
        this.emit('text', data.toString('utf-8'));
      }
      return;
    }

    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    // 解包本帧承载的每条协议消息（服务端可能把多条批量塞进一帧）
    let remaining = buf;
    while (remaining.length >= 5) {
      const { msgType, payload, remaining: next } = unpackMessage(remaining);

      if (msgType === null) {
        // 解包失败 → 余下字节按裸视频处理
        this._onVideoData(remaining);
        return;
      }

      switch (msgType) {
        case MsgTypeVideoData:
          this._onVideoData(payload);
          break;
        case MsgTypeAudioData:
          this._enqueue({ type: 'audio', data: clone(payload) });
          break;
        case MsgTypeSessionError:
          this.emit('error', new Error(`Session error: ${payload.toString('utf-8')}`));
          this.close();
          this._finish(new Error(`Session error: ${payload.toString('utf-8')}`));
          return;
        case MsgTypeKeepAlive:
          break;
        default:
          if (next && next.length > 0) {
            this._onVideoData(next);
          }
          break;
      }

      remaining = next;
    }
  }

  // _onVideoData 处理一段视频传输字节：先作为"解复用前原始容器"暴露（诊断），
  // 再经 RTP 判定 + PS 解复用重组为 annex-b 访问单元。
  _onVideoData(raw) {
    this._enqueue({ type: 'rawVideo', data: clone(raw) });
    const payloads = this.rtp.feed(raw);
    for (const p of payloads) {
      this._feedContainer(p);
    }
  }

  // _feedContainer 处理一段已去 RTP 封装的载荷：决定容器（每个会话仅一次），
  // 是 PS 则解复用，否则原样投递。
  _feedContainer(data) {
    // 容器仅从首个载荷决定一次。MEDIAINFO 头只是提示而非真相。
    if (!this.containerKnown) {
      this.containerKnown = true;
      if (
        (this.mediaInfo && this.mediaInfo.container === 'PS') ||
        ((!this.mediaInfo || this.mediaInfo.container === '') && isPSData(data))
      ) {
        this.ps = new PsDemuxer();
        if (this.mediaInfo && this.mediaInfo.container === '') {
          this.mediaInfo.container = 'PS';
          this.mediaInfo.clockRate = 90000;
        }
      }
    }

    if (this.ps == null) {
      this._deliverFrame(data, 0, false);
      return;
    }
    for (const f of this.ps.Feed(data)) {
      this._deliverFrame(f.data, f.pts, f.hasPTS);
    }
  }

  // _deliverFrame 恢复每帧元数据并把解复用后的 annex-b 访问单元交给调用方。
  _deliverFrame(data, pts, hasPTS) {
    let codec = this.mediaInfo ? this.mediaInfo.codec : '';
    if (!codec) {
      codec = sniffCodec(data);
      if (codec && this.mediaInfo) this.mediaInfo.codec = codec;
    }
    const isKeyFrame = codec ? analyzeFrame(data, codec) : false;
    const meta = {
      codec,
      isKeyFrame,
      pts: hasPTS ? Number(pts) : 0,
      hasPTS,
    };
    // 'video' = 解复用后的 annex-b（主输出，与 go-client OnVideoData/OnVideoFrame 对齐）；
    // 'videoFrame' = 附带帧元数据的同一份数据。
    this._enqueue({ type: 'video', data: clone(data) });
    this._enqueue({ type: 'videoFrame', data: clone(data), meta });
  }

  _applyMediaInfo(sdpInfo) {
    if (!sdpInfo) return;
    this.mediaInfo = {
      container: '',
      codec: sdpInfo.videoCodec || '',
      clockRate: sdpInfo.videoClockRate || 0,
    };
  }

  // ---- 异步投递队列 ----
  // 默认同步投递；asyncDelivery>0 时把事件入队、由 drain 循环按序处理，使慢消费者
  // 不阻塞读循环（go-client 的 AsyncDelivery 通道）。
  _enqueue(event) {
    if (this.asyncDelivery > 0) {
      this._queue.push(event);
      this._drain();
    } else {
      this._dispatch(event);
    }
  }

  async _drain() {
    if (this._draining) return;
    this._draining = true;
    try {
      while (this._queue.length > 0) {
        const ev = this._queue.shift();
        this._dispatch(ev);
        // 让出事件循环，避免饿死连接读取
        await Promise.resolve();
      }
    } finally {
      this._draining = false;
    }
  }

  _dispatch(ev) {
    switch (ev.type) {
      case 'video':
        this.emit('video', ev.data);
        break;
      case 'videoFrame':
        this.emit('videoFrame', ev.data, ev.meta);
        break;
      case 'rawVideo':
        this.emit('rawVideo', ev.data);
        break;
      case 'audio':
        this.emit('audio', ev.data);
        break;
    }
  }
}
