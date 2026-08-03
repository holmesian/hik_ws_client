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

export class HikMediaClient extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.ws = null;
    this.sdp = '';
    this.sdpInfo = null;
    this.serverPKD = '';
    this.serverRand = '';
    this.connected = false;
    this._closing = false;
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
        this.emit('close', code, reason);
      });

      this.ws.on('message', (data, isBinary) => {
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
            const err = new Error(`Server error ${resp.errorCode}: ${resp.errorMsg}`);
            this.emit('error', err);
            reject(err);
            return;
          }

          this.serverPKD = resp.PKD || '';
          this.serverRand = resp.rand || '';
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
    const deviceURL = `ws://${this.config.deviceIP}:${this.config.devicePort}/openUrl/${this.config.password}`;

    const reqData = {
      sequence: 0,
      cmd: 'realplay',
      url: deviceURL,
      key: '',
      authorization: '',
      token: '',
    };

    this.ws.send(JSON.stringify(reqData));
    this.emit('realplay_sent', deviceURL);
  }

  async run() {
    await this.connect();
    await this.authenticate();
    await this.realplay();
  }

  close() {
    this._closing = true;
    this.connected = false;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  _handleMessage(data, isBinary) {
    if (!isBinary) {
      try {
        const resp = JSON.parse(data.toString('utf-8'));
        const code = resp.errorCode || 0;

        if (code !== 0) {
          const errMsg = resp.errorMsg || `Server error code=${code}`;
          this.emit('error', new Error(errMsg));
          return;
        }

        if (resp.sdp) {
          this.sdp = resp.sdp;
          this.sdpInfo = parseSDP(resp.sdp);
          this.emit('sdp', this.sdpInfo);
        }

        this.emit('json', resp);
      } catch {
        this.emit('text', data.toString('utf-8'));
      }
      return;
    }

    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const { msgType, payload, remaining } = unpackMessage(buf);

    if (msgType === null) {
      this.emit('video', buf);
      return;
    }

    switch (msgType) {
      case MsgTypeVideoData:
        this.emit('video', payload);
        break;
      case MsgTypeAudioData:
        this.emit('audio', payload);
        break;
      case MsgTypeSessionError:
        this.emit('error', new Error(`Session error: ${payload.toString('utf-8')}`));
        break;
      case MsgTypeKeepAlive:
        break;
      default:
        if (remaining && remaining.length > 0) {
          this.emit('video', remaining);
        }
        break;
    }
  }
}
