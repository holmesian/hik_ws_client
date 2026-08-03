import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { HikMediaClient } from './client.js';
import { parseProxyURL } from './config.js';
import { CameraRegistry, createDefaultRegistry } from './camera-registry.js';

export class HikRelayServer {
  constructor(options = {}) {
    this.port = options.port || 8080;
    this.host = options.host || '0.0.0.0';
    this.httpServer = null;
    this.wss = null;
    this.sessions = new Map();
    this.sessionCounter = 0;

    // 摄像头注册表
    this.registry = options.registry || createDefaultRegistry();
  }

  start() {
    this.httpServer = createServer((req, res) => {
      this._handleHTTP(req, res);
    });

    this.wss = new WebSocketServer({ server: this.httpServer });

    this.wss.on('connection', (clientWs, req) => {
      this._handleClientConnection(clientWs, req);
    });

    this.httpServer.listen(this.port, this.host, () => {
      console.log(`Hikvision WS Relay Server listening on ws://${this.host}:${this.port}`);
      console.log(`  Stream endpoint: ws://${this.host}:${this.port}/live/:cameraCode`);
      console.log(`  Health check:    http://${this.host}:${this.port}/health`);
      console.log(`  Camera list:     http://${this.host}:${this.port}/cameras`);
    });

    return this;
  }

  _handleHTTP(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // 健康检查
    if (url.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        sessions: this.sessions.size,
        cameras: this.registry.list(),
      }));
      return;
    }

    // 摄像头列表
    if (url.pathname === '/cameras') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const cameras = this.registry.list().map(code => ({
        cameraCode: code,
        online: true,
      }));
      res.end(JSON.stringify({ cameras }));
      return;
    }

    // 获取单个摄像头信息 (脱敏)
    const cameraMatch = url.pathname.match(/^\/cameras\/([^\/]+)$/);
    if (cameraMatch) {
      const cameraCode = cameraMatch[1];
      if (this.registry.has(cameraCode)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          cameraCode,
          online: true,
        }));
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Camera not found' }));
      }
      return;
    }

    res.writeHead(404);
    res.end('Not Found');
  }

  async _handleClientConnection(clientWs, req) {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // 解析路径: /live/:cameraCode 或 /live/:cameraCode?streamType=sub
    const liveMatch = url.pathname.match(/^\/live\/([^\/]+)$/);

    let config;
    let cameraCode;

    if (liveMatch) {
      // 方式一: 通过 cameraCode 播放
      cameraCode = liveMatch[1];
      const streamType = url.searchParams.get('streamType') || 'main';

      try {
        config = await this.registry.getConfig(cameraCode);
      } catch (err) {
        console.error(`Camera not found: ${cameraCode}`);
        clientWs.close(1008, `Camera not found: ${cameraCode}`);
        return;
      }
    } else {
      // 方式二: 兼容旧版,通过 url 参数播放
      const proxyURL = url.searchParams.get('url');
      if (!proxyURL) {
        clientWs.close(1008, 'Invalid endpoint. Use /live/:cameraCode or ?url=');
        return;
      }
      try {
        config = parseProxyURL(proxyURL);
        cameraCode = 'direct';
      } catch (err) {
        clientWs.close(1008, `Invalid URL: ${err.message}`);
        return;
      }
    }

    const sessionId = ++this.sessionCounter;
    const session = {
      id: sessionId,
      cameraCode,
      clientWs,
      hikClient: null,
      stats: { videoBytes: 0, audioBytes: 0, frames: 0, startTime: Date.now() },
    };
    this.sessions.set(sessionId, session);

    console.log(`[Session ${sessionId}] cameraCode=${cameraCode} -> ${config.deviceIP}:${config.devicePort}`);

    const hikClient = new HikMediaClient(config);
    session.hikClient = hikClient;

    hikClient.on('connected', () => {
      console.log(`[Session ${sessionId}] Connected to Hikvision proxy`);
      this._sendToClient(session, { type: 'status', status: 'connected', cameraCode });
    });

    hikClient.on('authenticated', ({ pkd, rand }) => {
      console.log(`[Session ${sessionId}] Authenticated`);
      this._sendToClient(session, { type: 'status', status: 'authenticated', cameraCode });
    });

    hikClient.on('sdp', (sdpInfo) => {
      console.log(`[Session ${sessionId}] SDP received: ${sdpInfo.videoCodec || 'unknown'}`);
      this._sendToClient(session, {
        type: 'sdp',
        cameraCode,
        sdp: hikClient.sdp,
        info: {
          videoCodec: sdpInfo.videoCodec,
          videoClockRate: sdpInfo.videoClockRate,
          audioCodec: sdpInfo.audioCodec,
          audioClockRate: sdpInfo.audioClockRate,
        },
      });
    });

    hikClient.on('video', (data) => {
      session.stats.videoBytes += data.length;
      session.stats.frames++;

      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(data);
      }
    });

    hikClient.on('audio', (data) => {
      session.stats.audioBytes += data.length;

      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(data);
      }
    });

    hikClient.on('error', (err) => {
      console.error(`[Session ${sessionId}] Error: ${err.message}`);
      this._sendToClient(session, { type: 'error', cameraCode, message: err.message });
    });

    hikClient.on('close', () => {
      console.log(`[Session ${sessionId}] Hikvision connection closed`);
      this._cleanupSession(sessionId);
    });

    clientWs.on('close', () => {
      console.log(`[Session ${sessionId}] Client disconnected`);
      this._cleanupSession(sessionId);
    });

    clientWs.on('error', (err) => {
      console.error(`[Session ${sessionId}] Client WebSocket error: ${err.message}`);
    });

    hikClient.run().catch((err) => {
      console.error(`[Session ${sessionId}] Run error: ${err.message}`);
      this._sendToClient(session, { type: 'error', cameraCode, message: err.message });
      clientWs.close(1011, err.message);
    });
  }

  _sendToClient(session, obj) {
    if (session.clientWs.readyState === WebSocket.OPEN) {
      session.clientWs.send(JSON.stringify(obj));
    }
  }

  _cleanupSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    if (session.hikClient) {
      session.hikClient.close();
      session.hikClient = null;
    }

    const duration = Date.now() - session.stats.startTime;
    console.log(
      `[Session ${sessionId}] Closed. cameraCode=${session.cameraCode}, ` +
      `Duration: ${(duration / 1000).toFixed(1)}s, ` +
      `Frames: ${session.stats.frames}, ` +
      `Video: ${(session.stats.videoBytes / 1024).toFixed(1)}KB, ` +
      `Audio: ${(session.stats.audioBytes / 1024).toFixed(1)}KB`
    );

    this.sessions.delete(sessionId);
  }

  stop() {
    for (const [id, session] of this.sessions) {
      this._cleanupSession(id);
    }
    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }
    if (this.httpServer) {
      this.httpServer.close();
      this.httpServer = null;
    }
  }
}
