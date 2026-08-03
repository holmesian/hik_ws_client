# 前端播放器示例

## 重要说明

**浏览器原生不支持直接播放海康威视的私有流格式**。海康流通常是以下格式之一：
- PS (Program Stream) 封装的 H.264/H.265
- RTP 封装的裸流
- 私有协议的二进制数据

这些格式需要**转码或特殊解码器**才能在浏览器中播放。

## 解决方案

### 方案一：服务端转码 (推荐)

在 Node.js 服务端使用 ffmpeg 将流转码为浏览器支持的格式：

```javascript
// 在 relay.js 中添加转码
import { spawn } from 'child_process';

// 将海康流转为 fmp4 或 HLS
const ffmpeg = spawn('ffmpeg', [
  '-i', 'pipe:0',           // 从 stdin 读取
  '-c:v', 'libx264',        // 视频编码
  '-preset', 'ultrafast',
  '-tune', 'zerolatency',
  '-f', 'mp4',
  '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
  'pipe:1'                  // 输出到 stdout
]);

// 将海康流数据 pipe 给 ffmpeg
hikClient.on('video', (data) => {
  ffmpeg.stdin.write(data);
});

// ffmpeg 输出转码后的数据给前端
ffmpeg.stdout.on('data', (data) => {
  clientWs.send(data);
});
```

### 方案二：使用 WebAssembly 解码器

在前端使用 ffmpeg.js 或自定义解码器：

```html
<script src="https://cdn.jsdelivr.net/npm/ffmpeg.js@4.2.9003/ffmpeg.min.js"></script>
<script>
// 使用 ffmpeg.js 解码海康流
const ffmpeg = FFmpeg.createFFmpeg({ log: true });
await ffmpeg.load();

// 将接收到的数据写入虚拟文件系统
ffmpeg.FS('writeFile', 'input.ps', new Uint8Array(videoData));

// 解码
await ffmpeg.run('-i', 'input.ps', '-c:v', 'copy', '-f', 'rawvideo', 'output.yuv');

// 读取解码后的数据
const output = ffmpeg.FS('readFile', 'output.yuv');
</script>
```

### 方案三：使用 WebCodecs API (Chrome 86+)

```javascript
// 使用 WebCodecs API 硬解码 H.264
const decoder = new VideoDecoder({
  output: (frame) => {
    // 将解码后的帧绘制到 canvas
    const canvas = document.getElementById('canvas');
    const ctx = canvas.getContext('2d');
    ctx.drawImage(frame, 0, 0);
    frame.close();
  },
  error: (e) => console.error(e)
});

// 配置解码器
decoder.configure({
  codec: 'avc1.42001E',
  codedWidth: 1920,
  codedHeight: 1080
});

// 送入编码数据
decoder.decode(new EncodedVideoChunk({
  type: 'key',
  timestamp: 0,
  data: videoData
}));
```

### 方案四：使用现有播放器库

1. **mpegts.js** - 播放 MPEG-TS 流
2. **hls.js** - 播放 HLS 流
3. **flv.js** - 播放 FLV 流
4. **JSmpeg** - 基于 WebSocket 的 MPEG1 播放器

## 示例代码使用

### 1. 启动转发服务器

```bash
cd nodejs-hik-ws
npm start
```

### 2. 打开播放器页面

直接用浏览器打开 `simple-player.html` 或 `frontend-player.html`：

```bash
# 或者使用简单的 HTTP 服务器
npx serve examples
```

### 3. 输入参数连接

- **转发服务器**: `ws://localhost:8080`
- **摄像头 URL**: `wss://proxy.example.com/proxy/[ip]:port/openUrl/token`

## 数据流程

```
┌─────────┐      ┌──────────────┐      ┌─────────────┐      ┌─────────┐
│  摄像头  │ ───▶ │ 海康代理服务器 │ ───▶ │ Node.js转发  │ ───▶ │  浏览器  │
│ (设备)   │      │ (wss://...)   │      │ (ws://...)   │      │ (播放器) │
└─────────┘      └──────────────┘      └─────────────┘      └─────────┘
                                              │
                                              ▼
                                        ┌─────────────┐
                                        │  ffmpeg转码  │  (可选)
                                        │ (fmp4/HLS)  │
                                        └─────────────┘
```

## 推荐的完整方案

```javascript
// 修改 relay.js 添加转码支持
import { spawn } from 'child_process';

class HikRelayServer {
  // ... 原有代码 ...

  _handleClientConnection(clientWs, req) {
    // ... 原有代码 ...

    // 启动 ffmpeg 转码进程
    const ffmpeg = this._createFFmpeg(clientWs);

    hikClient.on('video', (data) => {
      // 送入 ffmpeg 转码
      if (ffmpeg.stdin.writable) {
        ffmpeg.stdin.write(data);
      }
    });

    // ffmpeg 输出转码后的 fmp4 数据
    ffmpeg.stdout.on('data', (chunk) => {
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(chunk);
      }
    });
  }

  _createFFmpeg(outputWs) {
    return spawn('ffmpeg', [
      '-hide_banner',
      '-loglevel', 'error',
      '-i', 'pipe:0',              // 输入: 海康流
      '-c:v', 'libx264',           // 视频编码: H.264
      '-preset', 'ultrafast',      // 最快编码速度
      '-tune', 'zerolatency',      // 低延迟
      '-g', '30',                  // GOP 大小
      '-f', 'mp4',                 // 输出格式: MP4
      '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
      'pipe:1'                     // 输出到管道
    ]);
  }
}
```

前端使用标准 video 标签即可播放转码后的 fmp4：

```html
<video id="video" autoplay playsinline></video>
<script>
const mediaSource = new MediaSource();
video.src = URL.createObjectURL(mediaSource);

mediaSource.addEventListener('sourceopen', () => {
  const sourceBuffer = mediaSource.addSourceBuffer('video/mp4; codecs="avc1.42E01E"');
  
  ws.onmessage = (e) => {
    sourceBuffer.appendBuffer(new Uint8Array(e.data));
  };
});
</script>
```
