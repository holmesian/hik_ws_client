import { HikRelayServer } from '../src/relay.js';
import { CameraRegistry } from '../src/camera-registry.js';

const port = parseInt(process.env.PORT || '8080', 10);
const host = process.env.HOST || '0.0.0.0';

// 创建摄像头注册表
const registry = new CameraRegistry();

// 从环境变量加载配置
// 方式1: JSON 数组
const envCameras = process.env.HIK_CAMERAS;
if (envCameras) {
  try {
    const cameras = JSON.parse(envCameras);
    registry.registerAll(cameras);
    console.log(`Loaded ${cameras.length} cameras from HIK_CAMERAS`);
  } catch (err) {
    console.error('Failed to parse HIK_CAMERAS:', err.message);
  }
}

// 方式2: 单个摄像头环境变量
for (const key of Object.keys(process.env)) {
  const match = key.match(/^HIK_CAMERA_(.+)_HOST$/);
  if (match) {
    const code = match[1];
    const host = process.env[key];
    const port = parseInt(process.env[`HIK_CAMERA_${code}_PORT`] || '443', 10);
    const ip = process.env[`HIK_CAMERA_${code}_IP`] || '';
    const devicePort = parseInt(process.env[`HIK_CAMERA_${code}_DEVICE_PORT`] || '554', 10);
    const username = process.env[`HIK_CAMERA_${code}_USER`] || 'admin';
    const password = process.env[`HIK_CAMERA_${code}_PASS`] || '';

    if (ip) {
      registry.register({
        cameraCode: code,
        proxyHost: host,
        proxyPort: port,
        deviceIP: ip,
        devicePort: devicePort,
        username,
        password,
      });
      console.log(`Loaded camera ${code} from env`);
    }
  }
}

// 方式3: 配置文件
import { readFileSync } from 'fs';
const configPath = process.env.HIK_CONFIG || './cameras.json';
try {
  const configData = readFileSync(configPath, 'utf-8');
  const config = JSON.parse(configData);
  if (config.cameras) {
    registry.registerAll(config.cameras);
    console.log(`Loaded ${config.cameras.length} cameras from ${configPath}`);
  }
} catch (err) {
  // 配置文件不存在则忽略
  if (err.code !== 'ENOENT') {
    console.error('Failed to load config file:', err.message);
  }
}

const server = new HikRelayServer({ port, host, registry });
server.start();

process.on('SIGINT', () => {
  console.log('\nShutting down...');
  server.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  server.stop();
  process.exit(0);
});
