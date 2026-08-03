/**
 * 摄像头注册表 - 根据 cameraCode 获取连接配置
 *
 * 支持两种方式:
 * 1. 静态配置: 在代码中预定义摄像头信息
 * 2. 动态查询: 通过 HTTP API 查询摄像头信息
 */

import { HikConfig } from './config.js';

/**
 * 摄像头信息
 * @typedef {Object} CameraInfo
 * @property {string} cameraCode - 摄像头编码
 * @property {string} proxyHost - 代理服务器主机
 * @property {number} proxyPort - 代理服务器端口
 * @property {string} deviceIP - 设备IP
 * @property {number} devicePort - 设备端口
 * @property {string} username - 用户名
 * @property {string} password - 密码
 * @property {string} [streamType] - 码流类型: main, sub, third
 */

export class CameraRegistry {
  constructor(options = {}) {
    // 静态摄像头配置表
    this.cameras = new Map();

    // 动态查询配置
    this.apiBaseURL = options.apiBaseURL || '';
    this.apiHeaders = options.apiHeaders || {};

    // 加载静态配置
    if (options.cameras) {
      for (const cam of options.cameras) {
        this.register(cam);
      }
    }
  }

  /**
   * 注册摄像头
   * @param {CameraInfo} cameraInfo
   */
  register(cameraInfo) {
    if (!cameraInfo.cameraCode) {
      throw new Error('cameraCode is required');
    }
    this.cameras.set(cameraInfo.cameraCode, cameraInfo);
  }

  /**
   * 批量注册摄像头
   * @param {CameraInfo[]} cameras
   */
  registerAll(cameras) {
    for (const cam of cameras) {
      this.register(cam);
    }
  }

  /**
   * 根据 cameraCode 获取摄像头配置
   * @param {string} cameraCode
   * @returns {Promise<HikConfig>}
   */
  async getConfig(cameraCode) {
    // 1. 先查静态配置
    const staticCam = this.cameras.get(cameraCode);
    if (staticCam) {
      return this._toHikConfig(staticCam);
    }

    // 2. 如果配置了 API，尝试动态查询
    if (this.apiBaseURL) {
      const dynamicCam = await this._fetchFromAPI(cameraCode);
      if (dynamicCam) {
        return this._toHikConfig(dynamicCam);
      }
    }

    throw new Error(`Camera not found: ${cameraCode}`);
  }

  /**
   * 检查摄像头是否存在
   * @param {string} cameraCode
   * @returns {boolean}
   */
  has(cameraCode) {
    return this.cameras.has(cameraCode);
  }

  /**
   * 获取所有已注册的摄像头编码
   * @returns {string[]}
   */
  list() {
    return Array.from(this.cameras.keys());
  }

  /**
   * 转换为 HikConfig
   * @param {CameraInfo} info
   * @returns {HikConfig}
   */
  _toHikConfig(info) {
    return new HikConfig({
      proxyHost: info.proxyHost,
      proxyPort: info.proxyPort,
      proxyPath: `/proxy/${info.deviceIP}:${info.devicePort}`,
      deviceIP: info.deviceIP,
      devicePort: info.devicePort,
      username: info.username || 'admin',
      password: info.password || '',
    });
  }

  /**
   * 从 API 查询摄像头信息
   * @param {string} cameraCode
   * @returns {Promise<CameraInfo|null>}
   */
  async _fetchFromAPI(cameraCode) {
    try {
      const url = `${this.apiBaseURL}/cameras/${cameraCode}`;
      const response = await fetch(url, {
        headers: this.apiHeaders,
      });

      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`API error: ${response.status}`);
      }

      return await response.json();
    } catch (err) {
      console.error(`Failed to fetch camera ${cameraCode}:`, err.message);
      return null;
    }
  }
}

/**
 * 创建默认注册表（从环境变量加载配置）
 * @returns {CameraRegistry}
 */
export function createDefaultRegistry() {
  const registry = new CameraRegistry();

  // 从环境变量加载摄像头配置
  // 格式: HIK_CAMERAS=[{"cameraCode":"cam001","proxyHost":"...",...}]
  const envCameras = process.env.HIK_CAMERAS;
  if (envCameras) {
    try {
      const cameras = JSON.parse(envCameras);
      registry.registerAll(cameras);
    } catch (err) {
      console.error('Failed to parse HIK_CAMERAS:', err.message);
    }
  }

  // 从环境变量加载单个摄像头
  // 格式: HIK_CAMERA_<CODE>_HOST, HIK_CAMERA_<CODE>_IP, ...
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
      }
    }
  }

  return registry;
}
