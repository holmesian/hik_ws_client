import { URL } from 'url';

export class HikConfig {
  constructor(options = {}) {
    this.proxyHost = options.proxyHost || '';
    this.proxyPort = options.proxyPort || 443;
    this.proxyPath = options.proxyPath || '';
    this.deviceIP = options.deviceIP || '';
    this.devicePort = options.devicePort || 554;
    this.username = options.username || 'admin';
    this.password = options.password || '';
    this.version = options.version || '0.1';
    this.cipherSuites = options.cipherSuites || 0;
  }
}

export function parseProxyURL(proxyURL) {
  const parsed = new URL(proxyURL);

  const proxyHost = parsed.hostname;
  const proxyPort = parsed.port ? parseInt(parsed.port, 10) : 443;

  const pathParts = parsed.pathname.replace(/^\//, '').split('/');

  if (pathParts.length < 2 || pathParts[0] !== 'proxy') {
    throw new Error('Invalid proxy path structure');
  }

  const deviceInfo = pathParts[1];
  let deviceIP = '';
  let devicePort = 554;

  if (deviceInfo.includes(']:')) {
    const parts = deviceInfo.slice(1).split(']:');
    deviceIP = '[' + parts[0] + ']';
    devicePort = parseInt(parts[1], 10);
  } else if (deviceInfo.split(':').length === 2) {
    const parts = deviceInfo.split(':');
    deviceIP = parts[0];
    devicePort = parseInt(parts[1], 10);
  } else {
    deviceIP = deviceInfo;
  }

  let username = 'admin';
  let password = '';

  if (pathParts.length > 3 && pathParts[2] === 'openUrl') {
    const authPart = pathParts[3];
    try {
      const decoded = Buffer.from(authPart, 'base64').toString('utf-8');
      if (decoded.includes(':')) {
        const parts = decoded.split(':');
        username = parts[0];
        password = parts[1];
      } else {
        password = decoded;
      }
    } catch {
      password = authPart;
    }
  }

  return new HikConfig({
    proxyHost,
    proxyPort,
    proxyPath: '/proxy/' + deviceInfo,
    deviceIP,
    devicePort,
    username,
    password,
  });
}
