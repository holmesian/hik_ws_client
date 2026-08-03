import { HikMediaClient } from './src/client.js';
import { parseProxyURL } from './src/config.js';

async function main() {
  const url = process.argv[2];
  if (!url) {
    console.error('Usage: node demo.js <wss://proxy-host/proxy/device-ip:port/openUrl/auth>');
    process.exit(1);
  }

  const config = parseProxyURL(url);
  console.log('Config:', {
    proxy: `${config.proxyHost}:${config.proxyPort}`,
    device: `${config.deviceIP}:${config.devicePort}`,
    username: config.username,
  });

  const client = new HikMediaClient(config);

  let frameCount = 0;
  let lastLogTime = Date.now();

  client.on('connected', () => console.log('Connected to proxy'));

  client.on('authenticated', ({ pkd, rand }) => {
    console.log(`Authenticated, PKD length=${pkd.length}`);
  });

  client.on('sdp', (sdpInfo) => {
    console.log('SDP received:\n' + sdpInfo.toString());
  });

  client.on('video', (data) => {
    frameCount++;
    const now = Date.now();
    if (now - lastLogTime >= 1000) {
      console.log(`Video: ${frameCount} frames, last=${data.length} bytes`);
      lastLogTime = now;
    }
  });

  client.on('audio', (data) => {
    console.log(`Audio: ${data.length} bytes`);
  });

  client.on('error', (err) => {
    console.error('Error:', err.message);
  });

  client.on('close', () => {
    console.log('Connection closed');
  });

  try {
    await client.run();

    await new Promise((resolve) => {
      client.on('close', resolve);
    });
  } catch (err) {
    console.error('Run failed:', err.message);
  } finally {
    client.close();
  }
}

main();
