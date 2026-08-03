import { describe, it } from 'node:test';
import assert from 'node:assert';
import { CameraRegistry } from '../src/camera-registry.js';

describe('camera-registry', () => {
  it('registers and retrieves camera by code', async () => {
    const registry = new CameraRegistry();
    registry.register({
      cameraCode: 'cam001',
      proxyHost: 'proxy.example.com',
      proxyPort: 6014,
      deviceIP: '192.168.1.64',
      devicePort: 8000,
      username: 'admin',
      password: 'pass',
    });

    const config = await registry.getConfig('cam001');
    assert.strictEqual(config.proxyHost, 'proxy.example.com');
    assert.strictEqual(config.deviceIP, '192.168.1.64');
    assert.strictEqual(config.devicePort, 8000);
    assert.strictEqual(config.username, 'admin');
    assert.strictEqual(config.password, 'pass');
  });

  it('throws for unknown camera code', async () => {
    const registry = new CameraRegistry();
    await assert.rejects(
      () => registry.getConfig('unknown'),
      /Camera not found/
    );
  });

  it('lists registered cameras', () => {
    const registry = new CameraRegistry();
    registry.register({ cameraCode: 'cam001', proxyHost: 'h1', deviceIP: '1.1.1.1' });
    registry.register({ cameraCode: 'cam002', proxyHost: 'h2', deviceIP: '2.2.2.2' });
    
    const list = registry.list();
    assert.deepStrictEqual(list.sort(), ['cam001', 'cam002']);
  });

  it('checks if camera exists', () => {
    const registry = new CameraRegistry();
    registry.register({ cameraCode: 'cam001', proxyHost: 'h1', deviceIP: '1.1.1.1' });
    
    assert.strictEqual(registry.has('cam001'), true);
    assert.strictEqual(registry.has('cam002'), false);
  });

  it('registers multiple cameras at once', () => {
    const registry = new CameraRegistry();
    registry.registerAll([
      { cameraCode: 'cam001', proxyHost: 'h1', deviceIP: '1.1.1.1' },
      { cameraCode: 'cam002', proxyHost: 'h2', deviceIP: '2.2.2.2' },
    ]);
    
    assert.strictEqual(registry.list().length, 2);
  });

  it('loads cameras from constructor options', () => {
    const registry = new CameraRegistry({
      cameras: [
        { cameraCode: 'cam001', proxyHost: 'h1', deviceIP: '1.1.1.1' },
      ],
    });
    
    assert.strictEqual(registry.has('cam001'), true);
  });
});
