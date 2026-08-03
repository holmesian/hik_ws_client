import { describe, it } from 'node:test';
import assert from 'node:assert';
import { parseProxyURL } from '../src/config.js';

describe('config', () => {
  it('parses IPv4 proxy URL', () => {
    const url = 'wss://example.com:6014/proxy/192.168.1.64:8000/openUrl/abc123';
    const config = parseProxyURL(url);
    assert.strictEqual(config.proxyHost, 'example.com');
    assert.strictEqual(config.proxyPort, 6014);
    assert.strictEqual(config.deviceIP, '192.168.1.64');
    assert.strictEqual(config.devicePort, 8000);
  });

  it('parses IPv6 proxy URL', () => {
    const url = 'wss://example.com:6014/proxy/[fd00:0:2c0:9::10c]:559/openUrl/mYqWpMI';
    const config = parseProxyURL(url);
    assert.strictEqual(config.proxyHost, 'example.com');
    assert.strictEqual(config.proxyPort, 6014);
    assert.strictEqual(config.deviceIP, '[fd00:0:2c0:9::10c]');
    assert.strictEqual(config.devicePort, 559);
  });

  it('parses URL without auth', () => {
    const url = 'wss://example.com:6014/proxy/192.168.1.64:8000';
    const config = parseProxyURL(url);
    assert.strictEqual(config.deviceIP, '192.168.1.64');
    assert.strictEqual(config.devicePort, 8000);
    assert.strictEqual(config.username, 'admin');
    assert.strictEqual(config.password, '');
  });

  it('throws on invalid URL', () => {
    assert.throws(() => parseProxyURL('wss://example.com/invalid/path'), /Invalid proxy path/);
  });
});
