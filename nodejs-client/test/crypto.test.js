import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateClientIVKey,
  generateRealplayKey,
  generateAuthorization,
  generateToken,
} from '../src/crypto.js';

describe('crypto', () => {
  it('generateClientIVKey returns 64-char hex strings', () => {
    const { iv, key } = generateClientIVKey();
    assert.strictEqual(iv.length, 64);
    assert.strictEqual(key.length, 64);
    assert.match(iv, /^[0-9a-f]+$/);
    assert.match(key, /^[0-9a-f]+$/);
  });

  it('generateRealplayKey returns hex string', () => {
    const pkd = 'a1b2c3d4e5f6'.repeat(20);
    const { iv, key } = generateClientIVKey();
    const result = generateRealplayKey(iv, key, pkd);
    assert.match(result, /^[0-9a-f]+$/);
    assert.ok(result.length > 0);
  });

  it('generateAuthorization returns hex string', () => {
    const { iv, key } = generateClientIVKey();
    const auth = generateAuthorization('rand123', 'password', key, iv);
    assert.match(auth, /^[0-9a-f]+$/);
    assert.ok(auth.length > 0);
  });

  it('generateToken returns hex string', () => {
    const { iv, key } = generateClientIVKey();
    const token = generateToken('ws://192.168.1.1/openUrl/test', key, iv);
    assert.match(token, /^[0-9a-f]+$/);
    assert.ok(token.length > 0);
  });
});
