import crypto from 'crypto';

const HIK_FIXED_KEY = Buffer.from('1234567891234567123456789123456712345678912345671234567891234567', 'hex');
const HIK_FIXED_IV = Buffer.from('12345678912345671234567891234567', 'hex');

function pkcs7Pad(data, blockSize) {
  const padding = blockSize - (data.length % blockSize);
  const padBuf = Buffer.alloc(padding, padding);
  return Buffer.concat([data, padBuf]);
}

function aesEncryptCBC(plaintext, key, iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const padded = pkcs7Pad(Buffer.from(plaintext, 'utf-8'), 16);
  return Buffer.concat([cipher.update(padded), cipher.final()]);
}

export function generateClientIVKey() {
  const nowMs = String(Date.now());
  const ivBytes = aesEncryptCBC(nowMs, HIK_FIXED_KEY, HIK_FIXED_IV);
  const keyBytes = aesEncryptCBC(nowMs, HIK_FIXED_KEY, HIK_FIXED_IV);

  let iv = ivBytes.toString('hex');
  let key = keyBytes.toString('hex');

  while (iv.length < 64) iv += iv;
  while (key.length < 64) key += key;

  return { iv, key };
}

export function generateRealplayKey(iv, key, pkdHex) {
  const plaintext = `${iv}:${key}`;
  const pkdBytes = Buffer.from(pkdHex, 'hex');
  const keyLen = pkdBytes.length;
  const nInt = BigInt('0x' + pkdBytes.toString('hex'));

  const msgUtf8 = Buffer.from(plaintext, 'utf-8');
  const block = Buffer.alloc(keyLen, 0);

  let t = keyLen;
  let i = msgUtf8.length - 1;

  while (i >= 0) {
    t--;
    block[t] = msgUtf8[i];
    i--;
  }

  t--;
  block[t] = 0;

  while (t > 2) {
    t--;
    let r = crypto.randomBytes(1)[0];
    while (r === 0) {
      r = crypto.randomBytes(1)[0];
    }
    block[t] = r;
  }

  block[1] = 0x02;
  block[0] = 0x00;

  const mInt = BigInt('0x' + block.toString('hex'));
  const eInt = BigInt(65537);
  const cInt = modPow(mInt, eInt, nInt);

  let cBytes = Buffer.from(cInt.toString(16).padStart(keyLen * 2, '0'), 'hex');
  if (cBytes.length < keyLen) {
    const padded = Buffer.alloc(keyLen, 0);
    cBytes.copy(padded, keyLen - cBytes.length);
    cBytes = padded;
  }

  return cBytes.toString('hex');
}

function modPow(base, exp, mod) {
  let result = BigInt(1);
  let b = base % mod;
  let e = exp;

  while (e > BigInt(0)) {
    if (e % BigInt(2) === BigInt(1)) {
      result = (result * b) % mod;
    }
    b = (b * b) % mod;
    e = e / BigInt(2);
  }

  return result;
}

export function generateAuthorization(randStr, password, keyHex, ivHex) {
  const plaintext = `${randStr}:${password}`;
  const keyBytes = Buffer.from(keyHex.slice(0, 64), 'hex');
  const ivBytes = Buffer.from(ivHex.slice(0, 32), 'hex');

  const key = keyBytes.length < 32 ? Buffer.concat([keyBytes, Buffer.alloc(32 - keyBytes.length, 0)]) : keyBytes;
  const iv = ivBytes;

  const enc = aesEncryptCBC(plaintext, key.slice(0, 32), iv.slice(0, 16));
  return enc.toString('hex');
}

export function generateToken(urlStr, keyHex, ivHex) {
  const urlHash = crypto.createHash('sha256').update(urlStr, 'utf-8').digest('hex');
  const keyBytes = Buffer.from(keyHex.slice(0, 64), 'hex');
  const ivBytes = Buffer.from(ivHex.slice(0, 32), 'hex');

  const key = keyBytes.length < 32 ? Buffer.concat([keyBytes, Buffer.alloc(32 - keyBytes.length, 0)]) : keyBytes;
  const iv = ivBytes;

  const enc = aesEncryptCBC(urlHash, key.slice(0, 32), iv.slice(0, 16));
  return enc.toString('hex');
}
