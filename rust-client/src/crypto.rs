//! 会话鉴权与密钥派生。对应 `go-client/crypto.go`、`python-client/hik_ws_client.py` 与
//! `php-client/src/Crypto.php`，线格式依据 `docs/protocol.md`「认证与密钥派生」。
//!
//! 协议约定（ADR-0004）：realplay 以空 key 请求，服务端据此不下发加密流，**媒体载荷本身
//! 不加密**，密钥交换只用于会话鉴权。因此默认 key/authorization/token 为空即可；当代理
//! 要求严格鉴权时，用本模块填实这三个字段（`HikConfig::use_realplay_auth`）。

use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{generic_array::GenericArray, BlockEncryptMut, KeyIvInit};
use cbc::Encryptor;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::hex;

// 海康 JS 播放器里硬编码的固定密钥。注意这两个字面量是**十六进制文本**，AES 用的是它们
// 解码后的字节（key 32 字节 = aes-256，IV 16 字节）——直接把 hex 串当密钥会得到完全不同
// 的密文（Go / Python / PHP 侧都是先解码再加密）。
const FIXED_KEY_HEX: &str = "1234567891234567123456789123456712345678912345671234567891234567";
const FIXED_IV_HEX: &str = "12345678912345671234567891234567";

/// 密钥派生（对照 `h5player.min.js` / `Decoder.js` 逆向所得，docs/protocol.md）：
///
/// 1. `password_md5 = MD5(password)`
/// 2. `salt_data    = SHA256(password_md5 + "rtsp" + username)`
/// 3. `auth_data    = SHA256(PKD + rand)`
/// 4. `combined     = SHA256(salt_data + auth_data + salt_data)`
/// 5. `secret_key   = hex(combined)`
pub fn generate_secret_key(pkd: &str, rand: &str, username: &str, password: &str) -> String {
    let mut md5 = md5::Md5::new();
    md5.update(password.as_bytes());
    let password_md5 = md5.finalize();

    let mut salt = Sha256::new();
    salt.update(password_md5);
    salt.update(b"rtsp");
    salt.update(username.as_bytes());
    let salt_data = salt.finalize();

    let mut auth = Sha256::new();
    auth.update(pkd.as_bytes());
    auth.update(rand.as_bytes());
    let auth_data = auth.finalize();

    let mut combined = Sha256::new();
    combined.update(salt_data);
    combined.update(auth_data);
    combined.update(salt_data);
    hex::encode(&combined.finalize())
}

/// AES-256-CBC 加密（PKCS#7 填充）。
fn aes_cbc_encrypt(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let mut enc = Encryptor::<aes::Aes256>::new_from_slices(key, iv).expect("key/iv length");
    let pad = 16 - plaintext.len() % 16;
    let mut buf = plaintext.to_vec();
    buf.extend(std::iter::repeat_n(pad as u8, pad));
    for block in buf.as_chunks_mut::<16>().0 {
        enc.encrypt_block_mut(GenericArray::from_mut_slice(block));
    }
    buf
}

/// 按当前时间派生客户端 IV 与 key（返回 hex，各至少 64 字符）。
pub fn generate_client_iv_key() -> (String, String) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    generate_client_iv_key_at(now_ms)
}

/// `generate_client_iv_key` 的可测版本：显式传入毫秒时间戳（输出因此确定）。
pub fn generate_client_iv_key_at(now_ms: u128) -> (String, String) {
    let plaintext = now_ms.to_string();
    let fixed_key = hex::decode(FIXED_KEY_HEX).expect("fixed key hex");
    let fixed_iv = hex::decode(FIXED_IV_HEX).expect("fixed iv hex");
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&fixed_key);
    iv.copy_from_slice(&fixed_iv);

    let ct = aes_cbc_encrypt(plaintext.as_bytes(), &key, &iv);
    // JS / Python 参考实现把值翻倍直到 64 个十六进制字符。
    let mut hexed = hex::encode(&ct);
    while hexed.len() < 64 {
        hexed.push_str(&hexed.clone());
    }
    (hexed.clone(), hexed)
}

/// 用 RSA + 海康魔改的 PKCS#1 v1.5 填充生成 realplay 的 `key` 字段：
/// `00 02 <非零随机填充> 00 <iv:key>`，指数固定 65537。
pub fn generate_realplay_key(iv: &str, key: &str, pkd_hex: &str) -> Result<String, Error> {
    let plaintext = format!("{iv}:{key}");
    let pkd = hex::decode(pkd_hex).map_err(|_| Error::Crypto("invalid PKD hex".into()))?;
    if pkd.is_empty() {
        return Err(Error::Crypto("empty PKD".into()));
    }
    let key_len = pkd.len();
    let msg = plaintext.as_bytes();
    if msg.len() + 3 > key_len {
        // 明文 + 0x00 分隔符 + 00 02 前缀放不进一个块。
        return Err(Error::Crypto(
            "realplay plaintext does not fit the modulus".into(),
        ));
    }

    let mut block = vec![0u8; key_len];
    let mut t = key_len;
    for &b in msg.iter().rev() {
        t -= 1;
        block[t] = b;
    }
    t -= 1; // 0x00 分隔符
    let mut rng = rand::thread_rng();
    while t > 2 {
        t -= 1;
        // 非零随机填充
        loop {
            let mut r = [0u8; 1];
            rng.fill_bytes(&mut r);
            if r[0] != 0 {
                block[t] = r[0];
                break;
            }
        }
    }
    block[1] = 0x02;
    block[0] = 0x00;

    let n = BigUint::from_bytes_be(&pkd);
    let m = BigUint::from_bytes_be(&block);
    let c = m.modpow(&BigUint::from(65537u32), &n);
    let mut c_bytes = c.to_bytes_be();
    // 左侧补零到模长。
    if c_bytes.len() < key_len {
        let mut padded = vec![0u8; key_len - c_bytes.len()];
        padded.extend_from_slice(&c_bytes);
        c_bytes = padded;
    }
    Ok(hex::encode(&c_bytes))
}

/// 从 hex 串取前 32 字节密钥 / 前 16 字节 IV（不足补零）。
fn key_iv(key_hex: &str, iv_hex: &str) -> ([u8; 32], [u8; 16]) {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    if let Ok(bytes) = hex::decode(&key_hex[..key_hex.len().min(64)]) {
        let n = bytes.len().min(32);
        key[..n].copy_from_slice(&bytes[..n]);
    }
    if let Ok(bytes) = hex::decode(&iv_hex[..iv_hex.len().min(32)]) {
        let n = bytes.len().min(16);
        iv[..n].copy_from_slice(&bytes[..n]);
    }
    (key, iv)
}

/// 生成 `authorization` 字段：AES-CBC(`rand:password`)。
pub fn generate_authorization(
    rand_str: &str,
    password: &str,
    key_hex: &str,
    iv_hex: &str,
) -> Result<String, Error> {
    let (key, iv) = key_iv(key_hex, iv_hex);
    let plaintext = format!("{rand_str}:{password}");
    Ok(hex::encode(&aes_cbc_encrypt(
        plaintext.as_bytes(),
        &key,
        &iv,
    )))
}

/// 生成 `token` 字段：AES-CBC(hex(SHA256(url)))。
pub fn generate_token(url: &str, key_hex: &str, iv_hex: &str) -> Result<String, Error> {
    let (key, iv) = key_iv(key_hex, iv_hex);
    let url_hash = {
        let mut h = Sha256::new();
        h.update(url.as_bytes());
        hex::encode(&h.finalize())
    };
    Ok(hex::encode(&aes_cbc_encrypt(
        url_hash.as_bytes(),
        &key,
        &iv,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 期望值由参考实现独立算出（docs/protocol.md 的派生步骤 + FIPS 校验过的 AES）。
    #[test]
    fn secret_key_derivation_vector() {
        assert_eq!(
            generate_secret_key("PKD", "rand", "admin", ""),
            "ae9a4cc0d0ea0ce6687984cb385c399a57265cca39f3541da0c449cfb7dcde75"
        );
        assert_eq!(
            generate_secret_key("abc", "def", "admin", "secret"),
            "690f817134552426e5ceb767d061ea59be84043d41e9402b88d1805aa8bda0e5"
        );
    }

    #[test]
    fn client_iv_key_is_deterministic_and_long() {
        let (iv, key) = generate_client_iv_key_at(1_700_000_000_000);
        // Go 侧 GenerateClientIVKey 对同一时间戳的实测输出（行为基准）。
        assert_eq!(
            iv,
            "bf11ff333f233150c77918a7d6ccc062bf11ff333f233150c77918a7d6ccc062"
        );
        assert_eq!(key, iv);
        assert_eq!(iv.len(), 64);
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn authorization_vector_matches_go_baseline() {
        let (iv, key) = generate_client_iv_key_at(1_700_000_000_000);
        // Go 侧 GenerateAuthorization("randval", "secret", key, iv) 的实测输出。
        assert_eq!(
            generate_authorization("randval", "secret", &key, &iv).unwrap(),
            "8d56b554484edddad7f0dc244df23616"
        );
    }

    #[test]
    fn token_vector_matches_go_baseline() {
        let (iv, key) = generate_client_iv_key_at(1_700_000_000_000);
        // Go 侧 GenerateToken("ws://127.0.0.1:559/openUrl/tok", key, iv) 的实测输出。
        assert_eq!(
            generate_token("ws://127.0.0.1:559/openUrl/tok", &key, &iv).unwrap(),
            "c737d613dd2ebfd72db89eda87e331315c074d45bd8aee9f7723fe204c06caec34592c1ee32d28856ae794de01b7a7ada03c13cc8a4cdb60398e2d6c572cd8a5fee08be8b5d7a80c46e3b62987ad0559"
        );
    }

    #[test]
    fn realplay_key_padding_layout() {
        // 2048 位测试密钥对（参考实现生成，仅测试用；e 固定 65537）。
        let n = "6a01b367f5b7e2c4ef6cf71963de7f17d022546a846a4e638936b36cac5152f6\
                 5d4869732b8c643f239996192a377bd38b418b09d2fc4052152d17f2220183bf9\
                 8d098e498369e604d672076d7733a9a9a8bfcc1a1678274f4409eb93f8f103255\
                 bcda9e786ffc8a2d7208b7d294f0d4d33c38487033d3360710acbe4e875c9e1fa\
                 054e28e1bfc059a860725d2b531b1a6ba9ca43813e9af425f92fc7e868c215130\
                 e70724ff51077bad66bf6bdeb7ec59d35fb3b2037e29a3284713d96c8633d043\
                 8c69217cce44abf6313dfa6d835a352d88943ff58584a7f8c288b8ec4aea9a5a\
                 257cb4bdd0a0e4841aac290757e9a107b87dc684eff8d6c18343cd785ac7";
        let d = "6694acc2ae423adc6e00990165e63a4095f59290dd006e48ddd02442c6619011\
                 bde543bde26761dec3996d697eb3e04cae964770c34dbd04715f88ab9402b936\
                 602f83b4ba23289172759831c87dc63933d2c14db2de129d107bb3dcf9c77c59\
                 e923eebea9375d3f6d88cb2cef4797e1ab63bbe74544b15fb7e887f144d6b265\
                 442c2dfc3f825fd1170cb443687f9a8d3362ec32265eb0eebe5d1c2eaaf07f21\
                 d91e3e244fbd1b9de37cac3cd5a7096e02ffac627d6f0c6214032ae2d321e6a6\
                 f3358282a7ec924954254a61028934302ad835f57fd152162a73912d4596a122\
                 bac95dcc329fc815936ea02b112ab29aaf506bccf4b91dc15a7ceb0996a58e61";
        let (iv_hex, key_hex) = generate_client_iv_key_at(1_700_000_000_000);
        let ct_hex = generate_realplay_key(&iv_hex, &key_hex, n).unwrap();

        let key_len = n.len() / 2;
        let ct = hex::decode(&ct_hex).unwrap();
        assert_eq!(ct.len(), key_len, "ciphertext must be one modulus long");

        // 用私钥解回明文块，校验魔改 PKCS#1 v1.5 布局：00 02 <非零填充> 00 <iv:key>。
        let n_int = BigUint::from_bytes_be(&hex::decode(n).unwrap());
        let d_int = BigUint::from_bytes_be(&hex::decode(d).unwrap());
        let m = BigUint::from_bytes_be(&ct).modpow(&d_int, &n_int);
        let mut block = m.to_bytes_be();
        let mut padded = vec![0u8; key_len - block.len()];
        padded.extend_from_slice(&block);
        block = padded;

        assert_eq!(block[0], 0x00);
        assert_eq!(block[1], 0x02);
        let sep = block[2..]
            .iter()
            .position(|&b| b == 0)
            .expect("no separator");
        assert!(sep >= 8, "padding separator at {sep} (too short)");
        let plaintext = String::from_utf8(block[2 + sep + 1..].to_vec()).unwrap();
        assert_eq!(plaintext, format!("{iv_hex}:{key_hex}"));
    }

    #[test]
    fn realplay_key_rejects_oversized_plaintext() {
        // 16 字节模数放不下 iv:key（>128 字符）——必须报错而不是死循环/panic。
        let n = "0102030405060708090a0b0c0d0e0f10";
        assert!(generate_realplay_key(&"a".repeat(64), &"b".repeat(64), n).is_err());
    }
}
