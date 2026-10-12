//! Base64 编解码（标准字母表，RFC 4648）。用于 WebSocket 握手的
//! `Sec-WebSocket-Key` / `Sec-WebSocket-Accept` 与 SDP 的
//! `sprop-parameter-sets`。手写实现以保持媒体层零第三方依赖。

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 标准 Base64 编码（含 `=` 填充）。
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// 标准 Base64 解码（RFC 4648 规范形式：长度为 4 的倍数、填充只在末尾）。
///
/// 与 Go 的 `base64.StdEncoding` 行为对齐：缺填充 / 多余填充 / 填充后还有数据 /
/// 非法字符一律拒绝。lenient 解码会把 `tok` 这种非 base64 令牌解成垃圾字节，
/// 与 Go 侧 `ParseProxyURL` 的取密码逻辑不符。
pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return Err(());
    }
    let groups = b.len() / 4;
    let mut out = Vec::with_capacity(groups * 3);
    let mut pad = 0usize;
    for (gi, group) in b.chunks(4).enumerate() {
        let last = gi + 1 == groups;
        let mut vals = [0u32; 4];
        for i in 0..4 {
            match group[i] {
                b'=' => {
                    // 只允许最后一组末尾的 1-2 个 '='。
                    if !last || i < 2 {
                        return Err(());
                    }
                    pad += 1;
                }
                c => {
                    if pad > 0 {
                        return Err(()); // 填充后还有数据
                    }
                    vals[i] = val6(c)?;
                }
            }
        }
        if pad > 2 {
            return Err(());
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

fn val6(c: u8) -> Result<u32, ()> {
    match c {
        b'A'..=b'Z' => Ok((c - b'A') as u32),
        b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
        b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn roundtrip() {
        for n in 0..300usize {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 7 + 13) as u8).collect();
            let encoded = encode(&bytes);
            assert_eq!(decode(&encoded).unwrap(), bytes, "n={n}");
        }
    }

    #[test]
    fn ws_accept_shape() {
        // Sec-WebSocket-Key 是 16 随机字节的 base64：长度恒为 24 字符带一个 '='
        let key = encode(&[0u8; 16]);
        assert_eq!(key.len(), 24);
        assert!(key.ends_with('='));
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode("abc").is_err()); // 长度非 4 倍数（缺填充）
        assert!(decode("Zm9vYmFy====").is_err()); // 过长填充
        assert!(decode("Zm9v YmFy").is_err()); // 含空白
        assert!(decode("Zm9v*").is_err()); // 非法字符
        assert!(decode("=Zm9").is_err()); // 填充不在末尾
        assert!(decode("Z==g").is_err()); // 填充后还有数据
    }
}
