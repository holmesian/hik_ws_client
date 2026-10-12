//! 十六进制编解码。媒体层与鉴权层都要用，手写实现以保持媒体层零第三方依赖
//! （与 Python 侧 `hik_media.py` 仅标准库一致）。

/// 把小写/大写十六进制串解码为字节。拒绝奇数长度与非十六进制字符。
pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// 编码为小写十六进制串。
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    out
}

fn hex_val(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(decode("000fa5ff").unwrap(), vec![0x00, 0x0f, 0xa5, 0xff]);
        assert_eq!(decode("000FA5FF").unwrap(), vec![0x00, 0x0f, 0xa5, 0xff]);
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode("abc").is_err()); // odd length
        assert!(decode("zz").is_err()); // non-hex
        assert!(decode("0g").is_err());
        assert!(decode(" 0").is_err());
    }
}
