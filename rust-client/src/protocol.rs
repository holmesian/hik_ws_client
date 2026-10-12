//! 协议封包：5 字节头（1 字节类型 + 4 字节大端长度）+ 净荷。
//!
//! 对应 `docs/protocol.md`「封包格式」与 `go-client/protocol.go`：
//!
//! - 一个 WebSocket 消息里可能连着多条协议消息，必须循环消费到尾，否则静默丢帧；
//! - 也存在**没有协议信封**的裸载荷消息，调用方按解包失败回退处理；
//! - `Length` 来自网络：**做加法前先扩成宽整数**。`uint32` 下 `5 + 0xFFFFFFFB` 回绕成 0，
//!   能骗过任何边界检查，随后越界读直接打死进程——这是真机摸底撞出来的，不是理论风险；
//! - `EncryptFlag`(0x80) 仅解析暴露，不据此解密：realplay 以空 key 请求，服务端不下发
//!   加密流，媒体载荷本身不加密（ADR-0004）。

/// 消息类型常量（协议文档「消息类型」表）。
pub const MSG_TYPE_HELLO: u8 = 0x01;
pub const MSG_TYPE_AUTH_REQUEST: u8 = 0x02;
pub const MSG_TYPE_AUTH_RESPONSE: u8 = 0x03;
pub const MSG_TYPE_KEY_EXCHANGE: u8 = 0x04;
pub const MSG_TYPE_SESSION_ERROR: u8 = 0x05;
pub const MSG_TYPE_KEEPALIVE: u8 = 0x06;
pub const MSG_TYPE_VIDEO_DATA: u8 = 0x40;
pub const MSG_TYPE_AUDIO_DATA: u8 = 0x41;

/// 加密标志：位于协议类型字节的最高位。
pub const ENCRYPT_FLAG: u8 = 0x80;

/// 解包错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// 不足 5 字节，协议头不完整。
    ShortHeader,
    /// 声明的净荷长度超过可用字节（截断的帧，或根本不是协议消息）。
    ShortPayload,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::ShortHeader => write!(f, "insufficient length for header"),
            ProtocolError::ShortPayload => write!(f, "insufficient length for payload"),
        }
    }
}

/// 解出的一条协议消息。`payload` / `remaining` 是借用的输入切片（零拷贝）。
#[derive(Debug)]
pub struct ProtocolMessage<'a> {
    /// 类型字节（已剥掉 `ENCRYPT_FLAG`）。
    pub msg_type: u8,
    /// 原始类型字节的最高位（加密标志）。仅暴露，不据此解密。
    pub encrypted: bool,
    /// 净荷。
    pub payload: &'a [u8],
    /// 本条消息之后的剩余字节（同一帧可能还有下一条协议消息）。
    pub remaining: &'a [u8],
}

/// 把净荷包进 5 字节协议头。
pub fn pack_message(msg_type: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(msg_type);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// 从 `data` 头部解出一条协议消息。
///
/// 头部不完整或声明长度超过可用字节时返回错误（调用方据此把剩余字节当裸视频处理），
/// 而不是返回空——裸 PS / 裸 Annex-B 不能被误剥。
pub fn unpack(data: &[u8]) -> Result<ProtocolMessage<'_>, ProtocolError> {
    if data.len() < 5 {
        return Err(ProtocolError::ShortHeader);
    }
    let typ = data[0];
    // 长度必须先扩成宽整数再做边界检查：媒体字节在任何"无协议信封"的帧上都会流到这里，
    // 那时这 4 个字节是任意的。真机上读到过 0xFFFFFFFB，uint32 下 5+length 回绕成 0，
    // 检查通过后 data[5:0] 直接打死进程。
    let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as u64;
    let need = 5u64 + length;
    if (data.len() as u64) < need {
        return Err(ProtocolError::ShortPayload);
    }
    let end = need as usize;
    Ok(ProtocolMessage {
        msg_type: typ & !ENCRYPT_FLAG,
        encrypted: typ & ENCRYPT_FLAG != 0,
        payload: &data[5..end],
        remaining: &data[end..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let packed = pack_message(MSG_TYPE_VIDEO_DATA, b"AB");
        assert_eq!(packed, vec![0x40, 0x00, 0x00, 0x00, 0x02, b'A', b'B']);
        let msg = unpack(&packed).unwrap();
        assert_eq!(msg.msg_type, MSG_TYPE_VIDEO_DATA);
        assert!(!msg.encrypted);
        assert_eq!(msg.payload, b"AB");
        assert!(msg.remaining.is_empty());
    }

    // type 0xC0 (0x40 | EncryptFlag) + length 2 + payload "AB"，尾部还有 1 字节。
    #[test]
    fn unpack_encrypted_flag_and_remaining() {
        let raw = [0xC0, 0x00, 0x00, 0x00, 0x02, b'A', b'B', 0xFF];
        let msg = unpack(&raw).unwrap();
        assert_eq!(msg.msg_type, MSG_TYPE_VIDEO_DATA);
        assert!(msg.encrypted);
        assert_eq!(msg.payload, b"AB");
        assert_eq!(msg.remaining, &[0xFF]);
    }

    // 媒体字节在无协议信封的帧上会流进 unpack，那 4 个长度字节是任意的。
    // 接近 2^32 的长度曾在 uint32 下让 5+length 回绕成 0、通过检查后打死进程。
    #[test]
    fn unpack_rejects_overflowing_length() {
        for length in [
            [0xFF, 0xFF, 0xFF, 0xFF],
            [0xFF, 0xFF, 0xFF, 0xFB],
            [0x7F, 0xFF, 0xFF, 0xFF],
        ] {
            let mut raw = vec![0x40];
            raw.extend_from_slice(&length);
            raw.extend_from_slice(b"AB");
            assert!(
                unpack(&raw).is_err(),
                "length {length:02X?} must be rejected"
            );
        }
    }

    #[test]
    fn unpack_rejects_short() {
        assert_eq!(
            unpack(&[0x40, 0x00]).unwrap_err(),
            ProtocolError::ShortHeader
        );
        assert_eq!(
            unpack(&[0x40, 0x00, 0x00, 0x00, 0x05, b'A']).unwrap_err(),
            ProtocolError::ShortPayload
        );
    }

    #[test]
    fn one_frame_many_messages() {
        // 一帧里两条协议消息：必须循环消费到尾（对应 go-client 的
        // TestIntegration_BatchedFrameConsumedToTail）。
        let mut frame = pack_message(MSG_TYPE_VIDEO_DATA, b"one");
        frame.extend_from_slice(&pack_message(MSG_TYPE_AUDIO_DATA, b"two"));
        frame.extend_from_slice(b"tail");

        let mut rest: &[u8] = &frame;
        let mut types = Vec::new();
        let mut payloads = Vec::new();
        while !rest.is_empty() {
            match unpack(rest) {
                Ok(msg) => {
                    types.push(msg.msg_type);
                    payloads.push(msg.payload.to_vec());
                    rest = msg.remaining;
                }
                Err(_) => {
                    // 解不出来 → 剩余整段是裸视频
                    payloads.push(rest.to_vec());
                    break;
                }
            }
        }
        assert_eq!(types, vec![MSG_TYPE_VIDEO_DATA, MSG_TYPE_AUDIO_DATA]);
        assert_eq!(
            payloads,
            vec![b"one".to_vec(), b"two".to_vec(), b"tail".to_vec()]
        );
    }
}
