//! 错误类型。
//!
//! 与 Go 侧一一对应：`ServerError` 是服务端在带内上报的错误（openUrl token 过期、凭据
//! 错误、设备不可达），**终态**——用同一个 URL 重试只会拿到同样的错误码，`Stream` 必须
//! 立即停止重连（盲目重试只会烧掉本来就很短的 token 时间窗，见 docs/protocol.md 错误码表）。

use std::fmt;

/// 服务端上报的错误：终态，不重试。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerError {
    pub code: i32,
    pub msg: String,
}

impl ServerError {
    pub fn new(code: i32, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server error code={} msg={}", self.code, self.msg)
    }
}

impl std::error::Error for ServerError {}

/// 客户端错误总类型。
#[derive(Debug)]
pub enum Error {
    /// 服务端带内错误（终态）。
    Server(ServerError),
    /// 传输层 I/O 错误（拨号、读、写、连接关闭）。
    Io(std::io::Error),
    /// 看门狗：`StallTimeout` 窗口内没有任何消息到达。
    Stalled,
    /// 协议数据畸形（如二进制会话错误消息、WebSocket 帧畸形）。
    Protocol(String),
    /// 尚未建立连接。
    NotConnected,
    /// 配置 / URL 解析错误。
    Config(String),
    /// 鉴权与密钥派生错误。
    Crypto(String),
    /// WebSocket 层错误（握手 / 帧）。
    WebSocket(String),
    /// TLS 错误。
    Tls(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Server(e) => write!(f, "{e}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Stalled => write!(f, "stream stalled: no data within StallTimeout"),
            Error::Protocol(s) => write!(f, "{s}"),
            Error::NotConnected => write!(f, "not connected"),
            Error::Config(s) => write!(f, "config error: {s}"),
            Error::Crypto(s) => write!(f, "crypto error: {s}"),
            Error::WebSocket(s) => write!(f, "websocket error: {s}"),
            Error::Tls(s) => write!(f, "tls error: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Server(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ServerError> for Error {
    fn from(e: ServerError) -> Self {
        Error::Server(e)
    }
}
