//! 连接配置与代理 URL 解析。对应 `go-client/config.go` 的 `HikConfig` / `ParseProxyURL`。

use std::time::Duration;

use crate::base64;
use crate::error::Error;

/// TLS 选项。对应 Go 侧 `*tls.Config` 的常用子集：
///
/// - 默认（`Default`）**校验证书**：webpki 根证书 + `extra_root_certs_der` 附加根。
///   Go 侧曾写死 `InsecureSkipVerify:true`（issue #33），本库默认安全；
/// - `danger_accept_invalid_certs` 仅用于自签测试代理，对应
///   `InsecureSkipVerify:true`，**不要在生产使用**。
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    /// 附加的根证书（DER 编码），如私有 CA。
    pub extra_root_certs_der: Vec<Vec<u8>>,
    /// 跳过证书校验（仅测试 / 自签代理）。
    pub danger_accept_invalid_certs: bool,
}

/// 连接配置。
#[derive(Debug, Clone)]
pub struct HikConfig {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub device_ip: String,
    pub device_port: u16,
    pub username: String,
    pub password: String,
    pub version: String,
    pub cipher_suites: u32,
    /// 逐帧调试日志。生产保持 false：每帧一行日志在多路并发下会淹没 I/O。
    pub verbose: bool,

    /// 传输失败（掉线、卡死、拨号失败）后的额外会话尝试次数。0 = 不重连。
    /// 服务端上报的错误（token 过期、凭据错误）永不重试。
    pub max_reconnects: u32,
    /// 重连基础退避；第 N 次重试等 N*`reconnect_wait`。零值默认 2s。
    pub reconnect_wait: Duration,
    /// 看门狗：该窗口内没有任何 WebSocket 消息到达即判定会话卡死。
    /// 这是发现"代理保持连接但设备停流"的唯一手段。`None` = 关闭。
    pub stall_timeout: Option<Duration>,
    /// keepalive ping 间隔（WebSocket 控制帧）。默认 20s。
    pub keepalive_interval: Duration,

    /// 是否使用 TLS（`wss`）。默认 `true`；`false` 仅用于 `ws://` 测试代理。
    pub use_tls: bool,
    pub tls_options: TlsOptions,

    /// realplay 请求是否用 `crypto` 模块填实 `key` / `authorization` / `token`。
    /// 默认 `false`：以空 key 请求，服务端据此不下发加密流，媒体载荷本身不加密
    /// （ADR-0004）。代理要求严格鉴权时再打开。
    pub use_realplay_auth: bool,
}

impl Default for HikConfig {
    fn default() -> Self {
        Self {
            proxy_host: String::new(),
            proxy_port: 443,
            device_ip: String::new(),
            device_port: 554,
            username: "admin".to_string(),
            password: String::new(),
            version: "0.1".to_string(),
            cipher_suites: 0,
            verbose: false,
            max_reconnects: 0,
            reconnect_wait: Duration::from_secs(2),
            stall_timeout: None,
            keepalive_interval: Duration::from_secs(20),
            use_tls: true,
            tls_options: TlsOptions::default(),
            use_realplay_auth: false,
        }
    }
}

impl HikConfig {
    /// 解析代理 URL。例：`wss://example.com:6014/proxy/[fd00::10c]:559/openUrl/<token>`
    ///
    /// 行为与 Go 侧 `ParseProxyURL` 一致：
    /// - `openUrl/<auth>` 段先尝试 base64 解码：解出来含 `:` 取 `user:pass`，
    ///   否则整体作 password，解失败则原样作 password；
    /// - 设备端口缺省 554（RTSP），代理端口缺省 443。
    pub fn from_proxy_url(proxy_url: &str) -> Result<Self, Error> {
        let (scheme, rest) = proxy_url
            .split_once("://")
            .ok_or_else(|| Error::Config(format!("invalid proxy URL: {proxy_url}")))?;
        let use_tls = match scheme {
            "wss" => true,
            "ws" => false,
            other => {
                return Err(Error::Config(format!(
                    "unsupported scheme {other:?}, want ws:// or wss://"
                )))
            }
        };

        // 权限段：到第一个 '/' 为止。
        let (authority, path_with_query) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (proxy_host, proxy_port) = parse_host_port(authority, 443)?;

        // 路径去掉 query 后按 '/' 切。
        let path = path_with_query.split('?').next().unwrap_or("");
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        if parts.len() < 2 || parts[0] != "proxy" {
            return Err(Error::Config("invalid proxy path structure".to_string()));
        }

        // 设备段：`[ipv6]:port` / `ipv4:port` / 裸 IP。
        let device_info = parts[1];
        let (device_ip, device_port) = if let Some(rest) = device_info.strip_prefix('[') {
            match rest.split_once("]:") {
                Some((ip, port)) => (format!("[{ip}]"), parse_port(port, 554)?),
                None => (device_info.to_string(), 554),
            }
        } else if device_info.matches(':').count() == 1 {
            let (ip, port) = device_info.split_once(':').unwrap();
            (ip.to_string(), parse_port(port, 554)?)
        } else {
            (device_info.to_string(), 554)
        };

        // 凭据段：/proxy/<device>/openUrl/<auth>
        let mut username = "admin".to_string();
        let mut password = String::new();
        if parts.len() > 3 && parts[2] == "openUrl" {
            let auth_part = parts[3];
            match base64::decode(auth_part) {
                Ok(decoded) => {
                    let decoded = String::from_utf8_lossy(&decoded).to_string();
                    match decoded.split_once(':') {
                        Some((u, p)) => {
                            username = u.to_string();
                            password = p.to_string();
                        }
                        None => password = decoded,
                    }
                }
                Err(()) => password = auth_part.to_string(),
            }
        }

        Ok(Self {
            proxy_host,
            proxy_port,
            device_ip,
            device_port,
            username,
            password,
            version: "0.1".to_string(),
            cipher_suites: 0,
            use_tls,
            ..Default::default()
        })
    }

    /// 拼出实际连接的媒体端点路径（对应 Go 侧 `buildMediaURL` 的 path+query）。
    pub fn media_url(&self) -> String {
        let scheme = if self.use_tls { "wss" } else { "ws" };
        format!(
            "{}://{}:{}/media?version={}&cipherSuites={}&sessionID=&proxy={}:{}",
            scheme,
            self.proxy_host,
            self.proxy_port,
            self.version,
            self.cipher_suites,
            self.device_ip,
            self.device_port
        )
    }

    /// realplay 请求里的设备 URL（openUrl token 即 password）。
    pub fn device_url(&self) -> String {
        format!(
            "ws://{}:{}/openUrl/{}",
            self.device_ip, self.device_port, self.password
        )
    }
}

/// 解析 `host:port` / `[ipv6]:port` / 裸 host。IPv6 主机保留方括号（拼 URL 时需要）。
fn parse_host_port(authority: &str, default_port: u16) -> Result<(String, u16), Error> {
    if let Some(rest) = authority.strip_prefix('[') {
        // [ipv6] 或 [ipv6]:port
        match rest.split_once(']') {
            Some((host, tail)) => {
                let port = match tail.strip_prefix(':') {
                    Some(p) => parse_port(p, default_port)?,
                    None => default_port,
                };
                Ok((format!("[{host}]"), port))
            }
            None => Err(Error::Config(format!(
                "invalid IPv6 authority: {authority}"
            ))),
        }
    } else if authority.matches(':').count() == 1 {
        let (host, port) = authority.split_once(':').unwrap();
        if host.is_empty() {
            return Err(Error::Config("empty proxy host".to_string()));
        }
        Ok((host.to_string(), parse_port(port, default_port)?))
    } else if authority.is_empty() {
        Err(Error::Config("empty proxy host".to_string()))
    } else {
        // 裸主机名 / IPv4 / 无端口 IPv6（URL 里不合法，按主机名处理）
        Ok((authority.to_string(), default_port))
    }
}

fn parse_port(s: &str, default_port: u16) -> Result<u16, Error> {
    if s.is_empty() {
        return Ok(default_port);
    }
    s.parse::<u16>()
        .map_err(|_| Error::Config(format!("invalid port: {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv6_with_port_and_base64_password() {
        // base64("auth_token") 不含 ':' → 整体作 password
        let cfg = HikConfig::from_proxy_url(
            "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/YXV0aF90b2tlbg==",
        )
        .unwrap();
        assert_eq!(cfg.proxy_host, "example.com");
        assert_eq!(cfg.proxy_port, 6014);
        assert_eq!(cfg.device_ip, "[1111::2222]");
        assert_eq!(cfg.device_port, 559);
        assert_eq!(cfg.username, "admin");
        assert_eq!(cfg.password, "auth_token");
        assert!(cfg.use_tls);
    }

    #[test]
    fn parse_ipv4_with_user_pass() {
        // admin:secret
        let cfg = HikConfig::from_proxy_url(
            "wss://10.0.0.1/proxy/192.168.1.64:554/openUrl/YWRtaW46c2VjcmV0",
        )
        .unwrap();
        assert_eq!(cfg.proxy_host, "10.0.0.1");
        assert_eq!(cfg.proxy_port, 443);
        assert_eq!(cfg.device_ip, "192.168.1.64");
        assert_eq!(cfg.device_port, 554);
        assert_eq!(cfg.username, "admin");
        assert_eq!(cfg.password, "secret");
    }

    #[test]
    fn parse_plain_token_default_rtsp_port() {
        let cfg =
            HikConfig::from_proxy_url("wss://example.com:6014/proxy/192.168.1.64/openUrl/token!!")
                .unwrap();
        assert_eq!(cfg.proxy_host, "example.com");
        assert_eq!(cfg.proxy_port, 6014);
        assert_eq!(cfg.device_ip, "192.168.1.64");
        assert_eq!(cfg.device_port, 554);
        assert_eq!(cfg.username, "admin");
        assert_eq!(cfg.password, "token!!");
    }

    #[test]
    fn parse_invalid_paths() {
        assert!(HikConfig::from_proxy_url("wss://example.com:6014/media?version=0.1").is_err());
        assert!(HikConfig::from_proxy_url("example.com:6014/proxy/x/openUrl/y").is_err());
        assert!(HikConfig::from_proxy_url("https://example.com/proxy/1.2.3.4/openUrl/y").is_err());
    }

    #[test]
    fn build_media_url() {
        let cfg =
            HikConfig::from_proxy_url("wss://example.com:6014/proxy/[fd00::10c]:559/openUrl/tok")
                .unwrap();
        assert_eq!(
            cfg.media_url(),
            "wss://example.com:6014/media?version=0.1&cipherSuites=0&sessionID=&proxy=[fd00::10c]:559"
        );
        assert_eq!(cfg.device_url(), "ws://[fd00::10c]:559/openUrl/tok");
    }

    #[test]
    fn ws_scheme_is_plain() {
        let cfg = HikConfig::from_proxy_url("ws://127.0.0.1:8080/proxy/127.0.0.1:559/openUrl/tok")
            .unwrap();
        assert!(!cfg.use_tls);
        assert_eq!(cfg.proxy_port, 8080);
        assert!(cfg.media_url().starts_with("ws://127.0.0.1:8080/media?"));
    }
}
