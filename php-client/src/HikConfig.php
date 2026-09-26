<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 连接配置。对齐 go-client 的 HikConfig。
 */
final class HikConfig
{
    public string $proxyHost = '';
    public int $proxyPort = 443;
    public string $proxyPath = '';
    public string $deviceIp = '';
    public int $devicePort = 554;
    public string $username = 'admin';
    public string $password = '';
    public string $version = '0.1';
    public int $cipherSuites = 0;

    /** 逐帧调试日志。生产保持 false——每帧一行日志会主导 I/O 与分配。 */
    public bool $verbose = false;

    /** 传输失败后额外重试次数（掉线、停滞、拨号失败）。0 表示不重连。 */
    public int $maxReconnects = 0;

    /** 重试退避基数（秒）；第 N 次重试等 N * reconnectWait。 */
    public float $reconnectWait = 2.0;

    /** 此窗口内没有任何消息则中止会话（秒）。0 关闭看门狗。 */
    public float $stallTimeout = 0.0;

    public static function fromProxyUrl(string $proxyUrl): self
    {
        $cfg = new self();
        $parts = parse_url($proxyUrl);
        if ($parts === false || !isset($parts['host'])) {
            throw new \InvalidArgumentException("invalid proxy url: {$proxyUrl}");
        }
        $cfg->proxyHost = $parts['host'];
        $cfg->proxyPort = $parts['port'] ?? 443;

        $path = trim($parts['path'] ?? '', '/');
        $pathParts = $path === '' ? [] : explode('/', $path);
        if (count($pathParts) < 2 || $pathParts[0] !== 'proxy') {
            throw new \InvalidArgumentException('invalid proxy path structure');
        }

        $deviceInfo = $pathParts[1];
        $deviceIp = $deviceInfo;
        $devicePort = 554;

        if (str_contains($deviceInfo, ']:')) {
            // IPv6 带端口：[::1]:559
            [$ip, $port] = explode(']:', substr($deviceInfo, 1), 2);
            $deviceIp = '[' . $ip . ']';
            $devicePort = (int) $port;
        } elseif (substr_count($deviceInfo, ':') === 1) {
            // IPv4 带端口：1.2.3.4:80
            [$ip, $port] = explode(':', $deviceInfo, 2);
            $deviceIp = $ip;
            $devicePort = (int) $port;
        }

        $cfg->deviceIp = $deviceIp;
        $cfg->devicePort = $devicePort;
        $cfg->proxyPath = '/proxy/' . $deviceInfo;

        if (count($pathParts) > 3 && $pathParts[2] === 'openUrl') {
            $authPart = $pathParts[3];
            $decoded = base64_decode($authPart, true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                [$u, $p] = explode(':', $decoded, 2);
                $cfg->username = $u;
                $cfg->password = $p;
            } elseif ($decoded !== false) {
                $cfg->password = $decoded;
            } else {
                $cfg->password = $authPart;
            }
        }

        return $cfg;
    }
}
