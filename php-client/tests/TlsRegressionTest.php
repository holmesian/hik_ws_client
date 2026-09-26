<?php
declare(strict_types=1);

/**
 * 传输层 TLS 回归：WebSocket::connect() 必须在一条真实 TLS 连接上完成握手。
 *
 * 为真缺陷而立：`ssl://` 包装器已在 stream_socket_client 阶段完成 TLS，旧代码却又调了一次
 * stream_socket_enable_crypto，同一 stream 上重复握手直接失败（`SSL/TLS already set-up for
 * this stream`），表现为 "TLS handshake failed"。所有单测都走 feedVideo / 协议层，没有一条
 * 真建过 TLS 连接，于是生产 wss:// 路径整条是坏的而测试全绿（testing.md 第五条）。
 *
 * 端点用子进程起一个只做 TLS 握手 + 回 101 的最小 server，证书由标准库在运行时生成，
 * 不依赖外部网络与已提交的 fixture。
 */

namespace HikWs\Tests;

final class TlsRegressionTest
{
    private static function makeCert(string $dir): array
    {
        $dn = ['commonName' => '127.0.0.1'];
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new($dn, $key, ['digest_alg' => 'sha256']);
        $crt = openssl_csr_sign($csr, null, $key, 2, ['digest_alg' => 'sha256']);
        openssl_x509_export($crt, $crtPem);
        openssl_pkey_export($key, $keyPem);
        $certFile = $dir . '/cert.pem';
        $keyFile = $dir . '/key.pem';
        file_put_contents($certFile, $crtPem);
        file_put_contents($keyFile, $keyPem);
        return [$certFile, $keyFile];
    }

    public static function register(): void
    {
        MiniTest::run('tls handshake completes on a live endpoint', function (): void {
            if (!extension_loaded('openssl')) {
                MiniTest::skip('openssl extension missing');
            }

            $dir = sys_get_temp_dir() . '/hik-tls-' . bin2hex(random_bytes(4));
            @mkdir($dir, 0700);
            [$certFile, $keyFile] = self::makeCert($dir);

            $port = self::freePort();
            $script = $dir . '/server.php';
            $serverCode = <<<'SRV'
<?php
[$_, $cert, $key, $port] = $argv;
$ctx = stream_context_create(['ssl'=>[
    'local_cert'=>$cert, 'local_pk'=>$key, 'allow_self_signed'=>true, 'verify_peer'=>false,
]]);
$srv = stream_socket_server("tls://127.0.0.1:{$port}", $errno, $errstr,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if ($srv === false) { fwrite(STDERR, "listen failed: $errstr"); exit(3); }
// 循环 accept，直到拿到一条能读到完整请求头的连接：就绪探测用的裸 TCP 连接会被这里丢弃。
$conn = false;
$deadline = microtime(true) + 10.0;
while (microtime(true) < $deadline) {
    $c = @stream_socket_accept($srv, 1.0);
    if ($c === false) { continue; }
    stream_set_timeout($c, 1);
    $peek = @fread($c, 4096);
    if ($peek === false || $peek === '') { @fclose($c); continue; }
    $conn = $c;
    // 已经读到一部分请求头，后续在主循环里继续累积。
    $pre = $peek;
    break;
}
if ($conn === false) { exit(4); }
stream_set_timeout($conn, 5);
// 读到请求头结尾，回一个 101（WebSocket 握手判成功即可）
$buf = $pre ?? '';
while (!str_contains($buf, "\r\n\r\n")) {
    $chunk = fread($conn, 4096);
    if ($chunk === false || $chunk === '') break;
    $buf .= $chunk;
}
$key = '';
foreach (explode("\r\n", $buf) as $line) {
    if (stripos($line, 'sec-websocket-key:') === 0) { $key = trim(substr($line, 18)); }
}
$accept = base64_encode(sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
fwrite($conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    . "Sec-WebSocket-Accept: {$accept}\r\nSec-WebSocket-Protocol: v1.0.0\r\n\r\n");
fflush($conn);
usleep(300000);
exit(0);
SRV;
            file_put_contents($script, $serverCode);

            $cmd = sprintf(
                '%s %s %s %s %d',
                escapeshellarg(PHP_BINARY),
                escapeshellarg($script),
                escapeshellarg($certFile),
                escapeshellarg($keyFile),
                $port
            );
            $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            if (!is_resource($proc)) {
                self::cleanup($dir);
                MiniTest::skip('cannot spawn TLS endpoint');
            }

            try {
                // 等端点就绪
                $ready = false;
                for ($i = 0; $i < 100; $i++) {
                    $probe = @stream_socket_client("tcp://127.0.0.1:{$port}", $e, $es, 0.2);
                    if ($probe !== false) { fclose($probe); $ready = true; break; }
                    usleep(50000);
                }
                MiniTest::assertTrue($ready, 'TLS endpoint 未就绪');

                $ws = new \HikWs\WebSocket('127.0.0.1', $port, '/media?x=1', 'v1.0.0', 5.0, true);
                $err = null;
                try {
                    $ws->connect();
                    $ws->close();
                } catch (\Throwable $e) {
                    $err = $e;
                }
                MiniTest::assertTrue(
                    $err === null,
                    'connect() 在真实 TLS 端点上不应失败，实际：' . ($err ? $err->getMessage() : '')
                );
            } finally {
                @proc_terminate($proc);
                foreach ($pipes as $p) { if (is_resource($p)) @fclose($p); }
                @proc_close($proc);
                self::cleanup($dir);
            }
        });
    }

    private static function cleanup(string $dir): void
    {
        foreach (glob($dir . '/*') ?: [] as $f) { @unlink($f); }
        @rmdir($dir);
    }

    private static function freePort(): int
    {
        $s = stream_socket_server('tcp://127.0.0.1:0', $e, $es);
        $name = stream_socket_get_name($s, false);
        fclose($s);
        return (int) substr($name, strrpos($name, ':') + 1);
    }
}
