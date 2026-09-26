<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 极简 WebSocket 客户端（RFC 6455），仅覆盖本协议所需：
 *  - 客户端握手（HTTP Upgrade，子协议 v1.0.0）；
 *  - 客户端帧掩码（必须掩码）；
 *  - 服务端下行帧不掩码，支持分片重组与 16/64 位长度。
 *
 * 只依赖标准库的 stream_socket_client / stream_select。TLS 用 stream 的 ssl 包装，
 * 默认不校验证书（代理多为自签或内网），与 go-client 的 InsecureSkipVerify 一致。
 */
final class WebSocket
{
    public const OP_CONT = 0x00;
    public const OP_TEXT = 0x01;
    public const OP_BINARY = 0x02;
    public const OP_CLOSE = 0x08;
    public const OP_PING = 0x09;
    public const OP_PONG = 0x0A;

    private const READ_CHUNK = 8192;

    /** @var resource|null */
    private $sock = null;
    private string $buffer = '';

    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $path,
        private readonly string $protocol = 'v1.0.0',
        private readonly float $connectTimeout = 10.0,
        private readonly bool $tls = true,
    ) {
    }

    public function isConnected(): bool
    {
        return $this->sock !== null;
    }

    /**
     * 建立 TCP/TLS 连接并完成 WebSocket 握手。
     */
    public function connect(): void
    {
        $scheme = $this->tls ? 'ssl' : 'tcp';
        $hostPort = $this->tls
            ? "ssl://{$this->host}:{$this->port}"
            : "tcp://{$this->host}:{$this->port}";
        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
                'SNI_enabled' => true,
            ],
        ]);
        $sock = @stream_socket_client(
            $hostPort,
            $errno,
            $errstr,
            $this->connectTimeout,
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        if ($sock === false) {
            throw new \RuntimeException("websocket dial error: {$errstr} ({$errno})");
        }
        stream_set_blocking($sock, true);
        $this->sock = $sock;
        $this->buffer = '';

        if ($this->tls) {
            // `ssl://` 包装器已在 stream_socket_client 阶段完成 TLS 握手，这里**不能**再调
            // stream_socket_enable_crypto —— 同一个 stream 上重复握手会直接失败
            // （`SSL/TLS already set-up for this stream`），调用方看到的是"TLS handshake failed"，
            // 但拨号本身其实是成功的。与 python-client 的 asyncio.open_connection(ssl=...) 等价：
            // TLS 只建立一次。
            stream_set_timeout($sock, (int) $this->connectTimeout);
        }

        $this->handshake();
    }

    private function handshake(): void
    {
        $key = base64_encode(random_bytes(16));
        $req = "GET {$this->path} HTTP/1.1\r\n"
            . "Host: {$this->host}:{$this->port}\r\n"
            . "Upgrade: websocket\r\n"
            . "Connection: Upgrade\r\n"
            . "Sec-WebSocket-Key: {$key}\r\n"
            . "Sec-WebSocket-Version: 13\r\n"
            . "Sec-WebSocket-Protocol: {$this->protocol}\r\n"
            . "\r\n";
        $this->writeRaw($req);

        // 读 HTTP 响应头（以 \r\n\r\n 结束）。
        $header = '';
        $deadline = microtime(true) + $this->connectTimeout;
        while (($pos = strpos($header, "\r\n\r\n")) === false) {
            if (microtime(true) > $deadline) {
                $this->close();
                throw new \RuntimeException('websocket handshake timeout');
            }
            $chunk = $this->readRawChunk($deadline);
            if ($chunk === '' && feof($this->sock)) {
                $this->close();
                throw new \RuntimeException('connection closed during handshake');
            }
            $header .= $chunk;
        }

        $head = substr($header, 0, $pos);
        $this->buffer = substr($header, $pos + 4);  // 响应后可能已带帧
        $lines = explode("\r\n", $head);
        $statusLine = $lines[0] ?? '';
        if (!preg_match('#^HTTP/1\.[01]\s+101#', $statusLine)) {
            $this->close();
            throw new \RuntimeException("websocket upgrade failed: {$statusLine}");
        }
        $expected = base64_encode(sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
        $accept = '';
        foreach (array_slice($lines, 1) as $line) {
            if (stripos($line, 'sec-websocket-accept:') === 0) {
                $accept = trim(substr($line, strlen('sec-websocket-accept:')));
            }
        }
        if ($accept !== '' && !hash_equals($expected, $accept)) {
            $this->close();
            throw new \RuntimeException('invalid Sec-WebSocket-Accept');
        }
    }

    /**
     * 读一条完整消息。返回 [opcode, payload]，连接关闭时抛 RuntimeException。
     *
     * @return array{0:int,1:string}
     */
    public function readMessage(?float $deadline = null): array
    {
        $fragments = '';
        $fragOp = null;
        while (true) {
            $frame = $this->readFrame($deadline);
            if ($frame === null) {
                throw new \RuntimeException('connection closed');
            }
            [$fin, $opcode, $payload] = $frame;

            if ($opcode === self::OP_PING) {
                $this->writeFrame(self::OP_PONG, $payload);
                continue;
            }
            if ($opcode === self::OP_PONG) {
                continue;
            }
            if ($opcode === self::OP_CLOSE) {
                $this->close();
                throw new \RuntimeException('connection closed by peer');
            }

            if ($opcode === self::OP_BINARY || $opcode === self::OP_TEXT) {
                if ($fin) {
                    return [$opcode, $payload];
                }
                $fragOp = $opcode;
                $fragments = $payload;
                continue;
            }

            if ($opcode === self::OP_CONT) {
                $fragments .= $payload;
                if ($fin) {
                    return [$fragOp ?? self::OP_BINARY, $fragments];
                }
                continue;
            }

            // 未知 opcode：忽略该帧。
        }
    }

    /**
     * @return array{0:bool,1:int,2:string}|null [fin, opcode, payload]，无数据时 null
     */
    private function readFrame(?float $deadline): ?array
    {
        $head = $this->readBytes(2, $deadline);
        if ($head === null) {
            return null;
        }
        $b0 = ord($head[0]);
        $b1 = ord($head[1]);
        $fin = ($b0 & 0x80) !== 0;
        $opcode = $b0 & 0x0F;
        $masked = ($b1 & 0x80) !== 0;
        $len = $b1 & 0x7F;
        if ($len === 126) {
            $ext = $this->readBytes(2, $deadline);
            if ($ext === null) {
                return null;
            }
            $len = (int) unpack('n', $ext)[1];
        } elseif ($len === 127) {
            $ext = $this->readBytes(8, $deadline);
            if ($ext === null) {
                return null;
            }
            // 64 位长度；RFC 6455 要求最高位为 0。
            $parts = unpack('N2', $ext);
            $len = ($parts[1] << 32) | $parts[2];
        }
        $mask = '';
        if ($masked) {
            $mask = $this->readBytes(4, $deadline);
            if ($mask === null) {
                return null;
            }
        }
        $payload = $len > 0 ? $this->readBytes($len, $deadline) : '';
        if ($payload === null) {
            return null;
        }
        if ($masked) {
            $payload = self::applyMask($payload, $mask);
        }
        return [$fin, $opcode, $payload];
    }

    private function readBytes(int $n, ?float $deadline): ?string
    {
        while (strlen($this->buffer) < $n) {
            if (microtime(true) > ($deadline ?? PHP_FLOAT_MAX)) {
                throw new \RuntimeException('read timeout');
            }
            $chunk = $this->readRawChunk($deadline);
            if ($chunk === '') {
                if (feof($this->sock)) {
                    return null;
                }
                continue;
            }
            $this->buffer .= $chunk;
        }
        $out = substr($this->buffer, 0, $n);
        $this->buffer = substr($this->buffer, $n);
        return $out;
    }

    /** 写一条消息（客户端帧必须掩码）。 */
    public function writeMessage(int $opcode, string $payload): void
    {
        $this->writeFrame($opcode, $payload);
    }

    private function writeFrame(int $opcode, string $payload): void
    {
        $len = strlen($payload);
        $header = chr(0x80 | ($opcode & 0x0F));
        if ($len < 126) {
            $header .= chr(0x80 | $len);
        } elseif ($len <= 0xFFFF) {
            $header .= chr(0x80 | 126) . pack('n', $len);
        } else {
            $header .= chr(0x80 | 127) . pack('N2', 0, $len);
        }
        $mask = random_bytes(4);
        $header .= $mask;
        $this->writeRaw($header . self::applyMask($payload, $mask));
    }

    public function close(): void
    {
        if ($this->sock !== null) {
            @fclose($this->sock);
            $this->sock = null;
        }
    }

    private static function applyMask(string $payload, string $mask): string
    {
        $len = strlen($payload);
        $out = $payload;
        for ($i = 0; $i < $len; $i++) {
            $out[$i] = chr(ord($payload[$i]) ^ ord($mask[$i & 3]));
        }
        return $out;
    }

    private function readRawChunk(?float $deadline): string
    {
        if ($this->sock === null) {
            return '';
        }
        $remaining = $deadline !== null ? max(0.0, $deadline - microtime(true)) : null;
        $sec = $remaining !== null ? (int) floor($remaining) : 0;
        $usec = $remaining !== null ? (int) (($remaining - $sec) * 1e6) : 0;
        stream_set_timeout($this->sock, $sec, $usec);
        $read = [$this->sock];
        $write = null;
        $except = null;
        $ready = @stream_select($read, $write, $except, $sec, $usec);
        if ($ready === false) {
            throw new \RuntimeException('stream_select failed');
        }
        if ($ready === 0) {
            // 超时：返回空串交给调用方判断 deadline/EOF。
            return '';
        }
        $chunk = @fread($this->sock, self::READ_CHUNK);
        return $chunk === false ? '' : $chunk;
    }

    private function writeRaw(string $data): void
    {
        if ($this->sock === null) {
            throw new \RuntimeException('not connected');
        }
        $off = 0;
        $len = strlen($data);
        while ($off < $len) {
            $written = @fwrite($this->sock, substr($data, $off));
            if ($written === false || $written === 0) {
                throw new \RuntimeException('socket write failed');
            }
            $off += $written;
        }
    }
}
