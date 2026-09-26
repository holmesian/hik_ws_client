<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 海康威视私有 WebSocket 协议的封包与常量。
 *
 * 封包格式（5 字节头）：
 *
 *     1 Byte   Type            （最高位 = EncryptFlag，仅解析暴露，不解密 — ADR-0004）
 *     4 Bytes  Length (BE)
 *     N Bytes  Payload
 *
 * 一个 WebSocket 帧里可能连着多条协议消息，必须循环消费到尾，否则静默丢帧。
 *
 * 长度字段来自网络：PHP 的整数已是任意精度，`5 + length` 不会像 Go 的 uint32 那样
 * 回绕，但声明长度超过实际字节时仍必须拒绝，不能切开返回。
 */
final class Protocol
{
    public const MSG_TYPE_HELLO        = 0x01;
    public const MSG_TYPE_AUTH_REQUEST = 0x02;
    public const MSG_TYPE_AUTH_RESPONSE = 0x03;
    public const MSG_TYPE_KEY_EXCHANGE = 0x04;
    public const MSG_TYPE_SESSION_ERROR = 0x05;
    public const MSG_TYPE_KEEPALIVE    = 0x06;
    public const MSG_TYPE_REALPLAY     = 0x20;
    public const MSG_TYPE_VIDEO_DATA   = 0x40;
    public const MSG_TYPE_AUDIO_DATA   = 0x41;

    /** 类型字节的最高位；仅解析暴露，不据此解密。 */
    public const ENCRYPT_FLAG = 0x80;

    /**
     * 解出一条协议消息。
     *
     * @return array{0:?int,1:?string,2:string} [msgType, payload, remaining]
     *   数据不足 5 字节、或声明长度超过可用字节时返回 [null, null, data]。
     */
    public static function unpack(string $data): array
    {
        if (strlen($data) < 5) {
            return [null, null, $data];
        }
        $msgType = ord($data[0]);
        // 长度字段来自网络。PHP 整数在 64 位上足够宽，但这里仍显式用 unpack('N')
        // 读出 32 位无符号值，语义与 Go 的 BigEndian.Uint32 一致。
        $length = (int) unpack('N', substr($data, 1, 4))[1];
        if (strlen($data) < 5 + $length) {
            return [null, null, $data];
        }
        $payload = substr($data, 5, $length);
        $remaining = substr($data, 5 + $length);
        return [$msgType, $payload, $remaining];
    }

    /**
     * 把一段字节里串联的协议消息全部解出来，逐条产出 [msgType, payload]。
     *
     * 一个 WebSocket 帧里可以串多条协议消息，只解第一条就是静默丢帧——设备把视频和
     * 音频打包进同一帧时，丢的是整条音轨。必须消费到尾。
     *
     * 某处解不出来时，把剩下的整段作为 [null, tail] 产出后停止，由调用方按原始视频
     * 处理。$data 为空时不产出任何东西。
     *
     * @return list<array{0:?int,1:string}>
     */
    public static function iterMessages(string $data): array
    {
        $out = [];
        while ($data !== '') {
            [$msgType, $payload, $remaining] = self::unpack($data);
            if ($msgType === null) {
                $out[] = [null, $data];
                return $out;
            }
            $out[] = [$msgType, $payload];
            $data = $remaining;
        }
        return $out;
    }

    /** 用 5 字节协议头包裹载荷。 */
    public static function pack(int $msgType, string $data): string
    {
        return chr($msgType & 0xFF) . pack('N', strlen($data)) . $data;
    }
}
