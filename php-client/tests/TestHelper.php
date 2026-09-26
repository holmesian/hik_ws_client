<?php

declare(strict_types=1);

namespace HikWs\Tests;

/**
 * 手写线格式构造器。
 *
 * **线格式一律手写字节，不复用实现里的构造逻辑**（testing.md 第二条）：与实现同源的
 * helper 会认同一个错误的字段布局，测试全绿而线上码流是坏的——PES 头长度那个 bug 第一版
 * 测试就是这么放过去的。下面只按 ISO/IEC 13818-1 的字段顺序拼字节，不引用实现的任何常量。
 */
final class TestHelper
{
    /** 最小 MPEG-PS pack 头：14 字节，pack_stuffing_length = 0。 */
    public static function psPack(): string
    {
        return "\x00\x00\x01\xBA" . str_repeat("\x00", 10);
    }

    /** 把 33 位 PTS 编成 5 字节 PES 时间戳字段（marker 位置位）。 */
    public static function encodePts(int $pts): string
    {
        return chr(0x20 | ((($pts >> 30) & 0x07) << 1) | 0x01)
            . chr(($pts >> 22) & 0xFF)
            . chr(((($pts >> 15) & 0x7F) << 1) | 0x01)
            . chr(($pts >> 7) & 0xFF)
            . chr((($pts & 0x7F) << 1) | 0x01);
    }

    /** 视频 PES 包（stream_id 0xE0），带标准 3 字节 MPEG-2 PES 可选头。 */
    public static function psVideoPes(string $payload, int $pts = -1): string
    {
        if ($pts >= 0) {
            $body = "\x80\x80\x05" . self::encodePts($pts) . $payload;
        } else {
            $body = "\x80\x00\x00" . $payload;
        }
        return "\x00\x00\x01\xE0" . pack('n', strlen($body)) . $body;
    }

    /** 按位拼 RBSP，用来手搓 SPS。 */
    public static function h265Sps(int $width, int $height): string
    {
        $w = new BitWriter();
        $w->putBits(0x42, 8);   // NAL 头字节 0
        $w->putBits(0x01, 8);   // NAL 头字节 1（type 33 = SPS_NUT）
        $w->putBits(0, 4);      // sps_video_parameter_set_id
        $w->putBits(0, 3);      // sps_max_sub_layers_minus1
        $w->putBits(1, 1);      // sps_temporal_id_nesting_flag
        $w->putBits(0, 2);      // general_profile_space
        $w->putBits(0, 1);      // general_tier_flag
        $w->putBits(1, 5);      // general_profile_idc
        $w->putBits(0, 32);     // general_profile_compatibility_flag
        $w->putBits(0, 48);     // general_constraint_indicator_flag
        $w->putBits(93, 8);     // general_level_idc
        $w->putUe(0);           // sps_seq_parameter_set_id
        $w->putUe(1);           // chroma_format_idc
        $w->putUe($width);      // pic_width_in_luma_samples
        $w->putUe($height);     // pic_height_in_luma_samples
        $w->putBits(1, 1);      // conformance_window_flag
        $w->putUe(0);
        $w->putUe(0);
        $w->putUe(0);
        $w->putUe(0);
        return $w->bytes();
    }

    /** 手写 5 字节协议头：1 字节类型 + 4 字节大端长度。 */
    public static function protocolMsg(int $type, string $payload): string
    {
        return chr($type) . pack('N', strlen($payload)) . $payload;
    }

    /**
     * 手写一个服务器→客户端的 WebSocket 帧（不掩码，RFC 6455 §5.2）。
     * 只支持 <126 字节净荷，够用；不复用实现的客户端帧构造器（带掩码）。
     */
    public static function wsFrame(int $opcode, string $payload, bool $fin = true): string
    {
        if (strlen($payload) >= 126) {
            throw new \InvalidArgumentException('test frames are short only');
        }
        return chr(($fin ? 0x80 : 0x00) | $opcode) . chr(strlen($payload)) . $payload;
    }
}

/** 按位拼 RBSP。 */
final class BitWriter
{
    private string $buf = '';
    private int $nbits = 0;

    public function putBits(int $value, int $n): void
    {
        for ($i = $n - 1; $i >= 0; $i--) {
            if ($this->nbits % 8 === 0) {
                $this->buf .= "\x00";
            }
            if (($value >> $i) & 1) {
                $idx = strlen($this->buf) - 1;
                $this->buf[$idx] = chr(ord($this->buf[$idx]) | (0x80 >> ($this->nbits % 8)));
            }
            $this->nbits++;
        }
    }

    public function putUe(int $v): void
    {
        $v++;
        $nbits = $v === 0 ? 1 : (int) floor(log($v, 2)) + 1;
        $this->putBits(0, $nbits - 1);
        $this->putBits($v, $nbits);
    }

    public function bytes(): string
    {
        return $this->buf;
    }
}
