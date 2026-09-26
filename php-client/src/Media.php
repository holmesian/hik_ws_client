<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 编码嗅探与关键帧判定。移植自 go-client/media.go 的 sniffCodec / AnalyzeFrame。
 */
final class Media
{
    private const START_CODE = "\x00\x00\x01";

    /**
     * 从 annex-b 访问单元的 NAL 头推断编码，用于 MEDIAINFO 头解不出来的流。
     *
     * 用参数集判定（两台编码的 NAL 头两种读法不会撞）：H.265 的 VPS/SPS/PPS 是 layer 0 的
     * 32/33/34 型，首字节读 0x40/0x42/0x44；H.264 的 SPS 是 type 7 且 ref_idc 非 0，读
     * 0x27/0x47/0x67。两者都每关键帧前重发，所以总能命中。返回 "" 表示无结论。
     */
    public static function sniffCodec(string $data): string
    {
        $i = 0;
        $len = strlen($data);
        while ($i < $len) {
            $idx = strpos($data, self::START_CODE, $i);
            if ($idx === false) {
                break;
            }
            $nalPos = $idx + 3;
            if ($nalPos >= $len) {
                break;
            }
            $b = ord($data[$nalPos]);
            if ($b === 0x40 || $b === 0x42 || $b === 0x44) {
                return 'H265';
            }
            if (($b & 0x9F) === 7 && ($b & 0x60) !== 0) {
                return 'H264';
            }
            $i = $nalPos + 1;
        }
        return '';
    }

    /**
     * 扫描 annex-b 帧是否含关键帧 NAL。codec 用于消歧（H.264/H.265 NAL 类型重叠）。
     */
    public static function analyzeFrame(string $data, string $codec): bool
    {
        $isH265 = $codec === 'H265';
        $i = 0;
        $len = strlen($data);
        while ($i < $len) {
            $idx = strpos($data, self::START_CODE, $i);
            if ($idx === false) {
                break;
            }
            $nalPos = $idx + 3;
            if ($nalPos >= $len) {
                break;
            }
            $b = ord($data[$nalPos]);
            if ($isH265) {
                $t = ($b >> 1) & 0x3F;
                if ($t >= 16 && $t <= 21) {  // IRAP
                    return true;
                }
            } elseif (($b & 0x1F) === 5) {  // H.264 IDR
                return true;
            }
            $i = $nalPos + 1;
        }
        return false;
    }
}
