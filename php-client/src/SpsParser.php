<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 从码流内 SPS 还原分辨率。移植自 go-client/media.go 与 python-client/hik_media.py。
 *
 * MEDIAINFO 头从不携带分辨率，所以分辨率只能从码流内 SPS 还原。两条真机教训：
 *  - SPS 解析前先剥防竞争字节（EPB），否则 1280x720 会解成 2x1；
 *  - H.264 的 scaling_list() 可提前终止，按固定长度读 se(v) 会越过 NAL 尾，High profile
 *    设备分辨率恒为 0x0。
 */
final class SpsParser
{
    private const START_CODE = "\x00\x00\x01";

    /**
     * 去掉 NAL 的防竞争字节：00 00 之后紧跟的 0x03 是转义，必须丢。
     *
     * 编码器只会在 00 00 之后插入 03，所以该位置的 03 一定是 EPB，不是真实数据。
     */
    public static function stripEmulationPrevention(string $b): string
    {
        $len = strlen($b);
        if ($len < 3) {
            return $b;
        }
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $x = ord($b[$i]);
            if ($i >= 2 && $x === 3 && ord($b[$i - 1]) === 0 && ord($b[$i - 2]) === 0) {
                continue;
            }
            $out .= $b[$i];
        }
        return $out;
    }

    /**
     * 从 H.264 SPS NAL（含 1 字节 NAL 头）解出宽高。
     *
     * @return array{0:int,1:int} [width, height]
     */
    public static function parseH264Sps(string $raw): array
    {
        if (strlen($raw) < 2) {
            throw new \ValueError('sps too short');
        }
        $br = new BitReader(self::stripEmulationPrevention(substr($raw, 1)));

        $profileIdc = $br->readBits(8);
        $br->readBits(8);   // constraint flags + reserved
        $br->readBits(8);   // level_idc
        $br->readUe();      // seq_parameter_set_id

        $chromaFormatIdc = 1;
        if (in_array($profileIdc, [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135], true)) {
            $chromaFormatIdc = $br->readUe();
            if ($chromaFormatIdc === 3) {
                $br->readBit();  // separate_colour_plane_flag
            }
            $br->readUe();       // bit_depth_luma_minus8
            $br->readUe();       // bit_depth_chroma_minus8
            $br->readBit();      // qpprime_y_zero_transform_bypass_flag
            if ($br->readBit() === 1) {  // seq_scaling_matrix_present_flag
                $count = $chromaFormatIdc === 3 ? 12 : 8;
                for ($i = 0; $i < $count; $i++) {
                    if ($br->readBit() === 1) {  // scaling_list_present
                        $size = $i >= 6 ? 64 : 16;
                        self::skipScalingList($br, $size);
                    }
                }
            }
        }

        $br->readUe();       // log2_max_frame_num_minus4
        $pocType = $br->readUe();
        if ($pocType === 0) {
            $br->readUe();   // log2_max_pic_order_cnt_lsb_minus4
        } elseif ($pocType === 1) {
            $br->readBit();  // delta_pic_order_always_zero_flag
            $br->readSe();   // offset_for_non_ref_pic
            $br->readSe();   // offset_for_top_to_bottom_field
            $num = $br->readUe();
            for ($i = 0; $i < $num; $i++) {
                $br->readSe();
            }
        }

        $br->readUe();       // max_num_ref_frames
        $br->readBit();      // gaps_in_frame_num_value_allowed_flag
        $picWidthMbsMinus1 = $br->readUe();
        $picHeightMapUnitsMinus1 = $br->readUe();
        $frameMbsOnlyFlag = $br->readBit();
        if ($frameMbsOnlyFlag === 0) {
            $br->readBit();  // mb_adaptive_frame_field_flag
        }
        $br->readBit();      // direct_8x8_inference_flag

        $cropL = $cropR = $cropT = $cropB = 0;
        if ($br->readBit() === 1) {  // frame_cropping_flag
            $cropL = $br->readUe();
            $cropR = $br->readUe();
            $cropT = $br->readUe();
            $cropB = $br->readUe();
        }

        $width = ($picWidthMbsMinus1 + 1) * 16;
        $height = (2 - $frameMbsOnlyFlag) * ($picHeightMapUnitsMinus1 + 1) * 16;
        $subWc = $subHc = 1;
        if ($chromaFormatIdc === 1) {
            $subWc = 2;
            $subHc = 2;
        } elseif ($chromaFormatIdc === 2) {
            $subWc = 2;
            $subHc = 1;
        }
        $width -= ($cropL + $cropR) * $subWc;
        $height -= ($cropT + $cropB) * $subHc;
        if (!($width > 0 && $width <= 8192 && $height > 0 && $height <= 8192)) {
            throw new \ValueError("implausible dimensions {$width}x{$height}");
        }
        return [$width, $height];
    }

    /**
     * 从 H.265 (HEVC) SPS NAL（含 2 字节 NAL 头）解出宽高。
     *
     * @return array{0:int,1:int}
     */
    public static function parseH265Sps(string $raw): array
    {
        if (strlen($raw) < 3) {
            throw new \ValueError('h265 sps too short');
        }
        $br = new BitReader(self::stripEmulationPrevention(substr($raw, 2)));

        $br->readBits(4);  // sps_video_parameter_set_id
        $maxSubLayersMinus1 = $br->readBits(3);
        $br->readBit();    // sps_temporal_id_nesting_flag

        $br->readBits(8);    // profile_space + tier + profile_idc
        $br->readBits(32);   // profile_compatibility_flag
        $br->readBits(48);   // constraint_indicator
        $br->readBits(8);    // general_level_idc
        if ($maxSubLayersMinus1 > 0) {
            $subProfile = 0;
            $subLevel = 0;
            for ($i = 0; $i < $maxSubLayersMinus1; $i++) {
                $subProfile = ($subProfile << 1) | $br->readBit();
                $subLevel = ($subLevel << 1) | $br->readBit();
            }
            $br->readBits(2 * (8 - $maxSubLayersMinus1));
            for ($i = 0; $i < $maxSubLayersMinus1; $i++) {
                if (($subProfile >> ($maxSubLayersMinus1 - 1 - $i)) & 1) {
                    $br->readBits(8 + 32 + 48 + 8);
                }
                if (($subLevel >> ($maxSubLayersMinus1 - 1 - $i)) & 1) {
                    $br->readBits(8);
                }
            }
        }

        $br->readUe();       // sps_seq_parameter_set_id
        $chromaFormatIdc = $br->readUe();
        if ($chromaFormatIdc === 3) {
            $br->readBit();  // separate_colour_plane_flag
        }
        $picWidth = $br->readUe();
        $picHeight = $br->readUe();
        $cropL = $cropR = $cropT = $cropB = 0;
        if ($br->readBit() === 1) {  // conf_win_flag
            $cropL = $br->readUe();
            $cropR = $br->readUe();
            $cropT = $br->readUe();
            $cropB = $br->readUe();
        }

        $subWc = $subHc = 1;
        if ($chromaFormatIdc === 1) {
            $subWc = 2;
            $subHc = 2;
        } elseif ($chromaFormatIdc === 2) {
            $subWc = 2;
            $subHc = 1;
        }
        $width = $picWidth - ($cropL + $cropR) * $subWc;
        $height = $picHeight - ($cropT + $cropB) * $subHc;
        if (!($width > 0 && $width <= 8192 && $height > 0 && $height <= 8192)) {
            throw new \ValueError("implausible h265 dimensions {$width}x{$height}");
        }
        return [$width, $height];
    }

    /**
     * 按规范消耗一个 scaling_list()：表提前终止时不能按固定长度读 se(v)。
     *
     * H.264 7.3.2.1.1.1 只在 nextScale 非 0 时读 delta_scale，遇到 0 即提前结束，剩余表项
     * 是推断出来的、不编码。
     */
    private static function skipScalingList(BitReader $br, int $size): void
    {
        $lastScale = 8;
        $nextScale = 8;
        for ($i = 0; $i < $size; $i++) {
            if ($nextScale !== 0) {
                $delta = $br->readSe();
                $nextScale = ($lastScale + $delta + 256) % 256;
            }
            if ($nextScale !== 0) {
                $lastScale = $nextScale;
            }
        }
    }

    /**
     * 在 annex-b 基本流（一个访问单元）里扫 SPS 并解出宽高。
     *
     * @return array{0:int,1:int,2:?string,3:bool} [width, height, sps(含起始码的整段 NAL), ok]
     */
    public static function recoverResolution(string $data, string $codec): array
    {
        if ($codec === '') {
            return [0, 0, null, false];
        }
        $isH265 = $codec === 'H265';
        $spsType = $isH265 ? 33 : 7;
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
            $ntype = $isH265 ? (($b >> 1) & 0x3F) : ($b & 0x1F);
            if ($ntype === $spsType) {
                $end = $len;
                $nxt = strpos($data, self::START_CODE, $nalPos);
                if ($nxt !== false) {
                    $end = $nxt;
                    if ($end > $nalPos && $data[$end - 1] === "\x00") {  // 4 字节起始码留了个尾零
                        $end--;
                    }
                }
                $sps = substr($data, $idx, $end - $idx);
                try {
                    if ($isH265) {
                        [$w, $h] = self::parseH265Sps(substr($sps, 3));
                    } else {
                        [$w, $h] = self::parseH264Sps(substr($sps, 3));
                    }
                } catch (\ValueError | \RuntimeException) {
                    return [0, 0, null, false];
                }
                return [$w, $h, $sps, true];
            }
            $i = $nalPos + 1;
        }
        return [0, 0, null, false];
    }
}

/**
 * SPS 位解析用的极简大端位读取器。
 */
final class BitReader
{
    private string $data;
    private int $pos = 0;

    public function __construct(string $data)
    {
        $this->data = $data;
    }

    public function readBit(): int
    {
        $byteIdx = $this->pos >> 3;
        if ($byteIdx >= strlen($this->data)) {
            throw new \RuntimeException('sps truncated');
        }
        $bit = (ord($this->data[$byteIdx]) >> (7 - ($this->pos & 7))) & 1;
        $this->pos++;
        return $bit;
    }

    public function readBits(int $n): int
    {
        $v = 0;
        for ($i = 0; $i < $n; $i++) {
            $v = ($v << 1) | $this->readBit();
        }
        return $v;
    }

    public function readUe(): int
    {
        $leading = 0;
        while ($this->readBit() === 0) {
            $leading++;
            if ($leading > 31) {
                throw new \ValueError('ue(v) too long');
            }
        }
        if ($leading === 0) {
            return 0;
        }
        return (1 << $leading) - 1 + $this->readBits($leading);
    }

    public function readSe(): int
    {
        $ue = $this->readUe();
        if ($ue % 2 === 0) {
            return -intdiv($ue + 1, 2);
        }
        return intdiv($ue + 1, 2);
    }
}
