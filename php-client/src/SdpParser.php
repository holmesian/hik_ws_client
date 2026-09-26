<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 从 realplay 返回的 SDP 解出 MediaInfo。移植自 go-client/media.go 与 python-client/hik_media.py。
 *
 * SDP 只是提示（ADR-0002）：MEDIAINFO 头的 magic 不一定是 IMKH（有设备发 HVAG，字段布局
 * 不同），且该头从不携带分辨率；有设备在 video m-line 上写 a=rtpmap:8 PCMA/8000，照抄会把
 * 25fps 算成 2.22fps。PS 时钟恒为 90kHz。
 */
final class SdpParser
{
    public static function parse(string $sdp): MediaInfo
    {
        $info = new MediaInfo($sdp);
        $mediaHeader = '';
        foreach (explode("\n", $sdp) as $line) {
            $line = trim($line);
            if (str_starts_with($line, 'a=Media_header:MEDIAINFO=')) {
                $mediaHeader = rtrim(substr($line, strlen('a=Media_header:MEDIAINFO=')), ';');
            } elseif (str_starts_with($line, 'a=rtpmap:')) {
                // a=rtpmap:96 H264/90000 —— 相机也发 a=rtpmap:0 /0，不命名编码。
                $fields = preg_split('/\s+/', $line, 2);
                if (count($fields) !== 2) {
                    continue;
                }
                $parts = explode('/', $fields[1], 2);
                if ($parts[0] !== '') {
                    $info->codec = strtoupper($parts[0]);
                }
                if (count($parts) === 2) {
                    $rate = $parts[1];
                    if ($rate !== '' && ctype_digit($rate)) {
                        $info->clockRate = (int) $rate;
                    }
                }
            } elseif (str_starts_with($line, 'a=fmtp:')) {
                $idx = strpos($line, 'sprop-parameter-sets=');
                if ($idx === false) {
                    continue;
                }
                $rest = substr($line, $idx + strlen('sprop-parameter-sets='));
                if (($semi = strpos($rest, ';')) !== false) {
                    $rest = substr($rest, 0, $semi);
                }
                foreach (explode(',', $rest) as $ps) {
                    $ps = trim($ps);
                    if ($ps !== '') {
                        $info->parameterSets[] = $ps;
                    }
                }
                if ($info->codec === 'H264' && count($info->parameterSets) > 0) {
                    $raw = base64_decode($info->parameterSets[0], true);
                    if ($raw !== false) {
                        try {
                            [$w, $h] = SpsParser::parseH264Sps($raw);
                            $info->width = $w;
                            $info->height = $h;
                        } catch (\ValueError | \RuntimeException) {
                            // 解析失败保持 0；由码流内 SPS 兜底
                        }
                    }
                }
            }
        }

        self::applyMediaHeader($info, $mediaHeader);
        if ($info->container === 'PS') {
            // PS 时间戳恒为 90kHz，与 rtpmap 无关。
            $info->clockRate = 90000;
        }
        return $info;
    }

    /**
     * 解码 40 字节 IMKH 头（a=Media_header:MEDIAINFO=<hex> 的负载）。
     *
     * 只取容器与编码字段；头不带分辨率。magic 不是 IMKH（如 HVAG）则整段留空，由码流嗅探
     * 兜底——这正是线上有一整类设备解不出来的原因。
     */
    private static function applyMediaHeader(MediaInfo $info, string $hexStr): void
    {
        $hexStr = trim($hexStr);
        if ($hexStr === '' || strlen($hexStr) % 2 !== 0 || !ctype_xdigit($hexStr)) {
            return;
        }
        $raw = hex2bin($hexStr);
        if ($raw === false || strlen($raw) < 12 || substr($raw, 0, 4) !== 'IMKH') {
            return;
        }
        $c = [ord($raw[8]), ord($raw[9])];
        if ($c === [2, 0]) {
            $info->container = 'PS';
        } elseif ($c === [1, 0]) {
            $info->container = 'HIK';
        } elseif ($c === [4, 0]) {
            $info->container = 'RTP';
        } elseif ($c === [8, 0]) {
            $info->container = 'GB';
        } elseif ($c === [16, 0]) {
            $info->container = 'RAW';
        }
        $cc = [ord($raw[10]), ord($raw[11])];
        if ($cc === [1, 0] || $cc === [0, 1]) {
            $info->codec = 'H264';
        } elseif ($cc === [5, 0]) {
            $info->codec = 'H265';
        }
    }
}
