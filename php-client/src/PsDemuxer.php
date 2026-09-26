<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 从海康 MPEG-PS 容器里重组视频基本流。
 *
 * 设备的单个 NAL 会被拆到多个 PES 包里（一个 PES 头可能落在某个 VPS 中间），所以原始
 * 载荷不能当 annex-b 扫起始码——既会漏掉真 NAL，又会把 PES stream_id 误当成 NAL 头。
 *
 * 一个 PS pack 正好承载一个访问单元，所以 pack 头关掉上一帧：天然一帧延迟，流结束必须
 * flush。$0xBD private_stream_1 被跳过（ADR-0004：不解析、不外露——它自带 PTS，当视频
 * 处理既会把密文拼进码流、又会取错帧时间戳）。
 *
 * 移植自 go-client/psdemux.go 与 python-client/hik_media.py。
 */
final class PsDemuxer
{
    private const PS_END_CODE     = 0xB9; // program end；容器用到的最小 ID
    private const PS_PACK_START   = 0xBA; // pack header —— 一个访问单元的起点
    private const PS_SYSTEM_START = 0xBB; // system header；PSM / PES 都在它之上
    private const PES_VIDEO_FIRST = 0xE0;
    private const PES_VIDEO_LAST  = 0xEF;

    private const START_CODE = "\x00\x00\x01";

    private string $buf = '';
    private string $au = '';
    private int $pts = 0;
    private bool $hasPts = false;
    /** 是否见过 pack 头；之前收到的是本会话没见过的残帧。 */
    private bool $synced = false;

    /**
     * 吞入一段 PS 字节，返回它完成的访问单元。
     *
     * 分片可能在任意位置切断一个 pack；剩余部分缓冲到下一次调用。缓冲最多只保留一个
     * 不完整单元（PES 包按 64KiB 长度界定），因此不会无限增长。
     *
     * @return list<PsFrame>
     */
    public function feed(string $data): array
    {
        $this->buf .= $data;
        $out = [];
        $off = 0;
        $len = strlen($this->buf);
        while ($off < $len) {
            [$n, $frame, $ok] = $this->step(substr($this->buf, $off));
            if (!$ok) {
                break;
            }
            if ($frame !== null) {
                $out[] = $frame;
            }
            $off += $n;
        }
        $this->buf = substr($this->buf, $off);
        return $out;
    }

    /**
     * 解析一个容器单元。
     *
     * @return array{0:int,1:?PsFrame,2:bool} [消费字节数, 完成的访问单元或 null, 是否继续]
     */
    private function step(string $b): array
    {
        $len = strlen($b);
        if ($len < 4) {
            return [0, null, false];
        }
        if ((ord($b[0]) | ord($b[1])) !== 0 || ord($b[2]) !== 0x01) {
            // 不在起始码上：resync，保留末尾 2 字节（可能是被截断的起始码头）。
            $idx = strpos($b, self::START_CODE);
            if ($idx !== false) {
                return [$idx, null, true];
            }
            return [$len - 2, null, true];
        }

        $sid = ord($b[3]);
        if ($sid === self::PS_PACK_START) {
            // 14 字节 pack 头 + pack_stuffing_length（第 13 字节低 3 位）。
            if ($len < 14) {
                return [0, null, false];
            }
            $n = 14 + (ord($b[13]) & 0x07);
            if ($len < $n) {
                return [0, null, false];
            }
            $f = $this->closeAu();
            $this->synced = true;
            return [$n, $f, true];
        }

        if ($sid >= self::PS_SYSTEM_START) {
            // system header / PSM / 所有 PES 都是 6 字节长度前缀形式。
            if ($len < 6) {
                return [0, null, false];
            }
            $n = 6 + (int) unpack('n', substr($b, 4, 2))[1];
            if ($len < $n) {
                return [0, null, false];
            }
            if ($sid >= self::PES_VIDEO_FIRST && $sid <= self::PES_VIDEO_LAST) {
                $this->appendPes(substr($b, 6, $n - 6));
            }
            return [$n, null, true];
        }

        // 非容器起始码（散落的 NAL 前缀）：跳过。
        return [3, null, true];
    }

    /** 流结束时释放仍缓冲的访问单元（一帧延迟是容器固有的，这里必然回收）。 */
    public function flush(): array
    {
        $f = $this->closeAu();
        return $f !== null ? [$f] : [];
    }

    private function closeAu(): ?PsFrame
    {
        if ($this->au === '') {
            return null;
        }
        $f = new PsFrame($this->au, $this->pts, $this->hasPts);
        $this->au = '';
        $this->pts = 0;
        $this->hasPts = false;
        return $f;
    }

    /**
     * 剥离 PES 头并把载荷追加到当前访问单元，从第一个携带 PTS 的 PES 取走帧 PTS。
     *
     * $b 是 6 字节起始码/长度前缀之后的字节。其后的 MPEG-2 PES 可选头是 3 字节，不是 2：
     *   b[0] '10' 标记 + scrambling/priority/alignment 标志（通常 0x80）
     *   b[1] PTS_DTS_flags（位 7-6）+ 其它标志
     *   b[2] PES_header_data_length，覆盖 b[3:3+hlen]
     * 把长度当成第 2 字节读，会把 0x80 的 PTS 标志当成 128 字节头长。
     */
    private function appendPes(string $b): void
    {
        // 直播从任意位置接入：第一个 pack 头之前的 PES 是没见过头的访问单元的尾巴，
        // 拼出来是一帧解不出的残帧，还自带 PTS 让首帧时间戳偏早，丢掉。
        if (!$this->synced) {
            return;
        }
        $len = strlen($b);
        if ($len < 3 || (ord($b[0]) & 0xC0) !== 0x80) {
            return;
        }
        $hlen = ord($b[2]);
        if ($len < 3 + $hlen) {
            return;
        }
        if ((ord($b[1]) & 0x80) !== 0 && $hlen >= 5 && !$this->hasPts) {
            $this->pts = self::readPts(substr($b, 3, 5));
            $this->hasPts = true;
        }
        $this->au .= substr($b, 3 + $hlen);
    }

    /** 从 5 字节 PES 时间戳字段解出 33 位 PTS。 */
    private static function readPts(string $b): int
    {
        return ((ord($b[0]) >> 1) & 0x07) << 30
            | ord($b[1]) << 22
            | ((ord($b[2]) >> 1) & 0x7F) << 15
            | ord($b[3]) << 7
            | (ord($b[4]) >> 1);
    }

    /**
     * b 是否以 MPEG-PS 起始码开头。接受任意 PS 起始码（>= 0xB9），不能只认 pack 头：
     * 直播从流的任意位置接入，首条消息可能落在音频 PES（0xC0）上。裸 annex-b 的 NAL
     * 头最高位恒为 0，到不了容器用的高 ID。
     */
    public static function isPsData(string $b): bool
    {
        return strlen($b) >= 4
            && $b[0] === "\x00" && $b[1] === "\x00" && $b[2] === "\x01"
            && ord($b[3]) >= self::PS_END_CODE;
    }
}

/** 一个从 PS 容器里还原出来的视频访问单元。 */
final class PsFrame
{
    public function __construct(
        public readonly string $data,
        public readonly int $pts,
        public readonly bool $hasPts,
    ) {
    }
}
