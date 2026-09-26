<?php

declare(strict_types=1);

namespace HikWs;

/**
 * RTP 二次封装的检测与剥离。
 *
 * 部分代理把容器塞进 RTP 而非裸传：一个 WebSocket 消息承载一个 RTP 包，携带一段
 * MPEG-PS 流的分片。封装的两部分都必须剥离：12 字节固定头 + CSRC 列表 + 可选扩展，
 * 以及 P 位置位时由最后一个字节计数的尾部填充。
 *
 * 判定必须会话级、跨消息互证：裸 MPEG-PS 流只有第一帧以 pack 头开头，其后每条消息
 * 都是容器中间的任意字节续传，而任意字节有 1/4 概率高两位是 0b10——一个完全合法的
 * RTP 版本字段。逐条判定会从裸 PS 部署的四分之一消息里切掉 12 字节头（实测 39/39
 * 台采集损坏，而帧数、关键帧数、分辨率全对）。
 *
 * 移植自 go-client/rtp.go 与 python-client/hik_media.py 的 RTPDetector。
 */
final class RtpDetector
{
    private const FIXED_HEADER = 12;
    /** 在前几条消息里找一对互证的 RTP 包。 */
    private const PROBE_MESSAGES = 4;

    private bool $decided = false;
    private bool $isRtp = false;
    /** @var list<string> */
    private array $held = [];

    /**
     * 返回已就绪可处理的载荷：held 期间无，判定后一次性全部返回。
     *
     * @return list<string>
     */
    public function feed(string $b): array
    {
        if ($this->decided) {
            return [$this->apply($b)];
        }
        if (count($this->held) === 0 && !self::headerPlausible($b)) {
            // 第一条消息不可能是 RTP —— 常见情形：裸 PS 以 00 开头。
            $this->decided = true;
            return [$b];
        }
        $this->held[] = $b;
        $this->isRtp = self::pairFound($this->held);
        if (!$this->isRtp && count($this->held) < self::PROBE_MESSAGES) {
            return [];
        }
        $this->decided = true;
        return $this->release();
    }

    /** 会话结束、尚未定案前释放持有的消息；没有确认对就按非 RTP 处理。 */
    public function flush(): array
    {
        if (count($this->held) === 0) {
            return [];
        }
        $this->decided = true;
        return $this->release();
    }

    public function isRtp(): bool
    {
        return $this->isRtp;
    }

    /** @return list<string> */
    private function release(): array
    {
        $out = [];
        foreach ($this->held as $h) {
            $out[] = $this->apply($h);
        }
        $this->held = [];
        return $out;
    }

    private function apply(string $b): string
    {
        return $this->isRtp ? self::strip($b) : $b;
    }

    /**
     * 剥离一个 RTP 包的固定头 + CSRC + 扩展头 + 尾部 padding。
     *
     * 只剥离没副作用：当且仅当确认是 RTP 会话时才调用本函数。任一处不足则返回原样
     * （说明这根本不是 RTP，由调用方回退到裸 PS/裸 annex-b，不会被误剥）。
     */
    public static function strip(string $b): string
    {
        $len = strlen($b);
        if ($len < self::FIXED_HEADER || (ord($b[0]) >> 6) !== 2) {
            return $b;
        }
        $n = self::FIXED_HEADER + 4 * (ord($b[0]) & 0x0F); // CSRC 列表
        if ((ord($b[0]) & 0x10) !== 0) {                    // 扩展头：2 字节 profile + 2 字节（以字为单位）长度
            if ($len < $n + 4) {
                return $b;
            }
            $n += 4 + 4 * (int) unpack('n', substr($b, $n + 2, 2))[1];
        }
        if ($n >= $len) {
            return $b;
        }
        $p = substr($b, $n);
        if ((ord($b[0]) & 0x20) !== 0) { // padding，由最后一个字节计数且含自身
            $pad = ord($p[strlen($p) - 1]);
            if ($pad === 0 || $pad > strlen($p)) {
                return $b;
            }
            $p = substr($p, 0, strlen($p) - $pad);
        }
        return $p;
    }

    /** b 是否可能是一个 RTP 包（只看版本字段 0b10）。 */
    public static function headerPlausible(string $b): bool
    {
        return strlen($b) >= self::FIXED_HEADER && (ord($b[0]) >> 6) === 2;
    }

    /**
     * held 消息里是否含有同一路 RTP 的两个包。落在包中段的消息（首字节不是 RTP 头）
     * 直接跳过，所以只需要较早的那条是包起点——一对不要求相邻。
     *
     * @param list<string> $msgs
     */
    public static function pairFound(array $msgs): bool
    {
        $count = count($msgs);
        for ($i = 0; $i < $count; $i++) {
            if (!self::headerPlausible($msgs[$i])) {
                continue;
            }
            for ($j = $i + 1; $j < $count; $j++) {
                if (self::headerPlausible($msgs[$j]) && self::consecutive($msgs[$i], $msgs[$j])) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * b 是否是 a 的同一路 RTP 流的后续包：SSRC 相同，序号领先 a 不超过探测窗口。
     * 允许中间隔着被消息分片藏起来的包；上限挡掉"容器字节恰好撞上 48 位一致"的巧合。
     */
    public static function consecutive(string $a, string $b): bool
    {
        if (substr($a, 8, 4) !== substr($b, 8, 4)) {
            return false;
        }
        $seqA = (int) unpack('n', substr($a, 2, 2))[1];
        $seqB = (int) unpack('n', substr($b, 2, 2))[1];
        $gap = ($seqB - $seqA) & 0xFFFF; // 16 位回绕，序号本就回绕
        return $gap >= 1 && $gap <= self::PROBE_MESSAGES;
    }
}
