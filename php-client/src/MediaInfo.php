<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 流的描述信息（SDP 级）。对齐 go-client 的 MediaInfo 与 python-client 的 MediaInfo。
 */
final class MediaInfo
{
    public string $sdp = '';
    /** PS / RTP / HIK / GB / RAW；空表示无 MEDIAINFO 头。 */
    public string $container = '';
    /** H264 / H265。 */
    public string $codec = '';
    public int $clockRate = 0;
    /** 一律从码流内 SPS 还原；MEDIAINFO 头不带分辨率，故首帧前恒为 0。 */
    public int $width = 0;
    public int $height = 0;
    /** @var list<string> sprop-parameter-sets 的 base64 SPS/PPS。 */
    public array $parameterSets = [];

    public function __construct(string $sdp = '')
    {
        $this->sdp = $sdp;
    }
}

/**
 * 单个还原出来的视频帧的描述。对齐 go-client 的 FrameMeta。
 */
final class FrameMeta
{
    public int $frameIndex = 0;
    public bool $isKeyFrame = false;
    public string $codec = '';
    public int $width = 0;
    public int $height = 0;
    /** hasPts 为真时是容器的 90kHz PTS，否则是按到达时间合成的。 */
    public int $pts = 0;
    public bool $hasPts = false;
    /** 相对开流的墙钟毫秒。 */
    public int $timestampMs = 0;
}
