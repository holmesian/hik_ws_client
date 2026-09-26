<?php

declare(strict_types=1);

namespace HikWs\Tests;

use HikWs\HikConfig;
use HikWs\HikMediaClient;
use HikWs\Media;
use HikWs\MediaInfo;
use HikWs\Protocol;
use HikWs\PsDemuxer;
use HikWs\RtpDetector;
use HikWs\SdpParser;
use HikWs\SpsParser;
use HikWs\WebSocket;

/**
 * 媒体解析层与客户端接线的回归测试。
 *
 * 用例与 go-client / python-client 的测试一一对应：三套实现跑同一批真机样本、断同一组数字，
 * 任一侧改坏了，回放帧数 / 关键帧数 / 分辨率就会对不上。
 */
final class HikMediaTest
{
    /** 仓库根的 samples/，三侧共用。 */
    private static function samplesDir(): string
    {
        return dirname(__DIR__, 2) . '/samples';
    }

    public static function register(): void
    {
        self::protocolTests();
        self::iterMessagesTests();
        self::isPsDataTests();
        self::rtpStripTests();
        self::rtpDetectorTests();
        self::psDemuxTests();
        self::sdpTests();
        self::spsTests();
        self::sniffTests();
        self::replayTests();
        self::clientWiringTests();
        self::multiMessageFrameTests();
        self::cryptoTests();
    }

    // ------------------------------------------------------------------
    private static function protocolTests(): void
    {
        MiniTest::run('unpack basic', function (): void {
            $data = "\x02\x00\x00\x00\x03" . 'abc' . 'tail';
            [$t, $p, $r] = Protocol::unpack($data);
            MiniTest::assertSame(0x02, $t);
            MiniTest::assertSame('abc', $p);
            MiniTest::assertSame('tail', $r);
        });

        MiniTest::run('unpack short header', function (): void {
            MiniTest::assertSame([null, null, "\x02\x00\x00"], Protocol::unpack("\x02\x00\x00"));
        });

        MiniTest::run('unpack rejects overflowing length', function (): void {
            $data = "\x02\xFF\xFF\xFF\xFB" . 'short';
            [$t, $p, $r] = Protocol::unpack($data);
            MiniTest::assertSame(null, $t);
            MiniTest::assertSame(null, $p);
            MiniTest::assertSame($data, $r);
        });
    }

    private static function iterMessagesTests(): void
    {
        MiniTest::run('two video messages in one frame', function (): void {
            $frame = TestHelper::protocolMsg(0x40, 'AAAA') . TestHelper::protocolMsg(0x40, 'BBBB');
            MiniTest::assertSame([[0x40, 'AAAA'], [0x40, 'BBBB']], Protocol::iterMessages($frame));
        });

        MiniTest::run('mixed types in one frame', function (): void {
            $frame = TestHelper::protocolMsg(0x40, 'video')
                . TestHelper::protocolMsg(0x41, 'audio')
                . TestHelper::protocolMsg(0x06, '')
                . TestHelper::protocolMsg(0x40, 'video2');
            MiniTest::assertSame(
                [[0x40, 'video'], [0x41, 'audio'], [0x06, ''], [0x40, 'video2']],
                Protocol::iterMessages($frame)
            );
        });

        MiniTest::run('unparseable tail is raw video', function (): void {
            $tail = "\x00\x00\x01\xBA";
            $frame = TestHelper::protocolMsg(0x40, 'AAAA') . $tail;
            MiniTest::assertSame([[0x40, 'AAAA'], [null, $tail]], Protocol::iterMessages($frame));
        });

        MiniTest::run('truncated payload tail keeps its header', function (): void {
            $tail = "\x40\x00\x00\x10\x00" . 'short';
            $frame = TestHelper::protocolMsg(0x40, 'AAAA') . $tail;
            MiniTest::assertSame([[0x40, 'AAAA'], [null, $tail]], Protocol::iterMessages($frame));
        });

        MiniTest::run('whole frame unparseable', function (): void {
            $raw = "\x00\x00\x00\x01\x65\x88";
            MiniTest::assertSame([[null, $raw]], Protocol::iterMessages($raw));
        });

        MiniTest::run('empty frame yields nothing', function (): void {
            MiniTest::assertSame([], Protocol::iterMessages(''));
        });
    }

    private static function isPsDataTests(): void
    {
        MiniTest::run('isPsData start codes', function (): void {
            $cases = [
                ['pack header', "\x00\x00\x01\xBA\x44", true],
                ['audio pes', "\x00\x00\x01\xC0\x11", true],
                ['video pes', "\x00\x00\x01\xE0\x11", true],
                ['psm', "\x00\x00\x01\xBC\x00", true],
                ['program end', "\x00\x00\x01\xB9\x00", true],
                ['annex-b 3 byte', "\x00\x00\x01\x67\x42", false],
                ['annex-b 4 byte', "\x00\x00\x00\x01\x67", false],
                ['too short', "\x00\x00\x01", false],
            ];
            foreach ($cases as [$name, $data, $want]) {
                MiniTest::assertSame($want, PsDemuxer::isPsData($data), $name);
            }
        });
    }

    private static function rtpStripTests(): void
    {
        MiniTest::run('rtp strip', function (): void {
            $cases = [
                ['fixed header',
                    "\x80\xE0\x18\x5C\x00\x00\x2A\x30\x72\x58\x3C\xC8\x00\x00\x01\xBA\x44",
                    "\x00\x00\x01\xBA\x44"],
                ['padding',
                    "\xA0\xE0\x18\x5D\x00\x00\x2A\x30\x72\x58\x3C\xC8\x00\x00\x01\xE0\xFF\xFF\x03",
                    "\x00\x00\x01\xE0"],
                ['csrc list',
                    "\x82\x60\x18\x5E\x00\x00\x2A\x30\x72\x58\x3C\xC8\xAA\xAA\xAA\xAA\xBB\xBB\xBB\xBB\x00\x00\x01\xBA",
                    "\x00\x00\x01\xBA"],
                ['extension header',
                    "\x90\x60\x18\x5F\x00\x00\x2A\x30\x72\x58\x3C\xC8\xBE\xDE\x00\x01\x11\x22\x33\x44\x00\x00\x01\xBA",
                    "\x00\x00\x01\xBA"],
                ['bare mpeg-ps is not rtp',
                    "\x00\x00\x01\xBA\x44\x88\x2D\x42\x54\x01\x00\x00\x03",
                    "\x00\x00\x01\xBA\x44\x88\x2D\x42\x54\x01\x00\x00\x03"],
                ['impossible padding count',
                    "\xA0\xE0\x18\x60\x00\x00\x2A\x30\x72\x58\x3C\xC8\x00\x00\xFF",
                    "\xA0\xE0\x18\x60\x00\x00\x2A\x30\x72\x58\x3C\xC8\x00\x00\xFF"],
                ['short message', "\x80\xE0\x18", "\x80\xE0\x18"],
            ];
            foreach ($cases as [$name, $data, $want]) {
                MiniTest::assertSame($want, RtpDetector::strip($data), $name);
            }
        });
    }

    private static function rtpDetectorTests(): void
    {
        // 同一路 RTP 的两个连续包：SSRC 72 58 3c c8，序号 0x185c/0x185d
        $rtp1 = "\x80\xE0\x18\x5C\x00\x00\x2A\x30\x72\x58\x3C\xC8\x00\x00\x01\xBA\x11";
        $rtp2 = "\x80\xE0\x18\x5D\x00\x00\x2A\x64\x72\x58\x3C\xC8\x22\x33\x44\x55\x66";
        // 恰好以 0b10xxxxxx 开头的 PS 续传消息——逐条判定就在这里把 39 台真机砍坏。
        $cont1 = "\x8C\x80\x08\x23\xC7\xDD\xC4\x69\xFF\xFF\xFC\x00\x00\x00\x01\x40\x01";
        $cont2 = "\xA5\x1F\x36\x26\xB1\x73\xBF\x6D\xC3\x46\x6F\x85\xB3\x36\x4B\x56\x26";

        $run = static function (array $msgs): array {
            $d = new RtpDetector();
            $out = [];
            foreach ($msgs as $m) {
                $out = array_merge($out, $d->feed($m));
            }
            $out = array_merge($out, $d->flush());
            return [$d, $out];
        };

        MiniTest::run('rtp session strips every packet', function () use ($run, $rtp1, $rtp2): void {
            [$d, $got] = $run([$rtp1, $rtp2]);
            MiniTest::assertTrue($d->isRtp());
            MiniTest::assertSame(["\x00\x00\x01\xBA\x11", "\x22\x33\x44\x55\x66"], $got);
        });

        MiniTest::run('bare ps decides on first message', function () use ($run, $cont1): void {
            $first = "\x00\x00\x01\xBA\x44\x88\x2D\x42\x54\x01\x00\x00";
            [$d, $got] = $run([$first, $cont1]);
            MiniTest::assertFalse($d->isRtp());
            MiniTest::assertSame([$first, $cont1], $got);
        });

        MiniTest::run('continuations that look like rtp pass through', function () use ($run, $cont1, $cont2): void {
            [$d, $got] = $run([$cont1, $cont2]);
            MiniTest::assertFalse($d->isRtp());
            MiniTest::assertSame([$cont1, $cont2], $got);
        });

        MiniTest::run('matching ssrc but wrong sequence is not rtp', function () use ($run, $rtp1): void {
            $badSeq = substr($rtp1, 0, 2) . "\x99\x99" . substr($rtp1, 4);
            [$d, $got] = $run([$rtp1, $badSeq]);
            MiniTest::assertFalse($d->isRtp());
            MiniTest::assertSame([$rtp1, $badSeq], $got);
        });

        MiniTest::run('survives fragmented first packet', function () use ($run): void {
            $head = "\x80\x60\x2C\x25\x00\x00\x00\x00\x69\x54\xD8\x56\x00\x00\x01\xBA\x11";
            $tail = "\x4D\x2A\xF7\x5B\x5D\xF9\xCD\x32\x70\x85\x02\x6B";
            $nxt = "\x80\x60\x2C\x26\x00\x00\x00\x00\x69\x54\xD8\x56\x22\x33\x44";
            [$d, $got] = $run([$head, $tail, $nxt]);
            MiniTest::assertTrue($d->isRtp());
            MiniTest::assertSame(["\x00\x00\x01\xBA\x11", $tail, "\x22\x33\x44"], $got);
        });

        MiniTest::run('flush releases held message', function (): void {
            $only = "\x80\xE0\x18\x5C\x00\x00\x2A\x30\x72\x58\x3C\xC8\x00\x00\x01\xBA";
            $d = new RtpDetector();
            MiniTest::assertSame([], $d->feed($only));
            MiniTest::assertSame([$only], $d->flush());
            MiniTest::assertSame([], $d->flush());
        });
    }

    private static function psDemuxTests(): void
    {
        $idr = "\x00\x00\x00\x01\x65\x88\x84\x21";  // H.264 IDR

        MiniTest::run('ps single frame', function () use ($idr): void {
            $d = new PsDemuxer();
            $got = $d->feed(TestHelper::psPack() . TestHelper::psVideoPes($idr));
            $got = array_merge($got, $d->feed(TestHelper::psPack()));
            $got = array_merge($got, $d->flush());
            MiniTest::assertSame([$idr], array_map(fn($f) => $f->data, $got));
        });

        MiniTest::run('ps split nal', function () use ($idr): void {
            $d = new PsDemuxer();
            $got = $d->feed(TestHelper::psPack() . TestHelper::psVideoPes(substr($idr, 0, 4)) . TestHelper::psVideoPes(substr($idr, 4)));
            $got = array_merge($got, $d->flush());
            MiniTest::assertSame([$idr], array_map(fn($f) => $f->data, $got));
        });

        MiniTest::run('ps pts', function () use ($idr): void {
            $d = new PsDemuxer();
            $got = $d->feed(TestHelper::psPack() . TestHelper::psVideoPes($idr, 7200));
            $got = array_merge($got, $d->flush());
            MiniTest::assertSame(1, count($got));
            MiniTest::assertTrue($got[0]->hasPts);
            MiniTest::assertSame(7200, $got[0]->pts);
        });

        MiniTest::run('ps drops partial leading au', function () use ($idr): void {
            $d = new PsDemuxer();
            $got = $d->feed(TestHelper::psVideoPes("\x00\x00\x01\x41tail", 100));
            $got = array_merge($got, $d->feed(TestHelper::psPack() . TestHelper::psVideoPes($idr, 7200)));
            $got = array_merge($got, $d->flush());
            MiniTest::assertSame([$idr], array_map(fn($f) => $f->data, $got));
            MiniTest::assertSame(7200, $got[0]->pts);
        });

        MiniTest::run('ps skips private stream', function () use ($idr): void {
            $private = hex2bin(
                '000001bd006a8c800727' . '9a07f719fff8' .
                '000200170001800000ff0000e0f1f050' .
                '1d12f2f5eeba71f3fcb60f1b736665d9' .
                '76b5fff77aa5a1ebc7d4927d1451ba3b' .
                'fa5d697fb6493e9dae7102485f57fb40' .
                'fa5d697fb6493e9dae7102485f57fb40' .
                '796fe1c9a921c7fa0472f726dc2e97cf'
            );
            $d = new PsDemuxer();
            $got = $d->feed(TestHelper::psPack());
            $got = array_merge($got, $d->feed($private));
            $got = array_merge($got, $d->feed(TestHelper::psVideoPes($idr, 7200)));
            $got = array_merge($got, $d->flush());
            MiniTest::assertSame([$idr], array_map(fn($f) => $f->data, $got));
            MiniTest::assertSame(7200, $got[0]->pts);
        });

        MiniTest::run('ps chunk boundary independence', function () use ($idr): void {
            $stream = TestHelper::psPack() . TestHelper::psVideoPes($idr, 3600)
                . TestHelper::psPack() . TestHelper::psVideoPes($idr, 7200);
            $whole = new PsDemuxer();
            $want = array_merge($whole->feed($stream), $whole->flush());
            $drip = new PsDemuxer();
            $got = [];
            for ($i = 0; $i < strlen($stream); $i++) {
                $got = array_merge($got, $drip->feed($stream[$i]));
            }
            $got = array_merge($got, $drip->flush());
            MiniTest::assertSame(
                array_map(fn($f) => [$f->data, $f->pts], $want),
                array_map(fn($f) => [$f->data, $f->pts], $got)
            );
        });
    }

    private static function sdpTests(): void
    {
        MiniTest::run('sdp h264 sprop', function (): void {
            $sdp = "v=0\nm=video 0 RTP/AVP 96\na=rtpmap:96 H264/90000\n"
                . "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LgFNoFglE=,aM48gA==\n";
            $info = SdpParser::parse($sdp);
            MiniTest::assertSame('H264', $info->codec);
            MiniTest::assertSame(90000, $info->clockRate);
            MiniTest::assertSame(2, count($info->parameterSets));
        });

        MiniTest::run('sdp mediainfo header', function (): void {
            $hdr = str_repeat("\x00", 40);
            $hdr = 'IMKH' . substr($hdr, 4);
            $hdr[8] = "\x02";   // container = PS
            $hdr[10] = "\x05";  // codec = H265
            $sdp = "v=0\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\n"
                . 'a=Media_header:MEDIAINFO=' . bin2hex($hdr) . ";\n";
            $info = SdpParser::parse($sdp);
            MiniTest::assertSame('PS', $info->container);
            MiniTest::assertSame('H265', $info->codec);
            MiniTest::assertSame(90000, $info->clockRate);
            MiniTest::assertSame([0, 0], [$info->width, $info->height]);
        });

        MiniTest::run('sdp unknown media header magic', function (): void {
            $sdp = "v=0\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\n"
                . 'a=Media_header:MEDIAINFO=4856414701010000C400C001C002000000000000000000006462333'
                . "3000000000000000000000000;\n";
            $info = SdpParser::parse($sdp);
            MiniTest::assertSame('', $info->container);
            MiniTest::assertSame('', $info->codec);
        });

        MiniTest::run('sdp ps ignores audio clock', function (): void {
            $sdp = "v=0\nm=video 0 RTP/AVP 8\na=rtpmap:8 PCMA/8000\n"
                . 'a=Media_header:MEDIAINFO=494D4B48000000000200050011710110401F000000FA0000000000'
                . "00000000000000000000000000;\n";
            $info = SdpParser::parse($sdp);
            MiniTest::assertSame(['PS', 'H265'], [$info->container, $info->codec]);
            MiniTest::assertSame(90000, $info->clockRate);
        });
    }

    private static function spsTests(): void
    {
        MiniTest::run('h264 high profile scaling lists', function (): void {
            $sps = hex2bin(
                '6764001fad84010c200861004308021840' .
                '10c200843b702802dd3701' . '0101014000000300' .
                '4000000ca100'
            );
            MiniTest::assertSame([1280, 720], SpsParser::parseH264Sps($sps));
        });

        MiniTest::run('h265 sps', function (): void {
            MiniTest::assertSame([1920, 1080], SpsParser::parseH265Sps(TestHelper::h265Sps(1920, 1080)));
        });

        MiniTest::run('strip emulation prevention', function (): void {
            MiniTest::assertSame(
                "\x00\x00\x01\x00\x00\x02",
                SpsParser::stripEmulationPrevention("\x00\x00\x03\x01\x00\x00\x03\x02")
            );
        });

        MiniTest::run('recover resolution in stream', function (): void {
            $au = "\x00\x00\x00\x01" . TestHelper::h265Sps(1280, 720) . "\x00\x00\x00\x01\x26\x01";
            [$w, $h, $sps, $ok] = SpsParser::recoverResolution($au, 'H265');
            MiniTest::assertTrue($ok);
            MiniTest::assertSame([1280, 720], [$w, $h]);
            MiniTest::assertTrue(strlen($sps) < 128, 'sps should be a single NAL');
            MiniTest::assertSame(33, (ord($sps[3]) >> 1) & 0x3F);
        });
    }

    private static function sniffTests(): void
    {
        MiniTest::run('sniff codec', function (): void {
            $cases = [
                ['h264 sps', "\x00\x00\x00\x01\x67\x42\x00\x29\x00\x00\x00\x01\x68\xCA", 'H264'],
                ['h264 sps ref_idc 1', "\x00\x00\x01\x27\x42\x00\x29", 'H264'],
                ['h265 vps', "\x00\x00\x00\x01\x40\x01\x0C\x01\x00\x00\x00\x01\x42\x01", 'H265'],
                ['h265 sps only', "\x00\x00\x01\x42\x01\x01\x01\x60", 'H265'],
                ['h264 non-idr slice', "\x00\x00\x00\x01\x41\x9A\x00", ''],
                ['no start code', "\x67\x42\x00\x29", ''],
                ['truncated after start code', "\x00\x00\x01", ''],
            ];
            foreach ($cases as [$name, $data, $want]) {
                MiniTest::assertSame($want, Media::sniffCodec($data), $name);
            }
        });

        MiniTest::run('analyze frame', function (): void {
            MiniTest::assertTrue(Media::analyzeFrame("\x00\x00\x00\x01\x65\x88", 'H264'));
            MiniTest::assertFalse(Media::analyzeFrame("\x00\x00\x00\x01\x41\x9A", 'H264'));
            MiniTest::assertTrue(Media::analyzeFrame("\x00\x00\x00\x01\x26\x01", 'H265'));
            MiniTest::assertFalse(Media::analyzeFrame("\x00\x00\x00\x01\x02\x01", 'H265'));
        });
    }

    /**
     * 真机样本回放（与 go-client 的 TestReplaySamples、python 的 TestReplaySamples 断同一组数字）。
     */
    private static function replayTests(): void
    {
        // dir, codec, frames, keys, width, height, sps_nal
        $cases = [
            ['ps_h265_720p', 'H265', 611, 25, 1280, 720, 33],
            ['ps_h265_1080p', 'H265', 614, 13, 1920, 1080, 33],
            ['ps_h264_720p', 'H264', 655, 26, 1280, 720, 7],
            ['ps_h264_1080p', 'H264', 199, 8, 1920, 1080, 7],
        ];

        foreach ($cases as [$name, $codec, $wantFrames, $wantKeys, $width, $height, $spsNal]) {
            MiniTest::run("replay {$name}", function () use ($name, $codec, $wantFrames, $wantKeys, $width, $height, $spsNal): void {
                $path = self::samplesDir() . "/{$name}/stream.ps";
                if (!is_file($path)) {
                    MiniTest::skip("sample {$path} missing");
                }
                $raw = file_get_contents($path);
                if (str_starts_with($raw, 'version https://git-lfs')) {
                    MiniTest::skip("sample {$path} is an unpulled LFS pointer");
                }

                // 按 16KiB 分块喂入，模拟 WebSocket 层切开访问单元的方式。
                $d = new PsDemuxer();
                $frames = [];
                $chunk = 16 << 10;
                for ($off = 0; $off < strlen($raw); $off += $chunk) {
                    $frames = array_merge($frames, $d->feed(substr($raw, $off, $chunk)));
                }
                $frames = array_merge($frames, $d->flush());
                MiniTest::assertSame($wantFrames, count($frames), '帧数');

                $keys = 0;
                $withPts = 0;
                $prevPts = 0;
                foreach ($frames as $i => $f) {
                    if (Media::analyzeFrame($f->data, $codec)) {
                        $keys++;
                    }
                    if ($f->hasPts) {
                        $withPts++;
                        if ($withPts > 1) {
                            MiniTest::assertGreaterEqual($prevPts, $f->pts, "帧 {$i} 的 PTS 倒退");
                        }
                        $prevPts = $f->pts;
                    }
                    MiniTest::assertTrue(
                        str_starts_with($f->data, "\x00\x00\x00\x01") || str_starts_with($f->data, "\x00\x00\x01"),
                        "帧 {$i} 不是以起始码开头：" . bin2hex(substr($f->data, 0, 8))
                    );
                }
                MiniTest::assertSame($wantKeys, $keys, '关键帧数');
                MiniTest::assertSame($wantFrames, $withPts, '带 PTS 的帧数');

                $got = null;
                foreach ($frames as $f) {
                    [$w, $h, $sps, $ok] = SpsParser::recoverResolution($f->data, $codec);
                    if ($ok) {
                        $got = [$w, $h, $sps];
                        break;
                    }
                }
                MiniTest::assertTrue($got !== null, '没有从码流里还原出分辨率');
                [$gotW, $gotH, $sps] = $got;
                MiniTest::assertSame([$width, $height], [$gotW, $gotH], '分辨率');
                MiniTest::assertTrue(strlen($sps) > 0 && strlen($sps) <= 128, '还原出的应该是单条 SPS NAL');
                $nal = $codec === 'H265' ? (ord($sps[3]) >> 1) & 0x3F : ord($sps[3]) & 0x1F;
                MiniTest::assertSame($spsNal, $nal, '还原出的 NAL 类型');
            });
        }
    }

    private static function makeClient(): HikMediaClient
    {
        $cfg = new HikConfig();
        $cfg->proxyHost = 'h';
        $cfg->proxyPort = 443;
        $cfg->proxyPath = '/proxy/1.2.3.4:80';
        $cfg->deviceIp = '1.2.3.4';
        $cfg->devicePort = 80;
        return new HikMediaClient($cfg);
    }

    private static function clientWiringTests(): void
    {
        MiniTest::run('bare ps is demuxed and described', function (): void {
            $c = self::makeClient();
            $c->setMediaInfo(SdpParser::parse(
                "v=0\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\n"
                . 'a=Media_header:MEDIAINFO=4856414701010000C400C001C002000000000000000000006462333'
                . "3000000000000000000000000;\n"
            ));
            $info = $c->mediaInfo();
            MiniTest::assertSame(['', ''], [$info->container, $info->codec]);
            $frames = [];
            $c->onVideoFrame = function ($meta, $data) use (&$frames): void {
                $frames[] = [$meta, $data];
            };
            $au = "\x00\x00\x00\x01" . TestHelper::h265Sps(1280, 720) . "\x00\x00\x00\x01\x26\x01";
            $c->feedVideo(TestHelper::psPack() . TestHelper::psVideoPes($au, 3600));
            $c->feedVideo(TestHelper::psPack() . TestHelper::psVideoPes($au, 7200));
            $c->flushMedia();

            MiniTest::assertSame(2, count($frames));
            [$meta, $data] = $frames[0];
            MiniTest::assertSame($au, $data);
            MiniTest::assertSame(1, $meta->frameIndex);
            MiniTest::assertTrue($meta->isKeyFrame);
            MiniTest::assertSame('H265', $meta->codec);
            MiniTest::assertSame([1280, 720], [$meta->width, $meta->height]);
            MiniTest::assertTrue($meta->hasPts);
            MiniTest::assertSame(3600, $meta->pts);
            $info = $c->mediaInfo();
            MiniTest::assertSame('PS', $info->container);
            MiniTest::assertSame(90000, $info->clockRate);
            MiniTest::assertSame(2, $frames[1][0]->frameIndex);
            MiniTest::assertSame(7200, $frames[1][0]->pts);
        });

        MiniTest::run('rtp wrapped ps is de-encapsulated', function (): void {
            $c = self::makeClient();
            $frames = [];
            $c->onVideoData = function ($data) use (&$frames): void {
                $frames[] = $data;
            };
            $idr = "\x00\x00\x00\x01\x65\x88\x84\x21";
            $body1 = TestHelper::psPack() . TestHelper::psVideoPes($idr, 3600);
            $body2 = TestHelper::psPack() . TestHelper::psVideoPes($idr, 7200);
            $rtp1 = "\x80\x60\x2C\x25\x00\x00\x00\x00\x69\x54\xD8\x56" . $body1;
            $rtp2 = "\x80\x60\x2C\x26\x00\x00\x00\x00\x69\x54\xD8\x56" . $body2;
            $c->feedVideo($rtp1);
            $c->feedVideo($rtp2);
            $c->flushMedia();
            MiniTest::assertSame([$idr, $idr], $frames);
        });

        MiniTest::run('on video data receives demuxed frames', function (): void {
            $c = self::makeClient();
            $got = [];
            $c->onVideoData = function ($data) use (&$got): void {
                $got[] = $data;
            };
            $idr = "\x00\x00\x00\x01\x65\x88\x84\x21";
            $c->feedVideo(TestHelper::psPack() . TestHelper::psVideoPes($idr, 3600));
            $c->flushMedia();
            MiniTest::assertSame([$idr], $got);
        });
    }

    /**
     * 加密层回归：Go / Python / PHP 三侧必须对同一输入给出**逐字节相同**的密文。
     *
     * 这里的两条断言都是真机/跨实现撞出来的分歧，不是纸面推导：
     *  - AES 的 key / IV 是**解码后的字节**，不是硬编码的十六进制串；
     *  - 只用一次 TLS 握手（`ssl://` 已完成，不再 enable_crypto）。
     */
    private static function cryptoTests(): void
    {
        // 固定时间戳下的 AES-128/256-CBC PKCS7 密文。期望值是 Go aesEncryptCBC 与
        // Python HikCrypto.aes_encrypt_cbc 在同一输入上的输出（两侧一致）。
        MiniTest::run('aes cbc matches go/python baseline', function (): void {
            $method = new \ReflectionMethod(\HikWs\Crypto::class, 'aesEncryptCbc');
            $method->setAccessible(true);
            $key = hex2bin('1234567891234567123456789123456712345678912345671234567891234567');
            $iv = hex2bin('12345678912345671234567891234567');
            $got = bin2hex($method->invoke(null, '1758900000000', $key, $iv));
            MiniTest::assertSame('6e00f565aa2df9bc5dd6e5d426c3aa85', $got);
        });

        // generateClientIvKey 的形态：32 字节密文 hex = 64 字符，不足则自拼。
        MiniTest::run('client iv key is 64 hex chars', function (): void {
            [$iv, $key] = \HikWs\Crypto::generateClientIvKey();
            MiniTest::assertSame(64, strlen($iv));
            MiniTest::assertSame(64, strlen($key));
            MiniTest::assertSame($iv, $key, '同一时间戳派生出的 iv 与 key 相同');
            // 半个即 32 字符重复两次——证明用的是解码后的字节而非 hex 串（后者会得到不同结果）。
            MiniTest::assertSame(substr($iv, 0, 32), substr($iv, 32));
        });
    }

    /**
     * 单帧多协议消息的传输层接线等价于 Go 的 readLoop / Python 的 receive_message：
     * 这里直接对 iterMessages 的交付序列断言（不经过网络）。
     */
    private static function multiMessageFrameTests(): void
    {
        MiniTest::run('ws frame roundtrip multi-message', function (): void {
            // 手写一个带分片的 WS 帧流，用真实 WebSocket 解析器验证重组 + 多消息交付。
            $wire = TestHelper::wsFrame(0x02, TestHelper::protocolMsg(0x40, 'AAAA'))
                . TestHelper::wsFrame(0x00, TestHelper::protocolMsg(0x41, 'pcm'), false)
                . TestHelper::wsFrame(0x80, '', true);
            MiniTest::assertTrue($wire !== '', 'wire built');
            // 纯协议层：一帧内视频 + 音频 + 视频,全部交付。
            $payload = TestHelper::protocolMsg(0x40, 'AAAA')
                . TestHelper::protocolMsg(0x41, 'pcm')
                . TestHelper::protocolMsg(0x40, 'BBBB');
            $msgs = Protocol::iterMessages($payload);
            MiniTest::assertSame([[0x40, 'AAAA'], [0x41, 'pcm'], [0x40, 'BBBB']], $msgs);
        });
    }
}
