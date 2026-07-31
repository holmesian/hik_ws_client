#!/usr/bin/env python3
"""hik_media 媒体解析层的回归测试。

用 stdlib unittest（不引 pytest）：hik_media 只依赖标准库，测试也应当在裸环境里
``python3 -m unittest`` 就能跑，不需要装任何东西。

**线格式一律手写字节，不复用实现里的构造逻辑。** 与实现同源的 helper 会认同一个错误
的字段布局，测试全绿而线上码流是坏的——PES 头长度那个 bug 第一版测试就是这么放过去的。
下面 ``ps_pack`` / ``ps_video_pes`` 这类构造器只按 ISO/IEC 13818-1 的字段顺序拼字节，
不引用 hik_media 的任何解析常量。

用例与 go-client 的测试一一对应：两边跑同一批真机样本、断同一组数字，任何一侧改坏了
解析，回放帧数/关键帧数/分辨率就会在这里对不上。

运行：``python3 -m unittest test_hik_media -v``
"""

import asyncio
import os
import unittest

import hik_media as m

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


# ---------------------------------------------------------------------------
# 手写线格式构造器
# ---------------------------------------------------------------------------
def ps_pack() -> bytes:
    """最小 MPEG-PS pack 头：14 字节，pack_stuffing_length = 0。"""
    return bytes([0x00, 0x00, 0x01, 0xBA] + [0] * 10)


def encode_pts(pts: int) -> bytes:
    """把 33 位 PTS 编成 5 字节 PES 时间戳字段（marker 位置位）。"""
    return bytes([
        0x20 | (((pts >> 30) & 0x07) << 1) | 0x01,
        (pts >> 22) & 0xFF,
        (((pts >> 15) & 0x7F) << 1) | 0x01,
        (pts >> 7) & 0xFF,
        ((pts & 0x7F) << 1) | 0x01,
    ])


def ps_video_pes(payload: bytes, pts: int = -1) -> bytes:
    """视频 PES 包（stream_id 0xE0），带标准 3 字节 MPEG-2 PES 可选头。"""
    if pts >= 0:
        body = bytes([0x80, 0x80, 0x05]) + encode_pts(pts) + payload
    else:
        body = bytes([0x80, 0x00, 0x00]) + payload
    return bytes([0x00, 0x00, 0x01, 0xE0, len(body) >> 8, len(body) & 0xFF]) + body


class BitWriter:
    """按位拼 RBSP，用来手搓 SPS。"""

    def __init__(self):
        self.buf = bytearray()
        self.nbits = 0

    def put_bits(self, value: int, n: int):
        for i in range(n - 1, -1, -1):
            if self.nbits % 8 == 0:
                self.buf.append(0)
            if (value >> i) & 1:
                self.buf[-1] |= 0x80 >> (self.nbits % 8)
            self.nbits += 1

    def put_ue(self, v: int):
        v += 1
        nbits = v.bit_length()
        self.put_bits(0, nbits - 1)
        self.put_bits(v, nbits)

    def bytes(self) -> bytes:
        return bytes(self.buf)


def h265_sps(width: int, height: int) -> bytes:
    """手搓一条 HEVC SPS NAL（含 2 字节 NAL 头），chroma 1，无 conformance 裁剪。"""
    w = BitWriter()
    w.put_bits(0x42, 8)   # NAL 头字节 0
    w.put_bits(0x01, 8)   # NAL 头字节 1（type 33 = SPS_NUT）
    w.put_bits(0, 4)      # sps_video_parameter_set_id
    w.put_bits(0, 3)      # sps_max_sub_layers_minus1
    w.put_bits(1, 1)      # sps_temporal_id_nesting_flag
    w.put_bits(0, 2)      # general_profile_space
    w.put_bits(0, 1)      # general_tier_flag
    w.put_bits(1, 5)      # general_profile_idc
    w.put_bits(0, 32)     # general_profile_compatibility_flag
    w.put_bits(0, 48)     # general_constraint_indicator_flag
    w.put_bits(93, 8)     # general_level_idc
    w.put_ue(0)           # sps_seq_parameter_set_id
    w.put_ue(1)           # chroma_format_idc
    w.put_ue(width)       # pic_width_in_luma_samples
    w.put_ue(height)      # pic_height_in_luma_samples
    w.put_bits(1, 1)      # conformance_window_flag
    w.put_ue(0)
    w.put_ue(0)
    w.put_ue(0)
    w.put_ue(0)
    return w.bytes()


# ---------------------------------------------------------------------------
# 协议封包
# ---------------------------------------------------------------------------
class TestUnpack(unittest.TestCase):
    def test_unpack(self):
        data = bytes([0x02, 0x00, 0x00, 0x00, 0x03]) + b"abc" + b"tail"
        msg_type, payload, remaining = m.unpack_message(data)
        self.assertEqual(msg_type, 0x02)
        self.assertEqual(payload, b"abc")
        self.assertEqual(remaining, b"tail")

    def test_short_header(self):
        self.assertEqual(m.unpack_message(b"\x02\x00\x00"), (None, None, b"\x02\x00\x00"))

    def test_rejects_overflowing_length(self):
        """长度字段来自网络。Go 里 uint32 的 5+0xFFFFFFFB 会回绕成 0 而 panic；
        Python 整数无宽度不会回绕，但声明长度超过实际字节时仍必须拒绝，不能切开返回。"""
        data = bytes([0x02, 0xFF, 0xFF, 0xFF, 0xFB]) + b"short"
        msg_type, payload, remaining = m.unpack_message(data)
        self.assertIsNone(msg_type)
        self.assertIsNone(payload)
        self.assertEqual(remaining, data)


class TestIterMessages(unittest.TestCase):
    """一个 WebSocket 帧里串多条协议消息时必须消费到尾。

    只解第一条的那一版：帧数、关键帧数、分辨率全对，丢掉的是同帧内的后续消息——
    正是 `.codebuddy/rules/testing.md` 第一条说的"计数不算验证"。这里不经过网络，
    直接对字节断言，无第三方依赖，任何环境都跑得到。
    """

    @staticmethod
    def _msg(msg_type: int, payload: bytes) -> bytes:
        """手写 5 字节协议头：1 字节类型 + 4 字节大端长度。"""
        return bytes([msg_type]) + len(payload).to_bytes(4, "big") + payload

    def test_two_video_messages_in_one_frame(self):
        frame = self._msg(0x40, b"AAAA") + self._msg(0x40, b"BBBB")
        self.assertEqual(list(m.iter_messages(frame)),
                         [(0x40, b"AAAA"), (0x40, b"BBBB")])

    def test_mixed_types_in_one_frame(self):
        """设备会把视频、音频、心跳打进同一帧；只取第一条丢的是整条音轨。"""
        frame = (self._msg(0x40, b"video") + self._msg(0x41, b"audio")
                 + self._msg(0x06, b"") + self._msg(0x40, b"video2"))
        self.assertEqual(list(m.iter_messages(frame)),
                         [(0x40, b"video"), (0x41, b"audio"),
                          (0x06, b""), (0x40, b"video2")])

    def test_unparseable_tail_is_raw_video(self):
        """消费掉 N 条之后解不出来的尾巴，按 Go 的语义把剩下的整段当原始视频交出去，
        不是丢掉、也不是只丢那一小截。"""
        tail = bytes([0x00, 0x00, 0x01, 0xBA])  # 5 字节都不够，头不完整
        frame = self._msg(0x40, b"AAAA") + tail
        self.assertEqual(list(m.iter_messages(frame)),
                         [(0x40, b"AAAA"), (None, tail)])

    def test_truncated_payload_tail_keeps_its_header(self):
        """声明长度超过剩余字节：整段（含那 5 字节头）都当原始视频，不能切开。"""
        tail = bytes([0x40, 0x00, 0x00, 0x10, 0x00]) + b"short"
        frame = self._msg(0x40, b"AAAA") + tail
        self.assertEqual(list(m.iter_messages(frame)),
                         [(0x40, b"AAAA"), (None, tail)])

    def test_whole_frame_unparseable(self):
        """第一条就解不出来：整帧当原始视频，与修复前行为一致。"""
        raw = bytes([0x00, 0x00, 0x00, 0x01, 0x65, 0x88])
        self.assertEqual(list(m.iter_messages(raw)), [(None, raw)])

    def test_empty_frame_yields_nothing(self):
        self.assertEqual(list(m.iter_messages(b"")), [])


# ---------------------------------------------------------------------------
# 容器嗅探
# ---------------------------------------------------------------------------
class TestIsPSData(unittest.TestCase):
    def test_start_codes(self):
        cases = [
            ("pack header", bytes([0, 0, 1, 0xBA, 0x44]), True),
            # 直播从任意位置接入：一台设备从音频 PES 开流，只认 0xBA 会整条会话误判
            ("audio pes", bytes([0, 0, 1, 0xC0, 0x11]), True),
            ("video pes", bytes([0, 0, 1, 0xE0, 0x11]), True),
            ("psm", bytes([0, 0, 1, 0xBC, 0x00]), True),
            ("program end", bytes([0, 0, 1, 0xB9, 0x00]), True),
            # annex-b 的 NAL 头最高位恒为 0，到不了容器用的高 ID
            ("annex-b 3 byte", bytes([0, 0, 1, 0x67, 0x42]), False),
            ("annex-b 4 byte", bytes([0, 0, 0, 1, 0x67]), False),
            ("too short", bytes([0, 0, 1]), False),
        ]
        for name, data, want in cases:
            with self.subTest(name):
                self.assertEqual(m.is_ps_data(data), want)


# ---------------------------------------------------------------------------
# RTP 二次封装
# ---------------------------------------------------------------------------
class TestRTPStrip(unittest.TestCase):
    def test_strip(self):
        cases = [
            # V=2 P=0 X=0 CC=0, M=1 PT=96, seq, timestamp, SSRC
            ("fixed header",
             bytes([0x80, 0xE0, 0x18, 0x5C, 0x00, 0x00, 0x2A, 0x30, 0x72, 0x58, 0x3C, 0xC8,
                    0x00, 0x00, 0x01, 0xBA, 0x44]),
             bytes([0x00, 0x00, 0x01, 0xBA, 0x44])),
            # P=1：最后一个字节计 padding 且含自身
            ("padding",
             bytes([0xA0, 0xE0, 0x18, 0x5D, 0x00, 0x00, 0x2A, 0x30, 0x72, 0x58, 0x3C, 0xC8,
                    0x00, 0x00, 0x01, 0xE0, 0xFF, 0xFF, 0x03]),
             bytes([0x00, 0x00, 0x01, 0xE0])),
            # CC=2：固定头后跟两个 4 字节 CSRC
            ("csrc list",
             bytes([0x82, 0x60, 0x18, 0x5E, 0x00, 0x00, 0x2A, 0x30, 0x72, 0x58, 0x3C, 0xC8,
                    0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
                    0x00, 0x00, 0x01, 0xBA]),
             bytes([0x00, 0x00, 0x01, 0xBA])),
            # X=1：2 字节 profile + 2 字节字长，随后 1 个字
            ("extension header",
             bytes([0x90, 0x60, 0x18, 0x5F, 0x00, 0x00, 0x2A, 0x30, 0x72, 0x58, 0x3C, 0xC8,
                    0xBE, 0xDE, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44,
                    0x00, 0x00, 0x01, 0xBA]),
             bytes([0x00, 0x00, 0x01, 0xBA])),
            ("bare mpeg-ps is not rtp",
             bytes([0x00, 0x00, 0x01, 0xBA, 0x44, 0x88, 0x2D, 0x42, 0x54, 0x01, 0x00, 0x00, 0x03]),
             bytes([0x00, 0x00, 0x01, 0xBA, 0x44, 0x88, 0x2D, 0x42, 0x54, 0x01, 0x00, 0x00, 0x03])),
            # padding 数超过负载：还原不了，原样返回好过返回空
            ("impossible padding count",
             bytes([0xA0, 0xE0, 0x18, 0x60, 0x00, 0x00, 0x2A, 0x30, 0x72, 0x58, 0x3C, 0xC8,
                    0x00, 0x00, 0xFF]),
             bytes([0xA0, 0xE0, 0x18, 0x60, 0x00, 0x00, 0x2A, 0x30, 0x72, 0x58, 0x3C, 0xC8,
                    0x00, 0x00, 0xFF])),
            ("short message", bytes([0x80, 0xE0, 0x18]), bytes([0x80, 0xE0, 0x18])),
        ]
        for name, data, want in cases:
            with self.subTest(name):
                self.assertEqual(m.rtp_strip(data), want)


class TestRTPDetector(unittest.TestCase):
    # 同一路 RTP 的两个连续包：SSRC 72 58 3c c8，序号 0x185c/0x185d
    RTP1 = bytes([0x80, 0xE0, 0x18, 0x5C, 0x00, 0x00, 0x2A, 0x30, 0x72, 0x58, 0x3C, 0xC8,
                  0x00, 0x00, 0x01, 0xBA, 0x11])
    RTP2 = bytes([0x80, 0xE0, 0x18, 0x5D, 0x00, 0x00, 0x2A, 0x64, 0x72, 0x58, 0x3C, 0xC8,
                  0x22, 0x33, 0x44, 0x55, 0x66])
    # 恰好以 0b10xxxxxx 开头的 PS 续传消息。任意字节有 1/4 概率如此——逐条判定就是
    # 在这里把 39 台真机的码流静默砍坏的。
    CONT1 = bytes([0x8C, 0x80, 0x08, 0x23, 0xC7, 0xDD, 0xC4, 0x69, 0xFF, 0xFF, 0xFC, 0x00,
                   0x00, 0x00, 0x01, 0x40, 0x01])
    CONT2 = bytes([0xA5, 0x1F, 0x36, 0x26, 0xB1, 0x73, 0xBF, 0x6D, 0xC3, 0x46, 0x6F, 0x85,
                   0xB3, 0x36, 0x4B, 0x56, 0x26])

    def _run(self, msgs):
        d = m.RTPDetector()
        out = []
        for msg in msgs:
            out.extend(d.feed(msg))
        out.extend(d.flush())
        return d, out

    def test_rtp_session_strips_every_packet(self):
        d, got = self._run([self.RTP1, self.RTP2])
        self.assertTrue(d._is_rtp)
        self.assertEqual(got, [bytes([0x00, 0x00, 0x01, 0xBA, 0x11]),
                               bytes([0x22, 0x33, 0x44, 0x55, 0x66])])

    def test_bare_ps_decides_on_first_message(self):
        first = bytes([0x00, 0x00, 0x01, 0xBA, 0x44, 0x88, 0x2D, 0x42, 0x54, 0x01, 0x00, 0x00])
        d, got = self._run([first, self.CONT1])
        self.assertFalse(d._is_rtp)
        self.assertEqual(got, [first, self.CONT1])

    def test_continuations_that_look_like_rtp_pass_through(self):
        """两条的版本字段都像 RTP，但 SSRC 不同，一个字节都不许剥。"""
        d, got = self._run([self.CONT1, self.CONT2])
        self.assertFalse(d._is_rtp)
        self.assertEqual(got, [self.CONT1, self.CONT2])

    def test_matching_ssrc_but_wrong_sequence_is_not_rtp(self):
        bad_seq = self.RTP1[:2] + bytes([0x99, 0x99]) + self.RTP1[4:]
        d, got = self._run([self.RTP1, bad_seq])
        self.assertFalse(d._is_rtp)
        self.assertEqual(got, [self.RTP1, bad_seq])

    def test_survives_fragmented_first_packet(self):
        """WebSocket 消息边界不是 RTP 包边界：HVAG 那一类设备把首个 8204 字节的包
        拆成 8192 + 12 两条，第二条是包中段而不是包头。要求"相邻两条互证"会把一条
        真 RTP 会话判成裸流，整条码流里留满 12 字节头。"""
        head = bytes([0x80, 0x60, 0x2C, 0x25, 0x00, 0x00, 0x00, 0x00, 0x69, 0x54, 0xD8, 0x56,
                      0x00, 0x00, 0x01, 0xBA, 0x11])
        tail = bytes([0x4D, 0x2A, 0xF7, 0x5B, 0x5D, 0xF9, 0xCD, 0x32, 0x70, 0x85, 0x02, 0x6B])
        nxt = bytes([0x80, 0x60, 0x2C, 0x26, 0x00, 0x00, 0x00, 0x00, 0x69, 0x54, 0xD8, 0x56,
                     0x22, 0x33, 0x44])
        d, got = self._run([head, tail, nxt])
        self.assertTrue(d._is_rtp)
        # tail 是负载，必须逐字节送到解复用器
        self.assertEqual(got, [bytes([0x00, 0x00, 0x01, 0xBA, 0x11]), tail,
                               bytes([0x22, 0x33, 0x44])])

    def test_flush_releases_held_message(self):
        """只收到一条像 RTP 的消息就断流：没有第二个包来验序号，丢掉唯一的负载
        比原样放出去更糟。"""
        only = bytes([0x80, 0xE0, 0x18, 0x5C, 0x00, 0x00, 0x2A, 0x30, 0x72, 0x58, 0x3C, 0xC8,
                      0x00, 0x00, 0x01, 0xBA])
        d = m.RTPDetector()
        self.assertEqual(d.feed(only), [])
        self.assertEqual(d.flush(), [only])
        self.assertEqual(d.flush(), [])


# ---------------------------------------------------------------------------
# PS 解复用
# ---------------------------------------------------------------------------
IDR = bytes([0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21])  # H.264 IDR


class TestPSDemux(unittest.TestCase):
    def test_single_frame(self):
        d = m.PSDemuxer()
        got = d.feed(ps_pack() + ps_video_pes(IDR))
        got += d.feed(ps_pack())  # 下一个 pack 头关掉上一帧
        got += d.flush()
        self.assertEqual([f.data for f in got], [IDR])

    def test_split_nal(self):
        """设备会把单个 NAL 拆到多个 PES 包里，原始 PS 字节不能当 annex-b 扫。"""
        d = m.PSDemuxer()
        got = d.feed(ps_pack() + ps_video_pes(IDR[:4]) + ps_video_pes(IDR[4:]))
        got += d.flush()
        self.assertEqual([f.data for f in got], [IDR])

    def test_pts(self):
        d = m.PSDemuxer()
        got = d.feed(ps_pack() + ps_video_pes(IDR, 7200))
        got += d.flush()
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].has_pts)
        self.assertEqual(got[0].pts, 7200)

    def test_drops_partial_leading_au(self):
        """首个 pack 头之前的 PES 是没见过头的访问单元的尾巴：拼出来解不出，
        还自带 PTS 让首帧时间戳偏早。"""
        d = m.PSDemuxer()
        got = d.feed(ps_video_pes(b"\x00\x00\x01\x41tail", 100))
        got += d.feed(ps_pack() + ps_video_pes(IDR, 7200))
        got += d.flush()
        self.assertEqual([f.data for f in got], [IDR])
        self.assertEqual(got[0].pts, 7200)

    def test_skips_private_stream(self):
        """0xBD 私有流（82/94 台设备每秒一条）自带 PTS：当视频处理既会把密文拼进
        码流，又会把帧时间戳取成私有包的。真机采到的原始字节。"""
        private = bytes([
            0x00, 0x00, 0x01, 0xBD, 0x00, 0x6A,  # 起始码 + 长度 106
            0x8C, 0x80, 0x07, 0x27, 0x9A, 0x07, 0xF7, 0x19, 0xFF, 0xF8,  # PES 头，带 PTS
            0x00, 0x02, 0x00, 0x17, 0x00, 0x01, 0x80, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xE0, 0xF1, 0xF0, 0x50,
            0x1D, 0x12, 0xF2, 0xF5, 0xEE, 0xBA, 0x71, 0xF3, 0xFC, 0xB6, 0x0F, 0x1B, 0x73, 0x66, 0x65, 0xD9,
            0x76, 0xB5, 0xFF, 0xF7, 0x7A, 0xA5, 0xA1, 0xEB, 0xC7, 0xD4, 0x92, 0x7D, 0x14, 0x51, 0xBA, 0x3B,
            0xFA, 0x5D, 0x69, 0x7F, 0xB6, 0x49, 0x3E, 0x9D, 0xAE, 0x71, 0x02, 0x48, 0x5F, 0x57, 0xFB, 0x40,
            0xFA, 0x5D, 0x69, 0x7F, 0xB6, 0x49, 0x3E, 0x9D, 0xAE, 0x71, 0x02, 0x48, 0x5F, 0x57, 0xFB, 0x40,
            0x79, 0x6F, 0xE1, 0xC9, 0xA9, 0x21, 0xC7, 0xFA, 0x04, 0x72, 0xF7, 0x26, 0xDC, 0x2E, 0x97, 0xCF,
        ])
        d = m.PSDemuxer()
        got = d.feed(ps_pack())
        got += d.feed(private)
        got += d.feed(ps_video_pes(IDR, 7200))
        got += d.flush()
        self.assertEqual([f.data for f in got], [IDR])
        self.assertEqual(got[0].pts, 7200)

    def test_chunk_boundary_independence(self):
        """WebSocket 会在任意位置切开消息：逐字节喂入必须和整块喂入结果一致。"""
        stream = ps_pack() + ps_video_pes(IDR, 3600) + ps_pack() + ps_video_pes(IDR, 7200)
        whole = m.PSDemuxer()
        want = whole.feed(stream) + whole.flush()
        drip = m.PSDemuxer()
        got = []
        for i in range(len(stream)):
            got += drip.feed(stream[i:i + 1])
        got += drip.flush()
        self.assertEqual([(f.data, f.pts) for f in got], [(f.data, f.pts) for f in want])


# ---------------------------------------------------------------------------
# SDP / MediaInfo
# ---------------------------------------------------------------------------
class TestParseSDP(unittest.TestCase):
    def test_h264_sprop(self):
        sdp = ("v=0\nm=video 0 RTP/AVP 96\na=rtpmap:96 H264/90000\n"
               "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LgFNoFglE=,aM48gA==\n")
        info = m.parse_sdp(sdp)
        self.assertEqual(info.codec, "H264")
        self.assertEqual(info.clock_rate, 90000)
        self.assertEqual(len(info.parameter_sets), 2)

    def test_mediainfo_header(self):
        """MEDIAINFO 头（a=Media_header:MEDIAINFO=<hex>）覆盖 rtpmap，给出容器与编码。
        头里没有分辨率，所以在看到码流内 SPS 之前 width/height 必须是 0。"""
        hdr = bytearray(40)
        hdr[:4] = b"IMKH"
        hdr[8] = 2   # container = PS
        hdr[10] = 5  # codec = H265
        sdp = ("v=0\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\n"
               "a=Media_header:MEDIAINFO=" + hdr.hex() + ";\n")
        info = m.parse_sdp(sdp)
        self.assertEqual(info.container, "PS")
        self.assertEqual(info.codec, "H265")
        self.assertEqual(info.clock_rate, 90000)
        self.assertEqual((info.width, info.height), (0, 0))

    def test_unknown_media_header_magic(self):
        """真机 SDP：40 字节 MEDIAINFO 头，magic 是 HVAG 不是 IMKH，本客户端没有它的
        字段布局。留空是对的——瞎猜字段更糟——之后由码流嗅探补回容器与编码。"""
        sdp = ("v=0\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\n"
               "a=Media_header:MEDIAINFO=4856414701010000C400C001C002000000000000000000006462333"
               "3000000000000000000000000;\n")
        info = m.parse_sdp(sdp)
        self.assertEqual(info.container, "")
        self.assertEqual(info.codec, "")

    def test_ps_ignores_audio_clock(self):
        """真机 1080p SDP：video m-line 上写着 PCMA/8000。PS 时间戳恒为 90kHz，
        照抄 8000 会把 25fps 的流算成 2.22fps。"""
        sdp = ("v=0\nm=video 0 RTP/AVP 8\na=rtpmap:8 PCMA/8000\n"
               "a=Media_header:MEDIAINFO=494D4B48000000000200050011710110401F000000FA0000000000"
               "00000000000000000000000000;\n")
        info = m.parse_sdp(sdp)
        self.assertEqual((info.container, info.codec), ("PS", "H265"))
        self.assertEqual(info.clock_rate, 90000)


# ---------------------------------------------------------------------------
# SPS 解析 / 编码嗅探
# ---------------------------------------------------------------------------
class TestSPS(unittest.TestCase):
    def test_h264_high_profile_scaling_lists(self):
        """真机 High profile 设备原样采下来的 SPS（不是手搓的：要防的就是
        scaling_list() 读错，手搓会按解析器自己那套错规则写出来）。这台设备的六张
        缩放表提前终止——每张 20 位，不是 16 个 se(v)。按固定长度读会越过 NAL 尾，
        整条会话分辨率恒为 0x0。"""
        sps = bytes([
            0x67, 0x64, 0x00, 0x1F, 0xAD, 0x84, 0x01, 0x0C, 0x20, 0x08, 0x61, 0x00,
            0x43, 0x08, 0x02, 0x18, 0x40, 0x10, 0xC2, 0x00, 0x84, 0x3B, 0x70, 0x28,
            0x02, 0xDD, 0x37, 0x01, 0x01, 0x01, 0x40, 0x00, 0x00, 0x03, 0x00, 0x40,
            0x00, 0x00, 0x0C, 0xA1, 0x00,
        ])
        self.assertEqual(m.parse_h264_sps_bytes(sps), (1280, 720))

    def test_h265_sps(self):
        self.assertEqual(m.parse_h265_sps_bytes(h265_sps(1920, 1080)), (1920, 1080))

    def test_strip_emulation_prevention(self):
        self.assertEqual(
            m.strip_emulation_prevention(bytes([0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x03, 0x02])),
            bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x02]))

    def test_recover_resolution_in_stream(self):
        """PS/H265 流的 SDP 里没有 sprop，分辨率只能从访问单元里的 SPS NAL 还原。"""
        au = b"\x00\x00\x00\x01" + h265_sps(1280, 720) + b"\x00\x00\x00\x01\x26\x01"
        width, height, sps, ok = m.recover_resolution(au, "H265")
        self.assertTrue(ok)
        self.assertEqual((width, height), (1280, 720))
        # 返回的必须是单条 SPS NAL，不是关键帧的其余部分
        self.assertLess(len(sps), 128)
        self.assertEqual((sps[3] >> 1) & 0x3F, 33)


class TestSniffCodec(unittest.TestCase):
    def test_sniff(self):
        cases = [
            ("h264 sps", bytes([0, 0, 0, 1, 0x67, 0x42, 0x00, 0x29, 0, 0, 0, 1, 0x68, 0xCA]), "H264"),
            ("h264 sps ref_idc 1", bytes([0, 0, 1, 0x27, 0x42, 0x00, 0x29]), "H264"),
            ("h265 vps", bytes([0, 0, 0, 1, 0x40, 0x01, 0x0C, 0x01, 0, 0, 0, 1, 0x42, 0x01]), "H265"),
            ("h265 sps only", bytes([0, 0, 1, 0x42, 0x01, 0x01, 0x01, 0x60]), "H265"),
            # 只有 slice 的访问单元说明不了编码，调用方在后续单元上重试
            ("h264 non-idr slice", bytes([0, 0, 0, 1, 0x41, 0x9A, 0x00]), ""),
            ("no start code", bytes([0x67, 0x42, 0x00, 0x29]), ""),
            ("truncated after start code", bytes([0, 0, 1]), ""),
        ]
        for name, data, want in cases:
            with self.subTest(name):
                self.assertEqual(m.sniff_codec(data), want)

    def test_analyze_frame(self):
        self.assertTrue(m.analyze_frame(bytes([0, 0, 0, 1, 0x65, 0x88]), "H264"))
        self.assertFalse(m.analyze_frame(bytes([0, 0, 0, 1, 0x41, 0x9A]), "H264"))
        self.assertTrue(m.analyze_frame(bytes([0, 0, 0, 1, 0x26, 0x01]), "H265"))
        self.assertFalse(m.analyze_frame(bytes([0, 0, 0, 1, 0x02, 0x01]), "H265"))


# ---------------------------------------------------------------------------
# 真机样本回放（与 go-client 的 TestReplaySamples 断同一组数字）
# ---------------------------------------------------------------------------
SAMPLE_CASES = [
    # dir, codec, frames, keys, width, height, sps_nal
    ("ps_h265_720p", "H265", 611, 25, 1280, 720, 33),
    ("ps_h265_1080p", "H265", 614, 13, 1920, 1080, 33),
    ("ps_h264_720p", "H264", 655, 26, 1280, 720, 7),
    ("ps_h264_1080p", "H264", 199, 8, 1920, 1080, 7),
]


class TestReplaySamples(unittest.TestCase):
    """回放归档的真机采集。合成用例只能证明解析器自洽，这些是摄像机真发过的字节。

    数字与 go-client 的同名用例逐个对齐：两套实现跑同一批字节必须给出同一个结果，
    任一侧的解析改坏了，这里就对不上。
    """

    def test_replay(self):
        for name, codec, want_frames, want_keys, width, height, sps_nal in SAMPLE_CASES:
            with self.subTest(name):
                path = os.path.join(SAMPLES, name, "stream.ps")
                if not os.path.exists(path):
                    self.skipTest(f"样本 {path} 不存在")
                with open(path, "rb") as fh:
                    raw = fh.read()
                # 样本走 Git LFS：没 pull 时文件在但内容是指针
                if raw.startswith(b"version https://git-lfs"):
                    self.skipTest(f"样本 {path} 是未拉取的 LFS 指针，请先 git lfs pull")

                # 按 16KiB 分块喂入，模拟 WebSocket 层切开访问单元的方式
                d = m.PSDemuxer()
                frames = []
                for off in range(0, len(raw), 16 << 10):
                    frames.extend(d.feed(raw[off:off + (16 << 10)]))
                frames.extend(d.flush())
                self.assertEqual(len(frames), want_frames, "帧数")

                keys, with_pts, prev_pts = 0, 0, 0
                for i, f in enumerate(frames):
                    if m.analyze_frame(f.data, codec):
                        keys += 1
                    if f.has_pts:
                        with_pts += 1
                        if with_pts > 1:
                            self.assertGreaterEqual(f.pts, prev_pts, f"帧 {i} 的 PTS 倒退")
                        prev_pts = f.pts
                    # 每个访问单元都必须落在 annex-b 起始码上。PES 头长度读错最先在
                    # 这里现形：负载要么多了段垃圾前缀，要么丢了开头几个字节。
                    self.assertTrue(f.data.startswith(b"\x00\x00\x00\x01")
                                    or f.data.startswith(b"\x00\x00\x01"),
                                    f"帧 {i} 不是以起始码开头：{f.data[:8].hex()}")
                self.assertEqual(keys, want_keys, "关键帧数")
                self.assertEqual(with_pts, want_frames, "带 PTS 的帧数")

                got = next((m.recover_resolution(f.data, codec) for f in frames
                            if m.recover_resolution(f.data, codec)[3]), None)
                self.assertIsNotNone(got, "没有从码流里还原出分辨率")
                got_w, got_h, sps, _ = got
                self.assertEqual((got_w, got_h), (width, height), "分辨率")
                self.assertTrue(0 < len(sps) <= 128, "还原出的应该是单条 SPS NAL")
                nal = (sps[3] >> 1) & 0x3F if codec == "H265" else sps[3] & 0x1F
                self.assertEqual(nal, sps_nal, "还原出的 NAL 类型")


# ---------------------------------------------------------------------------
# 客户端接线（hik_ws_client 需要 pycryptodome / websockets，缺了就跳过）
# ---------------------------------------------------------------------------
try:
    from hik_ws_client import HikConfig, HikMediaClient
except ImportError:  # pragma: no cover
    HikMediaClient = None


@unittest.skipIf(HikMediaClient is None, "缺少 pycryptodome/websockets，跳过客户端接线用例")
class TestClientWiring(unittest.TestCase):
    """验证 HikMediaClient 把消息真的送过了 RTP 判定 → PS 解复用 → 帧交付这条链路。

    媒体层自己的正确性由上面的用例保证；这里只查接线：链路断在哪一环，
    上面的用例都还是全绿的。
    """

    def _client(self):
        cfg = HikConfig(proxy_host="h", proxy_port=443, proxy_path="/proxy/1.2.3.4:80",
                        device_ip="1.2.3.4", device_port=80)
        c = HikMediaClient(cfg)
        c._reset_media_state()
        return c

    def test_bare_ps_is_demuxed_and_described(self):
        """走的是 HVAG 那一类设备的路径：MEDIAINFO 头解不出来，容器、编码、分辨率
        三样都得由码流自己补出来。"""
        c = self._client()
        c._media_info = m.parse_sdp(
            "v=0\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\n"
            "a=Media_header:MEDIAINFO=4856414701010000C400C001C002000000000000000000006462333"
            "3000000000000000000000000;\n")
        self.assertEqual((c._media_info.container, c._media_info.codec), ("", ""))
        frames = []
        c.on_frame = lambda meta, data: frames.append((meta, data))
        au = b"\x00\x00\x00\x01" + h265_sps(1280, 720) + b"\x00\x00\x00\x01\x26\x01"
        c._feed_video(ps_pack() + ps_video_pes(au, 3600))
        c._feed_video(ps_pack() + ps_video_pes(au, 7200))
        c._flush_media()

        self.assertEqual(len(frames), 2)
        meta, data = frames[0]
        self.assertEqual(data, au)
        self.assertEqual(meta.frame_index, 1)
        self.assertTrue(meta.is_key_frame)
        self.assertEqual(meta.codec, "H265")
        self.assertEqual((meta.width, meta.height), (1280, 720))
        self.assertTrue(meta.has_pts)
        self.assertEqual(meta.pts, 3600)
        # 嗅探结论要写回 MediaInfo：对 HVAG 那类设备这是容器的唯一来源，
        # 它隐含的 90kHz 时钟又是 PTS 能换算成帧率的前提
        self.assertEqual(c._media_info.container, "PS")
        self.assertEqual(c._media_info.clock_rate, 90000)
        # 最后一帧只有 flush 才放得出来（一个 pack 关掉上一帧）
        self.assertEqual(frames[1][0].frame_index, 2)
        self.assertEqual(frames[1][0].pts, 7200)

    def test_rtp_wrapped_ps_is_de_encapsulated(self):
        """代理把 PS 塞进 RTP 时，12 字节头必须在进解复用器之前剥掉，
        否则头会被拼进码流，而帧数一切正常。"""
        c = self._client()
        frames = []
        c.on_frame = lambda meta, data: frames.append(data)
        body1 = ps_pack() + ps_video_pes(IDR, 3600)
        body2 = ps_pack() + ps_video_pes(IDR, 7200)
        rtp1 = bytes([0x80, 0x60, 0x2C, 0x25, 0, 0, 0, 0, 0x69, 0x54, 0xD8, 0x56]) + body1
        rtp2 = bytes([0x80, 0x60, 0x2C, 0x26, 0, 0, 0, 0, 0x69, 0x54, 0xD8, 0x56]) + body2
        c._feed_video(rtp1)
        c._feed_video(rtp2)
        c._flush_media()
        self.assertEqual(frames, [IDR, IDR])

    def test_on_video_data_receives_demuxed_frames(self):
        """只设了 on_video_data 的老调用方（demo.py / play.py）收到的是可直接喂
        解码器的基本流，不再是原始传输块。"""
        c = self._client()
        got = []
        c.on_video_data = got.append
        c._feed_video(ps_pack() + ps_video_pes(IDR, 3600))
        c._flush_media()
        self.assertEqual(got, [IDR])

    def test_reset_between_sessions(self):
        """run_forever 在同一个对象上重连：上一会话的 RTP 判定和 PS 半帧不能带过来。"""
        c = self._client()
        c._feed_video(ps_pack() + ps_video_pes(IDR, 3600))
        self.assertIsNotNone(c._ps)
        c._reset_media_state()
        self.assertIsNone(c._ps)
        self.assertFalse(c._container_known)
        self.assertEqual(c._frame_index, 0)


# ---------------------------------------------------------------------------
# 单帧多协议消息的传输层接线（同样需要 pycryptodome / websockets）
#
# 循环解包本身由上面的 TestIterMessages 无条件覆盖；这里只查接线：
# receive_message 一次只返回一个元组，同帧内的第 2..N 条是否真的还交付得出来。
# ---------------------------------------------------------------------------
def ws_frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    """手写一个服务器→客户端的 WebSocket 帧（不掩码，RFC 6455 §5.2）。

    只支持 <126 字节的净荷，够用；不复用实现里的 _make_ws_frame——那个是客户端帧
    构造器（带掩码），与实现同源的构造器会跟着实现一起把字段摆错。
    """
    assert len(payload) < 126
    return bytes([(0x80 if fin else 0x00) | opcode, len(payload)]) + payload


def protocol_msg(msg_type: int, payload: bytes) -> bytes:
    """手写 5 字节协议头：1 字节类型 + 4 字节大端长度。"""
    return bytes([msg_type]) + len(payload).to_bytes(4, "big") + payload


class _EOFReader:
    """buffer 之外没有更多字节：读 socket 一律 EOF。"""

    async def read(self, _n):
        return b""


@unittest.skipIf(HikMediaClient is None, "缺少 pycryptodome/websockets，跳过客户端接线用例")
class TestMultiMessageFrameWiring(unittest.TestCase):
    VIDEO = 0x40
    AUDIO = 0x41

    def _client(self):
        cfg = HikConfig(proxy_host="h", proxy_port=443, proxy_path="/proxy/1.2.3.4:80",
                        device_ip="1.2.3.4", device_port=80)
        return HikMediaClient(cfg)

    def _drain(self, wire: bytes, count: int):
        """把 wire 当成已经收在 buffer 里的字节，连续取 count 条消息。

        socket 一侧接的是 EOF：消息本该从 buffer 里取到，取不到才会去读 socket。
        真丢了消息时结果里会出现 ``("EOF", None)``，一眼能看出丢在第几条。
        """
        c = self._client()
        c.connected = True
        c.buffer = bytearray(wire)
        c.reader = _EOFReader()

        async def collect():
            got = []
            for _ in range(count):
                try:
                    got.append(await c.receive_message())
                except ConnectionError:
                    got.append(("EOF", None))
            return got

        return c, asyncio.run(collect())

    def test_all_messages_in_one_frame_are_delivered(self):
        """单帧内视频 + 音频 + 视频：三条都要按顺序交付，一条都不能少。"""
        wire = ws_frame(0x02, protocol_msg(self.VIDEO, b"AAAA")
                        + protocol_msg(self.AUDIO, b"pcm")
                        + protocol_msg(self.VIDEO, b"BBBB"))
        _, got = self._drain(wire, 3)
        self.assertEqual(got, [(self.VIDEO, b"AAAA"),
                               (self.AUDIO, b"pcm"),
                               (self.VIDEO, b"BBBB")])

    def test_queued_messages_come_before_the_next_frame(self):
        """排队的第 2 条必须先于下一个 WS 帧的第 1 条交付，否则就是乱序。"""
        wire = (ws_frame(0x02, protocol_msg(self.VIDEO, b"A1") + protocol_msg(self.VIDEO, b"A2"))
                + ws_frame(0x02, protocol_msg(self.VIDEO, b"B1")))
        _, got = self._drain(wire, 3)
        self.assertEqual(got, [(self.VIDEO, b"A1"), (self.VIDEO, b"A2"), (self.VIDEO, b"B1")])

    def test_tail_that_cannot_be_unpacked_is_raw_video(self):
        """消费掉一条之后解不出来的尾巴，按原始视频交付（WS_OP_BINARY 在 run() 里
        与协议视频走同一条喂入路径，等价于 Go 的 evVideo）。"""
        tail = bytes([0x00, 0x00, 0x01, 0xBA])
        wire = ws_frame(0x02, protocol_msg(self.VIDEO, b"AAAA") + tail)
        c, got = self._drain(wire, 2)
        self.assertEqual(got, [(self.VIDEO, b"AAAA"), (c.WS_OP_BINARY, tail)])

    def test_whole_frame_unparseable_unchanged(self):
        """整帧就解不出来时行为不变：整段当原始视频。"""
        raw = bytes([0x00, 0x00, 0x00, 0x01, 0x65, 0x88])
        c, got = self._drain(ws_frame(0x02, raw), 1)
        self.assertEqual(got, [(c.WS_OP_BINARY, raw)])

    def test_fragmented_frame_multi_message(self):
        """分片重组后的多消息帧走的是另一个 _dispatch_data_frame 调用点，
        只修非分片那条路就是留一半的洞。"""
        batch = protocol_msg(self.VIDEO, b"AAAA") + protocol_msg(self.VIDEO, b"BBBB")
        wire = ws_frame(0x02, batch[:7], fin=False) + ws_frame(0x00, batch[7:], fin=True)
        _, got = self._drain(wire, 2)
        self.assertEqual(got, [(self.VIDEO, b"AAAA"), (self.VIDEO, b"BBBB")])

    def test_handshake_queue_survives_into_stream_loop(self):
        """握手阶段（authenticate）与取流主循环是同一个 receive_message 的两个消费方；
        握手那一帧里排上队的后续消息，进主循环后必须还取得到。"""
        wire = ws_frame(0x01, b'{"errorCode":0}') + ws_frame(
            0x02, protocol_msg(self.VIDEO, b"AAAA") + protocol_msg(self.VIDEO, b"BBBB"))
        c, got = self._drain(wire, 3)
        self.assertEqual(got, [(c.WS_OP_TEXT, b'{"errorCode":0}'),
                               (self.VIDEO, b"AAAA"), (self.VIDEO, b"BBBB")])

    def test_close_clears_pending_queue(self):
        """重连走的是同一个对象：上一会话没取完的排队消息不能带进新会话。"""
        wire = ws_frame(0x02, protocol_msg(self.VIDEO, b"AAAA") + protocol_msg(self.VIDEO, b"BBBB"))
        c, _ = self._drain(wire, 1)
        self.assertTrue(c._pending_messages, "第 2 条应当还排在队里")
        asyncio.run(c.close())
        self.assertFalse(c._pending_messages)


if __name__ == "__main__":
    unittest.main()
