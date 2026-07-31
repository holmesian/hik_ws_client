#!/usr/bin/env python3
"""
海康威视视频流媒体解析层 (Video stream media-parsing layer)

把 WebSocket 上收到的二进制帧还原成视频访问单元（AU）。这一层是 Go 版
``go-client`` 的 Python 移植，复用了同一批真机采集撞出来的修复。

关键教训（每条都来自线上实测，不是文档推测）：

* **RTP 判定必须会话级、跨多条消息互证，且容忍首包被拆成两条消息。** 逐条消息
  判定会把裸 PS 续传消息（任意字节有 1/4 概率高两位是 ``0b10``）误判成 RTP，静默
  砍掉每四条消息里一条的 12 字节头，帧数/关键帧数/分辨率却全对，只有严格走查才看得
  见。代理还会把首个 RTP 包拆成 8192 + 12 两条，第二条是包中段，因此"相邻两条互证"
  也不够——要在前 4 条里找一对。
* **MPEG-PS 嗅探接受任意起始码（``>= 0xB9``），不能只认 ``00 00 01 ba``。** 直播是从
  流的任意位置接进去的，一台设备从音频 PES（``00 00 01 c0``）处开流，只认 pack 头会
  整条会话被判成非 PS，原始传输块直接当帧下发。
* **PS 解复用必须跳过 ``private_stream_1``（0xBD）。** 它自带 PTS，当成视频既会把密文
  拼进码流、又会取错帧时间戳，而计数一切正常。82/94 台设备每秒插一条，验不出内容
  （ECB 加密），所以解复用器只跳过它，不解析、不外露。
* **SPS 的 ``scaling_list`` 不能按固定长度读 se(v)。** 表提前终止（delta_scale 为 0）
  时按固定长度读会越过 NAL 尾，一台 720p High profile 设备分辨率恒为 0x0。
* **PS 时钟恒为 90kHz，不能采信 SDP 的 rtpmap。** 有的设备在 video m-line 上写
  ``a=rtpmap:8 PCMA/8000``，照抄把 25fps 算成 2.22fps。
* **协议封包的长度字段来自网络，必须先扩成宽整数再做边界检查**，否则一个
  ``0xFFFFFFFB`` 会让 ``5 + length`` 回绕成 0（Go 的 uint32 里）而 panic。

模块只依赖标准库，方便在不需要加解密的环境（如单元测试）下直接 import。
"""

from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# MPEG-PS 起始码（00 00 01 之后的那个字节）
# ---------------------------------------------------------------------------
PS_END_CODE = 0xB9       # program end；容器用到的最小 ID
PS_PACK_START = 0xBA    # pack header —— 一个访问单元的起点
PS_SYSTEM_START = 0xBB  # system header / PSM / 所有 PES 都 >= 此值
PES_VIDEO_FIRST = 0xE0
PES_VIDEO_LAST = 0xEF

RTP_FIXED_HEADER = 12
RTP_PROBE_MESSAGES = 4  # 在前几条消息里找一对互证的 RTP 包

START_CODE = b"\x00\x00\x01"


# ---------------------------------------------------------------------------
# 协议封包（5 字节头：1 字节类型[最高位=加密] + 4 字节大端长度）
# ---------------------------------------------------------------------------
def unpack_message(data: bytes) -> Tuple[Optional[int], Optional[bytes], bytes]:
    """解包海康威视协议消息。

    返回 ``(msg_type, payload, remaining)``。数据不足 5 字节、或声明的长度超过可用
    字节时，返回 ``(None, None, data)``（原样返回由调用方决定是否当原始视频处理）。

    Python 的整数无宽度限制，所以 ``5 + length`` 不会像 Go 的 uint32 那样回绕，本函数
    天然不会因恶意长度而崩溃——但声明长度超过实际字节时仍必须返回 None，不能切开返回。
    """
    if len(data) < 5:
        return None, None, data
    msg_type = data[0]
    length = int.from_bytes(data[1:5], "big")  # 已经是任意精度，无回绕风险
    if len(data) < 5 + length:
        return None, None, data
    payload = data[5:5 + length]
    remaining = data[5 + length:]
    return msg_type, payload, remaining


def iter_messages(data: bytes) -> Iterator[Tuple[Optional[int], bytes]]:
    """把一段字节里串联的协议消息**全部**解出来，逐条产出 ``(msg_type, payload)``。

    一个 WebSocket 帧里可以串多条协议消息，只解第一条就是静默丢帧——设备把视频和
    音频打包进同一帧时，丢的是整条音轨。必须消费到尾。

    某处解不出来（头不完整或声明长度超过剩余字节）时，把**剩下的整段**作为
    ``(None, tail)`` 产出后停止，由调用方按原始视频处理；这与 Go ``client.go`` 读
    循环里 ``Unpack`` 失败即 ``emit(evVideo, buf); break`` 是同一语义。``data`` 为空
    时不产出任何东西。
    """
    while data:
        msg_type, payload, remaining = unpack_message(data)
        if msg_type is None:
            yield None, data
            return
        yield msg_type, payload
        data = remaining


# ---------------------------------------------------------------------------
# 容器嗅探
# ---------------------------------------------------------------------------
def is_ps_data(b: bytes) -> bool:
    """判断 b 是否以 MPEG-PS 起始码开头。

    接受任意 PS 起始码（``>= 0xB9``），不能只认 pack 头 ``0xBA``：直播从流的任意位置
    接进去，首条消息可能落在音频 PES（``0xC0``）甚至 program end（``0xB9``）上。裸
    annex-b 基本流的 NAL 头最高位恒为 0，永远到不了容器用的高 ID，因此这道下限不会把
    基本流误判成容器。
    """
    return len(b) >= 4 and b[0] == 0 and b[1] == 0 and b[2] == 1 and b[3] >= PS_END_CODE


# ---------------------------------------------------------------------------
# MPEG-PS 解复用
# ---------------------------------------------------------------------------
class PSDemuxer:
    """从海康 MPEG-PS 容器里重组视频基本流。

    设备的单个 NAL 会被拆到多个 PES 包里，所以原始载荷不能当 annex-b 扫起始码——既会
    漏掉真 NAL，又会把 PES stream_id 误当成 NAL 头。一个 PS pack 正好承载一个访问单元，
    所以 pack 头关掉上一帧：天然一帧延迟，流结束必须 Flush。

    #PrivateStream：0xBD 私有流被跳过（见模块顶注释）。
    """

    def __init__(self):
        self._buf = bytearray()
        self._au = bytearray()
        self._pts = 0
        self._has_pts = False
        self._synced = False  # 是否见过 pack 头；之前收到的是本会话没见过的残帧

    def feed(self, data: bytes) -> List["_Frame"]:
        self._buf.extend(data)
        out: List[_Frame] = []
        off = 0
        while off < len(self._buf):
            n, frame, ok = self._step(self._buf[off:])
            if not ok:
                break
            if frame is not None:
                out.append(frame)
            off += n
        del self._buf[:off]
        return out

    def _step(self, b: bytes):
        """解析一个容器单元，返回 (消费字节数, 完成的访问单元或 None, 是否继续)。"""
        if len(b) < 4:
            return 0, None, False
        if b[0] | b[1] != 0 or b[2] != 0x01:
            # 不在起始码上：resync，保留末尾 2 字节（可能是被截断的起始码头）
            idx = b.find(START_CODE)
            if idx >= 0:
                return idx, None, True
            return len(b) - 2, None, True

        sid = b[3]
        if sid == PS_PACK_START:
            if len(b) < 14:
                return 0, None, False
            n = 14 + (b[13] & 0x07)
            if len(b) < n:
                return 0, None, False
            f = self._close_au()
            self._synced = True
            return n, f, True
        elif sid >= PS_SYSTEM_START:
            # system header / PSM / 所有 PES 都是 6 字节长度前缀形式
            if len(b) < 6:
                return 0, None, False
            n = 6 + int.from_bytes(b[4:6], "big")
            if len(b) < n:
                return 0, None, False
            if PES_VIDEO_FIRST <= sid <= PES_VIDEO_LAST:
                self._append_pes(b[6:n])
            return n, None, True
        else:
            # 非容器起始码（散落的 NAL 前缀）：跳过
            return 3, None, True

    def flush(self) -> List["_Frame"]:
        f = self._close_au()
        return [f] if f is not None else []

    def _close_au(self):
        if len(self._au) == 0:
            return None
        f = _Frame(bytes(self._au), self._pts, self._has_pts)
        self._au = bytearray()
        self._pts = 0
        self._has_pts = False
        return f

    def _append_pes(self, b: bytes):
        # 直播从任意位置接入：第一个 pack 头之前的 PES 是没见过头的访问单元的尾巴，
        # 拼出来是一帧解不出的残帧，还自带 PTS 让首帧时间戳偏早，丢掉。
        if not self._synced:
            return
        if len(b) < 3 or (b[0] & 0xC0) != 0x80:
            return
        hlen = b[2]
        if len(b) < 3 + hlen:
            return
        # PES 可选头是 3 字节（不是 2）：flags1 / PTS_DTS_flags / header_data_length。
        # 把长度当成第 2 字节读，会把 0x80 的 PTS 标志当成 128 字节头长。
        if b[1] & 0x80 != 0 and hlen >= 5 and not self._has_pts:
            self._pts = _read_pts(b[3:8])
            self._has_pts = True
        self._au.extend(b[3 + hlen:])


class _Frame:
    """一个从 PS 容器里还原出来的视频访问单元。"""
    __slots__ = ("data", "pts", "has_pts")

    def __init__(self, data: bytes, pts: int, has_pts: bool):
        self.data = data
        self.pts = pts
        self.has_pts = has_pts


def _read_pts(b: bytes) -> int:
    """从 5 字节 PES 时间戳字段解出 33 位 PTS。"""
    return ((b[0] >> 1) & 0x07) << 30 | \
        b[1] << 22 | \
        ((b[2] >> 1) & 0x7F) << 15 | \
        b[3] << 7 | \
        (b[4] >> 1)


# ---------------------------------------------------------------------------
# RTP 二次封装的检测与剥离
# ---------------------------------------------------------------------------
def rtp_header_plausible(b: bytes) -> bool:
    """b 是否可能是一个 RTP 包（只看版本字段 0b10）。"""
    return len(b) >= RTP_FIXED_HEADER and (b[0] >> 6) == 2


def rtp_strip(b: bytes) -> bytes:
    """剥离一个 RTP 包的固定头 + CSRC + 扩展头 + 尾部 padding。

    只剥离没副作用：当且仅当确认是 RTP 会话时才调用本函数。两份头都要剥——只剥固定头
    会在包中段留下 128 字节错位；只剥 padding 会留下尾字节。任一处不足则返回原样（说明
    这根本不是 RTP，由调用方回退到裸 PS/裸 annex-b，不会被误剥）。
    """
    if len(b) < RTP_FIXED_HEADER or (b[0] >> 6) != 2:
        return b
    n = RTP_FIXED_HEADER + 4 * (b[0] & 0x0F)  # CSRC 列表
    if b[0] & 0x10 != 0:  # 扩展头：2 字节 profile + 2 字节（以字为单位的）长度
        if len(b) < n + 4:
            return b
        n += 4 + 4 * int.from_bytes(b[n + 2:n + 4], "big")
    if n >= len(b):
        return b
    p = b[n:]
    if b[0] & 0x20 != 0:  # padding，由最后一个字节计数且含自身
        pad = p[-1]
        if pad == 0 or pad > len(p):
            return b
        p = p[:-pad]
    return p


def rtp_consecutive(a: bytes, b: bytes) -> bool:
    """b 是否是 a 的同一路 RTP 流的后续包：SSRC 相同，序号领先 a 不超过探测窗口。

    允许中间隔着被消息分片藏起来的包；上限挡掉"容器字节恰好撞上 48 位一致"的巧合。
    """
    if a[8:12] != b[8:12]:
        return False
    seq_a = int.from_bytes(a[2:4], "big")
    seq_b = int.from_bytes(b[2:4], "big")
    gap = (seq_b - seq_a) & 0xFFFF  # 16 位回绕，序号本就回绕
    return 1 <= gap <= RTP_PROBE_MESSAGES


def rtp_pair_found(msgs: List[bytes]) -> bool:
    """held 消息里是否含有同一路 RTP 的两个包。

    落在包中段的消息（首字节不是 RTP 头）直接跳过，所以只需要较早的那条是包起点——
    一对不要求相邻。
    """
    for i in range(len(msgs)):
        if not rtp_header_plausible(msgs[i]):
            continue
        for j in range(i + 1, len(msgs)):
            if rtp_header_plausible(msgs[j]) and rtp_consecutive(msgs[i], msgs[j]):
                return True
    return False


class RTPDetector:
    """整条会话只判定一次：媒体消息是否被 RTP 包裹，并把该判定应用到每条消息。

    判定是会话级、跨消息的：RTP 有恒定 SSRC 和 +1 递增的序号，裸 PS 字节在所有 48 位上
    一致的概率为零。首包可能被代理拆成两条消息，故在前 ``RTP_PROBE_MESSAGES`` 条里找一对。
    """

    def __init__(self):
        self._decided = False
        self._is_rtp = False
        self._held: List[bytes] = []

    def feed(self, b: bytes) -> List[bytes]:
        """返回已就绪可处理的载荷：held 期间无，判定后一次性全部返回。"""
        if self._decided:
            return [self._apply(b)]
        if len(self._held) == 0 and not rtp_header_plausible(b):
            # 第一条消息不可能是 RTP —— 常见情形：裸 PS 以 00 开头
            self._decided = True
            return [b]
        self._held.append(bytes(b))
        self._is_rtp = rtp_pair_found(self._held)
        if not self._is_rtp and len(self._held) < RTP_PROBE_MESSAGES:
            return []
        self._decided = True
        return self._release()

    def flush(self) -> List[bytes]:
        if not self._held:
            return []
        self._decided = True
        return self._release()

    def _release(self) -> List[bytes]:
        out = [self._apply(h) for h in self._held]
        self._held = []
        return out

    def _apply(self, b: bytes) -> bytes:
        return rtp_strip(b) if self._is_rtp else b


# ---------------------------------------------------------------------------
# SPS 分辨率解析
# ---------------------------------------------------------------------------
class _BitReader:
    """SPS 位解析用的极简大端位读取器。"""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_bit(self) -> int:
        byte_idx = self.pos // 8
        if byte_idx >= len(self.data):
            raise EOFError("sps truncated")
        bit = (self.data[byte_idx] >> (7 - (self.pos % 8))) & 1
        self.pos += 1
        return bit

    def read_bits(self, n: int) -> int:
        v = 0
        for _ in range(n):
            v = (v << 1) | self.read_bit()
        return v

    def read_ue(self) -> int:
        leading = 0
        while self.read_bit() == 0:
            leading += 1
            if leading > 31:
                raise ValueError("ue(v) too long")
        if leading == 0:
            return 0
        return (1 << leading) - 1 + self.read_bits(leading)

    def read_se(self) -> int:
        ue = self.read_ue()
        if ue % 2 == 0:
            return -((ue + 1) // 2)
        return (ue + 1) // 2


def strip_emulation_prevention(b: bytes) -> bytes:
    """去掉 H.264/H.265 NAL 的防竞争字节：00 00 之后紧跟的 0x03 是转义，必须丢。

    不剥会导致 SPS 里第一个 00 00 0x 之后的所有字段位偏移错位（实测把 1280x720 解析成
    2x1）。编码器只会在 00 00 之后插入 03，所以该位置的 03 一定是 EPB，不是真实数据。
    """
    if len(b) < 3:
        return b
    out = bytearray()
    for i, x in enumerate(b):
        if i >= 2 and x == 3 and b[i - 1] == 0 and b[i - 2] == 0:
            continue
        out.append(x)
    return bytes(out)


def _skip_scaling_list(br: _BitReader, size: int):
    """按规范消耗一个 scaling_list()：表提前终止时不能按固定长度读 se(v)。

    规范（H.264 7.3.2.1.1.1）只在 nextScale 非 0 时读 delta_scale，遇到 0 即提前结束，
    剩余表项是推断出来的、不编码。实测一台 720p High profile 相机，6 个 16 项表各编了
    20 bit 而非 16 个值，按固定长度读会越过 NAL 尾、分辨率恒为 0x0。
    """
    last_scale = next_scale = 8
    for _ in range(size):
        if next_scale != 0:
            delta = br.read_se()
            next_scale = (last_scale + delta + 256) % 256
        if next_scale != 0:
            last_scale = next_scale


def parse_h264_sps_bytes(raw: bytes) -> Tuple[int, int]:
    """从H.264 SPS NAL（含 1 字节 NAL 头）解出宽高。"""
    if len(raw) < 2:
        raise ValueError("sps too short")
    br = _BitReader(strip_emulation_prevention(raw[1:]))

    profile_idc = br.read_bits(8)
    br.read_bits(8)   # constraint flags + reserved
    br.read_bits(8)   # level_idc
    br.read_ue()      # seq_parameter_set_id

    chroma_format_idc = 1
    if profile_idc in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135):
        chroma_format_idc = br.read_ue()
        if chroma_format_idc == 3:
            br.read_bit()  # separate_colour_plane_flag
        br.read_ue()      # bit_depth_luma_minus8
        br.read_ue()      # bit_depth_chroma_minus8
        br.read_bit()     # qpprime_y_zero_transform_bypass_flag
        if br.read_bit() == 1:  # seq_scaling_matrix_present_flag
            count = 12 if chroma_format_idc == 3 else 8
            for i in range(count):
                if br.read_bit() == 1:  # scaling_list_present
                    size = 64 if i >= 6 else 16
                    _skip_scaling_list(br, size)

    br.read_ue()      # log2_max_frame_num_minus4
    poc_type = br.read_ue()
    if poc_type == 0:
        br.read_ue()  # log2_max_pic_order_cnt_lsb_minus4
    elif poc_type == 1:
        br.read_bit()                          # delta_pic_order_always_zero_flag
        br.read_se()                           # offset_for_non_ref_pic
        br.read_se()                           # offset_for_top_to_bottom_field
        num = br.read_ue()
        for _ in range(num):
            br.read_se()

    br.read_ue()      # max_num_ref_frames
    br.read_bit()     # gaps_in_frame_num_value_allowed_flag
    pic_width_mbs_minus1 = br.read_ue()
    pic_height_map_units_minus1 = br.read_ue()
    frame_mbs_only_flag = br.read_bit()
    if frame_mbs_only_flag == 0:
        br.read_bit()  # mb_adaptive_frame_field_flag
    br.read_bit()     # direct_8x8_inference_flag

    crop_l = crop_r = crop_t = crop_b = 0
    if br.read_bit() == 1:  # frame_cropping_flag
        crop_l = br.read_ue()
        crop_r = br.read_ue()
        crop_t = br.read_ue()
        crop_b = br.read_ue()

    width = (pic_width_mbs_minus1 + 1) * 16
    height = (2 - frame_mbs_only_flag) * (pic_height_map_units_minus1 + 1) * 16
    sub_wc = sub_hc = 1
    if chroma_format_idc == 1:
        sub_wc, sub_hc = 2, 2
    elif chroma_format_idc == 2:
        sub_wc, sub_hc = 2, 1
    width -= (crop_l + crop_r) * sub_wc
    height -= (crop_t + crop_b) * sub_hc
    if not (0 < width <= 8192 and 0 < height <= 8192):
        raise ValueError(f"implausible dimensions {width}x{height}")
    return width, height


def parse_h265_sps_bytes(raw: bytes) -> Tuple[int, int]:
    """从H.265 (HEVC) SPS NAL（含 2 字节 NAL 头）解出宽高。"""
    if len(raw) < 3:
        raise ValueError("h265 sps too short")
    br = _BitReader(strip_emulation_prevention(raw[2:]))

    br.read_bits(4)  # sps_video_parameter_set_id
    max_sub_layers_minus1 = br.read_bits(3)
    br.read_bit()    # sps_temporal_id_nesting_flag

    br.read_bits(8)    # profile_space + tier + profile_idc
    br.read_bits(32)   # profile_compatibility_flag
    br.read_bits(48)   # constraint_indicator
    br.read_bits(8)    # general_level_idc
    if max_sub_layers_minus1 > 0:
        sub_profile = 0
        sub_level = 0
        for _ in range(max_sub_layers_minus1):
            p = br.read_bit(); sub_profile = (sub_profile << 1) | p
            l = br.read_bit(); sub_level = (sub_level << 1) | l
        br.read_bits(2 * (8 - max_sub_layers_minus1))
        for i in range(max_sub_layers_minus1):
            if (sub_profile >> (max_sub_layers_minus1 - 1 - i)) & 1:
                br.read_bits(8 + 32 + 48 + 8)
            if (sub_level >> (max_sub_layers_minus1 - 1 - i)) & 1:
                br.read_bits(8)

    br.read_ue()                  # sps_seq_parameter_set_id
    chroma_format_idc = br.read_ue()
    if chroma_format_idc == 3:
        br.read_bit()            # separate_colour_plane_flag
    pic_width = br.read_ue()
    pic_height = br.read_ue()
    crop_l = crop_r = crop_t = crop_b = 0
    if br.read_bit() == 1:       # conf_win_flag
        crop_l = br.read_ue()
        crop_r = br.read_ue()
        crop_t = br.read_ue()
        crop_b = br.read_ue()

    sub_wc = sub_hc = 1
    if chroma_format_idc == 1:
        sub_wc, sub_hc = 2, 2
    elif chroma_format_idc == 2:
        sub_wc, sub_hc = 2, 1
    width = pic_width - (crop_l + crop_r) * sub_wc
    height = pic_height - (crop_t + crop_b) * sub_hc
    if not (0 < width <= 8192 and 0 < height <= 8192):
        raise ValueError(f"implausible h265 dimensions {width}x{height}")
    return width, height


def recover_resolution(data: bytes, codec: str):
    """在 annex-b 基本流（一个访问单元）里扫 SPS 并解出宽高。

    返回 ``(width, height, sps, ok)``。MEDIAINFO 头不带分辨率，PS 容器交付的是 annex-b，
    所以分辨率只能从码流内 SPS 还原。命中时 sps 是含起始码的整段 NAL，便于归档调试。
    """
    if not codec:
        return 0, 0, None, False
    is_h265 = codec == "H265"
    sps_type = 33 if is_h265 else 7
    i = 0
    while i < len(data):
        idx = data.find(START_CODE, i)
        if idx < 0:
            break
        nal_pos = idx + 3
        if nal_pos >= len(data):
            break
        b = data[nal_pos]
        ntype = (b >> 1) & 0x3F if is_h265 else b & 0x1F
        if ntype == sps_type:
            end = len(data)
            nxt = data.find(START_CODE, nal_pos)
            if nxt >= 0:
                end = nxt
                if end > nal_pos and data[end - 1] == 0:  # 4 字节起始码留了个尾零
                    end -= 1
            sps = data[idx:end]
            try:
                if is_h265:
                    w, h = parse_h265_sps_bytes(sps[3:])
                else:
                    w, h = parse_h264_sps_bytes(sps[3:])
            except (ValueError, EOFError):
                return 0, 0, None, False
            return w, h, sps, True
        i = nal_pos + 1
    return 0, 0, None, False


# ---------------------------------------------------------------------------
# 编码嗅探 / 关键帧判定
# ---------------------------------------------------------------------------
def sniff_codec(data: bytes) -> str:
    """从 annex-b 访问单元的 NAL 头推断编码。用于 MEDIAINFO 头解不出来的流。

    用参数集判定（两台编码的 NAL 头两种读法不会撞）：H.265 的 VPS/SPS/PPS 是
    layer 0 的 32/33/34 型，首字节读 0x40/0x42/0x44；H.264 的 SPS 是 type 7 且
    ref_idc 非 0，读 0x27/0x47/0x67。两者都每关键帧前重发，所以总能命中。
    """
    i = 0
    while i < len(data):
        idx = data.find(START_CODE, i)
        if idx < 0:
            break
        nal_pos = idx + 3
        if nal_pos >= len(data):
            break
        b = data[nal_pos]
        if b in (0x40, 0x42, 0x44):
            return "H265"
        if (b & 0x9F) == 7 and (b & 0x60) != 0:
            return "H264"
        i = nal_pos + 1
    return ""


def analyze_frame(data: bytes, codec: str) -> bool:
    """扫描 annex-b 帧是否含关键帧 NAL。codec 用于消歧（H.264/H.265 NAL 类型重叠）。"""
    is_h265 = codec == "H265"
    i = 0
    while i < len(data):
        idx = data.find(START_CODE, i)
        if idx < 0:
            break
        nal_pos = idx + 3
        if nal_pos >= len(data):
            break
        b = data[nal_pos]
        if is_h265:
            t = (b >> 1) & 0x3F
            if 16 <= t <= 21:  # IRAP
                return True
        elif (b & 0x1F) == 5:  # H.264 IDR
            return True
        i = nal_pos + 1
    return False


# ---------------------------------------------------------------------------
# SDP / MediaInfo
# ---------------------------------------------------------------------------
@dataclass
class FrameMeta:
    """单个还原出来的视频帧的描述。"""
    frame_index: int = 0
    is_key_frame: bool = False
    codec: str = ""
    width: int = 0
    height: int = 0
    pts: int = 0            # has_pts 为真时是容器的 90kHz PTS，否则是按到达时间合成的
    has_pts: bool = False   # PTS 是否来自容器
    timestamp_ms: int = 0   # 相对开流的墙钟毫秒


@dataclass
class MediaInfo:
    """流的描述信息（SDP 级）。"""
    sdp: str = ""
    container: str = ""   # PS / RTP / HIK / GB / RAW；空表示无 MEDIAINFO 头
    codec: str = ""       # H264 / H265
    clock_rate: int = 0
    width: int = 0
    height: int = 0
    parameter_sets: List[str] = None

    def __post_init__(self):
        if self.parameter_sets is None:
            self.parameter_sets = []


def parse_sdp(sdp: str) -> MediaInfo:
    """从 realplay 返回的 SDP 字符串解出 MediaInfo。字段解析失败也返回（尽量多填）。"""
    info = MediaInfo(sdp=sdp)
    media_header = ""
    for line in sdp.split("\n"):
        line = line.strip()
        if line.startswith("a=Media_header:MEDIAINFO="):
            media_header = line[len("a=Media_header:MEDIAINFO="):].rstrip(";")
        elif line.startswith("a=rtpmap:"):
            fields = line.split(None, 1)
            if len(fields) != 2:
                continue
            parts = fields[1].split("/", 1)
            if parts[0]:
                info.codec = parts[0].upper()
            if len(parts) == 2:
                try:
                    info.clock_rate = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith("a=fmtp:"):
            idx = line.find("sprop-parameter-sets=")
            if idx < 0:
                continue
            rest = line[idx + len("sprop-parameter-sets="):]
            if ";" in rest:
                rest = rest[:rest.index(";")]
            for ps in rest.split(","):
                ps = ps.strip()
                if ps:
                    info.parameter_sets.append(ps)
            if info.codec == "H264" and info.parameter_sets:
                try:
                    import base64
                    raw = base64.b64decode(info.parameter_sets[0])
                    w, h = parse_h264_sps_bytes(raw)
                    info.width, info.height = w, h
                except Exception:
                    pass

    _apply_media_header(info, media_header)
    if info.container == "PS":
        # PS 时间戳恒为 90kHz，与 rtpmap 无关（见模块顶注释）。
        info.clock_rate = 90000
    return info


def _apply_media_header(info: MediaInfo, hex_str: str):
    """解码 40 字节 IMKH 头（a=Media_header:MEDIAINFO=<hex> 的负载）。

    只取容器与编码字段；头不带分辨率（播放器从解码器拿）。magic 不是 IMKH（如 HVAG）
    则整段留空，由码流嗅探兜底——这正是线上有一整类设备解不出来的原因。
    """
    import binascii
    try:
        raw = binascii.unhexlify(hex_str.strip())
    except (ValueError, binascii.Error):
        return
    if len(raw) < 12 or raw[:4] != b"IMKH":
        return
    c = (raw[8], raw[9])
    if c == (2, 0):
        info.container = "PS"
    elif c == (1, 0):
        info.container = "HIK"
    elif c == (4, 0):
        info.container = "RTP"
    elif c == (8, 0):
        info.container = "GB"
    elif c == (16, 0):
        info.container = "RAW"
    cc = (raw[10], raw[11])
    if cc in ((1, 0), (0, 1)):
        info.codec = "H264"
    elif cc == (5, 0):
        info.codec = "H265"
