#!/usr/bin/env python3
"""
海康威视私有 WebSocket 协议客户端
Hikvision Private WebSocket Protocol Client

基于 h5player.min.js 和 Decoder.js 逆向分析实现

协议流程:
1. 通过 proxy URL 解析目标设备信息
2. 建立 media WebSocket 连接并发送认证请求
3. 使用服务器下发的 PKD、rand 生成密钥（仅用于会话鉴权，媒体负载本身不加密）
4. 接收媒体消息，交给 hik_media 还原成视频访问单元

本文件只管传输：WebSocket 帧、鉴权、协议封包、心跳与重连。RTP 判定/剥离、MPEG-PS
解复用、SPS 与 SDP 解析都在 hik_media 里（只依赖标准库，可单独测试）。

Author: Daikx (代可行)
"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import secrets
import socket
import ssl
import struct
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Optional

import hik_media

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class HikConfig:
    """海康威视连接配置"""
    # 代理服务器地址
    proxy_host: str
    proxy_port: int
    proxy_path: str  # e.g., "/proxy/[1111::2222]:559"

    # 目标设备信息（从 URL 路径解析）
    device_ip: str  # 可能是 IPv4 或 IPv6
    device_port: int

    # 认证信息
    username: str = "admin"
    password: str = ""

    # 连接参数
    version: str = "0.1"
    cipher_suites: int = 0


class HikCrypto:
    """海康威视加密工具类

    本类是全模块唯一依赖 pycryptodome 的地方，且只服务于鉴权握手；传输层
    （帧解析、消息分发、重连）不碰加密。因此 AES/pad 采用惰性导入——放在用到
    它们的方法内部，使本模块在未安装 pycryptodome 时仍可导入，传输层用例得以
    无条件运行。运行真实连接时 pycryptodome 依然是必需依赖。
    """

    # 海康固定 AES 密钥（JS 代码中硬编码）
    HIK_FIXED_KEY = bytes.fromhex('1234567891234567123456789123456712345678912345671234567891234567')
    HIK_FIXED_IV = bytes.fromhex('12345678912345671234567891234567')

    @staticmethod
    def aes_encrypt_cbc(plaintext: str, key_hex: str, iv_hex: str) -> str:
        """
        AES-128-CBC PKCS7 加密（与 CryptoJS 兼容）
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        pt = pad(plaintext.encode('utf-8'), AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pt).hex()

    @staticmethod
    def generate_client_iv_key() -> tuple:
        """
        生成客户端 iv 和 key
        iv = AES_Encrypt(timestamp, FIXED_KEY, FIXED_IV).hex
        key = AES_Encrypt(timestamp, FIXED_KEY, FIXED_IV).hex
        如果 < 64 字符则重复一次
        """
        now_ms = str(int(time.time() * 1000))
        iv = HikCrypto.aes_encrypt_cbc(now_ms, HikCrypto.HIK_FIXED_KEY.hex(), HikCrypto.HIK_FIXED_IV.hex())
        key = HikCrypto.aes_encrypt_cbc(now_ms, HikCrypto.HIK_FIXED_KEY.hex(), HikCrypto.HIK_FIXED_IV.hex())
        if len(iv) < 64:
            iv = iv + iv
        if len(key) < 64:
            key = key + key
        return iv, key

    @staticmethod
    def generate_realplay_key(iv: str, key: str, PKD: str) -> str:
        """
        生成 realplay 的 key 字段
        使用 Z.prototype.encrypt (自定义 PKCS1-v1.5) RSA 加密
        key = RSA_Encrypt(iv:key, PKD)
        """
        # 构建 plaintext: iv (doubled hex) + ':' + key (doubled hex)
        plaintext = f"{iv}:{key}"
        # 使用 Z.prototype.encrypt 实现
        pkd_bytes = bytes.fromhex(PKD)
        key_len = len(pkd_bytes)
        n_int = int.from_bytes(pkd_bytes, 'big')

        # JS Z.prototype.encrypt 的 PKCS1-v1.5 填充
        # 从后向前写 UTF-8 字节到缓冲区
        msg_utf8 = bytearray(plaintext.encode('utf-8'))
        block = bytearray(key_len)
        t = key_len
        i = len(msg_utf8) - 1
        while i >= 0:
            r = msg_utf8[i]
            i -= 1
            t -= 1
            block[t] = r

        # 写入 0x00 分隔符
        t -= 1
        block[t] = 0

        # 随机非零填充（从后向前，JS: e[--t] = q[i--]）
        while t > 2:
            t -= 1
            r = secrets.token_bytes(1)[0]
            while r == 0:
                r = secrets.token_bytes(1)[0]
            block[t] = r

        # 前缀 0x00 0x02
        block[1] = 0x02
        block[0] = 0x00

        # RSA 加密: m^e mod n, e=65537
        m_int = int.from_bytes(bytes(block), 'big')
        c_int = pow(m_int, 65537, n_int)
        return c_int.to_bytes(key_len, 'big').hex()

    @staticmethod
    def generate_authorization(rand: str, auth: str, key: str, iv: str) -> str:
        """
        生成 authorization 字段
        authorization = AES_Encrypt(rand + ':' + auth, key[:32], iv[:16])
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        plaintext = f"{rand}:{auth}"
        key_bytes = bytes.fromhex(key[:64])
        iv_bytes = bytes.fromhex(iv[:32])
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b'\x00')
        cipher = AES.new(key_bytes[:32], AES.MODE_CBC, iv_bytes)
        return cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size)).hex()

    @staticmethod
    def generate_token(token_plain: str, key: str, iv: str) -> str:
        """
        生成 token 字段
        token = AES_Encrypt(token_plain, key[:32], iv[:16])
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        key_bytes = bytes.fromhex(key[:64])
        iv_bytes = bytes.fromhex(iv[:32])
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b'\x00')
        cipher = AES.new(key_bytes[:32], AES.MODE_CBC, iv_bytes)
        return cipher.encrypt(pad(token_plain.encode('utf-8'), AES.block_size)).hex()


class HikProtocol:
    """海康威视协议常量"""

    # 消息类型
    MSG_TYPE_HELLO = 0x01
    MSG_TYPE_AUTH_REQUEST = 0x02
    MSG_TYPE_AUTH_RESPONSE = 0x03
    MSG_TYPE_KEY_EXCHANGE = 0x04
    MSG_TYPE_SESSION_ERROR = 0x05
    MSG_TYPE_KEEPALIVE = 0x06
    MSG_TYPE_VIDEO_DATA = 0x40
    MSG_TYPE_AUDIO_DATA = 0x41

    # 子消息类型（视频/音频数据的子类型）
    SUB_TYPE_STREAM_START = 0x01
    SUB_TYPE_STREAM_DATA = 0x02
    SUB_TYPE_STREAM_END = 0x03

    # 加密标志
    ENCRYPT_FLAG = 0x80  # 0x80 表示加密

    @staticmethod
    def pack_message(msg_type: int, data: bytes) -> bytes:
        """打包海康威视协议消息"""
        # 消息头 = 1字节类型 + 4字节长度
        header = struct.pack('>BI', msg_type, len(data))
        return header + data

    @staticmethod
    def unpack_message(data: bytes) -> tuple:
        """解包海康威视协议消息（转发到 hik_media，统一实现）"""
        return hik_media.unpack_message(data)


class HikWebSocketClient:
    """海康威视私有 WebSocket 客户端"""

    # WebSocket 帧类型
    WS_OP_CONTINUATION = 0x00
    WS_OP_TEXT = 0x01
    WS_OP_BINARY = 0x02
    WS_OP_CLOSE = 0x08
    WS_OP_PING = 0x09
    WS_OP_PONG = 0x0A

    # 网络参数
    READ_CHUNK_SIZE = 65536          # 单次读取大小（原 8192，增大以提升吞吐）
    MAX_BUFFER_SIZE = 64 * 1024 * 1024  # 接收缓冲上限，防止内存无限增长
    HANDSHAKE_TIMEOUT = 15.0         # 握手超时（秒）

    def __init__(self, config: HikConfig,
                 read_timeout: Optional[float] = 60.0,
                 keepalive_interval: Optional[float] = 20.0):
        self.config = config
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.session_id: str = ""
        self.connected = False
        self.secret_key: Optional[str] = None

        # 稳定性参数
        self.read_timeout = read_timeout          # 无数据读超时（None 表示不限制）
        self.keepalive_interval = keepalive_interval  # 心跳间隔（None 表示禁用）
        self._keepalive_task: Optional[asyncio.Task] = None

        # 回调函数
        self.on_video_data: Optional[Callable[[bytes], None]] = None
        self.on_audio_data: Optional[Callable[[bytes], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_connected: Optional[Callable[[], None]] = None

        # 缓冲区（bytearray 避免 bytes 拼接的重复拷贝）
        self.buffer = bytearray()

        # WebSocket 分片帧重组状态
        self._frag_opcode: Optional[int] = None
        self._frag_buffer = bytearray()

        # 同一个 WS 帧里可以串多条协议消息，而 receive_message 一次只交得出一条，
        # 第 2..N 条在这里排队等后续调用取走
        self._pending_messages: Deque[tuple] = deque()

        # 状态机
        self.state = "disconnected"

    # RFC 6455 WebSocket GUID
    WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def _make_websocket_handshake(self, path: str) -> bytes:
        """生成 WebSocket 握手请求"""
        # 生成 WebSocket key
        key_b64 = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
        # 计算期望的 Sec-WebSocket-Accept（RFC 6455: SHA1(key + GUID) 的 base64）
        self._expected_accept = base64.b64encode(
            hashlib.sha1(key_b64.encode('ascii') + self.WS_GUID).digest()
        ).decode('ascii')

        # 构建 HTTP 请求
        request = f"GET {path} HTTP/1.1\r\n"
        request += f"Host: {self.config.proxy_host}:{self.config.proxy_port}\r\n"
        request += "Upgrade: websocket\r\n"
        request += "Connection: Upgrade\r\n"
        request += f"Sec-WebSocket-Key: {key_b64}\r\n"
        request += "Sec-WebSocket-Version: 13\r\n"
        request += "Sec-WebSocket-Protocol: v1.0.0\r\n"
        request += "\r\n"

        return request.encode('ascii')

    def _verify_handshake_headers(self, http_header: bytes):
        """校验握手响应头（Accept 不匹配仅告警，兼容私有服务器实现）"""
        header_lines = http_header.decode('ascii', errors='replace').split('\r\n')
        accept = None
        protocol = None
        for line in header_lines[1:]:
            lower = line.lower()
            if lower.startswith('sec-websocket-accept:'):
                accept = line.split(':', 1)[1].strip()
            elif lower.startswith('sec-websocket-protocol:'):
                protocol = line.split(':', 1)[1].strip()

        if protocol:
            logger.info(f"WebSocket protocol: {protocol}")
        if accept and accept != getattr(self, '_expected_accept', None):
            logger.warning("Sec-WebSocket-Accept mismatch (continuing anyway)")

    def _make_ws_frame(self, opcode: int, payload: bytes) -> bytes:
        """生成 WebSocket 帧"""
        frame = bytearray()

        # 第一个字节: FIN + opcode
        frame.append(0x80 | opcode)

        # 第二个字节: MASK + payload length
        if len(payload) < 126:
            frame.append(0x80 | len(payload))
        elif len(payload) < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack('>H', len(payload)))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack('>Q', len(payload)))

        # 生成掩码密钥
        mask_key = secrets.token_bytes(4)
        frame.extend(mask_key)

        # 掩码 payload（使用大整数 XOR，比逐字节循环快一个数量级以上）
        if payload:
            n = len(payload)
            mask_full = (mask_key * (n // 4 + 1))[:n]
            masked = (int.from_bytes(payload, 'big') ^ int.from_bytes(mask_full, 'big')).to_bytes(n, 'big')
            frame.extend(masked)
        return bytes(frame)

    def _parse_ws_frame(self, data) -> tuple:
        """解析 WebSocket 帧

        返回 (opcode, payload, remaining, is_fin)；数据不完整时 opcode 为 None。
        """
        if len(data) < 2:
            return None, None, data, True

        # 解析第一个字节
        first_byte = data[0]
        opcode = first_byte & 0x0F
        is_fin = bool(first_byte & 0x80)

        # 解析第二个字节
        second_byte = data[1]
        is_masked = bool(second_byte & 0x80)
        payload_length = second_byte & 0x7F

        # 读取扩展长度
        offset = 2
        if payload_length == 126:
            if len(data) < 4:
                return None, None, data, True
            payload_length = struct.unpack('>H', bytes(data[2:4]))[0]
            offset = 4
        elif payload_length == 127:
            if len(data) < 10:
                return None, None, data, True
            payload_length = struct.unpack('>Q', bytes(data[2:10]))[0]
            offset = 10

        # 客户端帧需要掩码，服务器帧不掩码
        if is_masked:
            if len(data) < offset + 4 + payload_length:
                return None, None, data, True
            mask_key = bytes(data[offset:offset + 4])
            offset += 4
            raw = bytes(data[offset:offset + payload_length])
            if raw:
                n = len(raw)
                mask_full = (mask_key * (n // 4 + 1))[:n]
                payload = (int.from_bytes(raw, 'big') ^ int.from_bytes(mask_full, 'big')).to_bytes(n, 'big')
            else:
                payload = b''
        else:
            if len(data) < offset + payload_length:
                return None, None, data, True
            payload = bytes(data[offset:offset + payload_length])

        remaining = data[offset + payload_length:]

        return opcode, payload, remaining, is_fin

    async def connect(self, path: str) -> bool:
        """建立 WebSocket 连接"""
        try:
            # 建立 SSL/TLS 连接（wss:// 需要 TLS）
            logger.info(f"Connecting to {self.config.proxy_host}:{self.config.proxy_port}")
            ssl_ctx = ssl.create_default_context()
            # 海康服务器可能是自签名证书，禁用验证
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config.proxy_host,
                    self.config.proxy_port,
                    ssl=ssl_ctx
                ),
                timeout=self.HANDSHAKE_TIMEOUT
            )

            # 开启 TCP keepalive / 关闭 Nagle，降低延迟并及时感知断链
            try:
                sock = self.writer.get_extra_info('socket')
                if sock is not None:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

            # 发送 WebSocket 握手
            handshake_request = self._make_websocket_handshake(path)
            self.writer.write(handshake_request)
            await self.writer.drain()

            # 接收握手响应（循环读取直到出现完整 HTTP 头，避免响应被 TCP 分段截断）
            response = bytearray()
            deadline = asyncio.get_event_loop().time() + self.HANDSHAKE_TIMEOUT
            while True:
                remaining_time = deadline - asyncio.get_event_loop().time()
                if remaining_time <= 0:
                    logger.error("WebSocket handshake timeout")
                    return False
                chunk = await asyncio.wait_for(self.reader.read(8192), timeout=remaining_time)
                if not chunk:
                    logger.error("WebSocket handshake failed: connection closed by peer")
                    return False
                response.extend(chunk)
                header_end = response.find(b'\r\n\r\n')
                if header_end != -1:
                    break
                if len(response) > 65536:
                    logger.error("WebSocket handshake failed: header too large")
                    return False

            http_header = bytes(response[:header_end])
            # 头之后可能紧跟一个 WebSocket 帧，先存起来
            self.buffer = bytearray(response[header_end + 4:])
            self._frag_opcode = None
            self._frag_buffer = bytearray()
            self._pending_messages.clear()

            # 检查状态码
            status_line = http_header.decode('ascii', errors='replace').split('\r\n')[0]
            if not status_line.startswith('HTTP/1.1 101'):
                logger.error(f"WebSocket handshake failed: {status_line}")
                return False

            self._verify_handshake_headers(http_header)
            logger.info("WebSocket handshake successful")

            self.connected = True
            self.state = "connected"
            if self.on_connected:
                try:
                    self.on_connected()
                except Exception as e:
                    logger.warning(f"on_connected callback error: {e}")
            logger.info("Connection established")
            return True

        except asyncio.TimeoutError:
            logger.error("Connection timed out")
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    async def close(self):
        """关闭连接（可重复调用）"""
        self.connected = False
        self.state = "disconnected"

        # 停止心跳任务
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            self._keepalive_task = None

        if self.writer:
            try:
                # 发送 WebSocket 关闭帧
                close_frame = self._make_ws_frame(self.WS_OP_CLOSE, b'')
                self.writer.write(close_frame)
                await asyncio.wait_for(self.writer.drain(), timeout=2.0)
            except Exception:
                pass

            try:
                self.writer.close()
                await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
            except Exception:
                pass
            self.writer = None
            self.reader = None

        # 清理缓冲，避免旧数据影响下次连接
        self.buffer = bytearray()
        self._frag_opcode = None
        self._frag_buffer = bytearray()
        self._pending_messages.clear()

        logger.info("Connection closed")

    async def send_message(self, msg_type: int, payload: bytes):
        """发送消息（二进制协议消息）"""
        if not self.connected:
            raise Exception("Not connected")

        # 打包协议消息
        protocol_msg = HikProtocol.pack_message(msg_type, payload)

        # 包装 WebSocket 帧
        ws_frame = self._make_ws_frame(self.WS_OP_BINARY, protocol_msg)

        self.writer.write(ws_frame)
        await self.writer.drain()

    async def send_text(self, text: str):
        """发送 TEXT 帧（JSON 等文本数据）"""
        if not self.connected:
            raise Exception("Not connected")

        ws_frame = self._make_ws_frame(self.WS_OP_TEXT, text.encode('utf-8'))
        self.writer.write(ws_frame)
        await self.writer.drain()

    def _dispatch_data_frame(self, opcode: int, payload: bytes) -> tuple:
        """把一个完整的数据帧转换成 (msg_type, payload)，同帧内的后续消息入队。

        一个 BINARY 帧里可以串多条协议消息（设备会把视频和音频打进同一帧），
        只解第一条会把其余的静默丢掉。解包循环在 hik_media.iter_messages 里，
        这里只负责把结果接住：第一条直接返回，第 2..N 条排进 _pending_messages。
        """
        if opcode == self.WS_OP_TEXT:
            # 服务器用 TEXT 帧发送 JSON 协议消息
            return self.WS_OP_TEXT, payload

        # BINARY: 解不出协议头的部分当原始数据（可能是视频/RTP流）
        messages = [(self.WS_OP_BINARY if msg_type is None else msg_type, msg_payload)
                    for msg_type, msg_payload in hik_media.iter_messages(payload)]
        if not messages:
            # 空帧：没有任何消息可解，保持原有行为交给上层
            return self.WS_OP_BINARY, payload
        self._pending_messages.extend(messages[1:])
        return messages[0]

    async def receive_message(self) -> tuple:
        """接收消息（阻塞）

        返回 (msg_type, payload)；连接关闭时返回 (None, None)。
        支持 WebSocket 分片帧（continuation）重组。
        """
        while True:
            # 消费顺序：排队的同帧后续消息 → buffer 里的 WS 帧 → socket。
            # 顺序错了会乱序交付，甚至再次丢掉排在队里的消息。
            if self._pending_messages:
                return self._pending_messages.popleft()

            if not self.connected:
                break

            # 再尝试从 buffer 消费
            while self.buffer:
                opcode, payload, remaining, is_fin = self._parse_ws_frame(self.buffer)
                if opcode is None:
                    # buffer 中数据不完整，需要读取更多
                    break
                self.buffer = bytearray(remaining)

                if opcode == self.WS_OP_PING:
                    # 响应 PING
                    pong_frame = self._make_ws_frame(self.WS_OP_PONG, payload)
                    self.writer.write(pong_frame)
                    await self.writer.drain()
                    continue

                if opcode == self.WS_OP_PONG:
                    # 心跳应答，忽略
                    continue

                if opcode == self.WS_OP_CLOSE:
                    logger.info("Server closed connection")
                    self.connected = False
                    return None, None

                if opcode == self.WS_OP_CONTINUATION:
                    # 分片续帧
                    if self._frag_opcode is None:
                        logger.warning("Unexpected continuation frame, dropped")
                        continue
                    self._frag_buffer.extend(payload)
                    if len(self._frag_buffer) > self.MAX_BUFFER_SIZE:
                        logger.error("Fragmented message too large, dropping")
                        self._frag_opcode = None
                        self._frag_buffer = bytearray()
                        continue
                    if not is_fin:
                        continue
                    full_payload = bytes(self._frag_buffer)
                    frag_opcode = self._frag_opcode
                    self._frag_opcode = None
                    self._frag_buffer = bytearray()
                    return self._dispatch_data_frame(frag_opcode, full_payload)

                # TEXT / BINARY 数据帧
                if not is_fin:
                    # 分片首帧，缓存等待续帧
                    self._frag_opcode = opcode
                    self._frag_buffer = bytearray(payload)
                    continue

                return self._dispatch_data_frame(opcode, payload)

            if not self.connected:
                break

            # 缓冲区数据不完整，需要读取更多
            try:
                if self.read_timeout:
                    data = await asyncio.wait_for(
                        self.reader.read(self.READ_CHUNK_SIZE),
                        timeout=self.read_timeout
                    )
                else:
                    data = await self.reader.read(self.READ_CHUNK_SIZE)
            except asyncio.TimeoutError:
                raise ConnectionError(
                    f"Read timeout after {self.read_timeout}s (no data from server)")

            if not data:
                self.connected = False
                raise ConnectionError("Connection closed by peer")

            self.buffer.extend(data)
            if len(self.buffer) > self.MAX_BUFFER_SIZE:
                raise ConnectionError("Receive buffer overflow, closing connection")

        return None, None

    async def _keepalive_loop(self):
        """周期性发送 WebSocket PING 保活"""
        try:
            while self.connected:
                await asyncio.sleep(self.keepalive_interval)
                if not self.connected or self.writer is None:
                    break
                try:
                    ping_frame = self._make_ws_frame(self.WS_OP_PING, b'')
                    self.writer.write(ping_frame)
                    await self.writer.drain()
                    logger.debug("Keepalive ping sent")
                except Exception as e:
                    logger.debug(f"Keepalive send failed: {e}")
                    break
        except asyncio.CancelledError:
            pass

    def start_keepalive(self):
        """启动心跳任务（幂等）"""
        if self.keepalive_interval and self._keepalive_task is None:
            self._keepalive_task = asyncio.ensure_future(self._keepalive_loop())


class HikMediaClient(HikWebSocketClient):
    """海康威视媒体流客户端"""

    def __init__(self, config: HikConfig, **kwargs):
        super().__init__(config, **kwargs)
        self._server_pkd: str = ""
        self._server_rand: str = ""
        self._server_cipher_suite: str = "0"
        self._server_version: str = ""
        self._server_stream_key: str = ""

        # 媒体解析层状态（与 go-client 一一对应）
        self._rtp = hik_media.RTPDetector()
        self._ps: Optional[hik_media.PSDemuxer] = None
        self._media_info: Optional[hik_media.MediaInfo] = None
        self._container_known: bool = False
        self._frame_index: int = 0
        self._stream_start: Optional[float] = None

        # 媒体层回调
        self.on_frame: Optional[Callable[[hik_media.FrameMeta, bytes], None]] = None
        self.on_media_info: Optional[Callable[[hik_media.MediaInfo], None]] = None
        self.on_sps: Optional[Callable[[bytes], None]] = None
        self.on_raw_video: Optional[Callable[[bytes], None]] = None

    def _reset_media_state(self):
        """重置媒体解析层。run_forever 会在同一个对象上重连，上一会话的 RTP 判定、
        PS 半帧和 SDP 都不能带进新会话——设备可能换了编码，甚至换了容器。"""
        self._rtp = hik_media.RTPDetector()
        self._ps = None
        self._media_info = None
        self._container_known = False
        self._frame_index = 0
        self._stream_start = None

    def _feed_video(self, data: bytes):
        """视频负载入口。RTP 判定器会扣住开头几条消息直到能定性，所以一次喂入可能
        放出 0 条、1 条或多条负载。"""
        for payload in self._rtp.feed(data):
            self._feed_container(payload)

    def _feed_container(self, data: bytes):
        """处理一条已去封装的负载。

        MPEG-PS 容器必须先解复用成访问单元：设备会把单个 NAL 拆到多个 PES 包里，
        原始 PS 字节当 annex-b 扫起始码是错的。其余容器原样下发。
        """
        self._safe_callback(self.on_raw_video, data)

        # 容器只在会话的第一条负载上判一次。MEDIAINFO 头只是线索：有一类设备的头
        # magic 是 HVAG 而非 IMKH，解不出来，container 为空但负载明明是 MPEG-PS，
        # 只能靠嗅探定性——而且只能在第一条上嗅，后续消息都是从 pack 中段续传的。
        if not self._container_known:
            self._container_known = True
            info = self._media_info
            if (info is not None and info.container == "PS") or \
               ((info is None or info.container == "") and hik_media.is_ps_data(data)):
                self._ps = hik_media.PSDemuxer()
                # 把嗅探结论写回去：对 HVAG 那一类设备这是容器的唯一来源，它隐含的
                # 90kHz PS 时钟又是 PTS 能换算成帧率的前提。不写回，调用方会在一条
                # 正被当 PS 解复用的流上读到空容器。
                if info is not None and info.container == "":
                    info.container = "PS"
                    info.clock_rate = 90000

        if self._ps is None:
            self._deliver_frame(data, 0, False)
            return
        for frame in self._ps.feed(data):
            self._deliver_frame(frame.data, frame.pts, frame.has_pts)

    def _deliver_frame(self, data: bytes, pts: int, has_pts: bool):
        """补齐单帧元信息后交给调用方。

        on_frame 优先于 on_video_data，避免同一份负载下发两次；只设 on_video_data
        的老调用方行为不变（收到的仍是可直接喂解码器的基本流）。
        """
        if self.on_frame is None and self.on_video_data is None:
            return
        if self._stream_start is None:
            self._stream_start = time.monotonic()
        self._frame_index += 1

        info = self._media_info
        codec = info.codec if info is not None else ""
        # 与容器同理：解不出的 MEDIAINFO 头会让编码为空，没有编码就判不了关键帧、
        # 也还原不了分辨率。码流自己会说它是什么编码。
        if not codec:
            codec = hik_media.sniff_codec(data)
            if codec and info is not None:
                info.codec = codec
        # 分辨率只能从码流内 SPS 还原（MEDIAINFO 头不带）。PS 流在第一个关键帧上补齐。
        if codec and (info is None or info.width == 0):
            width, height, sps, ok = hik_media.recover_resolution(data, codec)
            if ok:
                if info is not None:
                    info.width, info.height = width, height
                if sps:
                    self._safe_callback(self.on_sps, sps)

        elapsed = time.monotonic() - self._stream_start
        meta = hik_media.FrameMeta(
            frame_index=self._frame_index,
            is_key_frame=hik_media.analyze_frame(data, codec),
            codec=codec,
            timestamp_ms=int(elapsed * 1000),
        )
        if has_pts:
            meta.pts, meta.has_pts = pts, True
        elif info is not None and info.clock_rate > 0:
            meta.pts = int(elapsed * info.clock_rate)
        if info is not None:
            meta.width, meta.height = info.width, info.height

        if self.on_frame is not None:
            self._safe_callback(self.on_frame, meta, data)
            return
        self._safe_callback(self.on_video_data, data)

    def _flush_media(self):
        """流结束时把还压在手里的东西放出去：先是 RTP 判定器为定性扣住的负载，
        再是解复用器里的最后一个访问单元。顺序不能反——扣住的负载得先进解复用器。"""
        for payload in self._rtp.flush():
            self._feed_container(payload)
        if self._ps is None:
            return
        for frame in self._ps.flush():
            self._deliver_frame(frame.data, frame.pts, frame.has_pts)

    def _build_media_url(self) -> str:
        """构建 media WebSocket URL"""
        # media URL 格式: /media?version=0.1&cipherSuites=0&sessionID=&proxy=<device>
        # device_ip 已经包含括号（如 [1111::2222]），直接拼接
        proxy = f"{self.config.device_ip}:{self.config.device_port}"
        return f"/media?version={self.config.version}&cipherSuites={self.config.cipher_suites}&sessionID=&proxy={proxy}"

    async def authenticate(self) -> bool:
        """接收服务器下发的 PKD/rand（不需要主动发认证请求）"""
        try:
            msg_type, response = await self.receive_message()

            if msg_type is None:
                logger.error("Connection closed before authentication")
                return False

            if msg_type == self.WS_OP_TEXT:
                resp = json.loads(response.decode('utf-8'))

                if resp.get('errorCode') and resp.get('errorCode') != 0:
                    logger.error(f"Server error: {resp}")
                    if self.on_error:
                        self.on_error(resp.get('errorMsg', str(resp)))
                    return False

                self._server_pkd = resp.get('PKD', '')
                self._server_rand = resp.get('rand', '')
                # cipherSuite 可能是数字或字符串，统一转为字符串
                cs = resp.get('cipherSuite', resp.get('cipherSuites', '0'))
                self._server_cipher_suite = str(cs)
                self._server_version = str(resp.get('version', '1.0'))
                logger.info(
                    f"Received PKD/rand from server, "
                    f"cipherSuite={self._server_cipher_suite!r}, version={self._server_version!r}")
                return True

            else:
                logger.warning(f"Unexpected message type: 0x{msg_type:02x}")
                return False

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False

    async def realplay(self) -> bool:
        """发送 realplay 请求（启动视频流）"""
        try:
            # 构建目标 URL
            device_url = f"ws://{self.config.device_ip}:{self.config.device_port}/openUrl/{self.config.password}"

            # 构建 realplay 请求 - 空 key/authorization/token 会触发服务器直接返回视频流
            # 注: 若服务器要求加密字段，可用 HikCrypto.generate_client_iv_key /
            #     generate_realplay_key / generate_authorization / generate_token 生成
            realplay_data = {
                "sequence": 0,
                "cmd": "realplay",
                "url": device_url,
                "key": "",
                "authorization": "",
                "token": ""
            }

            logger.info(f"Sending realplay: {device_url}")
            await self.send_text(json.dumps(realplay_data))
            logger.info("realplay request sent")
            return True

        except Exception as e:
            logger.exception(f"realplay failed: {e}")
            return False

    # 常见错误码说明
    ERROR_MESSAGES = {
        0: "成功",
        28316423: "URL已过期，请获取新的有效URL",
        65559: "认证失败，请检查密码或权限",
        16777237: "RSA加密失败，请检查密钥生成逻辑",
    }

    def _safe_callback(self, cb, *args):
        """执行回调并隔离用户回调中的异常，避免影响主循环"""
        if cb is None:
            return
        try:
            cb(*args)
        except Exception as e:
            logger.warning(f"Callback error: {e}")

    def _handle_text_message(self, payload: bytes):
        """处理服务器 TEXT JSON 响应"""
        try:
            resp = json.loads(payload.decode('utf-8', errors='replace'))
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Malformed TEXT message ({e}), ignored: {payload[:100]!r}")
            return

        error_code = resp.get('errorCode', 0)

        if error_code == 0 and resp.get('sdp'):
            logger.info("realplay success, received SDP")
            logger.debug(f"SDP: {resp['sdp'][:100]}...")
            info = hik_media.parse_sdp(resp['sdp'])
            self._media_info = info
            self._safe_callback(self.on_media_info, info)
        elif error_code != 0:
            friendly_msg = self.ERROR_MESSAGES.get(
                error_code, f"未知错误 (errorCode: {error_code})")
            logger.error(f"realplay failed: {friendly_msg}")
            if error_code == 28316423:
                logger.error("提示: URL可能已过期，请从设备重新获取新的播放链接")
            self._safe_callback(self.on_error, friendly_msg)

    async def run(self):
        """运行客户端主循环"""
        self._reset_media_state()
        # 建立 media WebSocket 连接
        media_url = self._build_media_url()
        logger.info(f"Connecting to media endpoint: {media_url}")

        if not await self.connect(media_url):
            logger.error("Failed to connect to media endpoint")
            return False

        # 接收服务器下发的 PKD/rand
        if not await self.authenticate():
            return False

        # 生成密钥 (realplay 需要用 PKD 加密 iv:key)
        if self._server_pkd and self._server_rand:
            # 生成客户端 iv 和 key
            iv, key = HikCrypto.generate_client_iv_key()
            # 用服务器 PKD 加密生成 realplay_key
            self.secret_key = HikCrypto.generate_realplay_key(iv, key, self._server_pkd)
            logger.info(f"Realplay key generated: {self.secret_key[:32]}...")

        # 发送 realplay 请求
        if not await self.realplay():
            return False

        # 启动应用层心跳保活
        self.start_keepalive()

        # 处理响应和数据
        video_count = 0
        video_bytes = 0
        last_stat_time = time.monotonic()
        try:
            while self.connected:
                msg_type, payload = await self.receive_message()

                if msg_type is None:
                    break

                if msg_type == self.WS_OP_TEXT:
                    self._handle_text_message(payload)

                elif msg_type in (self.WS_OP_BINARY, HikProtocol.MSG_TYPE_VIDEO_DATA):
                    # 原始 BINARY 数据 / 协议视频数据
                    video_count += 1
                    video_bytes += len(payload)
                    # 高频路径：统计信息按秒聚合输出，避免逐帧打日志拖慢吞吐
                    now = time.monotonic()
                    if now - last_stat_time >= 1.0:
                        logger.info(
                            f"Video stream: {video_count} frames, "
                            f"{video_bytes / 1024:.1f} KB total, last frame {len(payload)} bytes")
                        last_stat_time = now
                    self._feed_video(payload)

                elif msg_type == HikProtocol.MSG_TYPE_AUDIO_DATA:
                    self._safe_callback(self.on_audio_data, payload)

                elif msg_type == HikProtocol.MSG_TYPE_KEEPALIVE:
                    logger.debug("Keepalive received")

                elif msg_type == HikProtocol.MSG_TYPE_SESSION_ERROR:
                    error = payload.decode('utf-8', errors='replace')
                    logger.error(f"Session error: {error}")
                    self._safe_callback(self.on_error, error)
                    break

        except (ConnectionError, asyncio.IncompleteReadError, OSError) as e:
            logger.error(f"Connection error: {e}")
            self._safe_callback(self.on_error, str(e))
        finally:
            # PS 一个 pack 关掉上一帧，天然压着最后一帧，不 flush 就会丢
            self._flush_media()
            if self._keepalive_task is not None:
                self._keepalive_task.cancel()
                self._keepalive_task = None

        logger.info(f"Stream ended. Total video frames: {video_count} ({video_bytes} bytes)")
        return True

    async def run_forever(self, max_retries: int = 0,
                          initial_backoff: float = 1.0,
                          max_backoff: float = 30.0):
        """带自动重连的主循环

        Args:
            max_retries: 最大连续重连次数，0 表示无限重连
            initial_backoff: 初始退避秒数（指数递增）
            max_backoff: 最大退避秒数
        """
        retries = 0
        backoff = initial_backoff
        while True:
            start = time.monotonic()
            try:
                await self.run()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Client crashed: {e}")
            finally:
                await self.close()

            # 会话若稳定运行超过 30 秒，则重置退避计数
            if time.monotonic() - start > 30:
                retries = 0
                backoff = initial_backoff

            retries += 1
            if max_retries and retries > max_retries:
                logger.error(f"Give up after {max_retries} retries")
                break

            logger.info(f"Reconnecting in {backoff:.1f}s (attempt {retries})...")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)


def parse_proxy_url(url: str) -> HikConfig:
    """
    解析海康威视代理 URL

    URL 格式: wss://<proxy_host>:<proxy_port>/proxy/<device_ip>:<device_port>/openUrl/<auth>

    例如: wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token

    返回:
        HikConfig 对象
    """
    from urllib.parse import urlparse

    # 解析 URL
    parsed = urlparse(url)

    # 获取代理服务器信息
    proxy_host = parsed.hostname or parsed.netloc.split(':')[0]
    proxy_port = parsed.port or 443

    # 解析路径
    path_parts = parsed.path.strip('/').split('/')

    # path_parts 应该是: ['proxy', '<device_ip>:<device_port>', 'openUrl', '<auth>']
    # 或者: ['proxy', '<device_ip>:<device_port>']  (没有 openUrl/auth)

    device_info = path_parts[1] if len(path_parts) > 1 else ""
    if not device_info:
        raise ValueError(f"Invalid proxy URL, missing device info: {url}")

    # 分离 IP 和端口
    try:
        if ':' in device_info:
            # 检查是否是 IPv6
            if device_info.startswith('['):
                # IPv6 格式: [ip]:port
                if ']:' in device_info:
                    ip_part, port_part = device_info[1:].split(']:', 1)
                    device_ip = '[' + ip_part + ']'
                    device_port = int(port_part)
                else:
                    # 纯 [ipv6] 无端口
                    device_ip = device_info
                    device_port = 554
            else:
                ip_part, port_part = device_info.rsplit(':', 1)
                device_ip = ip_part
                device_port = int(port_part)
        else:
            device_ip = device_info
            device_port = 554  # 默认 RTSP 端口
    except ValueError as e:
        raise ValueError(f"Invalid device address in URL: {device_info!r}") from e

    # 获取认证信息（如果有）
    username = "admin"
    password = ""
    if len(path_parts) > 3 and path_parts[2] == 'openUrl':
        auth = path_parts[3]
        # auth 可能是 base64 或明文（严格校验 base64，避免明文被误解码成乱码）
        try:
            decoded = base64.b64decode(auth.encode(), validate=True).decode('utf-8')
            if ':' in decoded:
                username, password = decoded.split(':', 1)
            else:
                password = decoded
        except Exception:
            password = auth

    return HikConfig(
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        proxy_path=f"/proxy/{device_info}",
        device_ip=device_ip,
        device_port=device_port,
        username=username,
        password=password
    )


def demo_callback(video_data: bytes):
    """视频数据回调示例（同步函数，回调在事件循环中直接调用）"""
    logger.debug(f"Received video data: {len(video_data)} bytes")


async def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='Hikvision WebSocket Client')
    parser.add_argument('url', help='Hikvision proxy URL (wss://...)')
    parser.add_argument('-u', '--username', default=None, help='Username (overrides URL)')
    parser.add_argument('-p', '--password', default=None, help='Password (overrides URL)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--reconnect', action='store_true', help='Auto reconnect on failure')
    parser.add_argument('--max-retries', type=int, default=0,
                        help='Max reconnect attempts (0 = unlimited)')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 解析 URL
    config = parse_proxy_url(args.url)

    # 只有命令行显式提供时才覆盖 URL 中解析出的用户名密码
    if args.username is not None:
        config.username = args.username
    if args.password is not None:
        config.password = args.password

    logger.info(f"Parsed configuration:")
    logger.info(f"  Proxy: {config.proxy_host}:{config.proxy_port}")
    logger.info(f"  Device: {config.device_ip}:{config.device_port}")
    logger.info(f"  Username: {config.username}")
    logger.info(f"  Path: {config.proxy_path}")

    # 创建客户端
    client = HikMediaClient(config)
    client.on_video_data = demo_callback
    client.on_error = lambda e: logger.error(f"Error: {e}")
    client.on_connected = lambda: logger.info("Connected!")

    # 运行客户端
    try:
        if args.reconnect:
            await client.run_forever(max_retries=args.max_retries)
        else:
            await client.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        await client.close()


if __name__ == '__main__':
    asyncio.run(main())
