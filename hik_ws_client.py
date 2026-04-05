#!/usr/bin/env python3
"""
海康威视私有 WebSocket 协议客户端
Hikvision Private WebSocket Protocol Client

基于 h5player.min.js 和 Decoder.js 逆向分析实现

协议流程:
1. 通过 proxy URL 解析目标设备信息
2. 建立 media WebSocket 连接并发送认证请求
3. 使用服务器下发的 PKD、rand 生成密钥
4. 接收并解密加密视频流

Author: Daikx (代可行)
"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import socket
import ssl
import struct
import time
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from dataclasses import dataclass
from typing import Optional, Callable

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class HikConfig:
    """海康威视连接配置"""
    # 代理服务器地址
    proxy_host: str
    proxy_port: int
    proxy_path: str  # e.g., "/proxy/[fd00:0:2c0:9::10c]:559"

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
    """海康威视加密工具类"""

    # 海康固定 AES 密钥（JS 代码中硬编码）
    HIK_FIXED_KEY = bytes.fromhex('1234567891234567123456789123456712345678912345671234567891234567')
    HIK_FIXED_IV = bytes.fromhex('12345678912345671234567891234567')

    @staticmethod
    def aes_encrypt_cbc(plaintext: str, key_hex: str, iv_hex: str) -> str:
        """
        AES-128-CBC PKCS7 加密（与 CryptoJS 兼容）
        """
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
        """解包海康威视协议消息"""
        if len(data) < 5:
            return None, None, data

        msg_type, length = struct.unpack('>BI', data[:5])

        if len(data) < 5 + length:
            return None, None, data

        payload = data[5:5+length]
        remaining = data[5+length:]

        return msg_type, payload, remaining


class HikWebSocketClient:
    """海康威视私有 WebSocket 客户端"""

    # WebSocket 帧类型
    WS_OP_CONTINUATION = 0x00
    WS_OP_TEXT = 0x01
    WS_OP_BINARY = 0x02
    WS_OP_CLOSE = 0x08
    WS_OP_PING = 0x09
    WS_OP_PONG = 0x0A

    def __init__(self, config: HikConfig):
        self.config = config
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.session_id: str = ""
        self.connected = False
        self.secret_key: Optional[str] = None

        # 回调函数
        self.on_video_data: Optional[Callable[[bytes], None]] = None
        self.on_audio_data: Optional[Callable[[bytes], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_connected: Optional[Callable[[], None]] = None

        # 缓冲区
        self.buffer = b''

        # 状态机
        self.state = "disconnected"

    def _make_websocket_handshake(self, path: str) -> bytes:
        """生成 WebSocket 握手请求"""
        # 生成 WebSocket key
        key = secrets.token_bytes(16)
        accept_key = base64.b64encode(
            hmac.new(
                b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
                key,
                hashlib.sha1
            ).digest()
        ).decode('ascii')

        # 构建 HTTP 请求
        request = f"GET {path} HTTP/1.1\r\n"
        request += f"Host: {self.config.proxy_host}:{self.config.proxy_port}\r\n"
        request += "Upgrade: websocket\r\n"
        request += "Connection: Upgrade\r\n"
        request += f"Sec-WebSocket-Key: {base64.b64encode(key).decode('ascii')}\r\n"
        request += "Sec-WebSocket-Version: 13\r\n"
        request += "Sec-WebSocket-Protocol: v1.0.0\r\n"
        request += "\r\n"

        return request.encode('ascii')

    def _parse_websocket_handshake(self, response: bytes) -> bool:
        """解析 WebSocket 握手响应"""
        try:
            # 找到 HTTP 头结束位置（\r\n\r\n）
            # 服务器可能在 101 响应后紧跟一个 WebSocket 帧，只取 HTTP 头部分
            header_end = response.find(b'\r\n\r\n')
            if header_end == -1:
                logger.error(f"WebSocket handshake failed: malformed response")
                return False

            header_bytes = response[:header_end]
            header_lines = header_bytes.decode('ascii', errors='replace').split('\r\n')

            # 检查状态码
            if not header_lines[0].startswith('HTTP/1.1 101'):
                logger.error(f"WebSocket handshake failed: {header_lines[0]}")
                return False

            # 检查 Sec-WebSocket-Protocol
            for line in header_lines[1:]:
                if line.lower().startswith('sec-websocket-protocol:'):
                    protocol = line.split(':', 1)[1].strip()
                    logger.info(f"WebSocket protocol: {protocol}")
                    break

            logger.info("WebSocket handshake successful")
            return True
        except Exception as e:
            logger.error(f"Error parsing WebSocket handshake: {e}")
            return False

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

        # 掩码 payload
        masked_payload = bytearray(payload)
        for i in range(len(payload)):
            masked_payload[i] ^= mask_key[i % 4]

        frame.extend(masked_payload)
        return bytes(frame)

    def _parse_ws_frame(self, data: bytes) -> tuple:
        """解析 WebSocket 帧"""
        if len(data) < 2:
            return None, None, data

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
                return None, None, data
            payload_length = struct.unpack('>H', data[2:4])[0]
            offset = 4
        elif payload_length == 127:
            if len(data) < 10:
                return None, None, data
            payload_length = struct.unpack('>Q', data[2:10])[0]
            offset = 10

        # 客户端帧需要掩码，服务器帧不掩码
        if is_masked:
            if len(data) < offset + 4:
                return None, None, data
            mask_key = data[offset:offset + 4]
            offset += 4
            if len(data) >= offset + payload_length:
                masked_payload = bytearray(data[offset:offset + payload_length])
                for i in range(len(masked_payload)):
                    masked_payload[i] ^= mask_key[i % 4]
                payload = bytes(masked_payload)
            else:
                payload = b''
        else:
            if len(data) < offset + payload_length:
                return None, None, data
            payload = data[offset:offset + payload_length]

        remaining = data[offset + payload_length:]

        return opcode, payload, remaining

    async def connect(self, path: str) -> bool:
        """建立 WebSocket 连接"""
        try:
            # 建立 SSL/TLS 连接（wss:// 需要 TLS）
            logger.info(f"Connecting to {self.config.proxy_host}:{self.config.proxy_port}")
            ssl_ctx = ssl.create_default_context()
            # 海康服务器可能是自签名证书，禁用验证
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            self.reader, self.writer = await asyncio.open_connection(
                self.config.proxy_host,
                self.config.proxy_port,
                ssl=ssl_ctx
            )

            # 发送 WebSocket 握手
            handshake_request = self._make_websocket_handshake(path)
            self.writer.write(handshake_request)
            await self.writer.drain()

            # 接收握手响应
            response = await self.reader.read(8192)

            # 找到 HTTP 头结束位置
            header_end = response.find(b'\r\n\r\n')
            if header_end == -1:
                logger.error("WebSocket handshake failed: no header end found")
                return False

            http_header = response[:header_end]
            # 头之后可能紧跟一个 WebSocket 帧，先存起来
            self.buffer = response[header_end + 4:]

            # 检查状态码
            status_line = http_header.decode('ascii', errors='replace').split('\r\n')[0]
            if not status_line.startswith('HTTP/1.1 101'):
                logger.error(f"WebSocket handshake failed: {status_line}")
                return False

            logger.info("WebSocket handshake successful")
            # 把 buffer 中的帧消费掉（服务器可能在握手后立即发帧）

            self.connected = True
            self.state = "connected"
            logger.info("Connection established")
            return True

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    async def close(self):
        """关闭连接"""
        self.connected = False
        self.state = "disconnected"

        if self.writer:
            try:
                # 发送 WebSocket 关闭帧
                close_frame = self._make_ws_frame(self.WS_OP_CLOSE, b'')
                self.writer.write(close_frame)
                await self.writer.drain()
            except:
                pass

            self.writer.close()
            try:
                await self.writer.wait_closed()
            except:
                pass

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

    async def receive_message(self) -> tuple:
        """接收消息（阻塞）"""
        while self.connected:
            # 先尝试从 buffer 消费
            while self.buffer:
                opcode, payload, self.buffer = self._parse_ws_frame(self.buffer)
                if opcode is None:
                    # buffer 中数据不完整，需要读取更多
                    break

                if opcode == self.WS_OP_TEXT:
                    # 服务器用 TEXT 帧发送 JSON 协议消息
                    # 返回 (opcode, payload) 让子类处理
                    return self.WS_OP_TEXT, payload

                elif opcode == self.WS_OP_BINARY:
                    # 解包协议消息，如果失败则返回原始数据（可能是视频/RTP流）
                    msg_type, msg_payload, _ = HikProtocol.unpack_message(payload)
                    if msg_type is not None:
                        return msg_type, msg_payload
                    else:
                        # 原始 BINARY 数据（视频流）
                        return self.WS_OP_BINARY, payload

                elif opcode == self.WS_OP_PING:
                    # 响应 PING
                    pong_frame = self._make_ws_frame(self.WS_OP_PONG, payload)
                    self.writer.write(pong_frame)
                    await self.writer.drain()

                elif opcode == self.WS_OP_CLOSE:
                    logger.info("Server closed connection")
                    self.connected = False
                    return None, None

            # 缓冲区数据不完整，需要读取更多
            data = await self.reader.read(8192)
            if not data:
                raise Exception("Connection closed")
            self.buffer += data


class HikMediaClient(HikWebSocketClient):
    """海康威视媒体流客户端"""

    def __init__(self, config: HikConfig):
        super().__init__(config)
        self._server_pkd: str = ""
        self._server_rand: str = ""
        self._server_cipher_suite: str = "0"
        self.on_error: Optional[Callable[[str], None]] = None
        self._server_stream_key: str = ""

    async def authenticate(self) -> bool:
        """接收服务器下发的 PKD/rand"""
        try:
            msg_type, response = await self.receive_message()

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
                logger.info(f"Received PKD/rand from server, cipherSuite={self._server_cipher_suite!r}")
                return True

            else:
                logger.warning(f"Unexpected message type: 0x{msg_type:02x}")
                return False

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False

    def _build_media_url(self) -> str:
        """构建 media WebSocket URL"""
        # media URL 格式: /media?version=0.1&cipherSuites=0&sessionID=&proxy=<device>
        # device_ip 已经包含括号（如 [fd00:0:2c0:9::10c]），直接拼接
        proxy = f"{self.config.device_ip}:{self.config.device_port}"
        return f"/media?version={self.config.version}&cipherSuites={self.config.cipher_suites}&sessionID=&proxy={proxy}"

    async def authenticate(self) -> bool:
        """接收服务器下发的 PKD/rand（不需要主动发认证请求）"""
        try:
            msg_type, response = await self.receive_message()

            if msg_type == self.WS_OP_TEXT:
                resp = json.loads(response.decode('utf-8'))

                if resp.get('errorCode') and resp.get('errorCode') != 0:
                    logger.error(f"Server error: {resp}")
                    if self.on_error:
                        self.on_error(resp.get('errorMsg', str(resp)))
                    return False

                self._server_pkd = resp.get('PKD', '')
                self._server_rand = resp.get('rand', '')
                self._server_cipher_suite = resp.get('cipherSuite', '0')
                self._server_version = resp.get('version', '1.0')
                logger.info(f"Received PKD/rand from server")
                logger.info(f"  cipherSuite: {self._server_cipher_suite}, version: {self._server_version}")
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

            # 生成 iv 和 key（客户端固定密钥加密时间戳）
            iv, key = HikCrypto.generate_client_iv_key()

            # 生成 realplay 的 key = AES_Encrypt(iv:key, PKD)
            realplay_key = HikCrypto.generate_realplay_key(iv, key, self._server_pkd)

            # authorization = AES_Encrypt(rand:auth, key_hex, iv)
            # auth = password (empty string for no auth)
            authorization = HikCrypto.generate_authorization(
                self._server_rand,
                self.config.password,
                key,
                iv
            )

            # token = AES_Encrypt(SHA256(url), key_hex, iv)
            token = HikCrypto.generate_token(
                hashlib.sha256(device_url.encode()).hexdigest(),
                key,
                iv
            )

            # 构建 realplay 请求 - 服务器返回 key 后不需要额外加密
            realplay_data = {
                "sequence": 0,
                "cmd": "realplay",
                "url": device_url,
                "key": "",  # 空 key 会触发服务器返回视频流
                "authorization": "",
                "token": ""
            }

            logger.info(f"Sending realplay: {device_url}")
            logger.debug(f"  iv={iv[:32]}, key={key[:32]}")
            logger.debug(f"  realplay_key={realplay_key[:32]}...")
            logger.debug(f"  authorization={authorization[:32]}...")
            await self.send_text(json.dumps(realplay_data))
            logger.info("realplay request sent")
            return True

        except Exception as e:
            logger.error(f"realplay failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    async def run(self):
        """运行客户端主循环"""
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

        # 处理响应和数据
        video_count = 0
        while self.connected:
            msg_type, payload = await self.receive_message()

            if msg_type is None:
                break

            if msg_type == self.WS_OP_TEXT:
                # 服务器 TEXT JSON 响应
                resp = json.loads(payload.decode('utf-8'))
                error_code = resp.get('errorCode', 0)
                
                # 常见错误码说明
                error_messages = {
                    0: "成功",
                    28316423: "URL已过期，请获取新的有效URL",
                    65559: "认证失败，请检查密码或权限",
                    16777237: "RSA加密失败，请检查密钥生成逻辑",
                }
                
                if error_code == 0 and resp.get('sdp'):
                    logger.info("realplay success, received SDP")
                    logger.debug(f"SDP: {resp['sdp'][:100]}...")
                elif error_code != 0:
                    error_msg = resp.get('errorMsg', '')
                    friendly_msg = error_messages.get(error_code, f"未知错误 (errorCode: {error_code})")
                    logger.error(f"realplay failed: {friendly_msg}")
                    if error_code == 28316423:
                        logger.error("提示: URL可能已过期，请从设备重新获取新的播放链接")
                    if self.on_error:
                        self.on_error(friendly_msg)

            elif msg_type == self.WS_OP_BINARY:
                # 原始 BINARY 数据（视频流）
                video_count += 1
                logger.info(f"Video data: {len(payload)} bytes (frame #{video_count})")
                if self.on_video_data:
                    self.on_video_data(payload)

            elif msg_type == HikProtocol.MSG_TYPE_VIDEO_DATA:
                video_count += 1
                logger.info(f"Video data: {len(payload)} bytes (total: {video_count} frames)")
                if self.on_video_data:
                    self.on_video_data(payload)

            elif msg_type == HikProtocol.MSG_TYPE_AUDIO_DATA:
                if self.on_audio_data:
                    self.on_audio_data(payload)

            elif msg_type == HikProtocol.MSG_TYPE_KEEPALIVE:
                logger.debug("Keepalive received")

            elif msg_type == HikProtocol.MSG_TYPE_SESSION_ERROR:
                error = payload.decode('utf-8')
                logger.error(f"Session error: {error}")
                if self.on_error:
                    self.on_error(error)
                break

        logger.info(f"Stream ended. Total video frames: {video_count}")
        return True


def parse_proxy_url(url: str) -> HikConfig:
    """
    解析海康威视代理 URL

    URL 格式: wss://<proxy_host>:<proxy_port>/proxy/<device_ip>:<device_port>/openUrl/<auth>

    例如: wss://ipcbasehkvideolj.example.com.com:6014/proxy/[fd00:0:2c0:9::10c]:559/openUrl/mYqWpMI

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

    # 分离 IP 和端口
    if ':' in device_info:
        # 检查是否是 IPv6
        if device_info.startswith('['):
            # IPv6 格式: [ip]:port
            parts = device_info[1:].split(']:')
            device_ip = '[' + parts[0] + ']'
            device_port = int(parts[1])
        else:
            parts = device_info.rsplit(':', 1)
            device_ip = parts[0]
            device_port = int(parts[1])
    else:
        device_ip = device_info
        device_port = 554  # 默认 RTSP 端口

    # 获取认证信息（如果有）
    username = "admin"
    password = ""
    if len(path_parts) > 3 and path_parts[2] == 'openUrl':
        auth = path_parts[3]
        # auth 可能是 base64 或明文
        try:
            decoded = base64.b64decode(auth.encode()).decode()
            if ':' in decoded:
                username, password = decoded.split(':', 1)
            else:
                password = decoded
        except:
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


async def demo_callback(video_data: bytes):
    """视频数据回调示例"""
    logger.info(f"Received video data: {len(video_data)} bytes")


async def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='Hikvision WebSocket Client')
    parser.add_argument('url', help='Hikvision proxy URL (wss://...)')
    parser.add_argument('-u', '--username', default='admin', help='Username')
    parser.add_argument('-p', '--password', default='', help='Password')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 解析 URL
    config = parse_proxy_url(args.url)

    # 覆盖用户名密码
    if args.username:
        config.username = args.username
    if args.password:
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
        await client.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        await client.close()


if __name__ == '__main__':
    asyncio.run(main())
