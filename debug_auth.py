#!/usr/bin/env python3
"""
海康威视加密调试脚本

用法:
1. 先在浏览器中配置 mitmproxy (mitmproxy --listen-port 8080)
2. 打开 hikplayer URL，让浏览器成功建立连接
3. 在 mitmdump 中可以看到 Wireshark 中看不到的明文 WS 流量
4. 或者：运行此脚本测试不同的 authorization 参数组合
"""

import json
import hashlib
import hmac
import secrets
import time

# ====== HikCrypto 实现 ======

class HikCrypto:
    HIK_FIXED_KEY = "12345678912345671234567891234567"

    @staticmethod
    def _hmac_sha1(key: bytes, data: bytes) -> bytes:
        if len(key) > 64:
            key = hashlib.sha1(key).digest()
        key = key.ljust(64, b'\x00')
        ipad = bytes(k ^ 0x36 for k in key)
        opad = bytes(k ^ 0x5c for k in key)
        inner = hashlib.sha1(ipad + data).digest()
        return hashlib.sha1(opad + inner).digest()

    @staticmethod
    def _sha1(data: bytes) -> bytes:
        return hashlib.sha1(data).digest()

    @staticmethod
    def generate_client_iv_key():
        now_ms = str(int(time.time() * 1000))
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        FIXED_KEY = HikCrypto.HIK_FIXED_KEY.encode()
        FIXED_IV = b"1234567891234567"
        key_bytes = AES.new(FIXED_KEY, AES.MODE_CBC, FIXED_IV).encrypt(pad(now_ms.encode(), 16))
        iv_raw = key_bytes.hex()
        iv = iv_raw if len(iv_raw) >= 64 else iv_raw + iv_raw
        key = iv_raw if len(iv_raw) >= 64 else iv_raw + iv_raw
        return iv, key

    @staticmethod
    def Z_encrypt(message: str, n_bytes: bytes, e: int = 65537) -> str:
        """Z.prototype.encrypt: 自定义 PKCS1-v1.5 RSA"""
        n_int = int.from_bytes(n_bytes, 'big')
        key_len = len(n_bytes)
        msg_utf8 = bytearray(message.encode('utf-8'))
        block = bytearray(key_len)
        t = key_len
        i = len(msg_utf8) - 1
        while i >= 0:
            r = msg_utf8[i]; i -= 1
            t -= 1; block[t] = r
        t -= 1; block[t] = 0
        i = key_len - 2
        while t > 2:
            t -= 1
            r = secrets.token_bytes(1)[0]
            while r == 0: r = secrets.token_bytes(1)[0]
            block[t] = r
            i -= 1
        block[1] = 0x02; block[0] = 0x00
        m_int = int.from_bytes(bytes(block), 'big')
        c_int = pow(m_int, e, n_int)
        return c_int.to_bytes(key_len, 'big').hex()

    @staticmethod
    def generate_authorization(username: str, cipher_suite: str, rand: str) -> str:
        """
        authorization = "HmacSHA1:" + HMAC(cipherSuite + ":" + rand + ":" + HMAC(username, FIXED_KEY), SHA1(FIXED_KEY))
        """
        k = HikCrypto._hmac_sha1(
            HikCrypto.HIK_FIXED_KEY.encode(),
            username.encode()
        )[:20]
        inner_input = f"{cipher_suite}:{rand}:".encode() + k
        inner_key = HikCrypto._sha1(HikCrypto.HIK_FIXED_KEY.encode())
        inner = HikCrypto._hmac_sha1(inner_key, inner_input)
        return "HmacSHA1:" + inner.hex()


# ====== 测试函数 ======

def test_authorization():
    """测试不同参数的 authorization"""
    print("=" * 60)
    print("Hikvision Authorization Generator")
    print("=" * 60)

    PKD = input("PKD (hex): ").strip() or "D24B417E0E5A3BFD69C1C5D1BFF98BDC1D2726CA3B093307375A341F7D9A3997135D6D8375BF59DA8D450C65AE09389177A9EBA53D52DDE1592392E689B425E68C9E44877FC0E5E1A62928BA2D27CEF42305009D04A05AFA38A2764AB7E9BB12C862FA0A69836F59D2D2A56C1952CE37DC6A0668F4D71F5D486AE796DAA4A5A08C5B0981B0A03689D06596F52656839930136F040B8E2E3B9164A8A5D16A47EF41DFF7FBA60962CA78641BAC0079D3341E1A88E439F1A4EAA33302537F837A5C3F0BB85C5709930755F77A0D6B838EA5BAF73F0FCC91B0B508AA41C16499644835AE1775DB4B264151F4549AA90F4551271F661BEE45FD0B47F9D36B424B2005"
    rand = input("rand (hex, from server): ").strip() or "5F57AA60DDB77ABBB4B5C4F675995ED3"
    username = input("username: ").strip() or "admin"
    cipher_suite = input("cipherSuite (0 or empty): ").strip() or "0"

    auth = HikCrypto.generate_authorization(username, cipher_suite, rand)
    print(f"\nGenerated authorization:")
    print(f"  username: {username}")
    print(f"  cipherSuite: {cipher_suite!r}")
    print(f"  rand: {rand}")
    print(f"  authorization: {auth}")

    # 生成测试用的 realplay 请求
    url = "ws://[fd00:0:2c0:9::10c]:559/openUrl/WtcNliV"
    pwd = input("\nPassword (from URL): ").strip() or "WtcNliV"

    print(f"\nTest realplay request:")
    print(json.dumps({
        "sequence": 0,
        "cmd": "realplay",
        "url": url,
        "key": "",
        "authorization": auth,
        "token": ""
    }, indent=2))


if __name__ == "__main__":
    test_authorization()
