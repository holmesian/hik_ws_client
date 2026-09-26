<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 会话鉴权与密钥派生。移植自 go-client/crypto.go 与 python-client/hik_ws_client.py。
 *
 * 协议约定（docs/protocol.md + ADR-0004）：realplay 以空 key 请求，服务端据此不下发加密流，
 * 媒体载荷本身不加密，密钥交换只用于会话鉴权。因此默认 key/authorization/token 为空即可；
 * 当代理要求严格鉴权时，可开启 HikConfig 的 useRealplayAuth 用本类填实这三个字段。
 */
final class Crypto
{
    private const FIXED_KEY = '1234567891234567123456789123456712345678912345671234567891234567';
    private const FIXED_IV  = '12345678912345671234567891234567';

    public static function generateSecretKey(string $pkd, string $rand, string $username, string $password): string
    {
        $passwordMd5 = md5($password, true);
        $saltData = hash('sha256', $passwordMd5 . 'rtsp' . $username, true);
        $authData = hash('sha256', $pkd . $rand, true);
        return hash('sha256', $saltData . $authData . $saltData);
    }

    /**
     * 生成客户端 IV 与 key（按时间戳派生）。
     *
     * @return array{0:string,1:string} [iv, key]
     */
    public static function generateClientIvKey(): array
    {
        $nowMs = (string) (int) floor(microtime(true) * 1000);
        $iv = bin2hex(self::aesEncryptCbc($nowMs, self::FIXED_KEY, self::FIXED_IV));
        while (strlen($iv) < 64) {
            $iv .= $iv;
        }
        $key = bin2hex(self::aesEncryptCbc($nowMs, self::FIXED_KEY, self::FIXED_IV));
        while (strlen($key) < 64) {
            $key .= $key;
        }
        return [$iv, $key];
    }

    /**
     * 用 RSA + 魔改 PKCS#1 v1.5 填充生成 realplay 的 key 字段。
     */
    public static function generateRealplayKey(string $iv, string $key, string $pkdHex): string
    {
        $plaintext = $iv . ':' . $key;
        $pkdBytes = hex2bin($pkdHex);
        if ($pkdBytes === false) {
            throw new \ValueError('invalid PKD hex');
        }
        $keyLen = strlen($pkdBytes);
        $n = gmp_import($pkdBytes, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        $block = str_repeat("\x00", $keyLen);
        $t = $keyLen;
        for ($i = strlen($plaintext) - 1; $i >= 0; $i--) {
            $t--;
            $block[$t] = $plaintext[$i];
        }
        $t--;
        $block[$t] = "\x00";
        while ($t > 2) {
            $t--;
            do {
                $r = random_bytes(1);
            } while ($r === "\x00");
            $block[$t] = $r;
        }
        if ($t > 1) {
            $block[1] = "\x02";
        }
        if ($t > 0) {
            $block[0] = "\x00";
        }

        $m = gmp_import($block, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        $c = gmp_powm($m, gmp_init(65537), $n);

        $cBytes = $c === 0 ? '' : gmp_export($c, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        if (strlen($cBytes) < $keyLen) {
            $cBytes = str_repeat("\x00", $keyLen - strlen($cBytes)) . $cBytes;
        }
        return bin2hex($cBytes);
    }

    public static function generateAuthorization(string $rand, string $password, string $keyHex, string $ivHex): string
    {
        $plaintext = $rand . ':' . $password;
        $keyBytes = self::normalizeKey($keyHex);
        $ivBytes = substr(hex2bin(substr($ivHex, 0, 32)) ?: '', 0, 16);
        return bin2hex(self::aesEncryptCbc($plaintext, $keyBytes, $ivBytes));
    }

    public static function generateToken(string $url, string $keyHex, string $ivHex): string
    {
        $urlHash = hash('sha256', $url);
        $keyBytes = self::normalizeKey($keyHex);
        $ivBytes = substr(hex2bin(substr($ivHex, 0, 32)) ?: '', 0, 16);
        return bin2hex(self::aesEncryptCbc($urlHash, $keyBytes, $ivBytes));
    }

    private static function normalizeKey(string $keyHex): string
    {
        $keyBytes = hex2bin(substr($keyHex, 0, 64));
        if ($keyBytes === false) {
            throw new \ValueError('invalid key hex');
        }
        if (strlen($keyBytes) < 32) {
            $keyBytes = str_pad($keyBytes, 32, "\x00");
        }
        return substr($keyBytes, 0, 32);
    }

    private static function aesEncryptCbc(string $plaintext, string $key, string $iv): string
    {
        $padded = self::pkcs7Pad($plaintext, 16);
        $out = openssl_encrypt($padded, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if ($out === false) {
            throw new \RuntimeException('aes-256-cbc encryption failed');
        }
        return $out;
    }

    private static function pkcs7Pad(string $data, int $blockSize): string
    {
        $padding = $blockSize - (strlen($data) % $blockSize);
        return $data . str_repeat(chr($padding), $padding);
    }
}
