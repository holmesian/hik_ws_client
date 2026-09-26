<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 代理在带内上报的错误（openUrl token 过期、凭据错误、设备不可达）。它是终态的：
 * 重连同一个 URL 只会拿到同样的码，所以 stream() 遇到它立即停止重连。
 *
 * 注意：PHP 的 Exception 已有 $code 属性，因此上报码存在 $hikCode 里。
 */
final class ServerError extends \RuntimeException
{
    public function __construct(
        public readonly int $hikCode,
        string $msg,
    ) {
        parent::__construct("server error code={$hikCode} msg={$msg}", $hikCode);
    }
}
