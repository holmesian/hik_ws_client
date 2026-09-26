#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * 取流 Demo：连上代理，把解复用后的 Annex-B 访问单元写到标准输出。
 *
 * 用法：
 *
 *     php8.4 demo.php 'wss://example.com:6014/proxy/[1111::2222]:559/openUrl/auth_token'
 *
 * openUrl token 一次性、分钟级过期：取到后必须立刻用，且不要为同一个链接跑两次。
 */

require __DIR__ . '/src/index.php';

use HikWs\HikConfig;
use HikWs\HikMediaClient;

$url = $argv[1] ?? '';
if ($url === '') {
    fwrite(STDERR, "usage: php demo.php <wss://proxy/.../openUrl/\<token\>>\n");
    exit(2);
}

$config = HikConfig::fromProxyUrl($url);
$client = new HikMediaClient($config);

$client->onMediaInfo = function ($info): void {
    fwrite(STDERR, sprintf(
        "[sdp] container=%s codec=%s clockRate=%d\n",
        $info->container ?: '(unknown)',
        $info->codec ?: '(unknown)',
        $info->clockRate
    ));
};

$client->onVideoFrame = function ($meta, string $data): void {
    fwrite(STDERR, sprintf(
        "[frame] #%d %d bytes key=%s codec=%s %dx%d pts=%d\n",
        $meta->frameIndex,
        strlen($data),
        $meta->isKeyFrame ? 'yes' : 'no',
        $meta->codec ?: '?',
        $meta->width,
        $meta->height,
        $meta->pts
    ));
    fwrite(STDOUT, $data);
};

$client->onError = function (\Throwable $e): void {
    fwrite(STDERR, "[error] {$e->getMessage()}\n");
};

try {
    $client->stream();
} finally {
    $client->close();
}
