<?php

declare(strict_types=1);

/**
 * hik_ws_client PHP 版 —— 自动加载入口（PSR-4 风格的极简实现，不依赖 composer）。
 *
 * 用法：
 *
 *     require __DIR__ . '/php-client/src/index.php';
 *     use HikWs\HikConfig;
 *     use HikWs\HikMediaClient;
 *
 *     $cfg = HikConfig::fromProxyUrl($argv[1]);
 *     $client = new HikMediaClient($cfg);
 *     $client->onVideoFrame = fn($meta, $data) => fwrite(STDOUT, $data);
 *     $client->stream();
 */

spl_autoload_register(static function (string $class): void {
    $prefix = 'HikWs\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
