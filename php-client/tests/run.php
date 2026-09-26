<?php

declare(strict_types=1);

/**
 * 测试入口：``php8.4 tests/run.php``（或 ``php tests/run.php``）。
 *
 * 不引 PHPUnit，与 python-client 用 stdlib unittest 的取向一致：媒体层只依赖标准库，
 * 测试也该在裸环境里直接跑。
 */

require __DIR__ . '/../src/index.php';
require __DIR__ . '/MiniTest.php';
require __DIR__ . '/TestHelper.php';
require __DIR__ . '/HikMediaTest.php';
require __DIR__ . '/TlsRegressionTest.php';

use HikWs\Tests\HikMediaTest;
use HikWs\Tests\TlsRegressionTest;
use HikWs\Tests\MiniTest;

HikMediaTest::register();
TlsRegressionTest::register();
exit(MiniTest::summary());
