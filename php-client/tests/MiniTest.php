<?php

declare(strict_types=1);

namespace HikWs\Tests;

/**
 * 极简断言与运行器：不引 PHPUnit，让 ``php8.4 tests/run.php`` 在裸环境就能跑。
 * 与 python-client 用 stdlib unittest 的取向一致。
 */
final class MiniTest
{
    public static int $passed = 0;
    public static int $failed = 0;
    public static int $skipped = 0;
    /** @var list<string> */
    public static array $failures = [];

    public static function run(string $name, callable $fn): void
    {
        try {
            $fn();
            self::$passed++;
            fwrite(STDOUT, "\xE2\x9C\x93 {$name}\n");
        } catch (SkipException $e) {
            self::$skipped++;
            fwrite(STDOUT, "s {$name} (skip: {$e->getMessage()})\n");
        } catch (\Throwable $e) {
            self::$failed++;
            self::$failures[] = "{$name}: {$e->getMessage()}";
            fwrite(STDOUT, "\xE2\x9C\x97 {$name}\n    {$e->getMessage()}\n");
        }
    }

    public static function assertTrue(bool $cond, string $msg = 'expected true'): void
    {
        if (!$cond) {
            throw new \RuntimeException($msg);
        }
    }

    public static function assertFalse(bool $cond, string $msg = 'expected false'): void
    {
        if ($cond) {
            throw new \RuntimeException($msg);
        }
    }

    public static function assertSame(mixed $want, mixed $got, string $msg = ''): void
    {
        if ($want !== $got) {
            $w = self::show($want);
            $g = self::show($got);
            throw new \RuntimeException(($msg !== '' ? "{$msg}: " : '') . "want {$w}, got {$g}");
        }
    }

    public static function assertLessEqual(int $max, int $got, string $msg = ''): void
    {
        if ($got > $max) {
            throw new \RuntimeException(($msg !== '' ? "{$msg}: " : '') . "want <= {$max}, got {$got}");
        }
    }

    public static function assertGreaterEqual(int $min, int $got, string $msg = ''): void
    {
        if ($got < $min) {
            throw new \RuntimeException(($msg !== '' ? "{$msg}: " : '') . "want >= {$min}, got {$got}");
        }
    }

    public static function skip(string $reason): never
    {
        throw new SkipException($reason);
    }

    private static function show(mixed $v): string
    {
        if (is_string($v)) {
            if (strlen($v) <= 24 && preg_match('/^[\x20-\x7e]*$/', $v)) {
                return "'{$v}'";
            }
            return 'hex:' . bin2hex($v);
        }
        return var_export($v, true);
    }

    public static function summary(): int
    {
        fwrite(STDOUT, "\n" . str_repeat('-', 60) . "\n");
        fwrite(STDOUT, 'passed ' . self::$passed . ', failed ' . self::$failed . ', skipped ' . self::$skipped . "\n");
        if (self::$failures) {
            fwrite(STDOUT, "\nfailures:\n");
            foreach (self::$failures as $f) {
                fwrite(STDOUT, "  - {$f}\n");
            }
        }
        return self::$failed === 0 ? 0 : 1;
    }
}

final class SkipException extends \RuntimeException
{
}
