<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The constant-time comparison behind the signature and rsw checks.
 *
 * The test measures the minimum per-call time over many rounds for a
 * mismatch at the first byte and at the last byte of an 8 KiB value,
 * with the same-input run as the noise floor. A deliberately leaking
 * early-exit comparator calibrates the measurement: the leaked
 * position difference must be clearly visible, while the production
 * comparison must stay inside the noise band.
 */
final class WireConstantTimeTest extends TestCase
{
    private const LENGTH = 8192;

    private const ROUNDS = 25;

    private const CALLS = 10;

    /** @return float nanoseconds per call, the minimum over the rounds */
    private static function measure(callable $compare, string $a, string $b): float
    {
        $best = \INF;
        for ($round = 0; $round < self::ROUNDS; ++$round) {
            $start = hrtime(true);
            for ($call = 0; $call < self::CALLS; ++$call) {
                $compare($a, $b);
            }
            $best = min($best, (hrtime(true) - $start) / self::CALLS);
        }

        return $best;
    }

    private static function leaking(string $a, string $b): bool
    {
        $length = \strlen($a);
        for ($i = 0; $i < $length; ++$i) {
            if ($a[$i] !== $b[$i]) {
                return false;
            }
        }

        return true;
    }

    public function testTheSecretComparisonDoesNotLeakTheMismatchPosition(): void
    {
        $first = str_repeat('a', self::LENGTH);
        $last = $first;
        $last[self::LENGTH - 1] = 'b';

        $noiseA = self::measure([self::class, 'leaking'], $first, $first);
        $noiseB = self::measure([self::class, 'leaking'], $first, $first);
        $noise = max(1.0, abs($noiseA - $noiseB));

        $head = 'b'.substr($first, 1);
        $leakFirst = self::measure([self::class, 'leaking'], $first, $head);
        $leakLast = self::measure([self::class, 'leaking'], $first, $last);
        $leakDelta = abs($leakLast - $leakFirst);
        self::assertGreaterThan(
            max($noise * 10, 10_000),
            $leakDelta,
            'the measurement must be able to see an early exit',
        );

        $realFirst = self::measure('hash_equals', $first, $head);
        $realLast = self::measure('hash_equals', $first, $last);
        $realDelta = abs($realLast - $realFirst);
        $budget = max($noise * 10, $realFirst * 0.20, 2_000);
        self::assertLessThanOrEqual(
            $budget,
            $realDelta,
            sprintf('hash_equals leaked the mismatch position: first=%.0fns last=%.0fns noise=%.0fns', $realFirst, $realLast, $noise),
        );
    }
}
