<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * The constant-time comparison behind the signature and rsw checks.
 *
 * Verifier::constantTimeEquals is the production entry point (it wraps
 * hash_equals), so that wrapper is what is measured here.
 *
 * Methodology. This replaced a minimum-of-rounds design whose
 * deliberately leaking positive control was not reliably detected on
 * the CI PHP 8.2 lane; such a run supports no security conclusion in
 * either direction.
 *
 *   1. Positive control. A char-by-char early-return comparator on hex
 *      strings is measured in the same interleaved rounds as the
 *      production probes. Before any production conclusion, the harness
 *      must see the control's first-byte vs last-byte mismatch delta
 *      above a wide margin. The margin is the median of paired
 *      per-round differences beyond the control delta floor and its
 *      median-absolute-deviation bound, with the trimmed-mean
 *      difference agreeing in sign.
 *      If the control is not detected, the whole timing assertion is
 *      marked inconclusive with a documented skip. The run refuses a
 *      false green: a passing production assertion without a working
 *      control proves nothing. It refuses a false red just as firmly:
 *      a single noisy measurement is not evidence of a leak.
 *
 *   2. Amplification. 51 rounds of 40 calls per probe on a 16 KiB
 *      value, bounded by construction: the whole file stays in the low
 *      single-digit seconds even on a loaded shared runner.
 *
 *   3. Noise-tolerant estimators. Per-round per-call means (never
 *      minima) are
 *      reduced with a median, cross-checked by a 20% trimmed mean.
 *      First-byte-mismatch, last-byte-mismatch and equal probes are
 *      interleaved in a per-round shuffled order driven by a fixed
 *      mt_srand seed, so the order randomization is real but the run is
 *      reproducible. Production conclusions use paired per-round
 *      differences (late round minus early round of the same round),
 *      which cancel runner-wide drift.
 *
 *   4. The assertion. The production comparator must show no
 *      position-dependent delta beyond a noise-derived budget. The
 *      budget is the larger of an absolute floor, a sigma multiple of
 *      the paired differences, and a fixed fraction of a full compare.
 *      The sigma multiple is capped at a fraction of a full compare,
 *      so runner noise cannot mask a full-length leak. A comparator
 *      that short-circuits at the last byte leaks roughly one full
 *      compare time and exceeds this budget by a wide factor.
 */
final class WireConstantTimeTest extends TestCase
{
    /** Probe string length in characters (a multiple of 16). */
    private const LENGTH = 16384;

    /** Odd, so the median has an unambiguous middle element. */
    private const ROUNDS = 51;

    private const CALLS = 40;

    /** Fixed seed: the interleaving is real but reproducible. */
    private const SEED = 0x4B697743;

    /** Minimum leaked delta (ns) the control must show to count as detected. */
    private const CONTROL_MIN_DELTA_NS = 20_000;

    /** ...and it must additionally clear this many MADs of its own noise. */
    private const CONTROL_SIGMA = 10;

    /** Absolute budget floor (ns) for the production assertion. */
    private const PROD_MIN_BUDGET_NS = 250;

    /** MADs of paired production differences allowed into the budget... */
    private const PROD_SIGMA = 12;

    /** ...but never more than this fraction of a full compare. */
    private const PROD_MAD_CAP_FRACTION = 0.15;

    /** The budget is at most this fraction of a full compare time. */
    private const PROD_FRACTION = 0.25;

    public function testTheSecretComparisonDoesNotLeakTheMismatchPosition(): void
    {
        $base = self::hexProbe(self::LENGTH);
        $first = $base;
        $first[0] = $base[0] === '0' ? '1' : '0';
        $last = $base;
        $last[self::LENGTH - 1] = $base[self::LENGTH - 1] === '0' ? '1' : '0';

        $control = static fn (string $a, string $b): bool => self::leaking($a, $b);
        $production = static fn (string $a, string $b): bool => Verifier::constantTimeEquals($a, $b);

        // Functional sanity first: both comparators must actually
        // compare (we are timing the right calls, not fast no-ops).
        self::assertTrue($control($base, $base));
        self::assertFalse($control($base, $first));
        self::assertFalse($control($base, $last));
        self::assertTrue($production($base, $base));
        self::assertFalse($production($base, $first));
        self::assertFalse($production($base, $last));

        $samples = self::runInterleavedRounds($control, $production, $base, $first, $last);

        // Positive control: paired per-round differences of the leaking
        // comparator (last-byte minus first-byte mismatch).
        $controlDiff = self::pairedDifferences($samples['control']);
        $controlDelta = self::median($controlDiff);
        $controlSpread = self::medianAbsoluteDeviation($controlDiff);
        $controlTrimmed = self::trimmedMean($controlDiff);
        $controlDetected = $controlDelta >= max(
            self::CONTROL_MIN_DELTA_NS,
            self::CONTROL_SIGMA * $controlSpread,
        ) && $controlTrimmed > 0;
        if (!$controlDetected) {
            self::markTestSkipped(sprintf(
                'inconclusive: the timing harness cannot see its own leaking'
                .' positive control on this runner (control delta'
                .' median=%.0fns trimmed=%.0fns required>=%.0fns'
                .' or %.0fns [mad=%.0fns]), so no conclusion about'
                .' %s is supportable in either direction',
                $controlDelta,
                $controlTrimmed,
                (float) self::CONTROL_MIN_DELTA_NS,
                self::CONTROL_SIGMA * $controlSpread,
                $controlSpread,
                Verifier::class.'::constantTimeEquals()',
            ));
        }

        // Production: the same paired-difference reduction. Under the
        // null (full-length compare) the median difference sits at
        // jitter scale; a last-byte short-circuit would show almost a
        // full compare time.
        $prodDiff = self::pairedDifferences($samples['production']);
        $prodDelta = abs(self::median($prodDiff));
        $prodTrimmed = abs(self::trimmedMean($prodDiff));
        $equalLevel = self::median($samples['production']['equal']);
        $prodSpread = self::medianAbsoluteDeviation($prodDiff);
        $noiseTerm = min(self::PROD_SIGMA * $prodSpread, self::PROD_MAD_CAP_FRACTION * $equalLevel);
        $budget = max(self::PROD_MIN_BUDGET_NS, $noiseTerm, self::PROD_FRACTION * $equalLevel);
        self::assertLessThanOrEqual(
            $budget,
            $prodDelta,
            sprintf(
                '%s leaked the mismatch position: |median(late-early)|=%.0fns'
                .' (trimmed=%.0fns) exceeds budget %.0fns'
                .' [floor=%d noise<=%.0f scale=%.0f; equal=%.0fns, mad=%.0fns]'
                .' — detected while the positive control showed %.0fns',
                Verifier::class.'::constantTimeEquals()',
                $prodDelta,
                $prodTrimmed,
                $budget,
                self::PROD_MIN_BUDGET_NS,
                $noiseTerm,
                self::PROD_FRACTION * $equalLevel,
                $equalLevel,
                $prodSpread,
                $controlDelta,
            ),
        );
    }

    /**
     * The leaking char-by-char early-return comparator: the known
     * position-dependent timing behavior the harness must be able to
     * see before any production conclusion is allowed.
     */
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

    /**
     * A varied hex pattern (rather than one repeated byte) so probes
     * look like real signature material to the cache.
     */
    private static function hexProbe(int $length): string
    {
        $pattern = 'a5f03b6c1e92d748';
        $repeats = intdiv($length, \strlen($pattern));

        return substr(str_repeat($pattern, $repeats + 1), 0, $length);
    }

    /**
     * @return array<string, array<string, list<float>>>
     *     nanoseconds-per-call samples indexed [comparator][probe][round]
     */
    private static function runInterleavedRounds(
        callable $control,
        callable $production,
        string $base,
        string $first,
        string $last,
    ): array {
        gc_collect_cycles();

        // Warm every (comparator, probe) path once untimed: first-touch
        // page faults and lazy binds must not land in a timed round.
        $comparators = ['control' => $control, 'production' => $production];
        $probePairs = static fn (string $probe): array => match ($probe) {
            'first' => [$base, $first],
            'last' => [$base, $last],
            default => [$base, $base],
        };
        foreach ($comparators as $compare) {
            foreach (['first', 'last', 'equal'] as $probe) {
                [$a, $b] = $probePairs($probe);
                $compare($a, $b);
                $compare($a, $b);
            }
        }

        mt_srand(self::SEED);
        $keys = [];
        foreach (array_keys($comparators) as $comparator) {
            foreach (['first', 'last', 'equal'] as $probe) {
                $keys[] = $comparator.'.'.$probe;
            }
        }

        $samples = [];
        for ($round = 0; $round < self::ROUNDS; ++$round) {
            // Real interleaving: a fresh shuffle every round, from the
            // fixed seed so the whole schedule is reproducible.
            $order = $keys;
            \shuffle($order);
            foreach ($order as $key) {
                [$comparator, $probe] = explode('.', $key);
                [$a, $b] = $probePairs($probe);
                $compare = $comparators[$comparator];
                $start = hrtime(true);
                for ($call = 0; $call < self::CALLS; ++$call) {
                    $compare($a, $b);
                }
                $samples[$comparator][$probe][] = (hrtime(true) - $start) / self::CALLS;
            }
        }

        return $samples;
    }

    /**
     * Per-round paired differences, late minus first. Pairing within a
     * round cancels runner-wide drift (CPU frequency scaling, noisy
     * neighbors) that would otherwise swamp the position signal.
     *
     * @param array<string, list<float>> $samples [probe][round]
     * @return list<float> nanoseconds
     */
    private static function pairedDifferences(array $samples): array
    {
        $diff = [];
        foreach ($samples['last'] as $round => $late) {
            $diff[] = $late - $samples['first'][$round];
        }

        return $diff;
    }

    /** @param list<float> $values */
    private static function median(array $values): float
    {
        return self::percentile($values, 0.5);
    }

    /** @param list<float> $values */
    private static function medianAbsoluteDeviation(array $values): float
    {
        $center = self::median($values);
        $deviations = array_map(static fn (float $v): float => abs($v - $center), $values);

        return self::median($deviations);
    }

    /**
     * The mean after discarding $trim of the values at each tail: keeps
     * the estimator tolerant of isolated scheduler hiccups while still
     * using the bulk of the samples (unlike the old minimum).
     *
     * @param list<float> $values
     */
    private static function trimmedMean(array $values, float $trim = 0.2): float
    {
        sort($values);
        $count = \count($values);
        $cut = (int) floor($count * $trim);
        $kept = \array_slice($values, $cut, $count - 2 * $cut);
        if ($kept === []) {
            return self::median($values);
        }

        return array_sum($kept) / \count($kept);
    }

    /** @param list<float> $values */
    private static function percentile(array $values, float $p): float
    {
        sort($values);
        $count = \count($values);
        self::assertGreaterThan(0, $count);
        $index = ($count - 1) * $p;
        $low = (int) floor($index);
        $high = (int) ceil($index);
        if ($low === $high) {
            return $values[$low];
        }

        return $values[$low] + ($values[$high] - $values[$low]) * ($index - $low);
    }
}
