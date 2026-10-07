<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Support;

use KiwiCaptcha\ExecutionChallengeGenerator;

/**
 * The white-box execution forger: a full-knowledge adversary who has
 * read the published verifier source and reimplements the five
 * version-6 acceptance envelopes exactly as
 * ExecutionChallengeGenerator does. It never opens a browser, never
 * measures layout, never waits for a microtask. It walks the public
 * program semantics (the same state machine the browserless oracle
 * already uses for versions 1-5) and, at every version-6 probe, emits
 * an entry inside the operand-derived envelope the walker will accept.
 *
 * This class is the honest measurement of the version-6 boundary under
 * the red-team program's full-knowledge adversary rule. The naive
 * oracle (BrowserlessForgerySolver) emits the pure-sim placeholders and
 * is rejected; that rejection rate never measured a forger who knew the
 * envelopes. The envelopes are deterministic functions of the operands
 * that ship with the program, so any reader of the open-source verifier
 * can compute them. Version 6 therefore costs an attacker one reading
 * of the source — the same class as versions 1-5 — and is NOT a browser
 * boundary.
 *
 * Envelope values chosen here (all inside the published bands):
 *   CSS_GEOM      fs exact, height = the interval floor (no layout)
 *   MUT_ORDER     the exact record-type string the churn draws
 *   EV_PHASE_FULL the constant "1234:3"
 *   RANGE_ORDER   the exact string length, fragment count = the floor
 *   INT_OBS       the geometry-explicit ratio, isIntersecting from the
 *                 threshold band
 */
final class WhiteBoxEnvelopeForger
{
    private function __construct()
    {
    }

    /**
     * The OP_CSS_GEOM acceptance envelope, reimplemented from the
     * published verifier (ExecutionChallengeGenerator::cssGeomEnvelope).
     *
     * @return array{0: int, 1: int, 2: int, 3: int} [fsLo, fsHi, hLo, hHi]
     */
    public static function cssGeomEnvelope(int $seed): array
    {
        $fs = 10 + (($seed >> 5) % 5);
        $brd = 1 + (($seed >> 3) % 3);
        $words = ['kiwicaptcha', 'execution', 'boundary'];
        $count = \count($words);
        $textLen = \strlen($words[$seed % $count]) + 1 + \strlen($words[($seed + 1) % $count]);
        $linesMax = max(1, intdiv($textLen * $fs * 4 + 319, 320) + 1);

        return [$fs, $fs, $fs + 2 * $brd, $linesMax * 2 * $fs + 2 * $brd + 2];
    }

    /**
     * The OP_MUT_ORDER acceptance envelope, reimplemented from the
     * published verifier (ExecutionChallengeGenerator::mutOrderEnvelope).
     *
     * @return array{0: string, 1: int} [expectedCodeString, recordCount]
     */
    public static function mutOrderEnvelope(int $b0, int $b1): array
    {
        $kids = 1 + ($b0 % 2);
        $expected = '1'.str_repeat('2', $kids + 1).(($b1 & 1) === 1 ? '3' : '').'7';
        $records = $kids + 2 + (($b1 & 1) === 1 ? 1 : 0);

        return [$expected, $records];
    }

    /**
     * The OP_RANGE_ORDER acceptance envelope, reimplemented from the
     * published verifier (ExecutionChallengeGenerator::rangeOrderEnvelope).
     *
     * @return array{0: int, 1: int, 2: int} [tExact, rectsLo, rectsHi]
     */
    public static function rangeOrderEnvelope(int $ra, int $rb): array
    {
        $words = ['alpha', 'beta', 'gamma', 'delta'];
        $w0 = $words[$ra % 4];
        $w1 = $words[($ra + 1) % 4];
        $w2 = $words[($ra + 2) % 4];
        $a = $ra % 5;
        $e = $rb % (\strlen($w2) + 1);
        $tExact = (\strlen($w0) - $a) + \strlen($w1) + $e;

        return [$tExact, 1, 16];
    }

    /**
     * The OP_INT_OBS acceptance envelope, reimplemented from the
     * published verifier (ExecutionChallengeGenerator::intObsEnvelope).
     *
     * @return array{0: int, 1: int, 2: int} [qLo, qHi, t0Pct]
     */
    public static function intObsEnvelope(int $seed): array
    {
        $m = 5 + ($seed % 36);
        $ih = min(max(40 - $m, 0), 20);
        $qExp = $ih * 5;
        $t0Pct = [0, 25, 50, 75][$seed % 4];

        return [max(0, $qExp - 2), min(100, $qExp + 2), $t0Pct];
    }

    /**
     * The constant OP_EV_PHASE_FULL body the published walker demands:
     * capture 1, target registration order 2 then 3, bubble 4, and the
     * bubble listener's dataset side effect "3".
     */
    public static function evPhaseFullBody(): string
    {
        return '1234:3';
    }

    /**
     * Forge a verifier-accepted executed trace of a decoded program
     * without a browser. The observed-height choice is the explicit
     * parameter (any 1..255, same as the naive oracle); the version-6
     * entries come from the reimplemented envelopes above.
     *
     * @param array{format: int, scope: string, action: string, op_version: int, ops: list<array{op: int, operands: array<string, mixed>}>} $program
     */
    public static function forge(array $program, int $observedHeight = 17): string
    {
        return ExecutionTraceFixture::executedTraceForWhiteBox($program, $observedHeight);
    }
}
