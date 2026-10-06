<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The cross-challenge brute-force budget of the step-up plane. The
 * per-challenge attempt cap alone allows ~1440 guesses/day (3 begins
 * per 15-minute window × 5 attempts × 96 windows). The verification
 * failures also feed an escalating lockout keyed by both the principal
 * and the target pseudonym. Each failure bumps the pair's window
 * counter; at every threshold the lockout is armed (or extended) for
 * the matching duration, and the owner is notified through the
 * configured hook. begin() and complete() both refuse while a lockout
 * holds, so the budget can never be farmed across fresh challenges.
 *
 * The escalation is monotone in the failure count: the more a pair
 * fails, the longer it sits out. A completed step-up clears the pair's
 * budget (the verified owner earned the reset; an attacker has not).
 */
final class StepUpLockoutGuard
{
    public const DIMENSION_PRINCIPAL = 'principal';
    public const DIMENSION_TARGET = 'target';

    /**
     * The escalation ladder: [failures within the window, lockout
     * seconds]. The default walks 5 → 5 min, 15 → 30 min, 40 → 2 h,
     * 100 → 24 h, so a sustained campaign ends in a full-day lockout
     * while a handful of typos costs five minutes.
     */
    public const DEFAULT_LADDER = [
        [5, 300],
        [15, 1800],
        [40, 7200],
        [100, 86400],
    ];

    /** The fixed failure-counter window: one day, the brute-force budget horizon. */
    public const DEFAULT_WINDOW_SECS = 86400;

    /** @var list<array{0: int, 1: int}> */
    private readonly array $ladder;

    /**
     * @param list<array{0: int, 1: int}> $ladder       the escalation
     *                                             ladder, ascending in
     *                                             both fields
     * @param StepUpOwnerNotifier|null    $notifyOwner called whenever a
     *                                             lockout is armed or
     *                                             extended
     * @param \Closure|null               $now        the epoch-seconds
     *                                             clock override for
     *                                             tests
     */
    public function __construct(
        private readonly StepUpChallengeStore $store,
        array $ladder = self::DEFAULT_LADDER,
        private readonly int $windowSecs = self::DEFAULT_WINDOW_SECS,
        private readonly ?StepUpOwnerNotifier $notifyOwner = null,
        private readonly ?\Closure $now = null,
    ) {
        if ($ladder === []) {
            throw new \InvalidArgumentException('The step-up lockout ladder must not be empty');
        }
        $previousFailures = 0;
        $previousLockout = 0;
        foreach ($ladder as $rung) {
            if (!\is_array($rung) || \count($rung) !== 2 || $rung[0] <= $previousFailures || $rung[1] <= $previousLockout) {
                throw new \InvalidArgumentException('The step-up lockout ladder must be strictly ascending in failures and lockout seconds');
            }
            $previousFailures = (int) $rung[0];
            $previousLockout = (int) $rung[1];
        }
        $this->ladder = array_map(static fn (array $rung): array => [(int) $rung[0], (int) $rung[1]], $ladder);
        if ($this->windowSecs < 1) {
            throw new \InvalidArgumentException('The step-up lockout window must be positive');
        }
    }

    /**
     * The seconds a pair must still wait, 0 when admissible. The
     * maximum of the principal and the target deadline: either
     * dimension's lockout holds the whole pair out.
     */
    public function retryAfterSecs(string $principalPseudonym, ?string $targetPseudonym, ?int $now = null): int
    {
        $now ??= $this->now();
        $deadlines = [$this->store->lockoutUntil(self::DIMENSION_PRINCIPAL, $principalPseudonym, $now)];
        if ($targetPseudonym !== null && $targetPseudonym !== '') {
            $deadlines[] = $this->store->lockoutUntil(self::DIMENSION_TARGET, $targetPseudonym, $now);
        }

        return max(0, max($deadlines) - $now);
    }

    /**
     * Record one failed verification for the pair: both budget keys
     * are bumped and each of them is escalated independently, so a
     * single abused account and a single hot target both cool off.
     */
    public function registerFailure(string $principalPseudonym, ?string $targetPseudonym): void
    {
        $now = $this->now();
        $this->escalate(self::DIMENSION_PRINCIPAL, $principalPseudonym, $now);
        if ($targetPseudonym !== null && $targetPseudonym !== '') {
            $this->escalate(self::DIMENSION_TARGET, $targetPseudonym, $now);
        }
    }

    /**
     * Clear the pair's budget: called on a completed step-up, so the
     * verified owner is not kept out by earlier typos while the
     * attacker's budget never resets (they never complete).
     */
    public function registerSuccess(string $principalPseudonym, ?string $targetPseudonym): void
    {
        $this->store->clearLockout(self::DIMENSION_PRINCIPAL, $principalPseudonym);
        if ($targetPseudonym !== null && $targetPseudonym !== '') {
            $this->store->clearLockout(self::DIMENSION_TARGET, $targetPseudonym);
        }
    }

    private function escalate(string $dimension, string $pseudonym, int $now): void
    {
        $failures = $this->store->countLockoutFailure($dimension, $pseudonym, $this->windowSecs);
        $lockoutSecs = null;
        foreach ($this->ladder as [$threshold, $secs]) {
            if ($failures >= $threshold) {
                $lockoutSecs = $secs;
            }
        }
        if ($lockoutSecs === null) {
            return;
        }
        $this->store->armLockout($dimension, $pseudonym, $now, $lockoutSecs);
        $this->notifyOwner?->notifyLockout($dimension, $pseudonym, $now + $lockoutSecs, $failures);
    }

    private function now(): int
    {
        return ($this->now) ? (int) ($this->now)() : time();
    }
}
