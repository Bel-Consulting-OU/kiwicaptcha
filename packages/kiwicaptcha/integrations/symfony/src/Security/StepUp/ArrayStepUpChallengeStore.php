<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * In-memory step-up store for test and dev semantics: single-process
 * only. The production wiring of the step-up plane always sits on the
 * Redis store (risk.enabled requires a risk Redis client), so this
 * implementation exists for unit tests and offline kernels.
 *
 * Mirrors the Redis store exactly, with an explicit clock: expiry is
 * evaluated on read, consume is a read-and-remove, and the attempt
 * accounting answers the same contract. Every record round-trips
 * through the strict wire decode, so this store observes the identical
 * schema the Redis store persists.
 */
final class ArrayStepUpChallengeStore implements StepUpChallengeStore
{
    /** @var array<string, array{record: StepUpChallenge, expiresAt: int}> */
    private array $challenges = [];

    /** @var array<string, int> */
    private array $beginWindows = [];

    /** @var array<string, string> */
    private array $totpSecrets = [];

    /** @var array<string, int> */
    private array $totpSteps = [];

    public function __construct(
        private readonly ?\Closure $now = null,
    ) {
    }

    public function create(StepUpChallenge $challenge, int $ttlSecs): string
    {
        $this->challenges[$challenge->id] = [
            'record' => StepUpChallenge::fromJson((string) json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES)),
            'expiresAt' => ($this->now()) + max(1, $ttlSecs),
        ];

        return $challenge->id;
    }

    public function read(string $challengeId): ?StepUpChallenge
    {
        return $this->live($challengeId);
    }

    public function consume(string $challengeId): ?StepUpChallenge
    {
        $record = $this->live($challengeId);
        if ($record !== null) {
            unset($this->challenges[$challengeId]);
        }

        return $record;
    }

    public function recordFailure(string $challengeId, int $maxAttempts): int
    {
        $record = $this->live($challengeId);
        if ($record === null) {
            return -1;
        }
        $attempts = $record->attempts + 1;
        if ($attempts >= max(1, $maxAttempts)) {
            unset($this->challenges[$challengeId]);

            return 0;
        }
        $this->challenges[$challengeId]['record'] = $record->withAttempts($attempts);

        return $attempts;
    }

    public function countBegin(string $principalPseudonym, int $windowSecs): int
    {
        $this->beginWindows[$principalPseudonym] = ($this->beginWindows[$principalPseudonym] ?? 0) + 1;

        return $this->beginWindows[$principalPseudonym];
    }

    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void
    {
        $this->totpSecrets[$principalPseudonym] = $secretRaw;
    }

    public function findTotpSecret(string $principalPseudonym): ?string
    {
        return $this->totpSecrets[$principalPseudonym] ?? null;
    }

    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool
    {
        if (($this->totpSteps[$principalPseudonym] ?? -1) >= $step) {
            return false;
        }
        $this->totpSteps[$principalPseudonym] = $step;

        return true;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    private function live(string $challengeId): ?StepUpChallenge
    {
        $entry = $this->challenges[$challengeId] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($this->now() >= $entry['expiresAt']) {
            unset($this->challenges[$challengeId]);

            return null;
        }

        return $entry['record'];
    }
}
