<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The server-side state of the step-up plane: challenge records, the
 * per-principal begin bound and the durable principal state of the
 * time-based handler, its enrollment secret and its replay guard.
 *
 * The challenge lifecycle is single-use and replay safe by
 * construction. create() mints an unguessable id under a TTL.
 * consume() answers the record to exactly one caller, with getdel
 * semantics. recordFailure() is the atomic attempt-accounting
 * transition that removes the record when the attempt cap is reached.
 * countBegin() is the store-backed rate bound of begin(), a fixed
 * per-principal window counter whose admission the handler compares
 * against the configured cap.
 *
 * Keys carry only pseudonyms and opaque ids: every key of this store
 * is derived from the deployment namespace plus either a random
 * challenge id or the principal pseudonym, never a raw identifier.
 */
interface StepUpChallengeStore
{
    /**
     * Persist a fresh challenge record under its own unguessable id
     * (the challenge id the signed ticket names) and answer that id.
     * The record expires after the given TTL.
     */
    public function create(StepUpChallenge $challenge, int $ttlSecs): string;

    /**
     * The live record of a challenge id, or null when absent or
     * expired. Non-consuming.
     *
     * @throws MalformedStepUpChallengeException when the persisted record violates the strict schema
     */
    public function read(string $challengeId): ?StepUpChallenge;

    /**
     * Atomically answer and remove the record of a challenge id: the
     * single-use consumption. Exactly one caller of a concurrent pair
     * receives the record; every other caller receives null.
     *
     * @throws MalformedStepUpChallengeException when the persisted record violates the strict schema
     */
    public function consume(string $challengeId): ?StepUpChallenge;

    /**
     * The attempt-accounting transition: atomically count one failed
     * verification. Answers the attempt count now used (>= 1) while the
     * challenge stays live, 0 when the cap is reached and the record
     * was removed, and -1 when the challenge is absent. A record that
     * fails the strict decode is removed and answered -2, fail-closed:
     * corrupt state never becomes a verifiable challenge.
     */
    public function recordFailure(string $challengeId, int $maxAttempts): int;

    /**
     * Count one begun challenge for the principal inside the fixed
     * window and answer the window's new admission count. The handler
     * refuses begin() while the count exceeds its configured cap.
     */
    public function countBegin(string $principalPseudonym, int $windowSecs): int;

    /**
     * Persist the enrollment secret of the time-based handler for the
     * principal (durable: no TTL). The secret is the raw binary key,
     * stored server-side keyed by the principal pseudonym. Encryption
     * at rest is out of scope for this store: the deployment protects
     * its risk Redis like every other security state.
     */
    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void;

    /**
     * The enrollment secret of the principal, or null when the
     * principal is not enrolled.
     */
    public function findTotpSecret(string $principalPseudonym): ?string;

    /**
     * The replay guard of the time-based handler: claim one time-step
     * for the principal. True when the step was unclaimed (this
     * verification is the first to use it); false when the step was
     * already used, so the same code can never verify twice.
     */
    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool;

    /**
     * Record that the principal just completed a step-up (any handler):
     * the marker lives for $ttlSecs and gates the WebAuthn enrollment
     * precondition, so stolen credentials can never mint a first
     * credential on a victim's account.
     */
    public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void;

    /**
     * Whether the same principal completed a step-up within the last
     * $withinSecs (a caller-supplied $now keeps the clock testable).
     */
    public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool;
}
