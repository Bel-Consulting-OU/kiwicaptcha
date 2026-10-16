<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * Optional capability of a target-state store: the idempotent
 * target-failure registration.
 *
 * A report path is at-least-once by nature (a webhook retry, a
 * redelivered job, two workers racing one delivery), so the failure
 * counter must be booked exactly once per report event id. The claim
 * and the counter increment run inside one script on the target
 * family's own slot, so a retry can never book a second failure and a
 * crash can never leave the claim without its effect. The report's
 * derived event id is the dedupe id, the same one the report's mark and
 * reputation channel dedupe on.
 *
 * A separate capability interface, so third-party implementations of
 * {@see TargetStateStoreInterface} keep compiling unchanged: a store
 * without it answers through registerTargetFailure(), whose semantics
 * stay exactly as documented (one failure per call).
 */
interface IdempotentTargetFailureStoreInterface
{
    /**
     * Registers one authentication failure against the target dimension
     * exactly once per event id. It increments the leaky failure
     * counter and PFADDs the failing source/asn spread elements, unless
     * that event id already booked a failure. A retried report is then
     * a no-op that returns the current state. An empty event id
     * disables the dedupe and books one failure per call.
     *
     * @return array{fails: int, spread_sources: int, spread_asns: int, first_ms: int, last_ms: int}
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function registerTargetFailureOnce(string $targetId, string $source, string $asn, string $eventId): array;
}
