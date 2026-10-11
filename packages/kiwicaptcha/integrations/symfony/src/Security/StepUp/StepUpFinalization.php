<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The typed answer of the shared {@see StepUpDemandFinalizer}: whether
 * the completed demand settled authorized, and under which reason
 * otherwise. A refusal reason names the failed stage (the recipe
 * rerun, the lifecycle state, the reassessment denial, an absent or
 * unbound demand) so the calling lane answers the right failure and
 * the log tells the operator which gate closed.
 */
final class StepUpFinalization
{
    public const AUTHORIZED = 'authorized';
    public const AUTHORIZED_REPLAY = 'authorized_replay';
    public const REFUSED_UNBOUND = 'refused_unbound';
    public const REFUSED_ABSENT = 'refused_absent';
    public const REFUSED_DIGEST = 'refused_digest';
    public const REFUSED_STATE = 'refused_state';
    public const REFUSED_DENIED = 'refused_denied';

    private function __construct(
        public readonly bool $authorized,
        public readonly string $reason,
        public readonly ?StepUpDemand $demand,
    ) {
    }

    public static function authorized(StepUpDemand $demand): self
    {
        return new self(true, self::AUTHORIZED, $demand);
    }

    /** The demand was already settled authorized by a previous owner; the effects replay idempotently. */
    public static function authorizedReplay(StepUpDemand $demand): self
    {
        return new self(true, self::AUTHORIZED_REPLAY, $demand);
    }

    public static function refusedUnbound(): self
    {
        return new self(false, self::REFUSED_UNBOUND, null);
    }

    public static function refusedAbsent(): self
    {
        return new self(false, self::REFUSED_ABSENT, null);
    }

    public static function refusedDigest(): self
    {
        return new self(false, self::REFUSED_DIGEST, null);
    }

    public static function refusedState(): self
    {
        return new self(false, self::REFUSED_STATE, null);
    }

    public static function refusedDenied(): self
    {
        return new self(false, self::REFUSED_DENIED, null);
    }
}
