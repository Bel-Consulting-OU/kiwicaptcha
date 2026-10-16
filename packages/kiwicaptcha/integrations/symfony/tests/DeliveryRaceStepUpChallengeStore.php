<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\MalformedStepUpChallengeException;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendLease;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendSettlement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorCompletion;

/**
 * A store decorator that places the competing request at the exact seam
 * the email one-time-code begin calls. A race test therefore drives a
 * real state move rather than a mock's opinion.
 *
 * The seams:
 *
 *  - `refuseNextLeaseClaim`: the next claim is answered as a held lease
 *    is answered. The claim is not taken, so the begin under test loses.
 *  - `throwOnLeaseClaim`: the claim cannot be made, the fail-closed path.
 *  - `throwOnAdmission`: the admission raises before any record lands,
 *    the pre-handoff refusal path.
 *
 * Every delegation is otherwise exact, and the recorder lists are the
 * evidence: `releasedReservations` proves a refused begin handed its mail
 * capacity back, and `admittedDuringRefusal` proves nothing entered the
 * store while the window was held.
 */
final class DeliveryRaceStepUpChallengeStore implements StepUpChallengeStore
{
    public bool $refuseNextLeaseClaim = false;

    public bool $throwOnLeaseClaim = false;

    public bool $throwOnAdmission = false;

    /** @var list<string> */
    public array $releasedReservations = [];

    /** @var list<string> */
    public array $admittedDuringRefusal = [];

    public function __construct(private readonly StepUpChallengeStore $inner)
    {
    }

    public function create(StepUpChallenge $challenge, int $ttlSecs): string
    {
        return $this->inner->create($challenge, $ttlSecs);
    }

    public function createAdmittedChallenge(StepUpChallenge $challenge, int $ttlSecs): string
    {
        if ($this->throwOnAdmission) {
            throw new \RuntimeException('the admission seam failed before any record landed');
        }

        return $this->inner->createAdmittedChallenge($challenge, $ttlSecs);
    }

    /**
     * @throws MalformedStepUpChallengeException
     */
    public function read(string $challengeId): ?StepUpChallenge
    {
        return $this->inner->read($challengeId);
    }

    public function consume(string $challengeId): ?StepUpChallenge
    {
        return $this->inner->consume($challengeId);
    }

    public function recordFailure(string $challengeId, int $maxAttempts): int
    {
        return $this->inner->recordFailure($challengeId, $maxAttempts);
    }

    public function countBegin(string $principalPseudonym, int $windowSecs): int
    {
        return $this->inner->countBegin($principalPseudonym, $windowSecs);
    }

    public function createDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        return $this->inner->createDemand($demand, $ttlSecs);
    }

    public function readDemand(string $demandId): ?StepUpDemand
    {
        return $this->inner->readDemand($demandId);
    }

    public function consumeDemand(string $demandId): ?StepUpDemand
    {
        return $this->inner->consumeDemand($demandId);
    }

    public function completeDemand(string $demandId, int $now, int $ttlSecs): ?StepUpDemand
    {
        return $this->inner->completeDemand($demandId, $now, $ttlSecs);
    }

    public function completeFactor(
        string $challengeId,
        string $demandId,
        string $presentedBindingHash,
        int $now,
        ?string $sessionHash = null,
        ?string $scope = null,
        ?string $lineageHash = null,
    ): ?StepUpFactorCompletion {
        return $this->inner->completeFactor($challengeId, $demandId, $presentedBindingHash, $now, $sessionHash, $scope, $lineageHash);
    }

    public function completedFactorOf(string $lineageHash, ?string $principalPseudonym, string $scope, int $now): ?string
    {
        return $this->inner->completedFactorOf($lineageHash, $principalPseudonym, $scope, $now);
    }

    public function claimDemandFinalization(string $demandId, int $now, int $claimSecs): ?StepUpDemand
    {
        return $this->inner->claimDemandFinalization($demandId, $now, $claimSecs);
    }

    public function settleDemandFinalization(string $demandId, StepUpDemandState $state, int $now, ?string $factor = null): ?StepUpDemand
    {
        return $this->inner->settleDemandFinalization($demandId, $state, $now, $factor);
    }

    public function recordDemandEffect(string $demandId, string $effect, int $now): ?StepUpDemand
    {
        return $this->inner->recordDemandEffect($demandId, $effect, $now);
    }

    public function demandIdForFamily(string $familyDigest): ?string
    {
        return $this->inner->demandIdForFamily($familyDigest);
    }

    public function createRootDemand(StepUpDemand $demand, int $ttlSecs): string
    {
        return $this->inner->createRootDemand($demand, $ttlSecs);
    }

    public function supersedeDemandWithChild(string $parentDemandId, StepUpDemand $child): ?StepUpDemand
    {
        return $this->inner->supersedeDemandWithChild($parentDemandId, $child);
    }

    public function claimDemandSendLease(string $demandId, int $resendAfterSecs, int $leaseSecs): ?StepUpDemandSendLease
    {
        if ($this->throwOnLeaseClaim) {
            throw new \RuntimeException('the delivery window cannot be claimed');
        }
        if ($this->refuseNextLeaseClaim) {
            $this->refuseNextLeaseClaim = false;
            $admitted = $this->inner->readDemand($demandId)?->activeChallengeId;
            if ($admitted !== null) {
                $this->admittedDuringRefusal[] = $admitted;
            }

            return null;
        }

        return $this->inner->claimDemandSendLease($demandId, $resendAfterSecs, $leaseSecs);
    }

    public function settleDemandSendLease(StepUpDemandSendSettlement $settlement): bool
    {
        return $this->inner->settleDemandSendLease($settlement);
    }

    /**
     * @param list<string> $budgetKeys
     * @param list<int>    $limits
     */
    public function reserveMailQuota(string $reservationId, array $budgetKeys, array $limits, int $windowSecs, int $leaseSecs): bool
    {
        return $this->inner->reserveMailQuota($reservationId, $budgetKeys, $limits, $windowSecs, $leaseSecs);
    }

    public function commitMailQuota(string $reservationId): void
    {
        $this->inner->commitMailQuota($reservationId);
    }

    public function releaseMailQuota(string $reservationId): bool
    {
        $this->releasedReservations[] = $reservationId;

        return $this->inner->releaseMailQuota($reservationId);
    }

    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void
    {
        $this->inner->saveTotpSecret($principalPseudonym, $secretRaw);
    }

    public function findTotpSecret(string $principalPseudonym): ?string
    {
        return $this->inner->findTotpSecret($principalPseudonym);
    }

    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool
    {
        return $this->inner->markTotpStep($principalPseudonym, $step, $ttlSecs);
    }

    public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void
    {
        $this->inner->markStepUpSuccess($principalPseudonym, $ttlSecs, $now);
    }

    public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool
    {
        return $this->inner->recentStepUpSuccess($principalPseudonym, $withinSecs, $now);
    }

    public function markSessionStepUpSuccess(string $sessionId, string $principalPseudonym, string $factor, int $ttlSecs, int $now): void
    {
        $this->inner->markSessionStepUpSuccess($sessionId, $principalPseudonym, $factor, $ttlSecs, $now);
    }

    public function recentSessionStepUpSuccess(string $sessionId, string $principalPseudonym, ?string $minFactor, int $withinSecs, int $now): bool
    {
        return $this->inner->recentSessionStepUpSuccess($sessionId, $principalPseudonym, $minFactor, $withinSecs, $now);
    }

    public function countLockoutFailure(string $dimension, string $pseudonym, int $windowSecs): int
    {
        return $this->inner->countLockoutFailure($dimension, $pseudonym, $windowSecs);
    }

    public function lockoutUntil(string $dimension, string $pseudonym, int $now): int
    {
        return $this->inner->lockoutUntil($dimension, $pseudonym, $now);
    }

    public function armLockout(string $dimension, string $pseudonym, int $now, int $ttlSecs): void
    {
        $this->inner->armLockout($dimension, $pseudonym, $now, $ttlSecs);
    }

    public function clearLockout(string $dimension, string $pseudonym): void
    {
        $this->inner->clearLockout($dimension, $pseudonym);
    }
}
