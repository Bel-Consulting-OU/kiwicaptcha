<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The one record an atomic factor completion answers: which challenge
 * and demand the transition consumed, and the subject it verified.
 *
 * Every field is read back from the strictly decoded server records
 * the transition consumed, never from a caller argument. The verified
 * subject follows the stored challenge: a principal-family challenge
 * verifies its subject pseudonym, the anonymous email-ownership family
 * verifies the address pseudonym it stores in the principal field.
 */
final class StepUpFactorCompletion
{
    public function __construct(
        public readonly string $challengeId,
        public readonly string $demandId,
        public readonly StepUpChallengeKind $kind,
        public readonly string $scope,
        public readonly string $verifiedSubjectPseudonym,
        public readonly ?string $sessionHash,
        public readonly ?string $chainId,
        public readonly string $completedFactor,
    ) {
    }

    /**
     * The completion of the two consumed records. The subject derives
     * from the challenge alone: the email-ownership family stores the
     * address pseudonym as its principal, every other family stores the
     * subject pseudonym the record was begun under.
     */
    public static function fromRecords(StepUpChallenge $challenge, StepUpDemand $demand, string $completedFactor): self
    {
        $subject = $challenge->kind === StepUpChallengeKind::EmailOwnership
            ? $challenge->principalPseudonym
            : (string) $challenge->principalSubject();
        if ($subject === '') {
            throw new \InvalidArgumentException('The consumed challenge names no verifiable subject');
        }

        return new self(
            $challenge->id,
            $demand->id,
            $challenge->kind,
            $challenge->scope,
            $subject,
            $challenge->sessionHash,
            $demand->chainId,
            $completedFactor,
        );
    }
}
