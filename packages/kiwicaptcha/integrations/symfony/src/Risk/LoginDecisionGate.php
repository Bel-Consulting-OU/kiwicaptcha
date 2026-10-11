<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskDecision;

/**
 * The post-credential, pre-session decision seam: one assessment with
 * the AuthenticationSuccess event and the resolved principal id. The
 * first-attempt login guard calls this so the engine's
 * firstAttemptEvidence can demand a step-up before the session is
 * granted. Separated from the concrete gateway so the guard is
 * testable and so a deployment can swap the implementation.
 */
interface LoginDecisionGate
{
    /**
     * @param string|null $session the raw continuity cookie value (32
     *                             hex chars), null when absent
     * @param string|null $device  the raw trusted-device cookie value
     *                             (32 hex chars), null when absent
     *
     * @param string|null $principal the raw user identifier. The engine
     *                             derives the keyed pseudonym itself, so
     *                             the judged identity is the one the
     *                             restore and reputation paths bind
     */
    public function loginDecision(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null, ?string $device = null): ?RiskDecision;
}
