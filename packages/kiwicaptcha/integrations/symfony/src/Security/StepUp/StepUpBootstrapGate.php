<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;

/**
 * The first-factor bootstrap gate: applications without email OTP have
 * no prior factor to complete a step-up with, so a first enrollment
 * would be a dead end. When enabled, a freshly verified signup or
 * recovery session may enroll a first factor. The marker is an
 * application-set request attribute ({@see self::ATTRIBUTE}) — the
 * application must only set it inside a signup/recovery flow that
 * verified the user out of band (email confirmation, recovery code).
 * The gate is off by default; the doctor warns when step-up is enabled
 * without either email OTP or this bootstrap.
 */
final class StepUpBootstrapGate
{
    /** The request attribute an application sets on a verified signup/recovery. */
    public const ATTRIBUTE = '_kiwi_signup_bootstrap';

    public function __construct(
        private readonly bool $enabled = false,
        private readonly ?\Symfony\Component\HttpFoundation\RequestStack $requestStack = null,
    ) {
    }

    public function allowsFirstEnrollment(?Request $request = null): bool
    {
        if (!$this->enabled) {
            return false;
        }
        $request ??= $this->requestStack?->getCurrentRequest();
        if ($request === null) {
            return false;
        }

        return $request->attributes->get(self::ATTRIBUTE) === true;
    }
}
