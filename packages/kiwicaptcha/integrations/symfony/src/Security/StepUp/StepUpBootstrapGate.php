<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;

/**
 * The first-factor bootstrap gate: applications without email OTP have
 * no prior factor to complete a step-up with, so a first enrollment
 * would be a dead end. When enabled, a freshly verified signup or
 * recovery session may enroll a first factor.
 *
 * The grant is never a request attribute (any client could set one).
 * The application calls {@see self::grant()} from inside a signup or
 * recovery flow that verified the user out of band (email confirmation,
 * recovery code); the gate stores a single-use marker in that session,
 * bound to the principal the application verified. The enrollment path
 * later calls {@see self::allowsFirstEnrollment()} with the same
 * principal spelling: a matching marker is consumed (one-time) and the
 * enrollment proceeds, any mismatch or a second attempt is refused. The
 * gate is off by default; the doctor warns when step-up is enabled
 * without either email OTP or this bootstrap.
 */
final class StepUpBootstrapGate
{
    /** The session key of the single-use, principal-bound grant. */
    private const SESSION_KEY = '_kiwi_signup_bootstrap_grant';

    public function __construct(
        private readonly bool $enabled = false,
        private readonly ?\Symfony\Component\HttpFoundation\RequestStack $requestStack = null,
    ) {
    }

    /**
     * Grant a one-time first-enrollment bootstrap to the session of
     * this request, bound to the given principal. Must be called only
     * from a signup/recovery flow that has already verified the user
     * out of band. A disabled gate or a request without a session
     * grants nothing (fail closed).
     */
    public function grant(Request $request, string $principal): void
    {
        if (!$this->enabled || $principal === '') {
            return;
        }
        $session = $request->hasSession() ? $request->getSession() : null;
        if ($session === null) {
            return;
        }
        $session->set(self::SESSION_KEY, ['principal' => hash('sha256', $principal)]);
    }

    /**
     * Whether this request may proceed to a first factor enrollment.
     * Consumes the session's grant on success (single-use); a missing
     * grant, a disabled gate, or a principal other than the granted one
     * answers false and leaves the marker for the principal it was
     * granted to. The principal spelling must equal the one passed to
     * {@see self::grant()}.
     */
    public function allowsFirstEnrollment(?Request $request = null, ?string $principal = null): bool
    {
        if (!$this->enabled) {
            return false;
        }
        $request ??= $this->requestStack?->getCurrentRequest();
        if ($request === null || $principal === null || $principal === '') {
            return false;
        }
        $session = $request->hasSession() ? $request->getSession() : null;
        if ($session === null) {
            return false;
        }
        $grant = $session->get(self::SESSION_KEY);
        if (!\is_array($grant) || !\is_string($grant['principal'] ?? null)) {
            return false;
        }
        if (!hash_equals($grant['principal'], hash('sha256', $principal))) {
            return false;
        }
        $session->remove(self::SESSION_KEY);

        return true;
    }
}
