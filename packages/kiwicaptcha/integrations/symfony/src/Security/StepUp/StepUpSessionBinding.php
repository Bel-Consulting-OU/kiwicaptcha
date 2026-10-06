<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;

/**
 * The session binding of step-up completion: the completion of a
 * challenge is only ever accepted for the same principal that began
 * it. {@see \BelConsulting\KiwiCaptchaBundle\Controller\StepUpController::complete()}
 * re-resolves the principal of the current request and binds it here
 * before dispatching to a handler; every handler then requires the
 * bound principal to equal the challenge record's own — a stolen
 * ticket presented under another session is refused, never completed.
 *
 * A request that carries no binding (a handler reached without the
 * controller) matches nothing: fail closed, never open.
 */
final class StepUpSessionBinding
{
    /** The request attribute carrying the resolved principal pseudonym. */
    public const ATTRIBUTE = '_kiwi_step_up_principal';

    private function __construct()
    {
    }

    /** Bind the resolved principal pseudonym onto the request. */
    public static function bind(Request $request, string $principalPseudonym): void
    {
        $request->attributes->set(self::ATTRIBUTE, $principalPseudonym);
    }

    /**
     * Whether the request's bound principal is exactly the challenge's
     * principal. Absent or malformed bindings do not match.
     */
    public static function matches(Request $request, StepUpChallenge $challenge): bool
    {
        $bound = $request->attributes->get(self::ATTRIBUTE);
        if (!\is_string($bound) || $bound === '') {
            return false;
        }

        return hash_equals($challenge->principalPseudonym, $bound);
    }
}
