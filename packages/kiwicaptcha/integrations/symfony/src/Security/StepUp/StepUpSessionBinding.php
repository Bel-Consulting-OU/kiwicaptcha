<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;

/**
 * The session binding of step-up completion: the completion of a
 * challenge is only ever accepted for the same principal that began it
 * AND inside the same PHP session. {@see \BelConsulting\KiwiCaptchaBundle\Controller\StepUpController::complete()}
 * re-resolves the principal of the current request and binds it (plus
 * the session id) here before dispatching to a handler. Every handler
 * then requires the bound principal and session to equal the challenge
 * record's own. A stolen ticket presented under another session is
 * refused and never completed. A principal-level success marker alone
 * never authorizes enrollment: that proof is session-scoped.
 *
 * A request that carries no binding (a handler reached without the
 * controller) matches nothing: fail closed, never open.
 */
final class StepUpSessionBinding
{
    /** The request attribute carrying the resolved principal pseudonym. */
    public const ATTRIBUTE = '_kiwi_step_up_principal';

    /** The request attribute carrying the session id of this request. */
    public const SESSION_ATTRIBUTE = '_kiwi_step_up_session';

    private function __construct()
    {
    }

    /**
     * Bind the resolved principal pseudonym and the current session id
     * onto the request. The session id is read from the Symfony session
     * bag when one is started; without a started session the binding
     * carries an empty session and matches nothing (fail closed).
     */
    public static function bind(Request $request, string $principalPseudonym): void
    {
        $request->attributes->set(self::ATTRIBUTE, $principalPseudonym);
        $request->attributes->set(self::SESSION_ATTRIBUTE, self::sessionId($request));
    }

    /**
     * The session id of the request: the started Symfony session's id,
     * else the empty string. Never a client-supplied header.
     */
    public static function sessionId(Request $request): string
    {
        $session = $request->hasSession() ? $request->getSession() : null;
        if ($session === null || !$session->isStarted()) {
            return '';
        }

        return (string) $session->getId();
    }

    /**
     * Whether the request's bound principal and session match the
     * challenge. Absent or malformed bindings do not match. The
     * challenge's own recorded session hash is the authority: a
     * completion presented under a different session than the one that
     * began the challenge is refused, even for the same principal
     * (cross-session ticket replay / session fixation).
     *
     * An empty session id NEVER matches — on either side. A stateless
     * request (no started PHP session) can therefore never complete a
     * challenge, whatever the challenge recorded: the binding fails
     * closed rather than degenerating to a principal-only check.
     */
    public static function matches(Request $request, StepUpChallenge $challenge): bool
    {
        $bound = $request->attributes->get(self::ATTRIBUTE);
        if (!\is_string($bound) || $bound === '') {
            return false;
        }
        if (!hash_equals($challenge->principalPseudonym, $bound)) {
            return false;
        }
        $requestSession = self::sessionId($request);
        if ($requestSession === '') {
            return false;
        }
        $requestHash = StepUpChallenge::sessionHash($requestSession);
        $boundHash = $challenge->sessionHash;
        if ($boundHash === null || $boundHash === '') {
            // A challenge begun without a recorded session can never be
            // completed (an empty session id never matches).
            return false;
        }

        return $requestHash !== null && hash_equals($boundHash, $requestHash);
    }
}
