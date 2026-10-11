<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The delivery seam of the anonymous email-ownership factor. Unlike the
 * principal-bound passcode sender, this seam receives the raw address:
 * the requester just typed it, there is no account record to look up,
 * and delivering to it is the whole point of the factor.
 *
 * The application binds exactly one implementation and hands the code
 * to its own mailer; the bundle carries no mailer dependency. A
 * throwing sender fails the begin call fail-closed: no challenge
 * record survives an undelivered code.
 */
interface EmailOwnershipCodeSenderInterface
{
    /**
     * Deliver one 6-digit code to the presented address. The TTL is
     * passed so the message can state the deadline.
     *
     * @throws \Throwable when delivery failed; begin then answers a
     *                    refusal and removes the challenge record
     */
    public function send(string $email, string $code, int $ttlSecs): void;
}
