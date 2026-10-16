<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The handler family a challenge record belongs to. String-backed so
 * the persisted wire format is stable and machine-readable.
 */
enum StepUpChallengeKind: string
{
    case EmailOtp = 'email_otp';
    case Totp = 'totp';
    case WebAuthn = 'webauthn';
    /** The anonymous email-ownership challenge of the step_up_email carrier. */
    case EmailOwnership = 'email_ownership';

    /**
     * The proof class of this challenge kind: does the factor verify a
     * named account principal, or an address only?
     *
     * The rule lives here, on the kind, because the kind is what the
     * stored challenge record carries: the stores derive the class from
     * the record, never from a caller argument.
     *
     *  - email_otp, totp and webauthn are principal-authenticating.
     *    Each verifies material the account holds (a code sent to the
     *    account's address, a code from the account's totp secret, an
     *    assertion from the account's WebAuthn credential), and each
     *    record carries the account's subject pseudonym. A proof of
     *    these kinds therefore reproduces the principal a demand names.
     *  - email_ownership proves address ownership only. It verifies a
     *    code sent to a visitor-supplied mailbox and its record is
     *    deliberately anonymous with respect to the account subject
     *    (the wire decode refuses a subject on it). It can stand for
     *    the anonymous carrier's own demand, but a mailbox proof is not
     *    the account's proof and can never stand in for one.
     */
    public function provesPrincipal(): bool
    {
        return match ($this) {
            self::EmailOtp, self::Totp, self::WebAuthn => true,
            self::EmailOwnership => false,
        };
    }
}
