<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The email one-time-passcode reference handler: a 6 or 8 digit code
 * from random_int, delivered through the application-bound
 * {@see StepUpCodeSenderInterface}.
 *
 * Only a keyed hash of the code is stored, under a purpose-separated
 * key from the bundle's shared HKDF derivation. A store snapshot leaks
 * no second factor; the code itself lives solely in the delivery
 * channel. The challenge carries a 300 s configurable TTL, a 5-attempt
 * cap and single-use consumption. Begin is rate-bounded per principal
 * through a store-backed window counter, 3 admissions per 15 minutes
 * by default; beyond the bound begin answers a 429 refusal with the
 * window as the retry hint, fail-closed.
 *
 * The completion is the verified factor proof: the answered code
 * consumes the one record single-use, books the factor-plane proof
 * markers (the enrollment preconditions) and answers
 * {@see StepUpResult::proved()} naming the demand the challenge was
 * bound to. The proof books no outcome and restores no session; the
 * demand finalization owns the authorization and the effects.
 */
final class EmailOtpStepUpHandler implements StepUpHandlerInterface
{
    public const TICKET_FIELD = 'kiwi_step_up_ticket';
    public const CODE_FIELD = 'kiwi_step_up_code';

    private const HKDF_INFO = 'kiwi/v1/stepup-otp';

    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private const PROOF_MARKER_TTL_SECS = 900;

    /**
     * The delivery-reservation lease: how long a reserved mail slot is
     * held before a crashed worker's reservation commits by default
     * (spent is the fail-closed side, never free mail).
     */
    private const DELIVERY_LEASE_SECS = 30;

    private readonly string $otpKey;

    private readonly StepUpTicket $ticket;

    public function __construct(
        private readonly StepUpChallengeStore $store,
        StepUpTicket $ticket,
        private readonly StepUpCodeSenderInterface $sender,
        string $secretMaster,
        private readonly int $ttlSecs = 300,
        private readonly int $maxAttempts = 5,
        private readonly int $digits = 6,
        private readonly int $maxBegins = 3,
        private readonly int $beginWindowSecs = 900,
        private readonly string $completePath = '/kiwi/step-up/complete',
        private readonly ?\Closure $now = null,
        private readonly ?StepUpLockoutGuard $lockout = null,
    ) {
        if ($digits !== 6 && $digits !== 8) {
            throw new \InvalidArgumentException('The one-time passcode length must be 6 or 8 digits');
        }
        if (\strlen($secretMaster) < 32) {
            throw new \InvalidArgumentException('The step-up secret master must be at least 32 bytes (the same floor as secret_key)');
        }
        $this->otpKey = hash_hkdf('sha256', $secretMaster, 32, self::HKDF_INFO, self::HKDF_SALT);
        $this->ticket = $ticket;
    }

    public function assurance(): StepUpFactorAssurance
    {
        return StepUpFactorAssurance::emailOtp();
    }

    public function begin(Request $request, StepUpContext $context): Response
    {
        $now = $this->now();
        // The cross-challenge brute-force budget: while the requesting
        // context (or the shared account/target backstops) is locked
        // out, no fresh challenge is minted — unless the request rides
        // the owner's trusted context, which may always begin.
        $contextKey = StepUpLockoutGuard::contextKeyOf($request);
        $trusted = $this->lockout?->isTrustedContext($request, $context->principalPseudonym, $now) ?? false;
        $retryAfter = $this->lockout?->retryAfterSecs($context->principalPseudonym, $context->targetPseudonym, $now, $contextKey, $trusted) ?? 0;
        if ($retryAfter > 0) {
            return $this->refusal(
                $context,
                Response::HTTP_TOO_MANY_REQUESTS,
                'step_up_locked_out',
                'Too many failed verification attempts; retry after the lockout window.',
                ['Retry-After' => (string) $retryAfter],
            );
        }
        // The delivery reservation (mail capacity): one delivery
        // attempt, identified by the challenge id as its
        // deliveryAttemptId and generation 1 (the OTP handler funds a
        // single send). The reservation is the per-principal rate bound
        // AND the deployment budget in one generation-bound quota: it
        // only exists on an accepted begin — a refused or replayed
        // begin never reserves, so it can never deplete the mail
        // capacity. The reservation commits when the handoff is proven
        // or ambiguous (spent), and releases only on a failure proven
        // to have happened before the handoff.
        $code = str_pad((string) random_int(0, (10 ** $this->digits) - 1), $this->digits, '0', STR_PAD_LEFT);
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            $context->principalPseudonym,
            $context->targetPseudonym,
            $context->scope,
            $context->returnPath,
            $context->reason,
            $now,
            $this->ttlSecs,
            $this->maxAttempts,
            $this->codeHash($code),
            null,
            StepUpSessionBinding::sessionId($request),
            $context->targetOwned,
            false,
            null,
            $context->demandId,
        );
        $deliveryAttemptId = $challenge->id;
        $generation = 1;
        $reservationId = 'otp.'.$deliveryAttemptId.'.'.$generation;
        // The budget families carry the store's own bounded spelling:
        // a three-letter family, a colon, the pseudonym (or none for
        // the deployment-wide budget of the family). The store
        // prefixes the deployment namespace on top.
        $budgetKeys = [
            'otp:'.$context->principalPseudonym,
            'otp:',
        ];
        $budgetLimits = [$this->maxBegins, max($this->maxBegins, 1000)];
        try {
            $reserved = $this->store->reserveMailQuota(
                $reservationId,
                $budgetKeys,
                $budgetLimits,
                $this->beginWindowSecs,
                self::DELIVERY_LEASE_SECS,
            );
        } catch (\Throwable) {
            $reserved = false;
        }
        if (!$reserved) {
            return $this->refusal(
                $context,
                Response::HTTP_TOO_MANY_REQUESTS,
                'step_up_rate_limited',
                'Too many step-up codes were requested; retry after the window.',
                ['Retry-After' => (string) $this->beginWindowSecs],
            );
        }

        // The delivery-generation lease: the begin holding it is the one
        // whose code becomes the demand's authoritative factor. It is
        // claimed ahead of the challenge admission and settled after the
        // transport handoff, so two concurrent begins of one demand can
        // never both reach the mailbox. Without it the replace semantics
        // would let begin A admit its challenge, begin B replace it, and
        // only then A's transport hand off: both codes arrive, only B's
        // is valid, and mail ordering is uncontrolled, so the invalid one
        // can land last and look newest. The loser releases its quota and
        // answers a retryable conflict, so it never burns a delivery on a
        // code it did not send.
        $lease = $context->demandId === null
            ? null
            : $this->claimDeliveryLease($context->demandId);
        if ($context->demandId !== null && $lease === null) {
            // Another begin of this demand holds the delivery window, or
            // the claim could not be made at all. Either way this begin
            // cannot prove it owns the generation, so it sends nothing,
            // hands its mail capacity back and answers a retryable
            // conflict instead of replacing a challenge whose code is
            // already on its way.
            try {
                $this->store->releaseMailQuota($reservationId);
            } catch (\Throwable) {
            }

            return $this->deliveryLeaseRefusal($context, $context->demandId);
        }

        try {
            $this->store->createAdmittedChallenge($challenge, $this->ttlSecs);
        } catch (StepUpDemandAdmissionRefused $e) {
            // The demand can no longer admit a challenge: a fresh begin
            // replaces any standing challenge in the same atomic move,
            // so this refusal means the demand was already answered,
            // superseded, or expired. Nothing was stored, so the
            // reservation releases and the begin tells the browser to
            // request a fresh step-up.
            try {
                $this->store->releaseMailQuota($reservationId);
            } catch (\Throwable) {
            }
            $this->settleDeliveryLease($context, $lease, false);

            return $this->refusal(
                $context,
                Response::HTTP_CONFLICT,
                'step_up_challenge_active',
                'The step-up demand is no longer open, so no verification challenge can be admitted; request a fresh step-up.',
                ['Retry-After' => (string) $this->ttlSecs],
            );
        } catch (\Throwable $e) {
            // Proven pre-handoff failure: nothing was handed to the
            // transport, so the reservation releases (the mail capacity
            // returns) and no challenge record may outlive an
            // undelivered code.
            try {
                $this->store->releaseMailQuota($reservationId);
            } catch (\Throwable) {
            }
            try {
                $this->store->consume($challenge->id);
            } catch (\Throwable) {
            }
            $this->settleDeliveryLease($context, $lease, false);

            return $this->refusal(
                $context,
                Response::HTTP_SERVICE_UNAVAILABLE,
                'step_up_delivery_failed',
                'The verification code could not be delivered; try again.',
                [],
                $e,
            );
        }

        try {
            // The handoff. Past this call the outcome can be ambiguous:
            // the transport may have accepted the message before its
            // error surfaced.
            $this->sender->send($code, $context, $this->ttlSecs);
        } catch (\Throwable $e) {
            // Ambiguous failure at or after the handoff: the
            // reservation commits (spent; never a free extra send),
            // and no challenge record survives a code the factor cannot
            // vouch for. Fail-closed.
            try {
                $this->store->commitMailQuota($reservationId);
            } catch (\Throwable) {
            }
            try {
                $this->store->consume($challenge->id);
            } catch (\Throwable) {
                // The record expires with its TTL regardless.
            }
            // Ambiguous at or after the handoff: the delivery is spent,
            // so the lease promotes as sent, exactly as the send counter
            // does. A code the transport may have delivered is never
            // handed back as if it were never sent.
            $this->settleDeliveryLease($context, $lease, true);

            return $this->refusal(
                $context,
                Response::HTTP_SERVICE_UNAVAILABLE,
                'step_up_delivery_failed',
                'The verification code could not be delivered; try again.',
                [],
                $e,
            );
        }

        // The handoff succeeded: the reservation commits (the delivery
        // is spent and vouched for) and the generation promotes, so this
        // begin's code is the demand's authoritative factor from here on.
        $this->settleDeliveryLease($context, $lease, true);
        try {
            $this->store->commitMailQuota($reservationId);
        } catch (\Throwable) {
            // The delivery already happened; a failed commit is a
            // metrics concern, never a reason to refuse the begin.
        }

        return $this->presentation($context, $challenge, $now, $deliveryAttemptId, $generation);
    }

    public function complete(Request $request): StepUpResult
    {
        $boundSessionId = StepUpSessionBinding::sessionId($request);
        $boundContextKey = StepUpLockoutGuard::contextKeyOf($request);
        $now = $this->now();
        $resolved = $this->challengeOfRequest($request, $now);
        if ($resolved instanceof StepUpChallengeExpired) {
            return StepUpResult::failed(StepUpResult::FAIL_EXPIRED);
        }
        if ($resolved === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE);
        }
        $challenge = $resolved;
        if ($challenge->kind !== StepUpChallengeKind::EmailOtp) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }
        // The completion is bound to the session that began the
        // challenge: a ticket presented under another principal is
        // refused before any code is compared.
        if (!StepUpSessionBinding::matches($request, $challenge)) {
            return StepUpResult::failed(StepUpResult::FAIL_SESSION_MISMATCH, $challenge->id);
        }
        $trusted = $this->lockout?->isTrustedContext($request, $challenge->principalPseudonym, $now) ?? false;
        $retryAfter = $this->lockout?->retryAfterSecs($challenge->principalPseudonym, $challenge->targetPseudonym, $now, $boundContextKey, $trusted) ?? 0;
        if ($retryAfter > 0) {
            return StepUpResult::failed(StepUpResult::FAIL_LOCKED_OUT, $challenge->id);
        }
        if ($challenge->expired($now)) {
            $this->store->consume($challenge->id);

            return StepUpResult::failed(StepUpResult::FAIL_EXPIRED, $challenge->id);
        }
        $code = $this->fieldString($request, self::CODE_FIELD);
        if (!preg_match('/^[0-9]{6,8}$/D', $code) || !hash_equals((string) $challenge->codeHash, $this->codeHash($code))) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }

        // The single-use boundary is one atomic transition: the challenge
        // consumption and the demand completion are the same script, so
        // a verified factor can never strand beside a demand that stayed
        // open, and a lost race consumes nothing. A replayed completion
        // answers unknown_challenge and never reaches a proof.
        if (!$this->completeAtomically($request, $challenge, $now)) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }
        $this->lockout?->registerSuccess($challenge->principalPseudonym, $challenge->targetOwned ? $challenge->targetPseudonym : null, $boundContextKey);

        return $this->proof($challenge, $boundSessionId);
    }

    /**
     * The atomic completion of one verified factor: the store's single
     * script consumes the challenge and completes its demand. A
     * challenge that names no demand consumes single-use as before; its
     * proof carries no demand id and finalizes nothing (the finalizer
     * refuses an unbound proof, fail closed).
     */
    private function completeAtomically(Request $request, StepUpChallenge $challenge, int $now): bool
    {
        if ($challenge->demandId === null) {
            return $this->store->consume($challenge->id) !== null;
        }
        $binding = StepUpSessionBinding::presentedBindingHash($request, $challenge);
        if ($binding === null) {
            return false;
        }

        return $this->store->completeFactor($challenge->id, $challenge->demandId, $binding, $now, $challenge->sessionHash, $challenge->scope, StepUpSessionBinding::lineageHash($request) ?? $challenge->sessionHash) !== null;
    }

    /**
     * The failure accounting of one rejected code: pending while
     * attempts remain, terminal when the cap is reached or the record
     * is gone.
     */
    private function failedAttempt(StepUpChallenge $challenge, string $contextKey = ''): StepUpResult
    {
        // Every rejected code feeds the cross-challenge brute-force
        // budget before the per-challenge attempt cap.
        $this->lockout?->registerFailure($challenge->principalPseudonym, $challenge->targetPseudonym, $contextKey);
        $answer = $this->store->recordFailure($challenge->id, $challenge->maxAttempts);
        if ($answer === 0) {
            return StepUpResult::failed(StepUpResult::FAIL_TOO_MANY_ATTEMPTS, $challenge->id);
        }
        if ($answer < 0) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }

        return StepUpResult::pending($challenge->id);
    }

    /**
     * The challenge of the request, the StepUpChallengeExpired marker
     * when the presented ticket is well-signed but past its own expiry,
     * or null when no live one resolves. The marker lets the completion
     * answer the expired failure code instead of a bare unknown.
     */
    private function challengeOfRequest(Request $request, int $now): StepUpChallenge|StepUpChallengeExpired|null
    {
        $ticket = $this->fieldString($request, self::TICKET_FIELD);
        if ($ticket === '') {
            return null;
        }
        $payload = $this->ticket->verify($ticket, $now);
        if ($payload === null) {
            $looked = $this->ticket->look($ticket);
            if ($looked !== null && $looked['expiresAt'] <= $now) {
                return StepUpChallengeExpired::marker();
            }

            return null;
        }

        return $this->store->read($payload['challengeId']);
    }

    /**
     * The factor-plane proof of the consumed record: FactorVerified,
     * never AuthorizedStepUp. No enrollment marker, no session restore,
     * no StepUpCompleted is booked here — the shared
     * {@see StepUpDemandFinalizer} creates those only after the demand
     * settles authorized.
     */
    private function proof(StepUpChallenge $challenge, string $boundSessionId): StepUpResult
    {
        return StepUpResult::proved($challenge, $this->assurance());
    }

    /** One submitted string field, or '' for an absent/non-string value. */
    private function fieldString(Request $request, string $key): string
    {
        $value = $request->request->all()[$key] ?? '';

        return \is_string($value) ? $value : '';
    }

    /**
     * The keyed hash of one code: the only stored form of the secret.
     */
    private function codeHash(string $code): string
    {
        return hash_hmac('sha256', $code, $this->otpKey);
    }

    /**
     * The begin presentation: a self-contained html form for the html
     * mode, the challenge document for the json mode. A stateless
     * begin (no session) also returns its one-time client secret here —
     * the only channel that ever carries the plaintext.
     */
    /**
     * @param string|null $deliveryAttemptId the reserved delivery
     *                                       attempt this begin funded,
     *                                       surfaced for auditability
     */
    private function presentation(StepUpContext $context, StepUpChallenge $challenge, int $now, ?string $deliveryAttemptId = null, ?int $generation = null): Response
    {
        $ticket = $this->ticket->issue($challenge->id, $challenge->expiresAt);
        $expiresIn = max(0, $challenge->expiresAt - $now);
        $clientSecret = $challenge->issuedClientSecret();
        if ($context->mode === StepUpContext::MODE_JSON) {
            $body = (string) json_encode(array_filter([
                'handler' => 'email_otp',
                'challenge' => $ticket,
                'expires_in' => $expiresIn,
                'digits' => $this->digits,
                'complete_path' => $this->completePath,
                'client_secret' => $clientSecret,
                'delivery_attempt_id' => $deliveryAttemptId,
                'delivery_generation' => $generation,
            ], static fn ($v): bool => $v !== null), JSON_UNESCAPED_SLASHES);

            return new Response($body, Response::HTTP_OK, ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
        }
        $action = htmlspecialchars($this->completePath, ENT_QUOTES);
        $ticketField = htmlspecialchars(self::TICKET_FIELD, ENT_QUOTES);
        $codeField = htmlspecialchars(self::CODE_FIELD, ENT_QUOTES);
        $ticketValue = htmlspecialchars($ticket, ENT_QUOTES);
        $reason = htmlspecialchars($context->reason, ENT_QUOTES);
        $secretInput = $clientSecret !== null && $clientSecret !== ''
            ? '<input type="hidden" name="'.htmlspecialchars(StepUpSessionBinding::CLIENT_SECRET_FIELD, ENT_QUOTES).'" value="'.htmlspecialchars($clientSecret, ENT_QUOTES).'">'
            : '';
        $html = <<<HTML
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Verification required</title></head>
            <body>
            <main style="max-width:28rem;margin:4rem auto;font-family:system-ui,sans-serif">
            <h1>Verification required</h1>
            <p>A {$this->digits}-digit code was sent to your address. It expires in {$expiresIn} seconds.</p>
            <p hidden>{$reason}</p>
            <form method="post" action="{$action}">
            <input type="hidden" name="{$ticketField}" value="{$ticketValue}">
            {$secretInput}
            <label for="kiwi-step-up-code">Code</label>
            <input id="kiwi-step-up-code" name="{$codeField}" inputmode="numeric" autocomplete="one-time-code" required minlength="6" maxlength="8">
            <button type="submit">Verify</button>
            </form>
            </main>
            </body>
            </html>
            HTML;

        return new Response($html, Response::HTTP_OK, ['Content-Type' => 'text/html; charset=utf-8', 'Cache-Control' => 'no-store']);
    }

    /**
     * Why a begin that could not claim the delivery window is refused.
     *
     * The store folds every cause into one null, so the reason is read
     * back from the demand and answered honestly. A window another
     * request holds is a retryable conflict. An exhausted demand budget
     * is a rate limit that tells the browser to request a fresh
     * step-up. A demand that can no longer accept a challenge answers
     * the conflict the admission refusal uses. An unreadable record
     * keeps the retryable conflict, because this begin cannot prove it
     * owns the generation. The read shapes the copy and the status only;
     * the refusal itself already stands.
     */
    private function deliveryLeaseRefusal(StepUpContext $context, string $demandId): Response
    {
        $live = null;
        try {
            $live = $this->store->readDemand($demandId);
        } catch (\Throwable) {
        }
        if ($live === null || !$live->state->isOpen() || $live->superseded() || $live->expired($this->now())) {
            return $this->refusal(
                $context,
                Response::HTTP_CONFLICT,
                'step_up_challenge_active',
                'The step-up demand is no longer open, so no verification challenge can be admitted; request a fresh step-up.',
                ['Retry-After' => (string) max(1, $live?->expiresAt - $this->now() ?? $this->ttlSecs)],
            );
        }
        $nowMs = $this->now() * 1000;
        $leaseUntilMs = $live->leaseUntilMs ?? 0;
        if ($leaseUntilMs > $nowMs) {
            return $this->refusal(
                $context,
                Response::HTTP_CONFLICT,
                'step_up_send_in_progress',
                'Another request is already sending a code for this step-up demand; retry in a moment.',
                ['Retry-After' => (string) max(1, (int) ceil(($leaseUntilMs - $nowMs) / 1000))],
            );
        }
        if (!$live->canSend()) {
            return $this->refusal(
                $context,
                Response::HTTP_TOO_MANY_REQUESTS,
                'step_up_rate_limited',
                'This demand was fully used; request a fresh step-up.',
                ['Retry-After' => (string) max(1, $live->expiresAt - $this->now())],
            );
        }

        return $this->refusal(
            $context,
            Response::HTTP_CONFLICT,
            'step_up_send_in_progress',
            'The delivery window for this step-up demand could not be claimed; retry in a moment.',
            ['Retry-After' => '1'],
        );
    }

    /**
     * The delivery-generation claim of one demand: the store's clock owns
     * the lease's liveness, and a null answer means this begin may not
     * send. A store failure fails the same way, so an unprovable claim
     * never becomes a silent send.
     */
    private function claimDeliveryLease(string $demandId): ?StepUpDemandSendLease
    {
        try {
            return $this->store->claimDemandSendLease($demandId, 0, self::DELIVERY_LEASE_SECS);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Settle the delivery-generation lease once the outcome is known. A
     * delivered generation promotes: the send budget is spent and the
     * demand keeps the advanced state. An undelivered one restores the
     * state the claim recorded, so a refused begin consumes neither a
     * delivery nor the demand's send budget.
     */
    private function settleDeliveryLease(StepUpContext $context, ?StepUpDemandSendLease $lease, bool $delivered): void
    {
        if ($lease === null || $context->demandId === null) {
            return;
        }
        try {
            $this->store->settleDemandSendLease(new StepUpDemandSendSettlement(
                $context->demandId,
                $lease->leaseUntilMs,
                $lease->claimAt,
                $lease->priorSends,
                $lease->priorLastSentAt,
                $delivered,
            ));
        } catch (\Throwable) {
            // The lease expires on its own, so a failed settlement costs
            // the next begin at most the remaining lease window.
        }
    }

    /**
     * @param array<string, string> $headers
     */
    private function refusal(
        StepUpContext $context,
        int $status,
        string $code,
        string $message,
        array $headers,
        ?\Throwable $cause = null,
    ): Response {
        if ($context->mode === StepUpContext::MODE_JSON) {
            $body = (string) json_encode(['error' => $code, 'message' => $message], JSON_UNESCAPED_SLASHES);

            return new Response($body, $status, $headers + ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
        }

        return new Response($message, $status, $headers + ['Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store']);
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }
}
