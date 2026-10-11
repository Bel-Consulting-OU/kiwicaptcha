<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainId;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The anonymous-completable step-up factor behind the step_up_email
 * carrier. A visitor whose issuance or submission was answered with the
 * step-up 403 proves control of an email address and receives a grant
 * the validator honors in place of a solved token.
 *
 * A code is only ever sent for a demand the engine raised. The 403
 * that names this carrier mints a {@see StepUpDemand} record, and both
 * begin() and complete() require its id. The scope, the session
 * binding and the chain id come from the stored record, never from the
 * request. A begin without a live, session-matched demand answers the
 * typed `STEP_UP_NOT_DEMANDED` refusal, so the factor cannot be driven
 * blind.
 *
 * begin(): a 6-digit code from random_int, valid for 10 minutes. The
 * stored records carry only pseudonyms: the address exists solely as
 * an HMAC-derived pseudonym and the code solely as a keyed hash, so a
 * store snapshot leaks neither the address nor the factor. Delivery
 * rides the application-bound {@see EmailOwnershipCodeSenderInterface}.
 * Each begin consumes the demand's send credit: one initial delivery
 * plus one resend after the resend delay, then the demand is spent.
 * Mail volume is bounded by fixed-window counters on top of the
 * demand gate: 3 per hour per address, 30 per hour per address domain,
 * 10 per hour per source, and a deployment-wide hourly budget. Every
 * counter key is confined to this factor's own key family.
 *
 * complete(): the answered code is consumed single-use together with
 * its demand and a grant is issued. The grant is a signed, expiring,
 * single-use token bound to its demand: the scope, the address
 * pseudonym, the session hash and the chain id. The scope must equal
 * the constraint scope at validation, the submitted address must
 * resolve to the grant's pseudonym, the session hash must match the
 * browser that began the challenge, and a bound chain id must be
 * re-presented with the submission. Single use is the store's atomic
 * get-and-delete consumption of a server-held record named by the
 * signature, so a captured grant answers exactly once across workers.
 *
 * The signing and hashing keys are purpose-separated derivations of
 * the step-up master through the bundle's shared HKDF shape, never the
 * master itself.
 */
final class EmailOwnershipStepUp
{
    /** The kind string the 403 step-up body and the grant share. */
    public const KIND = 'email_ownership';

    /** The begin path the 403 step-up body advertises. */
    public const BEGIN_PATH = '/kiwi/step-up/email/begin';

    /** The complete path the begin document advertises. */
    public const COMPLETE_PATH = '/kiwi/step-up/email/complete';

    /** The grant prefix: a validator value starting with it is a grant. */
    public const GRANT_PREFIX = 'kiwiemg1';

    /** The request field carrying the grant at form submission. */
    public const GRANT_FIELD = 'kiwi_step_up_grant';

    /** The begin request field carrying the address. */
    public const EMAIL_FIELD = 'email';

    /** The begin request field carrying the protected scope. */
    public const SCOPE_FIELD = 'scope';

    /** The begin and complete request field carrying the demand id. */
    public const DEMAND_FIELD = 'demand';

    /** The optional begin, complete and submit field carrying the chain id. */
    public const CHAIN_FIELD = 'kiwi_step_up_chain';

    private const CODE_HKDF_INFO = 'kiwi/v1/email-ownership-code';

    private const EMAIL_HKDF_INFO = 'kiwi/v1/email-ownership-email';

    private const GRANT_HKDF_INFO = 'kiwi/v1/email-ownership-grant';

    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private const GRANT_VERSION = 1;

    private readonly string $codeKey;

    private readonly string $emailKey;

    private readonly string $grantKey;

    /** The once-per-process guard of the deployment budget warning. */
    private bool $budgetWarned = false;

    public function __construct(
        private readonly StepUpChallengeStore $store,
        private readonly StepUpTicket $ticket,
        private readonly EmailOwnershipCodeSenderInterface $sender,
        private readonly ?ContinuityCookie $continuity,
        private readonly ?ClientIpResolver $clientIpResolver,
        private readonly string $defaultScope,
        string $masterSecret,
        private readonly int $ttlSecs = 600,
        private readonly int $maxAttempts = 5,
        private readonly int $maxBeginsPerEmail = 3,
        private readonly int $maxBeginsPerSource = 10,
        private readonly int $beginWindowSecs = 3600,
        /**
         * The scopes whose step-up demands this factor carries (built
         * from risk.scopes.*.carrier === 'step_up_email'). A demand for
         * any other scope is refused: the factor answers exactly the
         * scopes that name it.
         *
         * @var array<string, true>
         */
        private readonly array $emailCarrierScopes = [],
        /** The hourly per-domain begin bound (email_ownership.max_per_domain). */
        private readonly int $maxBeginsPerDomain = 30,
        /** The hourly deployment-wide begin budget. */
        private readonly int $maxBeginsGlobal = 1000,
        /** The minimum spacing between the two deliveries one demand funds. */
        private readonly int $resendAfterSecs = 60,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?\Closure $now = null,
    ) {
        if (\strlen($masterSecret) < 32) {
            throw new \InvalidArgumentException('The step-up secret master must be at least 32 bytes (the same floor as secret_key)');
        }
        $this->codeKey = hash_hkdf('sha256', $masterSecret, 32, self::CODE_HKDF_INFO, self::HKDF_SALT);
        $this->emailKey = hash_hkdf('sha256', $masterSecret, 32, self::EMAIL_HKDF_INFO, self::HKDF_SALT);
        $this->grantKey = hash_hkdf('sha256', $masterSecret, 32, self::GRANT_HKDF_INFO, self::HKDF_SALT);
    }

    /**
     * Mint the demand record for one raised step-up demand: the id the
     * 403 body hands to the visitor, the record the factor requires
     * before it sends anything. The demand lives for the code TTL and
     * carries the whole binding: scope, session hash, chain id and the
     * decision id that demanded the step-up. Null when the scope does
     * not name this carrier, or the store refused the record (the 403
     * then carries no demand, and begin() refuses every code request,
     * fail-closed).
     */
    public function mintDemand(
        string $scope,
        ?string $sessionHash,
        ?string $chainId,
        ?string $decisionId,
    ): ?string {
        if (!isset($this->emailCarrierScopes[$scope])) {
            return null;
        }
        $demand = StepUpDemand::mint(StepUpChallenge::mintId(), $scope, $sessionHash, $chainId, $decisionId, $this->now(), $this->ttlSecs);
        try {
            $this->store->createDemand($demand, $this->ttlSecs);
        } catch (\Throwable) {
            return null;
        }

        return $demand->id;
    }

    /**
     * The live demand of the request: present, unexpired and bound to
     * the presenting browser when the demand carries a session hash.
     * Null means no code may be sent or redeemed against it.
     */
    private function demandOf(Request $request, int $now): ?StepUpDemand
    {
        $id = $request->request->get(self::DEMAND_FIELD);
        if (!\is_string($id) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $id) !== 1) {
            return null;
        }
        try {
            $demand = $this->store->readDemand($id);
        } catch (\Throwable) {
            return null;
        }
        if ($demand === null || $demand->expired($now)) {
            return null;
        }
        if ($demand->sessionHash !== null) {
            $presented = $this->presentedSessionHash($request);
            if ($presented === null || !hash_equals($demand->sessionHash, $presented)) {
                return null;
            }
        }

        return $demand;
    }

    /**
     * Begin one email-ownership challenge: demand gate, rate bounds,
     * send-credit claim, mint the record, deliver the code, answer the
     * begin document. The scope, the session binding and the chain id
     * come from the demand record. The answer is always a json
     * document; the anonymous callers are programmatic.
     */
    public function begin(Request $request): Response
    {
        $now = $this->now();
        $email = $this->emailOf($request);
        if ($email === null) {
            return self::json(['error' => 'invalid_email', 'message' => 'A deliverable email address is required.'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $demand = $this->demandOf($request, $now);
        if ($demand === null || !isset($this->emailCarrierScopes[$demand->scope])) {
            return self::json(['error' => 'step_up_not_demanded', 'message' => 'No step-up demand stands for this browser; solve the challenge that was refused.'], Response::HTTP_FORBIDDEN);
        }
        $scope = $demand->scope;
        $emailPseudonym = $this->emailPseudonym($email);

        // The mail-volume bounds: per address (scope-free, so rotating
        // the demanded scope defeats nothing), per address domain, per
        // source and deployment-wide. Every bound counts the attempt,
        // refused deliveries included.
        $limited = $this->boundRefusal($emailPseudonym, $email, $request);
        if ($limited !== null) {
            return $limited;
        }

        // The demand's send credit: one initial delivery plus one
        // resend after the resend delay, then the demand is spent and
        // only a fresh engine demand can fund more mail.
        if (!$demand->canSend()) {
            return self::json(['error' => 'step_up_rate_limited', 'message' => 'This demand was fully used; request a fresh challenge.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) max(1, $demand->expiresAt - $now)]);
        }
        if ($demand->nextSendIsResend() && $demand->lastSentAt !== null && ($now - $demand->lastSentAt) < $this->resendAfterSecs) {
            $wait = max(1, $this->resendAfterSecs - ($now - $demand->lastSentAt));

            return self::json(['error' => 'step_up_resend_wait', 'message' => 'The resend opens shortly; wait for the stated interval.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $wait]);
        }
        $claimed = $this->claimSendCredit($demand, $now);
        if ($claimed === null) {
            // A concurrent begin claimed the same credit (or the record
            // vanished): exactly one delivery per claim, fail closed.
            return self::json(['error' => 'step_up_not_demanded', 'message' => 'No step-up demand stands for this browser; solve the challenge that was refused.'], Response::HTTP_FORBIDDEN);
        }

        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $sessionValue = $this->sessionValueOf($request);
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOwnership,
            $emailPseudonym,
            null,
            $scope,
            null,
            self::KIND,
            $now,
            $this->ttlSecs,
            $this->maxAttempts,
            $this->codeHash($code),
            null,
            $sessionValue,
        );
        try {
            $this->store->create($challenge, $this->ttlSecs);
            $this->sender->send($email, $code, $this->ttlSecs);
        } catch (\Throwable) {
            // Delivery refused: the demand credit returns (the visitor
            // may retry begin), and no challenge record may outlive an
            // undelivered code.
            $this->refundSendCredit($demand, $now);
            try {
                $this->store->consume($challenge->id);
            } catch (\Throwable) {
            }

            return self::json(['error' => 'step_up_delivery_failed', 'message' => 'The code could not be delivered; try again.'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        return self::json(array_filter([
            'kind' => self::KIND,
            'challenge' => $this->ticket->issue($challenge->id, $challenge->expiresAt),
            'expires_in' => max(0, $challenge->expiresAt - $now),
            'complete_path' => self::COMPLETE_PATH,
            'scope' => $scope,
            'demand' => $demand->id,
            'client_secret' => $challenge->issuedClientSecret(),
        ], static fn ($v): bool => $v !== null), Response::HTTP_OK);
    }

    /**
     * Complete one challenge: verify the code, consume the record and
     * its demand single-use, and answer the signed grant bound to
     * (scope, address pseudonym, session, chain id) exactly as the
     * demand carried it. A rejected code counts against the attempt
     * cap and removes the record at the cap.
     */
    public function complete(Request $request): Response
    {
        $now = $this->now();
        $demand = $this->demandOf($request, $now);
        if ($demand === null || !isset($this->emailCarrierScopes[$demand->scope])) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $ticket = (string) $request->request->get(EmailOtpStepUpHandler::TICKET_FIELD, '');
        $payload = $ticket === '' ? null : $this->ticket->verify($ticket, $now);
        $challenge = $payload === null ? null : $this->store->read($payload['challengeId']);
        if ($challenge === null || $challenge->kind !== StepUpChallengeKind::EmailOwnership) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        if (!hash_equals($challenge->scope, $demand->scope)) {
            // The challenge and its demand must name the same scope: a
            // ticket crossed between scopes completes nothing.
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        if ($challenge->expired($now)) {
            $this->store->consume($challenge->id);

            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_EXPIRED], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        if (!$this->sessionMatches($request, $challenge)) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_SESSION_MISMATCH], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $code = (string) $request->request->get(EmailOtpStepUpHandler::CODE_FIELD, '');
        if (!preg_match('/^[0-9]{6}$/D', $code) || !hash_equals((string) $challenge->codeHash, $this->codeHash($code))) {
            $answer = $this->store->recordFailure($challenge->id, $challenge->maxAttempts);
            if ($answer === 0) {
                return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_TOO_MANY_ATTEMPTS], Response::HTTP_UNPROCESSABLE_ENTITY);
            }
            if ($answer < 0) {
                return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            return self::json(['status' => 'pending', 'challenge_id' => $challenge->id], Response::HTTP_UNAUTHORIZED);
        }

        // The single-use boundary of the factor: exactly one completer
        // consumes the challenge record, then its demand. The demand
        // consumption runs after the challenge (the winner is decided
        // by the challenge consume), and a vanished demand fails the
        // completion closed: an expired demand funds no grant.
        $consumed = $this->store->consume($challenge->id);
        if ($consumed === null) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        try {
            $spentDemand = $this->store->consumeDemand($demand->id);
        } catch (\Throwable) {
            $spentDemand = null;
        }
        if ($spentDemand === null) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // The bound chain id rides the demand record: the value the
        // challenged transaction carried, re-presented at submission.
        return $this->grantResponse($challenge, (string) ($demand->chainId ?? ''), $now);
    }

    /**
     * The grant answer: the consumption record is minted here (the
     * client never picks its id), signed over, and answered once.
     */
    private function grantResponse(StepUpChallenge $challenge, string $chainId, int $now): Response
    {
        $grantRecord = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOwnership,
            $challenge->principalPseudonym,
            null,
            $challenge->scope,
            null,
            self::KIND,
            $now,
            $this->ttlSecs,
            1,
            null,
        );
        // The consumption record IS the single-use budget: the grant
        // names it, the validator's atomic consume spends it.
        $this->store->create($grantRecord, $this->ttlSecs);

        return self::json([
            'status' => 'succeeded',
            'grant' => $this->issueGrant($grantRecord, $challenge->scope, $challenge->sessionHash ?? '', $chainId),
            'expires_in' => $this->ttlSecs,
            'scope' => $challenge->scope,
        ], Response::HTTP_OK);
    }

    /**
     * Verify a presented grant: signature, structure, expiry. The
     * answer carries the scope, the address pseudonym, the session
     * hash (empty when the stateless binding applies), the chain id
     * (empty when unbound) and the consumption record id. Null on
     * anything suspicious.
     *
     * @return array{grantId: string, scope: string, emailPseudonym: string, sessionHash: string, chainId: string, expiresAt: int}|null
     */
    public function verifyGrant(string $grant, ?int $now = null): ?array
    {
        $prefix = self::GRANT_PREFIX.'.';
        if (!str_starts_with($grant, $prefix)) {
            return null;
        }
        $parts = explode('.', substr($grant, \strlen($prefix)), 2);
        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return null;
        }
        if (!hash_equals($this->sign($parts[0]), $parts[1])) {
            return null;
        }
        $raw = base64_decode(strtr($parts[0], '-_', '+/'), true);
        if ($raw === false) {
            return null;
        }
        try {
            $payload = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($payload) || \count($payload) !== 7) {
            return null;
        }
        [$version, $grantId, $scope, $emailPseudonym, $sessionHash, $chainId, $expiresAt] = array_values($payload);
        if ($version !== self::GRANT_VERSION
            || !\is_string($grantId) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $grantId) !== 1
            || !\is_string($scope) || preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $scope) !== 1
            || !\is_string($emailPseudonym) || preg_match('/^[0-9a-f]{32}$/D', $emailPseudonym) !== 1
            || !\is_string($sessionHash) || ($sessionHash !== '' && preg_match('/^[0-9a-f]{64}$/D', $sessionHash) !== 1)
            || !\is_string($chainId) || ($chainId !== '' && !ChainId::isValid($chainId))
            || !\is_int($expiresAt)
        ) {
            return null;
        }
        if (($now ?? $this->now()) >= $expiresAt) {
            return null;
        }

        return ['grantId' => $grantId, 'scope' => $scope, 'emailPseudonym' => $emailPseudonym, 'sessionHash' => $sessionHash, 'chainId' => $chainId, 'expiresAt' => $expiresAt];
    }

    /**
     * Consume the grant exactly once: the atomic store consume of the
     * signed record. True for exactly one caller of a concurrent pair.
     *
     * @param array{grantId: string, scope: string, emailPseudonym: string, sessionHash: string, chainId: string, expiresAt: int} $grant
     */
    public function consumeGrant(array $grant): bool
    {
        return $this->store->consume($grant['grantId']) !== null;
    }

    /**
     * The grant for a submission: verify, bind, consume. The answer is
     * the verified grant payload or null; null means the demand stands.
     * A session-bound grant requires the same browser session, a bound
     * chain id requires the same value re-presented at submission, and
     * the submitted address must resolve to the grant's pseudonym. The
     * factor proves one address, and only the form that uses it may
     * spend the proof.
     *
     * @return array{grantId: string, scope: string, emailPseudonym: string, sessionHash: string, chainId: string, expiresAt: int}|null
     */
    public function redeem(string $grant, string $scope, Request $request, ?string $presentedChainId = null, ?string $submittedEmail = null): ?array
    {
        $payload = $this->verifyGrant($grant);
        if ($payload === null || !hash_equals($payload['scope'], $scope)) {
            return null;
        }
        $submitted = $submittedEmail === null ? '' : strtolower(trim($submittedEmail));
        if ($submitted === '' || !hash_equals($payload['emailPseudonym'], $this->emailPseudonym($submitted))) {
            return null;
        }
        if ($payload['sessionHash'] !== '') {
            $presented = $this->presentedSessionHash($request);
            if ($presented === null || !hash_equals($payload['sessionHash'], $presented)) {
                return null;
            }
        }
        if ($payload['chainId'] !== ''
            && ($presentedChainId === null || !hash_equals($payload['chainId'], $presentedChainId))
        ) {
            return null;
        }
        if (!$this->consumeGrant($payload)) {
            return null;
        }

        return $payload;
    }

    /**
     * Issue the signed grant over the consumption record: the payload
     * is the base64url json [v, grantId, scope, emailPseudonym,
     * sessionHash, chainId, expiresAt], then the base64url HMAC.
     */
    private function issueGrant(StepUpChallenge $grantRecord, string $scope, string $sessionHash, string $chainId): string
    {
        $body = (string) json_encode([
            self::GRANT_VERSION,
            $grantRecord->id,
            $scope,
            $grantRecord->principalPseudonym,
            $sessionHash,
            $chainId,
            $grantRecord->expiresAt,
        ], JSON_UNESCAPED_SLASHES);
        $encoded = rtrim(strtr(base64_encode($body), '+/', '-_'), '=');

        return self::GRANT_PREFIX.'.'.$encoded.'.'.$this->sign($encoded);
    }

    private function sign(string $body): string
    {
        return rtrim(strtr(base64_encode(hash_hmac('sha256', $body, $this->grantKey, true)), '+/', '-_'), '=');
    }

    /**
     * The stored pseudonym of the address: the truncated HMAC, never
     * the address itself, in the 32-hex shape the challenge records
     * carry.
     */
    private function emailPseudonym(string $email): string
    {
        return substr(hash_hmac('sha256', $email, $this->emailKey), 0, 32);
    }

    private function codeHash(string $code): string
    {
        return hash_hmac('sha256', $code, $this->codeKey);
    }

    /**
     * The presented address: a bounded, syntactically deliverable
     * address of at most 254 bytes. The check is shape-only; ownership
     * is what the code proves.
     */
    private function emailOf(Request $request): ?string
    {
        $email = $request->request->get(self::EMAIL_FIELD);
        if (!\is_string($email) || \strlen($email) > 254) {
            return null;
        }
        $trimmed = trim($email);
        if (filter_var($trimmed, FILTER_VALIDATE_EMAIL) === false) {
            return null;
        }

        return strtolower($trimmed);
    }

    /**
     * The mail-volume bounds of one begin attempt, each a fixed-window
     * counter in this factor's own key family. The per-address bound
     * keys on the address pseudonym alone, so a rotating demanded scope
     * defeats nothing. The domain bound keys on the keyed pseudonym of
     * the address domain. The global bound carries the deployment-wide
     * hourly budget and warns at its 80 percent mark. Null answers
     * "inside every bound"; a Response answers the refusal.
     */
    private function boundRefusal(string $emailPseudonym, string $email, Request $request): ?Response
    {
        $emailAdmissions = $this->store->countBegin('emg:email:'.$emailPseudonym, $this->beginWindowSecs);
        if ($emailAdmissions > $this->maxBeginsPerEmail) {
            return self::json(['error' => 'step_up_rate_limited', 'message' => 'Too many codes were requested for this address; retry after the window.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $this->beginWindowSecs]);
        }
        $domain = substr($email, (int) strrpos($email, '@') + 1);
        if ($domain !== '') {
            $domainAdmissions = $this->store->countBegin('emg:dom:'.$this->domainPseudonym($domain), $this->beginWindowSecs);
            if ($domainAdmissions > $this->maxBeginsPerDomain) {
                return self::json(['error' => 'step_up_rate_limited', 'message' => 'Too many codes were requested for this address domain; retry after the window.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $this->beginWindowSecs]);
            }
        }
        $source = $this->sourcePseudonym($request);
        if ($source !== null) {
            $sourceAdmissions = $this->store->countBegin('emg:src:'.$source, $this->beginWindowSecs);
            if ($sourceAdmissions > $this->maxBeginsPerSource) {
                return self::json(['error' => 'step_up_rate_limited', 'message' => 'Too many codes were requested from this source; retry after the window.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $this->beginWindowSecs]);
            }
        }
        $globalAdmissions = $this->store->countBegin('emg:global', $this->beginWindowSecs);
        if ($globalAdmissions > $this->maxBeginsGlobal) {
            return self::json(['error' => 'step_up_rate_limited', 'message' => 'The deployment mail budget is spent; retry after the window.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $this->beginWindowSecs]);
        }
        $this->warnNearBudget($globalAdmissions);

        return null;
    }

    /** The keyed pseudonym of an address domain, never the domain itself. */
    private function domainPseudonym(string $domain): string
    {
        return substr(hash_hmac('sha256', $domain, $this->emailKey), 0, 32);
    }

    /**
     * The one-shot deployment budget warning at the 80 percent mark:
     * the once-per-process guard keeps a sustained campaign from
     * flooding the log, and a raising logger must never break begin().
     */
    private function warnNearBudget(int $globalAdmissions): void
    {
        if ($this->budgetWarned || $this->logger === null || $this->maxBeginsGlobal < 1) {
            return;
        }
        if ($globalAdmissions < (int) ceil($this->maxBeginsGlobal * 0.8)) {
            return;
        }
        $this->budgetWarned = true;
        try {
            $this->logger->warning('KiwiCaptcha: the email step-up begin budget passed 80 percent of its hourly deployment bound', [
                'admissions' => $globalAdmissions,
                'budget' => $this->maxBeginsGlobal,
            ]);
        } catch (\Throwable) {
        }
    }

    /**
     * Claim the demand's next send credit atomically: the store's
     * get-and-delete answers the record to exactly one claimer, and the
     * advanced record is re-created with the demand's remaining
     * lifetime. Null on a lost race or a store refusal: the delivery
     * never happens, fail-closed.
     */
    private function claimSendCredit(StepUpDemand $demand, int $now): ?StepUpDemand
    {
        try {
            $consumed = $this->store->consumeDemand($demand->id);
        } catch (\Throwable) {
            return null;
        }
        if ($consumed === null) {
            return null;
        }
        $claimed = $consumed->withSend($now);
        try {
            $this->store->createDemand($claimed, max(1, $consumed->expiresAt - $now));
        } catch (\Throwable) {
            return null;
        }

        return $claimed;
    }

    /**
     * Return a claimed credit after a refused delivery: the record is
     * restored to its exact pre-claim send state, so the visitor's
     * retry does not pay for an outage. Best effort: a failed refund
     * spends the credit (fail-closed, never a free extra send).
     */
    private function refundSendCredit(StepUpDemand $demand, int $now): void
    {
        try {
            $this->store->createDemand($demand, max(1, $demand->expiresAt - $now));
        } catch (\Throwable) {
        }
    }

    /**
     * The continuity identity of the request: the continuity cookie
     * value when presented, else the started session's id, else null
     * (a stateless begin, which mints the one-time client secret).
     */
    private function sessionValueOf(Request $request): ?string
    {
        $continuity = $this->continuity?->read($request);
        if (\is_string($continuity) && $continuity !== '') {
            return $continuity;
        }
        $session = $request->hasSession() ? $request->getSession() : null;
        if ($session !== null && $session->isStarted() && (string) $session->getId() !== '') {
            return (string) $session->getId();
        }

        return null;
    }

    /**
     * The session hash the current request must present for a
     * session-bound grant or challenge: the same derivation the begin
     * stored. Null when the request carries no continuity session.
     */
    public function presentedSessionHash(Request $request): ?string
    {
        $sessionValue = $this->sessionValueOf($request);

        return $sessionValue === null ? null : hash('sha256', $sessionValue);
    }

    /**
     * The completion binding: a session-bound challenge answers only
     * the browser that began it, a stateless challenge only a request
     * presenting the per-challenge client secret. Fail closed.
     */
    private function sessionMatches(Request $request, StepUpChallenge $challenge): bool
    {
        if ($challenge->sessionHash !== null && $challenge->sessionHash !== '') {
            $presented = $this->presentedSessionHash($request);

            return $presented !== null && hash_equals($challenge->sessionHash, $presented);
        }
        if ($challenge->clientSecretHash !== null && $challenge->clientSecretHash !== '') {
            $presented = (string) $request->request->get(StepUpSessionBinding::CLIENT_SECRET_FIELD, '');

            return $presented !== '' && $challenge->clientSecretMatches($presented);
        }

        return false;
    }

    /**
     * The keyed pseudonym of the source: HMAC over the resolved client
     * IP, never a raw address, stable inside the begin window.
     */
    private function sourcePseudonym(Request $request): ?string
    {
        try {
            $ip = $this->clientIpResolver !== null
                ? $this->clientIpResolver->resolve($request)
                : (string) ($request->getClientIp() ?? '');
        } catch (\Throwable) {
            return null;
        }
        if ($ip === '') {
            return null;
        }

        return substr(hash_hmac('sha256', $ip, $this->emailKey), 0, 32);
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $headers
     */
    private static function json(array $body, int $status, array $headers = []): Response
    {
        return new Response((string) json_encode($body, JSON_UNESCAPED_SLASHES), $status, $headers + ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
    }
}
