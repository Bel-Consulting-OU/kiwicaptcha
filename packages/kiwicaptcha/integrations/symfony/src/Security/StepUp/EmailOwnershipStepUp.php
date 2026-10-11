<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainId;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The anonymous-completable step-up factor behind the step_up_email
 * carrier. A visitor whose issuance or submission was answered with the
 * step-up 403 proves control of an email address and receives a grant
 * the validator honors in place of a solved token.
 *
 * begin(): a 6-digit code from random_int, valid for 10 minutes. The
 * stored record carries only pseudonyms: the address exists solely as
 * an HMAC-derived pseudonym and the code solely as a keyed hash, so a
 * store snapshot leaks neither the address nor the factor. Delivery
 * rides the application-bound {@see EmailOwnershipCodeSenderInterface}.
 * Begin is bounded by fixed-window counters: 3 per hour per (scope,
 * address pseudonym) and 10 per hour per source, each key confined to
 * this factor's own key family.
 *
 * complete(): the answered code is consumed single-use and a grant is
 * issued. The grant is a signed, expiring, single-use token bound to
 * its transaction. The scope must equal the constraint scope at
 * validation, the session hash must match the browser that began the
 * challenge, and a bound chain id must be re-presented with the
 * submission. Single use is the store's atomic get-and-delete
 * consumption of a server-held record named by the signature, so a
 * captured grant answers exactly once across workers.
 *
 * The signing and hashing keys are purpose-separated derivations of the
 * step-up master through the bundle's shared HKDF shape, never the
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
     * Begin one email-ownership challenge: rate-limit, mint the record,
     * deliver the code, answer the begin document. The answer is always
     * a json document; the anonymous callers are programmatic.
     */
    public function begin(Request $request): Response
    {
        $now = $this->now();
        $email = $this->emailOf($request);
        if ($email === null) {
            return self::json(['error' => 'invalid_email', 'message' => 'A deliverable email address is required.'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $scope = $this->scopeOf($request);
        if ($scope === null) {
            return self::json(['error' => 'invalid_scope', 'message' => 'The scope must be 1-128 chars of [A-Za-z0-9._:-].'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $chainId = $this->chainOf($request);
        if ($chainId === false) {
            return self::json(['error' => 'invalid_chain', 'message' => 'The chain id must be 1-64 chars of [A-Za-z0-9_-].'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $emailPseudonym = $this->emailPseudonym($email);
        $emailAdmissions = $this->store->countBegin('emg:email:'.$scope.':'.$emailPseudonym, $this->beginWindowSecs);
        if ($emailAdmissions > $this->maxBeginsPerEmail) {
            return self::json(['error' => 'step_up_rate_limited', 'message' => 'Too many codes were requested for this address; retry after the window.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $this->beginWindowSecs]);
        }
        $source = $this->sourcePseudonym($request);
        if ($source !== null) {
            $sourceAdmissions = $this->store->countBegin('emg:src:'.$source, $this->beginWindowSecs);
            if ($sourceAdmissions > $this->maxBeginsPerSource) {
                return self::json(['error' => 'step_up_rate_limited', 'message' => 'Too many codes were requested from this source; retry after the window.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $this->beginWindowSecs]);
            }
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
            // Delivery refused: no record may outlive an undelivered
            // code. A record the consume cannot find expires with its
            // TTL regardless.
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
            'client_secret' => $challenge->issuedClientSecret(),
        ], static fn ($v): bool => $v !== null), Response::HTTP_OK);
    }

    /**
     * Complete one challenge: verify the code, consume the record
     * single-use, and answer the signed grant bound to (scope,
     * session, chain id). A rejected code counts against the attempt
     * cap and removes the record at the cap.
     */
    public function complete(Request $request): Response
    {
        $now = $this->now();
        $ticket = (string) $request->request->get(EmailOtpStepUpHandler::TICKET_FIELD, '');
        $payload = $ticket === '' ? null : $this->ticket->verify($ticket, $now);
        $challenge = $payload === null ? null : $this->store->read($payload['challengeId']);
        if ($challenge === null || $challenge->kind !== StepUpChallengeKind::EmailOwnership) {
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
        // consumes the challenge record.
        $consumed = $this->store->consume($challenge->id);
        if ($consumed === null) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // The bound chain id: the value the completion re-presents, or
        // empty when the factor was begun outside a chain. The grant
        // then requires the same value at submission.
        $chainId = $this->chainOf($request);
        if ($chainId === false) {
            return self::json(['error' => 'invalid_chain', 'message' => 'The chain id must be 1-64 chars of [A-Za-z0-9_-].'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        return $this->grantResponse($challenge, (string) $chainId, $now);
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
     * answer carries the scope, the session hash (empty when the
     * stateless binding applies), the chain id (empty when unbound) and
     * the consumption record id. Null on anything suspicious.
     *
     * @return array{grantId: string, scope: string, sessionHash: string, chainId: string, expiresAt: int}|null
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

        return ['grantId' => $grantId, 'scope' => $scope, 'sessionHash' => $sessionHash, 'chainId' => $chainId, 'expiresAt' => $expiresAt];
    }

    /**
     * Consume the grant exactly once: the atomic store consume of the
     * signed record. True for exactly one caller of a concurrent pair.
     *
     * @param array{grantId: string, scope: string, sessionHash: string, chainId: string, expiresAt: int} $grant
     */
    public function consumeGrant(array $grant): bool
    {
        return $this->store->consume($grant['grantId']) !== null;
    }

    /**
     * The grant for a submission: verify, bind, consume. The answer is
     * the verified grant payload or null; null means the demand stands.
     * A session-bound grant requires the same browser session, a bound
     * chain id requires the same value re-presented at submission.
     *
     * @return array{grantId: string, scope: string, sessionHash: string, chainId: string, expiresAt: int}|null
     */
    public function redeem(string $grant, string $scope, Request $request, ?string $presentedChainId = null): ?array
    {
        $payload = $this->verifyGrant($grant);
        if ($payload === null || !hash_equals($payload['scope'], $scope)) {
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
     * The scope the grant will bind to: the presented value when valid,
     * else the configured default. Null only on a malformed presented
     * value.
     */
    private function scopeOf(Request $request): ?string
    {
        $scope = $request->request->get(self::SCOPE_FIELD);
        if (!\is_string($scope) || $scope === '') {
            return $this->defaultScope;
        }
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $scope) !== 1) {
            return null;
        }

        return $scope;
    }

    /**
     * The optional chain id: false on a malformed value, null when
     * absent, the validated id otherwise.
     */
    private function chainOf(Request $request): false|null|string
    {
        $chain = $request->request->get(self::CHAIN_FIELD);
        if (!\is_string($chain) || $chain === '') {
            return null;
        }

        return ChainId::isValid($chain) ? $chain : false;
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
