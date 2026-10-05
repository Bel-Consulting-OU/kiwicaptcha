<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Exception\CounterException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * The phishing-resistant target of the step-up plane: WebAuthn, over
 * the web-auth/webauthn-lib package (the pure-PHP WebAuthn library).
 * The class is the concrete lib-backed handler. The whole feature sits
 * behind one installation check: the constructor refuses with
 * {@see self::NOT_IMPLEMENTED_MESSAGE} when the library is absent.
 * Activating the handler is exactly one composer require, and a
 * deployment without the library keeps the historical refusal, word
 * for word.
 *
 * Ceremony flow: begin() mints a 32-byte ceremony challenge, pins it
 * into the challenge record as a keyed hash (the same never-the-secret
 * rule as the code handlers; the challenge alone proves nothing), and
 * presents the options document. An enrolled principal receives the
 * assertion (login) ceremony over its registered credentials; an
 * unenrolled principal receives the creation (registration) ceremony,
 * whose validated credential becomes the principal's first enrollment.
 * complete() loads the presented credential through the library's
 * loader, pins the echoed challenge against the stored hash, then runs
 * the library's validator: the origin binding, the RP-id hash, user
 * presence and verification, and the sign-count check. A counter that
 * fails to advance answers the replayed failure code, and an assertion
 * over an unregistered credential answers the unknown-credential code.
 * On success the single-use record is consumed and the credit runs
 * through {@see StepUpCompletionCredit}, exactly once per challenge.
 */
final class WebAuthnStepUpHandler implements StepUpHandlerInterface
{
    public const NOT_IMPLEMENTED_MESSAGE = 'WebAuthn step-up requires the web-auth/webauthn-lib package: require it (composer require web-auth/webauthn-lib) to activate the phishing-resistant handler; without the package the handler refuses with this exact message';

    public const TICKET_FIELD = 'kiwi_step_up_ticket';
    public const CREDENTIAL_FIELD = 'kiwi_step_up_credential';

    public const CEREMONY_CREATION = 'creation';
    public const CEREMONY_ASSERTION = 'assertion';

    /** The failure code of an assertion over an unregistered credential. */
    public const FAIL_UNKNOWN_CREDENTIAL = 'unknown_credential';

    private const CHALLENGE_HKDF_INFO = 'kiwi/v1/stepup-webauthn-challenge';

    private const CHALLENGE_HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private readonly string $challengeKey;

    private readonly PublicKeyCredentialLoader $loader;

    private readonly AuthenticatorAttestationResponseValidator $creationValidator;

    private readonly AuthenticatorAssertionResponseValidator $assertionValidator;

    /**
     * @param bool|null $libPresent the installation-check seam: null
     *                              auto-detects the library, and the
     *                              container path never passes it
     */
    public function __construct(
        private readonly StepUpChallengeStore $store,
        private readonly StepUpTicket $ticket,
        private readonly StepUpCompletionCredit $credit,
        private readonly ?WebAuthnCredentialRegistry $registry,
        private readonly string $master,
        private readonly int $challengeTtlSecs = 300,
        private readonly int $maxAttempts = 5,
        private readonly int $maxBegins = 3,
        private readonly int $beginWindowSecs = 900,
        private readonly string $completePath = '/kiwi/step-up/complete',
        private readonly ?\Closure $now = null,
        private readonly ?bool $libPresent = null,
    ) {
        if (\strlen($master) < 32) {
            throw new \InvalidArgumentException('The WebAuthn handler master must be at least 32 bytes (the same floor as secret_key)');
        }
        $this->challengeKey = hash_hkdf('sha256', $master, 32, self::CHALLENGE_HKDF_INFO, self::CHALLENGE_HKDF_SALT);
        $present = $libPresent ?? \class_exists(PublicKeyCredentialLoader::class);
        if (!$present) {
            throw new \LogicException(self::NOT_IMPLEMENTED_MESSAGE);
        }
        if ($this->registry === null) {
            throw new \LogicException('WebAuthn step-up needs its credential registry wired; the bundle extension wires it whenever the handler is enabled');
        }
        $factory = new CeremonyStepManagerFactory();
        $this->creationValidator = new AuthenticatorAttestationResponseValidator(null, null, null, null, null, $factory->creationCeremony());
        $this->assertionValidator = new AuthenticatorAssertionResponseValidator($this->registry, null, null, null, null, $factory->requestCeremony());
        $manager = AttestationStatementSupportManager::create([new NoneAttestationStatementSupport()]);
        $this->loader = PublicKeyCredentialLoader::create(AttestationObjectLoader::create($manager));
    }

    public function begin(Request $request, StepUpContext $context): Response
    {
        $now = $this->now();
        $enrolled = $this->registry->registeredCredentialsOf($context->principalPseudonym);
        $admissions = $this->store->countBegin($context->principalPseudonym, $this->beginWindowSecs);
        if ($admissions > $this->maxBegins) {
            return $this->refusal(
                $context,
                Response::HTTP_TOO_MANY_REQUESTS,
                'step_up_rate_limited',
                'Too many step-up challenges were begun for this account; retry after the window.',
                ['Retry-After' => (string) $this->beginWindowSecs],
            );
        }

        $challengeBytes = random_bytes(32);
        $ceremony = $enrolled === [] ? self::CEREMONY_CREATION : self::CEREMONY_ASSERTION;
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            $context->principalPseudonym,
            $context->targetPseudonym,
            $context->scope,
            $context->returnPath,
            $context->reason,
            $now,
            $this->challengeTtlSecs,
            $this->maxAttempts,
            $this->challengeHash($challengeBytes),
            $ceremony,
        );
        $this->store->create($challenge, $this->challengeTtlSecs);

        return $this->presentation($context, $challenge, $challengeBytes, $enrolled, $ceremony, (string) $request->getHost());
    }

    public function complete(Request $request): StepUpResult
    {
        $now = $this->now();
        $resolved = $this->challengeOfRequest($request, $now);
        if ($resolved instanceof StepUpChallengeExpired) {
            return StepUpResult::failed(StepUpResult::FAIL_EXPIRED);
        }
        if ($resolved === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE);
        }
        $challenge = $resolved;
        if ($challenge->kind !== StepUpChallengeKind::WebAuthn || $challenge->ceremony === null || $challenge->codeHash === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }
        if ($challenge->expired($now)) {
            $this->store->consume($challenge->id);

            return StepUpResult::failed(StepUpResult::FAIL_EXPIRED, $challenge->id);
        }
        $payload = (string) $request->request->get(self::CREDENTIAL_FIELD, (string) $request->query->get(self::CREDENTIAL_FIELD, ''));
        if ($payload === '') {
            $payload = (string) $request->getContent();
        }
        try {
            $decoded = json_decode($payload, true, 64, JSON_THROW_ON_ERROR);
            $credential = $this->loader->loadArray(\is_array($decoded) ? $decoded : []);
        } catch (\Throwable $e) {
            return $this->failedAttempt($challenge);
        }
        $response = $credential->response;
        try {
            $presentedChallenge = (string) $response->clientDataJSON->challenge;
        } catch (\Throwable) {
            return $this->failedAttempt($challenge);
        }
        if (!hash_equals($challenge->codeHash, $this->challengeHash($presentedChallenge))) {
            return $this->failedAttempt($challenge);
        }
        $host = (string) $request->getHost();
        if ($host === '') {
            return $this->failedAttempt($challenge);
        }
        try {
            if ($response instanceof AuthenticatorAttestationResponse) {
                if ($challenge->ceremony !== self::CEREMONY_CREATION) {
                    // A begun assertion ceremony is completed by the
                    // assertion of an enrolled credential, never by
                    // registering a fresh one over it.
                    return $this->failedAttempt($challenge);
                }
                $source = $this->creationValidator->check(
                    $response,
                    $this->creationOptions($challenge, $presentedChallenge, $host),
                    $host,
                );
                $this->registry->saveCredentialSource($source);
            } elseif ($response instanceof AuthenticatorAssertionResponse) {
                if ($challenge->ceremony !== self::CEREMONY_ASSERTION) {
                    return $this->failedAttempt($challenge);
                }
                $source = $this->registry->findOneByCredentialId($credential->rawId);
                if ($source === null) {
                    $this->store->consume($challenge->id);

                    return StepUpResult::failed(self::FAIL_UNKNOWN_CREDENTIAL, $challenge->id);
                }
                try {
                    $updated = $this->assertionValidator->check(
                        $source,
                        $response,
                        $this->assertionOptions($challenge, $presentedChallenge, $host, $source),
                        $host,
                        $challenge->principalPseudonym,
                    );
                    // The validator updates the returned source only:
                    // persist the advanced sign count in the registry.
                    $this->registry->saveCredentialSource($updated);
                } catch (CounterException) {
                    // The signature verified but the sign count failed
                    // to advance: a cloned or replayed authenticator.
                    return StepUpResult::failed(StepUpResult::FAIL_REPLAYED_STEP, $challenge->id);
                }
            } else {
                return $this->failedAttempt($challenge);
            }
        } catch (\Throwable $e) {
            return $this->failedAttempt($challenge);
        }

        $consumed = $this->store->consume($challenge->id);
        if ($consumed === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }

        return $this->credit($challenge);
    }

    private function creationOptions(StepUpChallenge $challenge, string $challengeBytes, string $host): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($host, $host),
            PublicKeyCredentialUserEntity::create(
                $challenge->principalPseudonym,
                $challenge->principalPseudonym,
                'step-up'),
            $challengeBytes,
            [
                new PublicKeyCredentialParameters('public-key', -7),
                new PublicKeyCredentialParameters('public-key', -257),
            ],
            null,
            null,
            [],
            max(1, $challenge->expiresAt - $challenge->createdAt),
        );
    }

    private function assertionOptions(StepUpChallenge $challenge, string $challengeBytes, string $host, PublicKeyCredentialSource $source): PublicKeyCredentialRequestOptions
    {
        return new PublicKeyCredentialRequestOptions(
            $challengeBytes,
            $host,
            [PublicKeyCredentialDescriptor::create('public-key', $source->publicKeyCredentialId)],
            'preferred',
            max(1, $challenge->expiresAt - $challenge->createdAt),
        );
    }

    private function challengeHash(string $challengeBytes): string
    {
        return hash_hmac('sha256', $challengeBytes, $this->challengeKey);
    }

    private function failedAttempt(StepUpChallenge $challenge): StepUpResult
    {
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
     * or null when no live one resolves.
     */
    private function challengeOfRequest(Request $request, int $now): StepUpChallenge|StepUpChallengeExpired|null
    {
        $ticket = (string) $request->request->get(self::TICKET_FIELD, $request->query->get(self::TICKET_FIELD, ''));
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

    private function credit(StepUpChallenge $challenge): StepUpResult
    {
        try {
            return $this->credit->credit($challenge->id, $challenge);
        } catch (\Throwable) {
            return StepUpResult::failed(StepUpResult::FAIL_OUTCOME_UNAVAILABLE, $challenge->id);
        }
    }

    /**
     * The begin presentation: the options document (the json payload
     * the browser navigator.credentials call consumes) for the json
     * mode, and the same document embedded in a page for the html mode.
     *
     * @param list<PublicKeyCredentialSource> $enrolled
     */
    private function presentation(StepUpContext $context, StepUpChallenge $challenge, string $challengeBytes, array $enrolled, string $ceremony, string $host): Response
    {
        $ticket = $this->ticket->issue($challenge->id, $challenge->expiresAt);
        $expiresIn = max(0, $challenge->expiresAt - $this->now());
        $options = $ceremony === self::CEREMONY_ASSERTION
            ? new PublicKeyCredentialRequestOptions(
                $challengeBytes,
                $host,
                array_map(
                    static fn (PublicKeyCredentialSource $source): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create('public-key', $source->publicKeyCredentialId),
                    $enrolled,
                ),
                'preferred',
                max(1, $expiresIn),
            )
            : $this->creationOptions($challenge, $challengeBytes, $host);
        $document = [
            'handler' => 'webauthn',
            'ceremony' => $ceremony,
            'challenge' => $ticket,
            'public_key' => json_decode((string) json_encode($options, JSON_UNESCAPED_SLASHES), true),
            'expires_in' => $expiresIn,
            'complete_path' => $this->completePath,
        ];
        if ($context->mode === StepUpContext::MODE_JSON) {
            $body = (string) json_encode($document, JSON_UNESCAPED_SLASHES);

            return new Response($body, Response::HTTP_OK, ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
        }
        $optionsJson = htmlspecialchars((string) json_encode($document, JSON_UNESCAPED_SLASHES), ENT_QUOTES);
        $action = htmlspecialchars($this->completePath, ENT_QUOTES);
        $html = <<<HTML
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Security key</title></head>
            <body>
            <main style="max-width:28rem;margin:4rem auto;font-family:system-ui,sans-serif">
            <h1>Security key</h1>
            <p>Use your security key or platform authenticator to continue.</p>
            <div id="kiwi-webauthn-options" data-options="{$optionsJson}"></div>
            <form method="post" action="{$action}"><button type="submit">Continue</button></form>
            </main>
            </body>
            </html>
            HTML;

        return new Response($html, Response::HTTP_OK, ['Content-Type' => 'text/html; charset=utf-8', 'Cache-Control' => 'no-store']);
    }

    /**
     * @param array<string, string> $headers
     */
    private function refusal(StepUpContext $context, int $status, string $code, string $message, array $headers = []): Response
    {
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
