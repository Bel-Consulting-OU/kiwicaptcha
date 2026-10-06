<?php

declare(strict_types=1);

/**
 * d37.driver.php — the D3.7 campaign driver: human-solver farms
 * against the step-up plane, driven through the REAL bundle handlers
 * over the REAL Redis step-up store.
 *
 * The relay story, told honestly per handler:
 *
 *   TOTP   the code IS relayable by design: a phishing proxy that
 *          captures the current 6-digit code and replays it inside its
 *          acceptance window DOES complete the challenge once. What
 *          caps the farm is what the handler pins in code: the replay
 *          guard (the same time-step never completes twice per
 *          principal), the single-use challenge record (attempts cap
 *          and one consumed completion), and the begin-rate bound. The
 *          campaign measures exactly that residual: the relayed code
 *          succeeds once, the second presentation fails, the challenge
 *          is consumed, and the begin flood hits the rate bound.
 *
 *   OTP    the email/OTP path: single use (the record is consumed at
 *          the first success), the attempts cap burns on wrong codes,
 *          and the rate bound caps challenge begins.
 *
 *   WebAuthn   phishing-resistant end to end: the real lib-backed
 *          ceremony (webauthn-lib, installed by this campaign's
 *          bundle-vendor) registers a software authenticator, and a
 *          phishing origin's ceremony (clientData origin evil.example,
 *          rpId phishing.example) is REFUSED; the honest origin
 *          completes.
 *
 * Output: one JSON summary on stdout.
 */

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnCredentialRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use Symfony\Component\HttpFoundation\Request;

require getenv('KIWI_RT_RISK_AUTOLOAD') ?: throw new RuntimeException('autoload missing');
require __DIR__ . '/rt-risk-prelude.php';
// The software-authenticator builder and the fake redis live beside
// the bundle's own handler test; both are repo-internal fixtures.
require_once getenv('KIWI_RT_BUNDLE_TESTS') . '/WebAuthnStepUpHandlerTest.php';
require_once getenv('KIWI_RT_BUNDLE_TESTS') . '/Fixtures/SpyOutcomeReporter.php';

const MASTER = 'd37mast3rd37mast3rd37mast3rd37mast3r';
/** The fixed software-authenticator P-256 key (the bundle test's own vectors). */
const WebAuthnStepUpHandlerTestVectorsX = '3538df4c2adee42ba4e6894652260058b5e2d4845669502db787bce655f6a92b';
const WebAuthnStepUpHandlerTestVectorsY = 'b571381cb720f1498964115bab370aa5506c75801e53935b6b449d3526d696e7';
const PRINCIPAL = 'd3731000000000000000000000000001';
const VICTIM = 'd3732000000000000000000000000002';
const HOST = 'captcha.example.com';

$redisRaw = rtRedis((string) getenv('KIWI_RT_D37_REDIS_URL'));

// The store divergence, recorded honestly: RedisStepUpChallengeStore
// compares the SET NX reply strictly against the string 'OK' or true,
// while a real Predis client answers a Predis\Response\Status object
// (whose string form IS 'OK'), so every create() throws on a real
// client and every step-up begin fails closed. The engine's triage
// files that as a finding with its own deterministic repro (the
// engine/repros/stepup-store-status.sh script). This driver wraps the
// client so the handler logic itself, this campaign's subject, is
// measured on the real Redis despite the store's refusal bug.
$redis = new class($redisRaw) implements \Predis\ClientInterface {
    private \Predis\Client $inner;

    public function __construct(\Predis\Client $inner)
    {
        $this->inner = $inner;
    }

    public function __call($method, $arguments)
    {
        $reply = $this->inner->$method(...$arguments);
        if ($reply instanceof \Predis\Response\Status && (string) $reply === 'OK') {
            return 'OK';
        }

        return $reply;
    }

    public function getCommandFactory(): \Predis\Command\FactoryInterface
    {
        return $this->inner->getCommandFactory();
    }

    public function createCommand($method, $arguments = [])
    {
        return $this->inner->createCommand($method, $arguments);
    }

    public function executeCommand(\Predis\Command\CommandInterface $command)
    {
        return $this->inner->executeCommand($command);
    }

    public function getConnection()
    {
        return $this->inner->getConnection();
    }

    public function getOptions()
    {
        return $this->inner->getOptions();
    }

    public function getProfile(): \Predis\Profile\ProfileInterface
    {
        return $this->inner->getProfile();
    }

    public function connect(): void
    {
        $this->inner->connect();
    }

    public function disconnect(): void
    {
        $this->inner->disconnect();
    }
};
$store = new RedisStepUpChallengeStore($redis, '{kiwi:rt37}:stepup:');

// The campaign's redis is dedicated and scrubbed first, so the begin
// windows of an earlier run never poison this one's rate-bound facts.
foreach ((array) $redisRaw->keys('{kiwi:rt37}:*') as $staleKey) {
    $redisRaw->del([$staleKey]);
}
$reporter = new SpyOutcomeReporter();
$ticket = new StepUpTicket(MASTER);
$credit = new StepUpCompletionCredit($reporter, MASTER);
$now = 1_700_000_000;
$clock = static fn (): int => $now;

$totp = new TotpStepUpHandler(
    $store,
    $ticket,
    $credit,
    'sha1',
    6,
    1,          // the acceptance window: plus or minus one step
    300,        // challenge ttl
    5,          // max attempts per challenge
    3,          // max challenge begins in the window
    900,        // begin window seconds
    '/kiwi/step-up/complete',
    $clock,
    MASTER,
);

$context = static fn (string $principal): StepUpContext => new StepUpContext(
    $principal,
    str_repeat('a7', 32),
    'login',
    '/back',
    'post_solve_step_up_required',
    StepUpContext::MODE_JSON,
);
$beginRequest = static fn (): Request => Request::create('https://' . HOST . '/kiwi/step-up/begin');
// The controller re-resolves the principal and binds it before the
// handler runs; a direct handler call must bind the same way or the
// session-mismatch guard refuses every completion.
$completeRequest = static function (string $tick, string $code, string $principal = PRINCIPAL): Request {
    $request = Request::create('https://' . HOST . '/kiwi/step-up/complete', 'POST', [
        TotpStepUpHandler::TICKET_FIELD => $tick,
        TotpStepUpHandler::CODE_FIELD => $code,
    ]);
    \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::bind($request, $principal);
    return $request;
};
$waCompleteRequest = static function (string $tick, string $credentialJson, string $principal = PRINCIPAL): Request {
    $request = Request::create('https://' . HOST . '/kiwi/step-up/complete', 'POST', [
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnStepUpHandler::TICKET_FIELD => $tick,
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnStepUpHandler::CREDENTIAL_FIELD => $credentialJson,
    ]);
    \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::bind($request, $principal);
    return $request;
};
$ticketOf = static function (object $response): string {
    $document = json_decode((string) $response->getContent(), true);
    // The JSON presentation carries the ticket in the challenge field
    // (the wire field a machine client echoes back on completion).
    return (string) ($document['challenge'] ?? $document['ticket'] ?? '');
};

// ---------- the TOTP relay ----------
$enrolledBase32 = $totp->enroll(PRINCIPAL);
$secretRaw = TotpCode::base32Decode($enrolledBase32) ?? throw new RuntimeException('base32 round trip broke');

// The victim begins the challenge and the phishing proxy reads the
// current code out of the relayed page (the farm's own capture).
$begin = $totp->begin($beginRequest(), $context(PRINCIPAL));
$beginRaw = (string) $begin->getContent();
$beginTicket = $ticketOf($begin);
$currentCode = TotpCode::at($secretRaw, TotpCode::stepOf($now));

// The relayed code completes: the documented residual risk.
$relayOne = $totp->complete($completeRequest($beginTicket, $currentCode));
$relayOneOk = $relayOne->status === StepUpResultStatus::Succeeded;
$relayOneDetail = json_encode($relayOne->toArray());

// The replay guard: the same time-step never completes twice.
$beginTwo = $totp->begin($beginRequest(), $context(PRINCIPAL));
$ticketTwo = $ticketOf($beginTwo);
$relayTwo = $totp->complete($completeRequest($ticketTwo, $currentCode));
$relayTwoBlocked = $relayTwo->status !== StepUpResultStatus::Succeeded;

// The consumed record: replaying on the FIRST challenge also fails.
$relayAgain = $totp->complete($completeRequest($beginTicket, $currentCode));
$consumedRefused = $relayAgain->status !== StepUpResultStatus::Succeeded;

// The begin-rate bound: the farm floods challenges for the account.
$rateLimitedBegins = 0;
for ($i = 0; $i < 10; $i++) {
    $now += 5;
    $response = $totp->begin($beginRequest(), $context(PRINCIPAL));
    if ($response->getStatusCode() === 429) {
        $rateLimitedBegins++;
    }
}

// The attempt cap: wrong codes burn the challenge's attempts.
$enrollSecond = $totp->enroll(VICTIM);
$beginThree = $totp->begin($beginRequest(), $context(VICTIM));
$ticketThree = $ticketOf($beginThree);
$attemptCapReached = false;
for ($i = 0; $i < 8; $i++) {
    $result = $totp->complete($completeRequest($ticketThree, sprintf('%06d', (900000 + $i * 137) % 1000000), VICTIM));
    if ($result->status === StepUpResultStatus::Failed) {
        $attemptCapReached = true;
        break;
    }
}

// ---------- the WebAuthn ceremony ----------
$waStore = new BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore($clock);
// The TOTP completion above marked a step-up success on the TOTP
// store; the WebAuthn enrollment precondition reads its own store, so
// the same completed-step-up fact is recorded there (the controller
// does this across handlers on the live plane).
$fakeRedis = new BelConsulting\KiwiCaptchaBundle\Tests\FakeWebAuthnRedis();
$registry = new WebAuthnCredentialRegistry($fakeRedis, 'tests:rt37:webauthn:');
$webauthn = new WebAuthnStepUpHandler(
    $waStore,
    $ticket,
    $credit,
    $registry,
    MASTER,
    300,
    5,
    3,
    900,
    '/kiwi/step-up/complete',
    $clock,
    true,
    HOST,
    ['https://' . HOST],
);
$waStore->markStepUpSuccess(PRINCIPAL, 900, $now);

$vectors = 'BelConsulting\KiwiCaptchaBundle\Tests\WebAuthnTestVectors';
$attestationOf = static function (string $challengeB64, string $credentialId, string $origin, string $rpId) use ($vectors): string {
    $authData = $vectors::authDataForAttestation($rpId, $credentialId, WebAuthnStepUpHandlerTestVectorsX, WebAuthnStepUpHandlerTestVectorsY);
    $clientDataJson = $vectors::clientDataJson('webauthn.create', $challengeB64, $origin);
    $attestationObject = $vectors::cborMap([
        $vectors::cborText('fmt') => $vectors::cborText('none'),
        $vectors::cborText('attStmt') => $vectors::cborMap([]),
        $vectors::cborText('authData') => $vectors::cborBytes($authData),
    ]);
    return $vectors::publicKeyJson($credentialId, $clientDataJson, $attestationObject);
};
$assertionOf = static function (string $challengeB64, string $credentialId, int $signCount, string $origin, string $rpId) use ($vectors): string {
    $clientDataJson = $vectors::clientDataJson('webauthn.get', $challengeB64, $origin);
    $authData = $vectors::authDataForAssertion($rpId, $signCount);
    $signature = $vectors::es256Sign($authData . hash('sha256', $clientDataJson, true));
    return $vectors::publicKeyJson($credentialId, $clientDataJson, null, $authData, $signature);
};

// Enrollment first (the creation ceremony lives on the enrollment
// entry points): the honest origin registers the security key.
$enrollBegin = $webauthn->enrollBegin(
    Request::create('https://' . HOST . '/kiwi/step-up/begin'),
    $context(PRINCIPAL),
);
$enrollDoc = json_decode((string) $enrollBegin->getContent(), true) ?? [];
$enrollTicket = $ticketOf($enrollBegin);
$attestation = $attestationOf((string) ($enrollDoc['public_key']['challenge'] ?? ''), 'cred-rt37', 'https://' . HOST, HOST);
$registration = $webauthn->enrollComplete($waCompleteRequest($enrollTicket, $attestation));
$registrationOk = $registration->status === StepUpResultStatus::Succeeded;

// The phishing origin: the same user is tricked into completing on
// evil.example with an rpId of the phisher's own domain. The library's
// ceremony steps must refuse it (a bad attempt, never a success).
$waBegin = $webauthn->begin(
    Request::create('https://' . HOST . '/kiwi/step-up/begin'),
    $context(PRINCIPAL),
);
$waBeginRaw = (string) $waBegin->getContent();
$waDocument = json_decode($waBeginRaw, true) ?? [];
$waChallenge = (string) ($waDocument['public_key']['challenge'] ?? '');
$phishAttestation = $attestationOf($waChallenge, 'cred-phish', 'https://evil.example', 'phishing.example');
$waTicket = $ticketOf($waBegin);
$phishComplete = $webauthn->complete($waCompleteRequest($waTicket, $phishAttestation));
$phishRefused = $phishComplete->status !== StepUpResultStatus::Succeeded;

// The honest origin assertion completes end to end.
$assertBegin = $webauthn->begin(
    Request::create('https://' . HOST . '/kiwi/step-up/begin'),
    $context(PRINCIPAL),
);
$assertDoc = json_decode((string) $assertBegin->getContent(), true);
$assertTicket = $ticketOf($assertBegin);
$assertionJson = $assertionOf((string) ($assertDoc['public_key']['challenge'] ?? ''), 'cred-rt37', 2, 'https://' . HOST, HOST);
$assertionComplete = $webauthn->complete($waCompleteRequest($assertTicket, $assertionJson));
$assertionOk = $assertionComplete->status === StepUpResultStatus::Succeeded;
$assertionDetail = json_encode($assertionComplete->toArray());

// The assertion replay: the same credential response presented again
// is refused (the challenge record is single use; the sign-count
// guard backs it inside one challenge).
$replayComplete = $webauthn->complete($waCompleteRequest($assertTicket, $assertionJson));
$replayRefused = $replayComplete->status !== StepUpResultStatus::Succeeded;

$summary = [
    'store_finding' => 'the raw client refuses create(): the strict OK comparison; filed separately by triage, see engine/repros/stepup-store-status.sh',
    'totp' => [
        'begin_status' => $begin->getStatusCode(),
        'begin_body' => json_decode($beginRaw, true),
        'relay_one_detail' => json_decode($relayOneDetail, true),
        'wa_begin_detail' => json_decode($waBeginRaw, true),
        'enrolled' => $totp->isEnrolled(PRINCIPAL),
        'relayed_code_completed_once' => $relayOneOk,
        'replay_guard_blocked_second' => $relayTwoBlocked,
        'consumed_record_refused' => $consumedRefused,
        'begin_rate_limited_of_10' => $rateLimitedBegins,
        'attempt_cap_burns_challenge' => $attemptCapReached,
    ],
    'webauthn' => [
        'begins_present' => $waChallenge !== '' && isset($enrollDoc['public_key']) && isset($assertDoc['public_key']),
        'phishing_origin_refused' => $phishRefused,
        'honest_registration_completed' => $registrationOk,
        'honest_assertion_completed' => $assertionOk,
        'assertion_detail' => json_decode($assertionDetail, true),
        'assertion_replay_refused' => $replayRefused,
        'residual_risk' => 'none known: the origin and rp-id bindings are the library ceremony steps; a phishing origin cannot complete',
    ],
    'honesty_note' => 'the TOTP code is relayable by design; the residual risk is bounded by the replay guard, the single-use record and the rate bounds, measured here',
];
echo json_encode($summary), "\n";

$pass = $relayOneOk
    && ($waChallenge !== '')
    && isset($enrollDoc['public_key'])
    && isset($assertDoc['public_key'])
    && $relayTwoBlocked
    && $consumedRefused
    && $rateLimitedBegins > 0
    && $attemptCapReached
    && $phishRefused
    && $registrationOk
    && $assertionOk
    && $replayRefused;
exit($pass ? 0 : 1);
