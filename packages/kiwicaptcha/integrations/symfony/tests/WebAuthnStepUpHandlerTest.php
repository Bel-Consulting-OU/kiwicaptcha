<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnCredentialRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use Cose\Algorithm\Signature\ECDSA\ECSignature;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The WebAuthn step-up handler against the in-memory store and a
 * software authenticator emulation: a minimal binary builder for the
 * authenticator data and its key map, over a fixed P-256 key. Covered:
 * the registration and assertion ceremonies end to end with the
 * completion credit. Also the sign-count replay guard, the
 * unknown-credential refusal, the origin and RP-id bindings of the
 * library's ceremony steps, the ceremony confusion refusal, the
 * attempt cap, and the no-library refusal with the exact actionable
 * message.
 */
final class WebAuthnStepUpHandlerTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';

    private const SESSION = 'test-session-id-0000000000000001';

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const TARGET = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';

    private const HOST = 'captcha.example.com';

    // The fixed software-authenticator key (P-256, ES256).
    private const D_HEX = 'a5d95a322aeb864573820f95a7711eb261b991d93d24648509db022917c0a068';

    private const X_HEX = '3538df4c2adee42ba4e6894652260058b5e2d4845669502db787bce655f6a92b';

    private const Y_HEX = 'b571381cb720f1498964115bab370aa5506c75801e53935b6b449d3526d696e7';

    private ArrayStepUpChallengeStore $store;

    private SpyOutcomeReporter $reporter;

    private ?WebAuthnCredentialRegistry $registry = null;

    private ?FakeWebAuthnRedis $fakeRedis = null;

    private int $now = 1700000000;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore($this->clock());
        $this->reporter = new SpyOutcomeReporter();
        $this->registry = null;
        $this->fakeRedis = null;
    }

    public function testTheNoLibraryPathRefusesWithTheActionableMessage(): void
    {
        try {
            $this->handler(libPresent: false);
            self::fail('the handler must refuse without the library');
        } catch (\LogicException $e) {
            self::assertSame(WebAuthnStepUpHandler::NOT_IMPLEMENTED_MESSAGE, $e->getMessage());
        }
    }

    public function testStepUpRefusesTheUnenrolledPrincipal(): void
    {
        // The critical property: step-up never hands a registration
        // ceremony to a principal without a key, because an attacker
        // holding stolen credentials is exactly that principal.
        $handler = $this->handler();
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        self::assertSame(Response::HTTP_FORBIDDEN, $begin->getStatusCode());
        self::assertStringContainsString('step_up_enrollment_required', (string) $begin->getContent());
        self::assertStringNotContainsString('creation', (string) $begin->getContent());
        self::assertSame(1, $this->store->countBegin(self::PRINCIPAL, 3600), 'the probe is the only admission: a refused begin consumes no rate budget');
    }

    /**
     * The strongest-factor floor under migration: a fresh marker plus
     * a reconcile lock held by another reader makes an empty index
     * UNKNOWN, never evidence that the account is key-less. Begin
     * answers a retryable 503 (never the 403 credential-less refusal,
     * never a creation ceremony), and enrollment refuses rather than
     * bootstrapping first-key from migration-stale data.
     */
    public function testAnInMigrationEmptyIndexIsRetryableNeverCredentialLessOrBootstrap(): void
    {
        $handler = $this->handler();
        $redis = $this->fakeRedis();
        // Inside the dual-read window, with the fleet reconcile cadence
        // held by another reader: this node may not trust the empty set.
        $redis->setex(
            'tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER,
            604800,
            (string) \time(),
        );
        $redis->locks['tests:webauthn:credential:reconcile-lock'] = '1';

        $lookup = $this->registry()->registeredCredentialsOf(self::PRINCIPAL);
        self::assertNull($lookup, 'an in-migration empty answer is UNKNOWN, never []');

        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        self::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $begin->getStatusCode(), 'retryable, never 403-credential-less');
        self::assertStringContainsString('step_up_credential_lookup_retry', (string) $begin->getContent());
        self::assertStringNotContainsString('creation', (string) $begin->getContent(), 'no ceremony is minted from stale data');
        self::assertSame(1, $this->store->countBegin(self::PRINCIPAL, 3600), 'the retry refusal consumes no rate budget: this call is the only increment');

        $enroll = $handler->enrollBegin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        self::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $enroll->getStatusCode(), 'enrollment never bootstraps from UNKNOWN');
        self::assertStringContainsString('step_up_credential_lookup_retry', (string) $enroll->getContent());
    }

    /**
     * A SCAN backend failure mid-walk must never be treated as a
     * complete empty keyspace: the backfill marker is not stamped, the
     * lookup answers UNKNOWN (retryable), and no first-key bootstrap
     * becomes eligible from a failed pass.
     */
    public function testAFailedScanWalkNeverStampsTheMarkerOrAnswersKnownEmpty(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();
        $redis->scanMalformed = true;

        $lookup = $registry->registeredCredentialsOf(self::PRINCIPAL);
        self::assertNull($lookup, 'a failed walk is UNKNOWN, never []');
        self::assertNull(
            $redis->get('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER),
            'a failed walk never stamps the backfill marker'
        );

        // Dual-read with the lock free: the winning claim's walk also
        // fails → UNKNOWN, not a fresh [] that would authorize bootstrap.
        $redis->scanMalformed = false;
        $redis->setex(
            'tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER,
            604800,
            (string) \time(),
        );
        $redis->scanMalformed = true;
        $again = $registry->registeredCredentialsOf(self::PRINCIPAL);
        self::assertNull($again, 'a failed reconcile under the lock is UNKNOWN');
        // The failed walk released the cadence so the next lookup can
        // retry immediately instead of waiting out the 300 s TTL.
        self::assertArrayNotHasKey(
            'tests:webauthn:credential:reconcile-lock',
            $redis->locks,
            'a failed walk must not pin the fleet reconcile lock'
        );
    }

    /**
     * A retryable lookup miss on completion must leave the challenge
     * alive: the client is told to retry, so spending single-use would
     * make the next attempt unknown_challenge instead.
     */
    public function testCompletionLookupRetryDoesNotConsumeTheChallenge(): void
    {
        $handler = $this->handler();
        $redis = $this->fakeRedis();
        // Mint a real enrollment challenge while the index is known.
        $this->store->markSessionStepUpSuccess(self::SESSION, self::PRINCIPAL, 'email_otp', 900, $this->now);
        $begin = $handler->enrollBegin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);
        $challengeId = (string) $document['challenge'];

        // Index goes UNKNOWN (in-window, lock held elsewhere) before complete.
        $redis->setex(
            'tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER,
            604800,
            (string) \time(),
        );
        $redis->locks['tests:webauthn:credential:reconcile-lock'] = '1';

        $result = $handler->enrollComplete($this->completeRequest($challengeId, ''));
        self::assertSame('step_up_credential_lookup_retry', $result->failureCode, 'retryable, fail-closed');
        self::assertNotNull($result->challengeId, 'the refusal carries the challenge id');
        self::assertNotNull(
            $this->store->read($result->challengeId),
            'the challenge must survive a retryable lookup miss so the client can complete once the index settles'
        );
        // And the same ticket still resolves (not consumed → not unknown).
        $unlocked = $this->fakeRedis();
        unset($unlocked->locks['tests:webauthn:credential:reconcile-lock']);
        $retry = $handler->enrollComplete($this->completeRequest($challengeId, ''));
        self::assertNotSame(
            StepUpResult::FAIL_UNKNOWN_CHALLENGE,
            $retry->failureCode,
            'a second attempt on the same ticket must not answer unknown_challenge'
        );
    }

    public function testTheEnrollmentEntryPointCompletesAndEnrolls(): void
    {
        $handler = $this->handler();
        $this->store->markSessionStepUpSuccess(self::SESSION, self::PRINCIPAL, 'email_otp', 900, $this->now);
        $begin = $handler->enrollBegin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);
        self::assertSame('webauthn', $document['handler']);
        self::assertSame('creation', $document['ceremony']);
        self::assertSame(self::HOST, $document['public_key']['rp']['id']);

        $credentialId = 'test-credential-id-bytes-01';
        $attestation = $this->attestation($document['public_key']['challenge'], $credentialId);
        $result = $handler->enrollComplete($this->completeRequest($document['challenge'], $attestation));
        self::assertSame(StepUpResultStatus::Succeeded, $result->status, (string) json_encode($result->toArray()));
        self::assertFalse($result->creditedPrincipal, 'enrollment credits nothing');
        self::assertCount(0, $this->reporter->reports, 'enrollment is not a step-up completion');

        // The validated credential is enrolled: the next begin answers
        // the assertion ceremony over it.
        $second = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document2 = $this->documentOf($second);
        self::assertSame('assertion', $document2['ceremony']);
        self::assertSame(WebAuthnTestVectors::base64Url($credentialId), $document2['public_key']['allowCredentials'][0]['id']);
        self::assertSame('required', $document2['public_key']['userVerification'], 'user verification is required, never preferred');
    }

    public function testEnrollmentDemandsACompletedStepUpFirst(): void
    {
        $handler = $this->handler();
        $begin = $handler->enrollBegin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        self::assertSame(Response::HTTP_FORBIDDEN, $begin->getStatusCode());
        self::assertStringContainsString('step_up_enrollment_requires_session_step_up', (string) $begin->getContent());
    }

    public function testEnrollmentRefusesAnotherSessionOfTheSamePrincipal(): void
    {
        // The victim completed step-up in session A; session B of the
        // same account must not enroll a factor (N1).
        $handler = $this->handler();
        $this->store->markSessionStepUpSuccess('session-A', self::PRINCIPAL, 'email_otp', 900, $this->now);
        $begin = $handler->enrollBegin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        self::assertSame(Response::HTTP_FORBIDDEN, $begin->getStatusCode());
        self::assertStringContainsString('step_up_enrollment_requires_session_step_up', (string) $begin->getContent());
    }

    public function testTheOptionsNeverHonorTheHostHeader(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $hostile = Request::create('https://'.self::HOST.'/kiwi/step-up/begin');
        $hostile->server->set('HTTP_HOST', 'evil.test');
        $begin = $handler->begin($hostile, $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);
        self::assertSame(self::HOST, $document['public_key']['rpId'], 'the rp id comes from configuration, never the Host header');
        self::assertStringNotContainsString('evil.test', (string) json_encode($document), 'a forged host never reaches the options');
    }

    public function testATicketOrCredentialInTheQueryStringIsIgnored(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        $queryOnly = Request::create(
            'https://'.self::HOST.'/kiwi/step-up/complete?'.http_build_query([
                WebAuthnStepUpHandler::TICKET_FIELD => $document['challenge'],
                WebAuthnStepUpHandler::CREDENTIAL_FIELD => $this->assertion($document['public_key']['challenge'], 'cred-A', 1),
            ]),
        );
        $result = $handler->complete($queryOnly);
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $result->failureCode, 'secrets ride the POST body only');
    }

    public function testAnAssertionWithoutUserVerificationIsRefused(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 4);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        $noUv = $this->assertion($document['public_key']['challenge'], 'cred-A', 5, noUserVerification: true);
        $result = $handler->complete($this->completeRequest($document['challenge'], $noUv));
        self::assertSame(StepUpResultStatus::Pending, $result->status, 'a UV-less assertion spends an attempt, never completes');
    }

    public function testTheWebAuthnHandlerRefusesAHalfConfiguredRelyingParty(): void
    {
        try {
            new WebAuthnStepUpHandler(
                $this->store,
                new StepUpTicket(self::MASTER),
                $this->registry(),
                self::MASTER,
                300,
                5,
                3,
                900,
                '/kiwi/step-up/complete',
                $this->clock(),
                true,
                self::HOST,
                [],
            );
            self::fail('an origin-less relying party configuration must refuse');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('allowed_origins', $e->getMessage());
        }
    }

    public function testTheHtmlPageCarriesTheTicketAndTheNavigatorCall(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_HTML));
        $html = (string) $begin->getContent();
        self::assertStringContainsString('navigator.credentials.get', $html, 'the html mode drives the ceremony');
        self::assertStringContainsString('name="kiwi_step_up_ticket"', $html, 'the form carries the ticket');
        self::assertStringContainsString('id="kiwi-webauthn-credential"', $html, 'the form carries the credential');
    }

    public function testTheAssertionCeremonyCompletesAndAdvancesTheCounter(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        $assertion = $this->assertion($document['public_key']['challenge'], 'cred-A', 5);
        $result = $handler->complete($this->completeRequest($document['challenge'], $assertion));
        self::assertSame(StepUpResultStatus::Succeeded, $result->status, (string) json_encode($result->toArray()));
        // FactorVerified, never AuthorizedStepUp: the proof books no
        // credit; the shared StepUpDemandFinalizer owns the write.
        self::assertFalse($result->creditedPrincipal, 'a factor proof books no credit');
        self::assertFalse($result->creditedTarget, 'a factor proof books no credit');
        self::assertSame('webauthn', $result->factor, 'the proof names its factor');
        self::assertSame(5, $this->registry()->findOneByCredentialId('cred-A')?->counter, 'the sign count advanced in the registry');
    }

    public function testAReplayedSignCountIsRefusedAsReplayed(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 5);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        $assertion = $this->assertion($document['public_key']['challenge'], 'cred-A', 5);
        $result = $handler->complete($this->completeRequest($document['challenge'], $assertion));
        self::assertSame(StepUpResultStatus::Failed, $result->status);
        self::assertSame(StepUpResult::FAIL_REPLAYED_STEP, $result->failureCode);
    }

    public function testAnAssertionOverAnUnknownCredentialIsRefused(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 5);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        $assertion = $this->assertion($document['public_key']['challenge'], 'cred-NOT-ENROLLED', 6);
        $result = $handler->complete($this->completeRequest($document['challenge'], $assertion));
        self::assertSame(StepUpResultStatus::Failed, $result->status);
        self::assertSame(WebAuthnStepUpHandler::FAIL_UNKNOWN_CREDENTIAL, $result->failureCode);
    }

    public function testABadOriginIsRefusedAsABadAttempt(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        $attestation = $this->attestation($document['public_key']['challenge'], 'cred-x', origin: 'https://evil.example');
        $result = $handler->complete($this->completeRequest($document['challenge'], $attestation));
        // The plane answers one bad attempt as pending (the challenge
        // stays live inside its attempt cap), never as a success.
        self::assertSame(StepUpResultStatus::Pending, $result->status);
        self::assertSame(0, count($this->reporter->reports), 'no credit for a refused ceremony');
    }

    public function testAWrongRpIdHashIsRefusedAsABadAttempt(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        $attestation = $this->attestation($document['public_key']['challenge'], 'cred-x', rpId: 'phishing.example');
        $result = $handler->complete($this->completeRequest($document['challenge'], $attestation));
        self::assertSame(StepUpResultStatus::Pending, $result->status);
        self::assertSame([], $this->reporter->reports, 'no credit for a foreign RP hash');
    }

    public function testACeremonyConfusionIsRefused(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 5);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);
        self::assertSame('assertion', $document['ceremony']);

        // The begun ceremony is the assertion one: a fresh registration
        // can never complete it (a fresh key would otherwise enroll over
        // the enrolled factor).
        $creditedBefore = count($this->reporter->reports);
        $attestation = $this->attestation($document['public_key']['challenge'], 'cred-EVIL');
        $result = $handler->complete($this->completeRequest($document['challenge'], $attestation));
        self::assertSame(StepUpResultStatus::Pending, $result->status);
        self::assertCount($creditedBefore, $this->reporter->reports, 'a registration never completes an assertion challenge');
    }

    public function testAForeignCeremonyChallengeIsRefused(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        $foreignChallenge = random_bytes(32);
        $attestation = $this->attestation(WebAuthnTestVectors::base64Url($foreignChallenge), 'cred-x');
        $result = $handler->complete($this->completeRequest($document['challenge'], $attestation));
        self::assertSame(StepUpResultStatus::Pending, $result->status);
        self::assertSame([], $this->reporter->reports, 'a challenge the server never minted earns nothing');
    }

    public function testTheAttemptCapTerminalizesTheChallenge(): void
    {
        $handler = $this->handler(maxAttempts: 2);
        $this->enroll($handler, 'cred-A', 0);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        $attestation = $this->attestation(WebAuthnTestVectors::base64Url(random_bytes(32)), 'cred-first');
        $result = $handler->complete($this->completeRequest($document['challenge'], $attestation));
        self::assertSame(StepUpResultStatus::Pending, $result->status, 'the first attempt stays live');
        $attestation = $this->attestation(WebAuthnTestVectors::base64Url(random_bytes(32)), 'cred-second');
        $result = $handler->complete($this->completeRequest($document['challenge'], $attestation));
        self::assertSame(StepUpResult::FAIL_TOO_MANY_ATTEMPTS, $result->failureCode, 'the cap terminalizes the challenge');
    }

    public function testAnUnknownOrExpiredChallengeAnswersItsOwnCodes(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $result = $handler->complete($this->completeRequest('not-a-ticket', '{}'));
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $result->failureCode);

        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);
        $this->now += 400;
        $result = $handler->complete($this->completeRequest($document['challenge'], '{}'));
        self::assertSame(StepUpResult::FAIL_EXPIRED, $result->failureCode);
    }

    public function testSingleUseCompletionCannotCreditTwice(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);
        $assertion = $this->assertion($document['public_key']['challenge'], 'cred-A', 2);
        $result = $handler->complete($this->completeRequest($document['challenge'], $assertion));
        self::assertSame(StepUpResultStatus::Succeeded, $result->status);
        $credited = count($this->reporter->reports);
        $replay = $handler->complete($this->completeRequest($document['challenge'], $assertion));
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $replay->failureCode, 'the record is consumed once');
        self::assertCount($credited, $this->reporter->reports, 'a replay never credits again');
    }

    public function testTheAllowListLookupReadsOneBatchedRoundTrip(): void
    {
        $handler = $this->handler();
        $this->enroll($handler, 'cred-A', 0);
        $redis = $this->fakeRedis();
        // Steady state: the index backfill already ran (here: pinned
        // explicitly so the measured round is the one every ceremony
        // pays after the one-time cursor pass).
                // An aged marker: the dual-read upgrade horizon has closed, so
        // the lookup is index-only (the steady state these tests pin).
        $redis->setex('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER, 604800, (string) (time() - WebAuthnCredentialRegistry::INDEX_DUAL_READ_SECS - 60));
        $redis->batches = 0;
        $redis->batchedKeys = [];
        $redis->commands = [];

        $begin = $handler->begin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);

        // The lookup reads the principal's index members and fetches
        // them in one pipelined batch. The ceremony therefore pays two
        // store round trips whatever the deployment's enrolled
        // credential count — and never a keyspace-wide key scan.
        self::assertSame(1, $redis->batches, 'the allow-list lookup is one pipelined batch');
        self::assertSame(
            [$this->credentialKey('cred-A')],
            $redis->batchedKeys,
            'the batch carries one read per indexed credential key of this principal',
        );
        self::assertSame(0, $redis->unservedCommands, 'every lookup read rides the batch, never a silently ignored call');
        self::assertContains('SMEMBERS', $redis->commands, 'discovery is the principal index');
        self::assertNotContains('KEYS', $redis->commands, 'HOLE: the registry fell back to a keyspace-wide key scan');
        self::assertNotContains('SCAN', $redis->commands, 'the steady state never re-runs the backfill pass');
        self::assertSame(
            [WebAuthnTestVectors::base64Url('cred-A')],
            array_column($document['public_key']['allowCredentials'], 'id'),
            'the ceremony allow-list carries the batched record',
        );
    }

    public function testTheAllowListKeepsTheBatchOrderAndSkipsUnreadableRecords(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();
        $registry->saveCredentialSource($this->record('cred-A', self::PRINCIPAL, 1));
        $registry->saveCredentialSource($this->record('cred-B', str_repeat('9', 32), 2));
        $registry->saveCredentialSource($this->record('cred-C', self::PRINCIPAL, 3));
        // One record whose bytes never deserialize, one empty value, and
        // one record gone between the discovery call and the batch read:
        // the lookup answers the readable records and skips the rest.
        $redis->values[$this->credentialKey('cred-BROKEN')] = '{not-json';
        $redis->values[$this->credentialKey('cred-EMPTY')] = '';
        $redis->values[$this->credentialKey('cred-GONE')] = 'value';
        $redis->expired[$this->credentialKey('cred-GONE')] = true;

        // First lookup: no marker yet, so the one-time cursor pass
        // indexes the legacy values. Undecodable/gone bytes are skipped
        // at that pass (they never ride an index), and cred-B belongs to
        // another principal: only A and C land in this principal's set.
        $warmed = $registry->registeredCredentialsOf(self::PRINCIPAL);
        self::assertContains('SCAN', $redis->commands, 'the un-indexed deployment backfills once');
        self::assertSame(
            ['cred-A', 'cred-C'],
            array_map(static fn (\Webauthn\CredentialRecord $record): string => $record->publicKeyCredentialId, $warmed),
            'the warm-up pass already answers the readable principal records'
        );

        // A record corrupted later, after it was indexed, must still be skipped
        // at lookup time — the batch-time filter the original contract
        // pinned — while its index member keeps riding the batch.
        $registry->saveCredentialSource($this->record('cred-D', self::PRINCIPAL, 4));
        $redis->values[$this->credentialKey('cred-D')] = '{not-json';

        // Close the dual-read horizon: past it the same lookup costs
        // one index read plus one batch, and the batch holds only this
        // principal's members (no reconcile walk).
        $redis->setex('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER, 604800, (string) (time() - WebAuthnCredentialRegistry::INDEX_DUAL_READ_SECS - 60));
        $redis->batches = 0;
        $redis->batchedKeys = [];
        $redis->commands = [];
        $found = $registry->registeredCredentialsOf(self::PRINCIPAL);

        self::assertSame(1, $redis->batches, 'the steady lookup is one pipelined batch');
        self::assertSame(
            [
                $this->credentialKey('cred-A'),
                $this->credentialKey('cred-C'),
                $this->credentialKey('cred-D'),
            ],
            $redis->batchedKeys,
            'the batch carries this principal\'s indexed records only, in index order'
        );
        self::assertNotContains('KEYS', $redis->commands, 'HOLE: the registry fell back to a keyspace-wide key scan');
        self::assertNotContains('SCAN', $redis->commands, 'the steady state never re-runs the backfill pass');
        self::assertSame(
            ['cred-A', 'cred-C'],
            array_map(static fn (\Webauthn\CredentialRecord $record): string => $record->publicKeyCredentialId, $found),
            'the principal records come back in the batch order with the corrupted one skipped',
        );
    }

    public function testALegacyUnindexedRecordIsIndexedOnceAndFoundThereafter(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();
        // The upgrade starting state: the record bytes exist (written
        // by the current save path) but the index membership and the
        // marker do not — exactly what a pre-index deployment carries.
        $registry->saveCredentialSource($this->record('cred-LEGACY', self::PRINCIPAL, 7));
        $indexKey = 'tests:webauthn:principal:'.hash('sha256', self::PRINCIPAL);
        unset($redis->sets[$indexKey]);

        $found = $registry->registeredCredentialsOf(self::PRINCIPAL);
        self::assertCount(1, $found, 'the cursor pass finds the pre-index record');
        self::assertSame('cred-LEGACY', $found[0]->publicKeyCredentialId);
        self::assertContains('SCAN', $redis->commands, 'the first lookup scans once');

        // The marker now pins the walk; past the dual-read horizon the
        // second lookup goes straight to the index, never another pass.
        self::assertNotNull($redis->get('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER));
        $redis->setex('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER, 604800, (string) (time() - WebAuthnCredentialRegistry::INDEX_DUAL_READ_SECS - 60));
        $redis->commands = [];
        $again = $registry->registeredCredentialsOf(self::PRINCIPAL);
        self::assertCount(1, $again, 'the indexed record still answers');
        self::assertNotContains('SCAN', $redis->commands, 'the steady state adds no further scan');
        self::assertContains('SMEMBERS', $redis->commands, 'the steady lookup reads the index');
    }

    /**
     * The N-1 visibility window the auditor closed: a marker exists
     * (backfill ran) but a pre-index node writes another credential without
     * SADDing it. During the dual-read horizon the lookup reconciles
     * with one bounded walk and the enrolled key stays visible — the
     * 403 step_up_enrollment_required on a genuinely enrolled
     * principal never fires. An age-less legacy marker restamps so its
     * horizon actually closes later.
     */
    public function testAnUnindexedLegacyWriteStaysVisibleDuringTheDualReadWindow(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();
        // The previous build's age-less marker: present, but undatable.
        $redis->setex('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER, 604800, '1');
        $key = 'tests:webauthn:credential:'.hash('sha256', 'cred-N1');
        $serialized = (string) json_encode([
            'publicKeyCredentialId' => base64_encode('cred-N1'),
            'type' => 'public-key',
            'transports' => [],
            'attestationType' => 'none',
            'trustPath' => [],
            'aaguid' => '00000000-0000-0000-0000-000000000000',
            'credentialPublicKey' => base64_encode('key-material'),
            'userHandle' => base64_encode('n1-principal'),
            'counter' => 3,
        ]);
        // The old node's write: record bytes, no index membership.
        $redis->setex($key, 31536000, $serialized);

        $found = $registry->registeredCredentialsOf('n1-principal');
        self::assertCount(1, $found, 'the reconcile walk surfaces the pre-index write: '.json_encode($redis->commands));
        self::assertSame('cred-N1', $found[0]->publicKeyCredentialId);
        self::assertContains('SCAN', $redis->commands, 'the open horizon reconciles with one walk');

        // The age-less marker restamped: the horizon now has a date and
        // will close one dual-read window from this moment.
        $stamped = $redis->get('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER);
        self::assertIsNumeric($stamped, 'the legacy marker is restamped');
        self::assertGreaterThan(1_000_000_000, (int) $stamped, 'restamped to a real timestamp');
    }

    /**
     * The fence closes: past the dual-read horizon the index alone
     * decides (no walk ever runs again), and a record written without
     * index membership by that point is outside the contract — the
     * migration window is over, not the mechanism.
     */
    public function testTheDualReadWindowClosesAndIndexOnlyLookupsNeverWalkAgain(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();
        $redis->setex('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER, 604800, (string) (time() - WebAuthnCredentialRegistry::INDEX_DUAL_READ_SECS - 60));
        // One indexed credential of the principal (the honest write)…
        $registry->saveCredentialSource($this->record('cred-INDEXED', 'closed-principal', 1));
        // …and one that a writer outside the contract left un-indexed.
        $unindexed = 'tests:webauthn:credential:'.hash('sha256', 'cred-UNINDEXED');
        $redis->setex($unindexed, 31536000, (string) json_encode([
            'publicKeyCredentialId' => base64_encode('cred-UNINDEXED'),
            'type' => 'public-key',
            'transports' => [],
            'attestationType' => 'none',
            'trustPath' => [],
            'aaguid' => '00000000-0000-0000-0000-000000000000',
            'credentialPublicKey' => base64_encode('key-material'),
            'userHandle' => base64_encode('closed-principal'),
            'counter' => 1,
        ]));

        $redis->commands = [];
        $found = $registry->registeredCredentialsOf('closed-principal');
        self::assertCount(1, $found, 'the closed horizon answers from the index alone');
        self::assertSame('cred-INDEXED', $found[0]->publicKeyCredentialId);
        self::assertNotContains('SCAN', $redis->commands, 'past the horizon no walk ever runs');
        self::assertNotContains('KEYS', $redis->commands, 'never a keyspace scan');
    }

    public function testSaveCredentialSourceMaintainsThePrincipalIndex(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();
        // Marker present from the start: any discovery must come from
        // the index the save maintains — there is no backfill to lean on.
                // An aged marker: the dual-read upgrade horizon has closed, so
        // the lookup is index-only (the steady state these tests pin).
        $redis->setex('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER, 604800, (string) (time() - WebAuthnCredentialRegistry::INDEX_DUAL_READ_SECS - 60));
        $registry->saveCredentialSource($this->record('cred-IDX', self::PRINCIPAL, 1));
        $registry->saveCredentialSource($this->record('cred-IDX-OTHER', str_repeat('7', 32), 1));

        $indexKey = 'tests:webauthn:principal:'.hash('sha256', self::PRINCIPAL);
        self::assertSame(
            [$this->credentialKey('cred-IDX')],
            $redis->sets[$indexKey] ?? [],
            'the save lands the record key in exactly its own principal index'
        );
        $redis->commands = [];
        $found = $registry->registeredCredentialsOf(self::PRINCIPAL);
        self::assertCount(1, $found, 'the index answers the allow-list');
        self::assertNotContains('SCAN', $redis->commands, 'no backfill runs when the marker is present');
        self::assertNotContains('KEYS', $redis->commands, 'never a keyspace scan');
    }

    /**
     * The rollback guard is one atomic CAS, never a GET-then-SETEX
     * pair. A concurrent writer between those two commands is exactly
     * how the persisted counter used to rewind: both writers read the
     * old counter, both pass the client-side comparison, and the later
     * write lands lower. The command shape pins the change; the
     * counter outcomes pin the semantics.
     */
    public function testSaveCredentialSourceIsOneAtomicCasThatRefusesRollbacks(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();

        // A fresh credential lands through exactly one script: the
        // counter CAS plus the index membership — never a bare
        // GET/SETEX pair and never a follow-up index write.
        $registry->saveCredentialSource($this->record('cred-CAS', self::PRINCIPAL, 7));
        self::assertSame(
            ['EVAL'],
            $redis->commands,
            'the save path is one atomic script, no client-side read-compare race'
        );
        $indexKey = 'tests:webauthn:principal:'.hash('sha256', self::PRINCIPAL);
        self::assertContains(
            $this->credentialKey('cred-CAS'),
            $redis->sets[$indexKey] ?? [],
            'the index membership landed inside the same transaction'
        );
        $key = $this->credentialKey('cred-CAS');
        $stored = json_decode((string) $redis->values[$key], true);
        self::assertSame(7, $stored['counter'], 'the first write lands');

        // A rollback is refused inside the transaction: the stored
        // counter (and record bytes) survive untouched.
        $redis->commands = [];
        $registry->saveCredentialSource($this->record('cred-CAS', self::PRINCIPAL, 5));
        self::assertSame(['EVAL'], $redis->commands, 'a refused CAS writes nothing else');
        $stored = json_decode((string) $redis->values[$key], true);
        self::assertSame(7, $stored['counter'], 'the rollback never lands');

        // Equal counters stay allowed (the authenticator may repeat a
        // zero increment); a forward counter replaces the record.
        $registry->saveCredentialSource($this->record('cred-CAS', self::PRINCIPAL, 7));
        $stored = json_decode((string) $redis->values[$key], true);
        self::assertSame(7, $stored['counter'], 'an equal counter is not a rollback');
        $registry->saveCredentialSource($this->record('cred-CAS', self::PRINCIPAL, 9));
        $stored = json_decode((string) $redis->values[$key], true);
        self::assertSame(9, $stored['counter'], 'a forward counter replaces the record');
    }

    /**
     * The documented fail-open of the counter CAS: an unreadable prior
     * record carries no counter to defend, so a forward write lands
     * over the corrupt bytes (the script only refuses a readable
     * strictly-higher counter). Corrupt bytes never freeze the
     * credential forever.
     */
    public function testAnUnreadablePriorRecordNeverWedgesTheCredential(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();
        $key = $this->credentialKey('cred-CORRUPT');
        $redis->values[$key] = '{broken-json';

        $registry->saveCredentialSource($this->record('cred-CORRUPT', self::PRINCIPAL, 5));
        $stored = json_decode((string) $redis->values[$key], true);
        self::assertSame(5, $stored['counter'], 'an unreadable prior is overwritten by the validated write');
        self::assertSame(['EVAL'], $redis->commands, 'still one atomic script');
    }

    /**
     * The dual-read window must never scan the whole keyspace per
     * authentication: one bounded reconcile runs per fleet-wide lock
     * TTL, later lookups serve the index immediately.
     */
    public function testDualReadReconcilesAtMostOncePerLockTtl(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();
        // A fresh (in-window) marker with a legacy un-indexed record.
        $redis->setex('tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER, 604800, (string) time());
        $redis->setex($this->credentialKey('cred-THROTTLE'), 31536000, (string) json_encode([
            'publicKeyCredentialId' => base64_encode('cred-THROTTLE'),
            'type' => 'public-key',
            'transports' => [],
            'attestationType' => 'none',
            'trustPath' => [],
            'aaguid' => '00000000-0000-0000-0000-000000000000',
            'credentialPublicKey' => base64_encode('key-material'),
            'userHandle' => base64_encode('throttle-principal'),
            'counter' => 2,
        ]));

        $redis->commands = [];
        $first = $registry->registeredCredentialsOf('throttle-principal');
        self::assertCount(1, $first, 'the first in-window lookup reconciles and finds the legacy write');
        self::assertContains('SCAN', $redis->commands, 'the claimed lock runs exactly one walk');

        $redis->commands = [];
        $second = $registry->registeredCredentialsOf('throttle-principal');
        self::assertCount(1, $second, 'the index still answers');
        self::assertNotContains('SCAN', $redis->commands, 'the held lock suppresses a second walk (no per-request keyspace scan)');
    }

    /**
     * Inside the dual-read window a NON-empty index is trustworthy for
     * the strongest-factor floor, and this caller also takes the fleet
     * cadence when it wins it so a PARTIAL index (a second key written
     * by a pre-index node) heals. A loser of the lock still serves the
     * index — never a keyspace walk per request.
     */
    public function testDualReadHealsAPartialIndexUnderTheFleetLockWithoutPerRequestWalks(): void
    {
        $registry = $this->registry();
        $redis = $this->fakeRedis();
        $registry->saveCredentialSource($this->record('cred-SHORT', self::PRINCIPAL, 1));
        // A second credential the pre-index node wrote WITHOUT SADDing.
        $redis->setex($this->credentialKey('cred-LEGACY-2'), 31536000, (string) json_encode([
            'publicKeyCredentialId' => base64_encode('cred-LEGACY-2'),
            'type' => 'public-key',
            'transports' => [],
            'attestationType' => 'none',
            'trustPath' => [],
            'aaguid' => '00000000-0000-0000-0000-000000000000',
            'credentialPublicKey' => base64_encode('key-material'),
            'userHandle' => base64_encode(self::PRINCIPAL),
            'counter' => 0,
        ]));
        $redis->setex(
            'tests:webauthn:'.WebAuthnCredentialRegistry::BACKFILL_MARKER,
            604800,
            (string) \time(),
        );

        // Lock free: the in-window lookup claims it, walks once, and
        // the partial index becomes complete.
        $redis->commands = [];
        $found = $registry->registeredCredentialsOf(self::PRINCIPAL);
        self::assertCount(2, $found, 'the winning claim heals the second key into the allow-list');
        self::assertContains('SCAN', $redis->commands, 'the winner runs exactly one walk');

        // Lock held elsewhere: serve the (now complete) index, never walk.
        $redis->locks['tests:webauthn:credential:reconcile-lock'] = 'other-node';
        $redis->commands = [];
        $again = $registry->registeredCredentialsOf(self::PRINCIPAL);
        self::assertCount(2, $again, 'the index still answers');
        self::assertNotContains('SCAN', $redis->commands, 'a lock loser never runs a keyspace walk');
    }

    private function enroll(WebAuthnStepUpHandler $handler, string $credentialId, int $counter): void
    {
        // The enrollment precondition: a completed step-up for the same
        // principal within the lookback. A fresh principal earns it the
        // way every other handler grants it, through a completion.
        $this->store->markSessionStepUpSuccess(self::SESSION, self::PRINCIPAL, 'email_otp', 900, $this->now);
        $begin = $handler->enrollBegin($this->beginRequest(), $this->context(StepUpContext::MODE_JSON));
        $document = $this->documentOf($begin);
        self::assertSame('creation', $document['ceremony'], 'the enrollment entry point issues the creation ceremony');
        $attestation = $this->attestation($document['public_key']['challenge'], $credentialId);
        $result = $handler->enrollComplete($this->completeRequest($document['challenge'], $attestation));
        self::assertSame(StepUpResultStatus::Succeeded, $result->status, (string) json_encode($result->toArray()));
        self::assertFalse($result->creditedPrincipal, 'enrollment never credits a step-up completion');
        if ($counter > 0) {
            $source = $this->registry()->findOneByCredentialId($credentialId);
            self::assertNotNull($source);
            $source->counter = $counter;
            $this->registry->saveCredentialSource($source);
        }
    }

    private function handler(bool $libPresent = true, int $maxAttempts = 5): WebAuthnStepUpHandler
    {
        return new WebAuthnStepUpHandler(
            $this->store,
            new StepUpTicket(self::MASTER),
            $this->registry(),
            self::MASTER,
            300,
            $maxAttempts,
            3,
            900,
            '/kiwi/step-up/complete',
            $this->clock(),
            $libPresent,
            self::HOST,
            ['https://'.self::HOST],
        );
    }

    private function registry(): WebAuthnCredentialRegistry
    {
        if ($this->registry === null) {
            $this->fakeRedis = new FakeWebAuthnRedis();
            $this->registry = new WebAuthnCredentialRegistry($this->fakeRedis, 'tests:webauthn:');
        }

        return $this->registry;
    }

    private function fakeRedis(): FakeWebAuthnRedis
    {
        $this->registry();

        return $this->fakeRedis;
    }

    /** The store key the registry derives from a credential id. */
    private function credentialKey(string $credentialId): string
    {
        return 'tests:webauthn:credential:'.hash('sha256', $credentialId);
    }

    private function record(string $credentialId, string $userHandle, int $counter): \Webauthn\CredentialRecord
    {
        return \Webauthn\CredentialRecord::create(
            $credentialId,
            'public-key',
            [],
            'none',
            new \Webauthn\TrustPath\EmptyTrustPath(),
            \Symfony\Component\Uid\Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            'key-material',
            $userHandle,
            $counter,
        );
    }

    private function clock(): \Closure
    {
        return function (): int {
            return $this->now;
        };
    }

    private function context(string $mode = StepUpContext::MODE_HTML): StepUpContext
    {
        return new StepUpContext(self::PRINCIPAL, self::TARGET, 'login', '/back', 'post_solve_step_up_required', $mode, true);
    }

    private function beginRequest(): Request
    {
        return $this->withSession(Request::create('https://'.self::HOST.'/kiwi/step-up/begin'));
    }

    private function completeRequest(string $ticket, string $credentialJson): Request
    {
        $request = $this->withSession(Request::create('https://'.self::HOST.'/kiwi/step-up/complete', 'POST', [
            WebAuthnStepUpHandler::TICKET_FIELD => $ticket,
            WebAuthnStepUpHandler::CREDENTIAL_FIELD => $credentialJson,
        ]));
        // The controller binds the re-resolved principal before the
        // handler runs; direct handler calls bind it the same way.
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::bind($request, self::PRINCIPAL);

        return $request;
    }

    /** A request carrying a started session with the test session id. */
    private function withSession(Request $request): Request
    {
        $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
        $storage->setId(self::SESSION);
        $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
        $session->start();
        $request->setSession($session);

        return $request;
    }

    /** @return array<string, mixed> */
    private function documentOf(\Symfony\Component\HttpFoundation\Response $response): array
    {
        self::assertSame(200, $response->getStatusCode(), $response->getContent());
        $document = json_decode((string) $response->getContent(), true);
        self::assertIsArray($document);

        return $document;
    }

    /**
     * The software authenticator's attestation (webauthn.create): a
     * none-format attestation object over the built authenticator data.
     */
    private function attestation(string $challengeB64, string $credentialId, string $origin = 'https://'.self::HOST, string $rpId = self::HOST): string
    {
        $authData = WebAuthnTestVectors::authDataForAttestation($rpId, $credentialId, self::X_HEX, self::Y_HEX);
        $clientDataJson = WebAuthnTestVectors::clientDataJson('webauthn.create', $challengeB64, $origin);
        $attestationObject = WebAuthnTestVectors::cborMap([
            WebAuthnTestVectors::cborText('fmt') => WebAuthnTestVectors::cborText('none'),
            WebAuthnTestVectors::cborText('attStmt') => WebAuthnTestVectors::cborMap([]),
            WebAuthnTestVectors::cborText('authData') => WebAuthnTestVectors::cborBytes($authData),
        ]);

        return WebAuthnTestVectors::publicKeyJson($credentialId, $clientDataJson, $attestationObject);
    }

    /**
     * The software authenticator's assertion (webauthn.get): the ES256
     * signature over authenticator data and the client data hash.
     */
    private function assertion(string $challengeB64, string $credentialId, int $signCount, string $origin = 'https://'.self::HOST, string $rpId = self::HOST, bool $noUserVerification = false): string
    {
        $clientDataJson = WebAuthnTestVectors::clientDataJson('webauthn.get', $challengeB64, $origin);
        $authData = WebAuthnTestVectors::authDataForAssertion($rpId, $signCount, $noUserVerification);
        $signature = WebAuthnTestVectors::es256Sign($authData.hash('sha256', $clientDataJson, true));

        return WebAuthnTestVectors::publicKeyJson($credentialId, $clientDataJson, null, $authData, $signature);
    }
}

/**
 * The minimal software-authenticator builder: the binary object
 * encoder, authenticator data, the none attestation object, the
 * signature signer, and the PublicKeyCredential JSON the browser
 * delivers.
 */
final class WebAuthnTestVectors
{
    public static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function clientDataJson(string $type, string $challengeB64, string $origin): string
    {
        return (string) json_encode([
            'type' => $type,
            'challenge' => $challengeB64,
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_UNESCAPED_SLASHES);
    }

    public static function authDataForAttestation(string $rpId, string $credentialId, string $xHex, string $yHex): string
    {
        $authData = hash('sha256', $rpId, true);
        $authData .= "\x45"; // UP | UV | AT
        $authData .= pack('N', 1);
        $authData .= str_repeat("\x00", 16); // the attested credential's zero id space
        $authData .= pack('n', strlen($credentialId)).$credentialId;
        // The credential public key map: the Ec2 P-256 pair for the
        $authData .= self::cborMap([
            "\x01" => "\x02",
            "\x03" => "\x26", // -7
            "\x20" => "\x01", // -1
            "\x21" => self::cborBytes(hex2bin($xHex)), // -2
            "\x22" => self::cborBytes(hex2bin($yHex)), // -3
        ]);

        return $authData;
    }

    public static function authDataForAssertion(string $rpId, int $signCount, bool $noUserVerification = false): string
    {
        $flags = $noUserVerification ? "\x01" : "\x05";

        return hash('sha256', $rpId, true).$flags.pack('N', $signCount);
    }

    public static function cborBytes(string $bytes): string
    {
        $len = strlen($bytes);
        if ($len < 24) {
            return "\x40".chr($len).$bytes;
        }
        if ($len < 256) {
            return "\x58".chr($len).$bytes;
        }

        return "\x59".pack('n', $len).$bytes;
    }

    public static function cborText(string $text): string
    {
        $len = strlen($text);
        if ($len < 24) {
            return chr(0x60 | $len).$text;
        }

        return "\x78".chr($len).$text;
    }

    /** @param array<string, string> $pairs string keys and string values, both already binary encoded */
    public static function cborMap(array $pairs): string
    {
        $count = count($pairs);
        $head = $count < 24 ? chr(0xa0 | $count) : "\xb8".chr($count);

        $out = $head;
        foreach ($pairs as $key => $value) {
            $out .= (string) $key.(string) $value;
        }

        return $out;
    }

    public static function es256Sign(string $data): string
    {
        $key = openssl_pkey_get_private(self::PEM);
        self::assert($key !== false, 'the test key did not load');
        $der = '';
        self::assert(openssl_sign($data, $der, $key, OPENSSL_ALGO_SHA256), 'openssl_sign failed');
        // The signature wire form is the raw r||s pair, not DER.
        return ECSignature::fromAsn1($der, 64);
    }

    private const PEM = <<<'PEM'
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpdlaMirrhkVzgg+V
        p3EesmG5kdk9JGSFCdsCKRfAoGihRANCAAQ1ON9MKt7kK6TmiUZSJgBYteLUhFZp
        UC23h7zmVfapK7VxOBy3IPFJiWQRW6s3CqVQbHWAHlOTW2tEnTUm1pbn
        -----END PRIVATE KEY-----
        PEM;

    private static function assert(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new \RuntimeException($message);
        }
    }

    public static function publicKeyJson(string $credentialId, string $clientDataJson, ?string $attestationObject, ?string $authData = null, ?string $signature = null): string
    {
        $payload = [
            'id' => self::base64Url($credentialId),
            'rawId' => self::base64Url($credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::base64Url($clientDataJson),
            ],
        ];
        if ($attestationObject !== null) {
            $payload['response']['attestationObject'] = self::base64Url($attestationObject);
        }
        if ($authData !== null) {
            $payload['response']['authenticatorData'] = self::base64Url($authData);
        }
        if ($signature !== null) {
            $payload['response']['signature'] = self::base64Url($signature);
        }

        return (string) json_encode($payload, JSON_UNESCAPED_SLASHES);
    }
}

/**
 * The in-memory stand-in for the registry's Redis surface: the commands
 * the credential registry issues (GET, SETEX, KEYS) and the pipelined
 * batch it reads records through, backed by one string table.
 *
 * The batch arm models the real client's answer: the queued reads run
 * against the table and answer in queue order. A batch queuing no read
 * or a command the store cannot answer throws, so a lookup shape this
 * double no longer models can never pass the suite as a silent no-op.
 */
final class FakeWebAuthnRedis implements \Predis\ClientInterface
{
    /** @var array<string, string> */
    public array $values = [];

    /** Set members in insertion order: index key => member keys. */
    public array $sets = [];

    /** Every command the registry issued (upper-cased), for shape asserts. */
    public array $commands = [];

    /** Keys the store answers null for: the record gone between the
     * discovery call and the batched read.
     *
     * @var array<string, true>
     */
    public array $expired = [];

    /** The pipelined batches served, one per lookup. */
    public int $batches = 0;

    /** The keys of the most recent batch, in queue order.
     *
     * @var list<string>
     */
    public array $batchedKeys = [];

    /** The calls no arm answered. */
    public int $unservedCommands = 0;

    /** SET NX lock keys (the reconcile cadence), kept out of $values
     * so the record SCAN never sees a lock as a credential. */
    public array $locks = [];

    /** When true, SCAN answers a non-array garbage reply (a failed
     * walk must never be treated as a complete empty keyspace). */
    public bool $scanMalformed = false;

    public function setex($key, $ttl, $value)
    {
        $this->values[(string) $key] = (string) $value;

        return true;
    }

    public function get($key)
    {
        $key = (string) $key;
        if (isset($this->expired[$key])) {
            return null;
        }

        return $this->values[$key] ?? null;
    }

    public function keys($pattern)
    {
        $this->commands[] = 'KEYS';
        $regex = '/^'.strtr(preg_quote((string) $pattern, '/'), ['\\*' => '.*', '\\?' => '.']).'$/';

        return array_values(array_filter(array_keys($this->values), static fn ($key) => preg_match($regex, (string) $key) === 1));
    }

    /** sadd: idempotent membership in insertion order. */
    public function sadd($key, ...$members): int
    {
        $this->commands[] = 'SADD';
        $key = (string) $key;
        $this->sets[$key] ??= [];
        $added = 0;
        foreach ($members as $member) {
            $member = (string) $member;
            if (!\in_array($member, $this->sets[$key], true)) {
                $this->sets[$key][] = $member;
                ++$added;
            }
        }

        return $added;
    }

    /** smembers: the members in insertion order, [] for a missing set. */
    public function smembers($key): array
    {
        $this->commands[] = 'SMEMBERS';
        return $this->sets[(string) $key] ?? [];
    }

    /** expire: served (the index TTL refresh), presence-aware. */
    public function expire($key, $ttl): int
    {
        $this->commands[] = 'EXPIRE';
        return isset($this->values[(string) $key]) || isset($this->sets[(string) $key]) ? 1 : 0;
    }

    /**
     * The cursor pass in one shot: the first reply carries the terminal
     * cursor and every value key matching the pattern, in insertion
     * order. The steady-state fake never simulates a multi-batch pass,
     * and the registry's loop accepts a terminal first reply exactly
     * like a small real scan.
     */
    public function scan($cursor, $options = []): array
    {
        $this->commands[] = 'SCAN';
        if ($this->scanMalformed) {
            throw new \RuntimeException('fixture: SCAN backend failure');
        }
        $pattern = (string) ($options['MATCH'] ?? '*');
        $regex = '/^'.strtr(preg_quote($pattern, '/'), ['\\*' => '.*', '\\?' => '.']).'$/';
        $matched = array_values(array_filter(array_keys($this->values), static fn ($key) => preg_match($regex, (string) $key) === 1));

        return ['0', $matched];
    }

    /**
     * The batched read: the callable queues reads on the pipeline and
     * the batch answers them in queue order, the way the real client
     * answers a pipelined batch.
     */
    public function pipeline(...$arguments): array
    {
        $callable = $arguments[0] ?? null;
        if (!\is_callable($callable)) {
            throw new \RuntimeException('the registry fixture serves the callable pipeline form only');
        }
        $pending = new FakeWebAuthnPipeline();
        $callable($pending);
        if ($pending->keys === []) {
            throw new \RuntimeException('the registry fixture refuses a batch that queues no read');
        }
        $this->batches++;
        $this->batchedKeys = $pending->keys;
        $responses = [];
        foreach ($pending->keys as $key) {
            $responses[] = $this->get($key);
        }

        return $responses;
    }

    public function getProfile(): \Predis\Profile\ProfileInterface
    {
        throw new \RuntimeException('the registry fixture never resolves a profile');
    }

    public function getCommandFactory(): \Predis\Command\FactoryInterface
    {
        throw new \RuntimeException('the registry fixture never resolves a command factory');
    }

    public function getOptions(): \Predis\Configuration\OptionsInterface
    {
        return new \Predis\Configuration\Options();
    }

    public function connect(): void
    {
    }

    public function disconnect(): void
    {
    }

    public function isConnected(): bool
    {
        return true;
    }

    public function getConnection(): \Predis\Connection\ConnectionInterface
    {
        throw new \RuntimeException('the registry fixture never exposes a connection');
    }

    public function createCommand($method, $arguments = []): \Predis\Command\CommandInterface
    {
        throw new \RuntimeException('unsupported: '.$method);
    }

    public function executeCommand(\Predis\Command\CommandInterface $command): mixed
    {
        return $this->__call($command->getId(), $command->getArguments());
    }

    public function __call($method, $arguments): mixed
    {
        $this->commands[] = strtoupper((string) $method);

        return match (strtoupper((string) $method)) {
            'GET' => $this->get((string) ($arguments[0] ?? '')),
            'SETEX' => $this->setex((string) ($arguments[0] ?? ''), (int) ($arguments[1] ?? 0), (string) ($arguments[2] ?? '')),
            'KEYS' => $this->keys((string) ($arguments[0] ?? '')),
            'SADD' => $this->sadd((string) ($arguments[0] ?? ''), ...array_slice($arguments, 1)),
            'SMEMBERS' => $this->smembers((string) ($arguments[0] ?? '')),
            'EXPIRE' => $this->expire((string) ($arguments[0] ?? ''), (int) ($arguments[1] ?? 0)),
            'SCAN' => $this->scan($arguments[0] ?? '0', \is_array($arguments[1] ?? null) ? $arguments[1] : []),
            'EVAL' => $this->evalCounterCas($arguments),
            'SET' => $this->setNxOrSet($arguments),
            'DEL' => $this->fakeDel(\array_map(strval(...), $arguments)),
            default => $this->unserved($method),
        };
    }

    /** DEL: drop string values and lock keys; returns how many went away. */
    private function fakeDel(array $keys): int
    {
        $gone = 0;
        foreach ($keys as $key) {
            if (isset($this->values[$key])) {
                unset($this->values[$key]);
                ++$gone;
            }
            if (isset($this->locks[$key])) {
                unset($this->locks[$key]);
                ++$gone;
            }
            if (isset($this->sets[$key])) {
                unset($this->sets[$key]);
                ++$gone;
            }
        }

        return $gone;
    }

    /**
     * The SET command as the registry uses it: `SET key value NX EX t`
     * for the reconcile lock (null on a held lock, 'OK' on the claim)
     * plus a plain two-argument set fallback.
     *
     * @param list<mixed> $arguments
     */
    private function setNxOrSet(array $arguments)
    {
        $key = (string) ($arguments[0] ?? '');
        $value = (string) ($arguments[1] ?? '');
        $options = $arguments[2] ?? null;
        $isNx = \is_array($options) && \in_array('NX', $options, true);
        if ($isNx && (isset($this->locks[$key]) || isset($this->values[$key]))) {
            return null;
        }
        if ($isNx) {
            $this->locks[$key] = $value;

            return 'OK';
        }
        $this->values[$key] = $value;

        return 'OK';
    }

    /**
     * The counter-rollback CAS in PHP, mirroring the registry's Lua:
     * one atomic read-compare-write over the stored JSON (an unreadable
     * prior falls through to the overwrite, like the script's failed
     * cjson decode). Called through the executor's Predis shape:
     * eval($script, $numKeys, $key, ...$argv).
     *
     * @param list<mixed> $arguments
     */
    private function evalCounterCas(array $arguments): int
    {
        // eval($script, $numKeys, recordKey, indexKey, ttl, json,
        // counter, indexTtl, hasPrincipal) — the counter CAS and the
        // index membership in ONE transaction, mirroring the registry.
        $key = (string) ($arguments[2] ?? '');
        $indexKey = (string) ($arguments[3] ?? '');
        $ttl = (int) ($arguments[4] ?? 0);
        $json = (string) ($arguments[5] ?? '');
        $incoming = (int) ($arguments[6] ?? 0);
        $hasPrincipal = (string) ($arguments[8] ?? '0') === '1';
        $existing = $this->get($key);
        if (\is_string($existing) && $existing !== '') {
            $decoded = json_decode($existing, true);
            if (\is_array($decoded) && isset($decoded['counter']) && is_numeric($decoded['counter'])
                && $incoming < (int) $decoded['counter']) {
                return 0;
            }
        }
        $this->setex($key, $ttl, $json);
        if ($hasPrincipal) {
            $this->sets[$indexKey] ??= [];
            if (!\in_array($key, $this->sets[$indexKey], true)) {
                $this->sets[$indexKey][] = $key;
            }
        }

        return 1;
    }

    /** An unmodelled call: no arm answers it, and the count shows it. */
    private function unserved($method): mixed
    {
        $this->unservedCommands++;

        return null;
    }
}

/**
 * The queue a batched registry read runs on: it records the keys the
 * registry queues and refuses every command that is not the read the
 * registry batches, so a shape the double does not model fails loudly.
 */
final class FakeWebAuthnPipeline
{
    /** @var list<string> */
    public array $keys = [];

    public function get($key): self
    {
        $this->keys[] = (string) $key;

        return $this;
    }

    public function __call($method, $arguments): mixed
    {
        throw new \RuntimeException('the registry fixture batches reads only, saw: '.$method);
    }
}
