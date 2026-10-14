<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The Redis step-up store over a real Predis client against a live
 * redis-server: the exact deployment reply surface. The finding this
 * pins: the SET NX reply of a real client is a
 * Predis\Response\Status object, so a strict 'OK'/bool comparison
 * threw on every create() and every step-up begin failed closed. The
 * fake-client suite cannot see that shape; this leg boots the real
 * client (KC_REDIS_URL) and walks begin() through complete().
 */
final class RedisStepUpChallengeStoreRealPredisTest extends TestCase
{
    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    /** The leg clock: the real server second the store scripts judge. */
    private int $now = 0;

    private const PREFIX = '{kiwi:rpreal}:stepup:';

    private const MASTER = 'real-predis-leg-master-key-0123456789abcdef';

    private \Predis\Client $client;

    private RedisStepUpChallengeStore $store;

    private TotpStepUpHandler $handler;

    protected function setUp(): void
    {
        $url = getenv('KC_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('KC_REDIS_URL not set — real-Predis step-up leg skipped');
        }
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client($url, ['timeout' => 2.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $this->now = time();
        $this->store = new RedisStepUpChallengeStore($this->client, self::PREFIX);
        $this->handler = new TotpStepUpHandler(
            $this->store,
            new StepUpTicket(self::MASTER),
            'sha1', 6, 1, 300, 5, 100, 900, '/kiwi/step-up/complete',
            fn (): int => $this->now,
            self::MASTER,
        );
    }

    protected function tearDown(): void
    {
        // The leg owns only its hash-tagged family; the sweep never
        // reaches another suite's keys on the shared instance.
        if (!isset($this->client)) {
            return;
        }
        try {
            $keys = $this->client->keys(self::PREFIX.'*');
            if ($keys !== []) {
                $this->client->del(...$keys);
            }
        } catch (\Throwable) {
            // a dead instance must not fail the shutdown path
        }
    }

    public function testTheRealClientAnswersAStatusObjectThatTheStoreAccepts(): void
    {
        $reply = $this->client->set(self::PREFIX.'reply-shape', 'x', 'EX', 60, 'NX');
        self::assertInstanceOf(\Predis\Response\Status::class, $reply, 'a real Predis SET answers the Status object, the exact shape the store must normalize');
        self::assertSame('OK', (string) $reply);

        $refused = $this->client->set(self::PREFIX.'reply-shape', 'y', 'EX', 60, 'NX');
        self::assertNull($refused, 'a lost NX race answers nil and must stay a refusal');
        $this->client->del(self::PREFIX.'reply-shape');
    }

    public function testBeginThroughCompleteWorksEndToEndOnTheRealClient(): void
    {
        $base32 = $this->enrollFirstTime();
        $secretRaw = (string) TotpCode::base32Decode($base32);

        // The demand plane rides the walk: the begin binds its challenge
        // to the demand the finalizer minted, and the completed proof
        // settles authorized through it. The credit is the finalizer's
        // booking, never the handler's.
        $reporter = new SpyOutcomeReporter();
        $finalizer = new StepUpDemandFinalizer(
            $this->store,
            new StepUpCompletionCredit($reporter, self::MASTER),
            null,
            null,
            null,
            null,
            null,
            null,
            fn (): int => $this->now,
            self::MASTER,
        );
        $demandId = (string) $finalizer->mintLoginDemand('login', self::PRINCIPAL, null, 600);
        self::assertNotSame('', $demandId, 'the login demand persists through the real client');

        $response = $this->handler->begin(
            Request::create('https://captcha.example.com/kiwi/step-up/begin'),
            new StepUpContext(self::PRINCIPAL, null, 'login', null, 'post_solve_step_up_required', StepUpContext::MODE_JSON, false, $demandId),
        );
        self::assertSame(200, $response->getStatusCode(), 'begin() must persist its record through the real client');

        $body = json_decode((string) $response->getContent(), true);
        self::assertIsArray($body);
        $ticket = (string) $body['challenge'];
        // A sessionless begin is stateless: the challenge mints its
        // one-time client secret and the completion must present it
        // (exactly one binding per challenge).
        $clientSecret = (string) ($body['client_secret'] ?? '');
        self::assertNotSame('', $clientSecret, 'a stateless begin returns its one-time client secret');

        $code = TotpCode::at($secretRaw, TotpCode::stepOf($this->now), 'sha1', 6);
        $result = $this->handler->complete($this->completeRequest($ticket, $code, $clientSecret));
        self::assertSame(StepUpResultStatus::Succeeded, $result->status, 'the record was persisted and consumed end to end');
        $finalization = $finalizer->finalizeLogin($result, 'login');
        self::assertTrue($finalization->authorized, 'the completed proof settles authorized through its demand');
        self::assertCount(1, $reporter->reports, 'the authorized settlement books the completion credit exactly once');
    }

    public function testTheConsumedRecordStaysSingleUseOnTheRealClient(): void
    {
        $this->enrollFirstTime();
        $response = $this->handler->begin(
            Request::create('https://captcha.example.com/kiwi/step-up/begin'),
            new StepUpContext(self::PRINCIPAL, null, 'login', null, 'post_solve_step_up_required', StepUpContext::MODE_JSON),
        );
        $ticket = (string) json_decode((string) $response->getContent(), true)['challenge'];
        self::assertNotNull($this->store->read($this->challengeIdOf($ticket)), 'the record is readable before consumption');

        self::assertNotNull($this->store->consume($this->challengeIdOf($ticket)));
        $result = $this->handler->complete($this->completeRequest($ticket, '000000'));
        self::assertSame(StepUpResultStatus::Failed, $result->status);
        self::assertSame(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $result->failureCode, 'the GETDEL boundary holds over the real client');
    }

    public function testACollidingMintedIdStillRefusesAndThrows(): void
    {
        $id = 'ccccccccccccccccccccccc';
        $this->store->create($this->challenge($id), 300);
        $this->expectException(\RuntimeException::class);
        $this->store->create($this->challenge($id), 300);
    }

    public function testASupersededDemandCompletesNoChallengeOnTheRealClient(): void
    {
        // The finding this pins, on the real server: the escalation
        // supersede wrote the parent's child link but left its state
        // open, so the completion script's open-state gate passed and
        // the weak proof landed behind the family's back. The
        // supersession marker is now judged inside the completion
        // script itself. The clock is the wall clock: the supersede
        // script takes its liveness decision on the Redis server time,
        // so frozen fixture timestamps would read as expired.
        $now = time();
        $demandId = 'realsupersededdemand000001';
        $this->store->createDemand(
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand::mint($demandId, 'login', null, null, null, $now, 300),
            300,
        );
        $challenge = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
            'realsupersededchallenge00001',
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            $now,
            300,
            5,
            str_repeat('a', 64),
            null,
            null,
            false,
            false,
            null,
            $demandId,
        );
        $this->store->create($challenge, 300);
        $child = $this->store->readDemand($demandId)->spawnChild('realsupersededchild0000001', $now, 'decision-2');
        self::assertNotNull($this->store->supersedeDemandWithChild($demandId, $child), 'the escalation replaces the open parent');
        self::assertNull(
            $this->store->completeFactor('realsupersededchallenge00001', $demandId, (string) $challenge->clientSecretHash, $now + 1, null),
            'the superseded parent completes no challenge on the real server',
        );
        self::assertNull($this->store->claimDemandFinalization($demandId, $now + 2, 30), 'the superseded parent is never claimed for finalization');
    }

    public function testAReleasedReservationRefundsItsBudgetsOnTheRealClient(): void
    {
        // The finding this pins: the settle script reads the budget
        // counters off the reservation marker. A release that only
        // dropped the marker answered true while the spend stood, and
        // the freed capacity never served again.
        $dom = 'dom:'.str_repeat('b', 32);
        self::assertTrue($this->store->reserveMailQuota('real.0.1', [$dom, 'global:'], [1, 1000], 3600, 30));
        self::assertFalse($this->store->reserveMailQuota('real.0.2', [$dom, 'global:'], [1, 1000], 3600, 30), 'the second reservation passes the limit of one');
        self::assertTrue($this->store->releaseMailQuota('real.0.1'), 'the pre-handoff release refunds the counters');
        self::assertSame('0', $this->client->get(self::PREFIX.'emb:'.$dom), 'the released reservation left no spend behind');
        self::assertTrue($this->store->reserveMailQuota('real.0.3', [$dom, 'global:'], [1, 1000], 3600, 30), 'the freed capacity serves again on the real server');
        // A committed reservation never releases: the spend stands.
        $this->store->commitMailQuota('real.0.3');
        self::assertFalse($this->store->releaseMailQuota('real.0.3'), 'a committed reservation never releases');
        self::assertSame('1', $this->client->get(self::PREFIX.'emb:'.$dom), 'the committed spend stands');
    }

    public function testTheFactorHistoryNeverRegressesFromStrongToWeakOnTheRealClient(): void
    {
        // The monotonic prior-rank parse, on the real server: the ranked
        // index entry the webauthn completion wrote must survive the
        // later email_otp completion of the same (session, scope) pair.
        // The bug this pins: the prior-rank parse double-counted the
        // ranked shape to eight tokens, so the monotonic gate never read
        // the stored rank and the weaker completion overwrote the
        // stronger one, regressing the history to email_otp.
        $session = hash('sha256', 'sess');
        $scope = 'checkout';

        $strongDemand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            $scope,
            $session,
            null,
            null,
            $this->now,
            600,
        );
        $this->store->createDemand($strongDemand, 600);
        $strong = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            self::PRINCIPAL,
            null,
            $scope,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'ceremony-challenge'),
            'assertion',
            'sess',
            false,
            false,
            null,
            $strongDemand->id,
        );
        $this->store->create($strong, 600);
        self::assertNotNull(
            $this->store->completeFactor($strong->id, $strongDemand->id, $session, $this->now, $session, $scope),
            'the webauthn completion must land on the real server',
        );
        self::assertSame('webauthn', $this->store->completedFactorOf($session, $scope, $this->now));

        $weakDemand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            $scope,
            $session,
            null,
            null,
            $this->now,
            600,
        );
        $this->store->createDemand($weakDemand, 600);
        $weak = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            $scope,
            null,
            'step_up',
            $this->now,
            600,
            5,
            hash('sha256', 'code'),
            null,
            'sess',
            false,
            false,
            null,
            $weakDemand->id,
        );
        $this->store->create($weak, 600);
        self::assertNotNull(
            $this->store->completeFactor($weak->id, $weakDemand->id, $session, $this->now, $session, $scope),
            'the weaker email_otp completion still lands on the real server',
        );
        self::assertSame(
            'webauthn',
            $this->store->completedFactorOf($session, $scope, $this->now),
            'the weaker completion never regresses the monotonic factor history on the real server',
        );
    }

    /**
     * First-time totp enrollment under the enrollment gate: the handler
     * refuses it without a session-scoped step-up completed in the
     * enrolling session, so the test books that proof first (the
     * established-factor floor accepts the email_otp completion).
     */
    private function enrollFirstTime(): string
    {
        $this->store->markSessionStepUpSuccess('sess-real', self::PRINCIPAL, 'email_otp', 900, $this->now);

        return $this->handler->enroll(self::PRINCIPAL, 'sess-real');
    }

    private function challengeIdOf(string $ticket): string
    {
        $payload = (new StepUpTicket(self::MASTER))->verify($ticket, $this->now);
        self::assertIsArray($payload);

        return (string) $payload['challengeId'];
    }

    private function challenge(string $id): StepUpChallenge
    {
        return StepUpChallenge::begin(
            $id,
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            $this->now,
            300,
            5,
            str_repeat('a', 64),
        );
    }

    private function completeRequest(string $ticket, string $code, string $clientSecret = ''): Request
    {
        $fields = [
            TotpStepUpHandler::TICKET_FIELD => $ticket,
            TotpStepUpHandler::CODE_FIELD => $code,
        ];
        if ($clientSecret !== '') {
            $fields[\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::CLIENT_SECRET_FIELD] = $clientSecret;
        }
        $request = Request::create('https://captcha.example.com/kiwi/step-up/complete', 'POST', $fields);
        // The controller binds the re-resolved principal before the
        // handler runs; direct handler calls bind it the same way.
        \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding::bind($request, self::PRINCIPAL);

        return $request;
    }
}
