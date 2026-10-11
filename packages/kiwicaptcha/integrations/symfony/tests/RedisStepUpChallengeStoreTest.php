<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The Redis step-up store over the emulated Predis client: the exact
 * command surface (SET EX NX records, GETDEL consumption, the attempt
 * and window and replay-guard scripts) with real key shapes under the
 * deployment namespace family. The atomic factor completion is
 * exercised over its two-key script: identity, state, liveness and
 * binding are judged in one step. The winner consumes the challenge
 * and completes the demand together, and the escalation marker lands
 * under the session hash and scope.
 */
final class RedisStepUpChallengeStoreTest extends TestCase
{
    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const DEMAND_ID = 'demandid0000000000000000000';

    private const SESSION_ID = 'kernel-test-session-00000001';

    private FakePredisClient $redis;

    private RedisStepUpChallengeStore $store;

    protected function setUp(): void
    {
        $this->redis = new FakePredisClient();
        $this->store = new RedisStepUpChallengeStore($this->redis, '{kiwi:test-ns}:stepup:');
    }

    public function testThePrefixMustBeAHashTaggedFamily(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RedisStepUpChallengeStore($this->redis, 'stepup:');
    }

    public function testRecordsAreSingleUse(): void
    {
        $challenge = $this->challenge('aaaaaaaaaaaaaaaaaaaaaaa');
        $this->store->create($challenge, 300);
        $key = '{kiwi:test-ns}:stepup:challenge:aaaaaaaaaaaaaaaaaaaaaaa';
        self::assertArrayHasKey($key, $this->redis->strings);
        self::assertStringContainsString('"principal":"'.self::PRINCIPAL.'"', $this->redis->strings[$key]);
        self::assertArrayHasKey($key, $this->redis->expirations, 'the record carries its TTL');

        self::assertNotNull($this->store->read('aaaaaaaaaaaaaaaaaaaaaaa'));
        self::assertNotNull($consumed = $this->store->consume('aaaaaaaaaaaaaaaaaaaaaaa'));
        self::assertSame(self::PRINCIPAL, $consumed->principalPseudonym);
        self::assertNull($this->store->read('aaaaaaaaaaaaaaaaaaaaaaa'), 'the consumed record is gone');
        self::assertNull($this->store->consume('aaaaaaaaaaaaaaaaaaaaaaa'), 'a second consumption answers null');
    }

    public function testTheAttemptScriptCountsAndRemovesAtTheCap(): void
    {
        $id = 'bbbbbbbbbbbbbbbbbbbbbbb';
        $this->store->create($this->challenge($id), 300);
        self::assertSame(1, $this->store->recordFailure($id, 3));
        self::assertSame(2, $this->store->recordFailure($id, 3));
        self::assertSame(0, $this->store->recordFailure($id, 3), 'the cap removes the record');
        self::assertSame(-1, $this->store->recordFailure($id, 3), 'a missing record answers -1');
    }

    public function testTheBeginWindowCountsPerPrincipal(): void
    {
        self::assertSame(1, $this->store->countBegin(self::PRINCIPAL, 900));
        self::assertSame(2, $this->store->countBegin(self::PRINCIPAL, 900));
        $other = 'ffffffffffffffffffffffffffffffff';
        self::assertSame(1, $this->store->countBegin($other, 900));
        self::assertArrayHasKey('{kiwi:test-ns}:stepup:begins:'.self::PRINCIPAL, $this->redis->counters);
    }

    public function testTheTotpStateIsDurableAndReplayGuarded(): void
    {
        $this->store->saveTotpSecret(self::PRINCIPAL, 'secret-bytes');
        self::assertSame('secret-bytes', $this->store->findTotpSecret(self::PRINCIPAL));
        self::assertNull($this->store->findTotpSecret('ffffffffffffffffffffffffffffffff'));
        self::assertArrayNotHasKey('{kiwi:test-ns}:stepup:totp:secret:'.self::PRINCIPAL, $this->redis->expirations, 'the enrollment carries no TTL');

        self::assertTrue($this->store->markTotpStep(self::PRINCIPAL, 1000, 90));
        self::assertFalse($this->store->markTotpStep(self::PRINCIPAL, 1000, 90), 'the same step is a replay');
        self::assertFalse($this->store->markTotpStep(self::PRINCIPAL, 999, 90), 'an earlier step is a replay');
        self::assertTrue($this->store->markTotpStep(self::PRINCIPAL, 1001, 90), 'a strictly newer step wins');
    }

    public function testTheAtomicFactorCompletionConsumesBothRecordsTogether(): void
    {
        $id = 'ccccccccccccccccccccccc';
        $this->store->create($this->challenge($id), 300);
        $this->store->createDemand($this->demand(self::DEMAND_ID, null), 300);
        // The emulated challenge helper binds no session; drive the
        // stateless secret hash so the script's binding lane runs.
        $challenge = $this->store->read($id);
        self::assertNotNull($challenge);
        $secretHash = (string) $challenge->clientSecretHash;

        $completion = $this->store->completeFactor($id, self::DEMAND_ID, $secretHash, 1700000000, FactorRequirement::EMAIL_OTP, null);

        self::assertNotNull($completion, 'the atomic transition answers the completion');
        self::assertSame($id, $completion->challengeId);
        self::assertSame(self::DEMAND_ID, $completion->demandId);
        self::assertSame(self::PRINCIPAL, $completion->verifiedSubjectPseudonym, 'the verified subject derives from the stored challenge');
        self::assertSame(StepUpChallengeKind::EmailOtp, $completion->kind);
        self::assertNull($this->store->read($id), 'the challenge is consumed');
        $demand = $this->store->readDemand(self::DEMAND_ID);
        self::assertNotNull($demand, 'the completed demand stays as the consumption proof');
        self::assertTrue($demand->state === StepUpDemandState::Completed, 'the demand completed in the same script');
        // A replay of the transition answers nothing.
        self::assertNull($this->store->completeFactor($id, self::DEMAND_ID, $secretHash, 1700000000, FactorRequirement::EMAIL_OTP, null), 'a spent pair completes no one twice');
    }

    public function testTheAtomicFactorCompletionRefusesACrossedOrUnboundPair(): void
    {
        $id = 'ddddddddddddddddddddddd';
        $this->store->create($this->challenge($id), 300);
        $this->store->createDemand($this->demand(self::DEMAND_ID, null), 300);
        $challenge = $this->store->read($id);
        self::assertNotNull($challenge);
        $secretHash = (string) $challenge->clientSecretHash;

        // The challenge names one demand exactly: another open demand
        // of the same scope completes nothing, and the pair survives.
        $other = $this->store->createDemand($this->demand('otherdemandid0000000000001', null), 300);
        self::assertNull($this->store->completeFactor($id, $other, $secretHash, 1700000000, FactorRequirement::EMAIL_OTP, null), 'a crossed pair completes nothing');
        self::assertNotNull($this->store->read($id), 'the crossed refusal consumed nothing');

        // The binding hash is judged inside the script: a browser that
        // presents no client secret completes nothing.
        self::assertNull($this->store->completeFactor($id, self::DEMAND_ID, str_repeat('b', 64), 1700000000, FactorRequirement::EMAIL_OTP, null), 'a wrong binding completes nothing');
        self::assertNotNull($this->store->read($id), 'the binding refusal consumed nothing');
        self::assertTrue($this->store->readDemand(self::DEMAND_ID)?->state->isOpen(), 'the binding refusal completed no demand');
    }

    public function testTheCompletionWritesTheEscalationMarkerForTheSession(): void
    {
        $id = 'eeeeeeeeeeeeeeeeeeeeeee';
        // A session-bound challenge writes the marker under its session
        // hash and scope; the stateless one writes none.
        $sessionChallenge = StepUpChallenge::begin(
            $id,
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            str_repeat('a', 64),
            null,
            'kernel-test-session-00000001',
            false,
            false,
            null,
            self::DEMAND_ID,
        );
        $this->store->create($sessionChallenge, 300);
        $binding = StepUpChallenge::sessionHash(self::SESSION_ID);
        $this->store->createDemand($this->demand(self::DEMAND_ID, $binding), 300);
        self::assertNotNull($this->store->completeFactor($id, self::DEMAND_ID, (string) $binding, 1700000000, FactorRequirement::EMAIL_OTP, $sessionChallenge->sessionHash));
        self::assertSame(FactorRequirement::EMAIL_OTP, $this->store->completedFactorOf((string) $binding, 'login', 1700000000), 'the marker names the completed factor');
        self::assertNull($this->store->completedFactorOf((string) $binding, 'signup', 1700000000), 'the marker is scoped');
        self::assertNull($this->store->completedFactorOf((string) $binding, 'login', 1700003001), 'the marker dies with the demand lifetime');
        self::assertNull($this->store->completedFactorOf(str_repeat('2', 64), 'login', 1700000000), 'an unmarked session answers nothing');
    }

    private function demand(string $id, ?string $sessionHash): StepUpDemand
    {
        return StepUpDemand::mint($id, 'login', $sessionHash, null, null, 1700000000, 300);
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
            1700000000,
            300,
            5,
            str_repeat('a', 64),
            null,
            null,
            false,
            false,
            null,
            self::DEMAND_ID,
        );
    }
}
