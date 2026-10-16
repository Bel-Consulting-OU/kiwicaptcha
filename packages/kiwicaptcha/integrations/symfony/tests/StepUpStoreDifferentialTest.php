<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\StepUpStoreDifferentialHarness;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The randomized differential lane of the two step-up stores over the
 * emulated Predis client. One action generator drives the array store
 * and the Redis store through the same seeded legal sequence, and
 * every observable answer must agree after every action. The property
 * code lives in the shared harness fixture, so the real-Predis lane
 * (StepUpStoreDifferentialRealPredisTest) runs the identical engine.
 *
 * Three store divergences the sweep surfaced are eliminated in src
 * with the parity demanded here. The supersede script requires the
 * exact lineage in both directions; both stores write the superseded
 * terminal inside the supersede transaction; both stores answer
 * lockout deadlines in epoch seconds. This file keeps a raw-state
 * parity pin for the supersede terminal, and the real-Predis lane
 * pins the epoch-second lockout contract against the live server.
 */
final class StepUpStoreDifferentialTest extends TestCase
{
    private const BASE_NOW = 1700000000;

    private const PREFIX = '{kiwi:diff}:stepup:';

    public static function providerSeeds(): \Generator
    {
        foreach (range(1, 20) as $seed) {
            yield 'seed '.$seed => [$seed];
        }
    }

    /**
     * The randomized property: for the same legal operation sequence,
     * both stores answer the same observable outcome after every
     * action, or the same equivalent refusal. A failure message names
     * the seed and the step, so the run reproduces exactly.
     */
    #[DataProvider('providerSeeds')]
    public function testBothStoresAnswerTheSameObservableSequence(int $seed): void
    {
        $harness = $this->harness();

        $harness->runSequence($seed, 40);
    }

    /**
     * Divergence pin one: the forged escalation child. The child names
     * a foreign parent link but inherits the exact parent expiry. The
     * array store refuses the whole transaction; the Redis script
     * accepts it and repoints the family index at the forged child.
     */
    public function testAForgedChildParentLinkRefusesOnBothStores(): void
    {
        [$arrayStore, $redisStore] = $this->stores();
        $digest = '5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f';
        $parent = StepUpDemand::mint('forgenparentid00000000001', 'login', null, null, 'decision-1', self::BASE_NOW, 600);
        $arrayStore->createDemand($parent, 600);
        $redisStore->createDemand($parent, 600);
        $forged = StepUpDemand::mint('forgenchildid00000000001', 'login', null, null, 'decision-1', self::BASE_NOW, 600, StepUpOperationBindingKind::None, $digest, null, null, false, 'foreignparentid000000001');
        self::assertSame($parent->expiresAt, $forged->expiresAt, 'the forged child inherits the exact parent expiry');

        $a = $arrayStore->supersedeDemandWithChild($parent->id, $forged);
        $r = $redisStore->supersedeDemandWithChild($parent->id, $forged);

        self::assertNull($a, 'the array store refuses the forged parent link');
        self::assertNull($r, 'the Redis script refuses it too: the lineage is exact in both directions, so a forged link can never sit in the family index');
        self::assertNull($redisStore->demandIdForFamily($forged->operationDigest), 'no family index entry points at the refused child');
        self::assertNull($redisStore->readDemand($forged->id), 'the refused child was never written');
        self::assertFalse((bool) $redisStore->readDemand($parent->id)?->superseded(), 'the parent stays live when the child refuses');
    }

    /**
     * Divergence pin two: the superseded parent state field. The
     * supersede of a finalizing parent answers a record whose state
     * field differs by store. The marker gates every transition on
     * both, so the follow-up superseded settlement lands only where
     * the state field was kept.
     */
    public function testTheSupersededTerminalIsWrittenInsideTheSupersedeOnBothStores(): void
    {
        [$arrayStore, $redisStore, $fake] = $this->stores();
        $parentId = 'statefielparentid0000001';
        $childId = 'statefielchildid00000001';
        $parent = StepUpDemand::mint($parentId, 'login', null, null, 'decision-1', self::BASE_NOW, 600);
        $arrayStore->createDemand($parent, 600);
        $redisStore->createDemand($parent, 600);
        self::assertNotNull($arrayStore->completeDemand($parentId, self::BASE_NOW, 600));
        self::assertNotNull($redisStore->completeDemand($parentId, self::BASE_NOW, 600));
        self::assertNotNull($arrayStore->claimDemandFinalization($parentId, self::BASE_NOW, 30));
        self::assertNotNull($redisStore->claimDemandFinalization($parentId, self::BASE_NOW, 30));
        $child = $arrayStore->readDemand($parentId)->spawnChild($childId, self::BASE_NOW, 'decision-2');

        $a = $arrayStore->supersedeDemandWithChild($parentId, $child);
        $r = $redisStore->supersedeDemandWithChild($parentId, $child);

        self::assertNotNull($a);
        self::assertNotNull($r);
        // Raw-state parity: the whole terminal transition is the one
        // supersede transaction on both stores. The parent carries the
        // superseded state, the stamp and the child link together; no
        // follow-up settlement exists on either lane.
        self::assertSame(StepUpDemandState::Superseded, $a->state, 'the array store writes the superseded terminal');
        self::assertSame(StepUpDemandState::Superseded, $r->state, 'the Redis script writes the superseded terminal in the same transaction');
        self::assertSame($childId, $a->supersededByDemandId);
        self::assertSame($childId, $r->supersededByDemandId, 'the marker itself agrees');
        // Each stamp is that store's own supersede-time: the array
        // store stamps its injected clock, the Redis script stamps the
        // server clock it owns. The stores never share a clock, so the
        // parity claim is the stamp provenance, not one shared value.
        self::assertSame(self::BASE_NOW, $a->stateAt, 'the array store stamps its own clock');
        self::assertSame((int) floor($fake->timeMs() / 1000), $r->stateAt, 'the Redis script stamps the server clock');

        self::assertNull($arrayStore->settleDemandFinalization($parentId, StepUpDemandState::Superseded, self::BASE_NOW), 'the array store: the terminal already stands, a second settle answers null');
        self::assertNull($redisStore->settleDemandFinalization($parentId, StepUpDemandState::Superseded, self::BASE_NOW), 'the Redis store: the terminal already stands, a second settle answers null');
        self::assertNull($arrayStore->settleDemandFinalization($parentId, StepUpDemandState::Authorized, self::BASE_NOW), 'the superseded parent authorizes through nothing on the array store');
        self::assertNull($redisStore->settleDemandFinalization($parentId, StepUpDemandState::Authorized, self::BASE_NOW), 'the superseded parent authorizes through nothing on the Redis store');
    }

    /**
     * The scoped completion history, pinned for parity. The escalation
     * index is keyed per (session hash, scope) pair on both stores. One
     * scope's completion must never overwrite the history another scope
     * of the same session earned, and every probe must answer
     * identically on the array store and the Redis script path.
     */
    public function testTheScopedCompletionHistoryAgreesOnBothStores(): void
    {
        [$arrayStore, $redisStore, $fake] = $this->stores();
        $fake->setTimeMs(self::BASE_NOW * 1000);
        $sessionId = 'differential-session-00000001';
        $binding = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::sessionHash($sessionId);

        $checkoutDemand = 'paritydemchk0000000000001';
        $loginDemand = 'paritydemlgn0000000000001';
        $scenario = static function (ArrayStepUpChallengeStore|RedisStepUpChallengeStore $store) use ($binding, $checkoutDemand, $loginDemand, $sessionId): array {
            $totp = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
                $store instanceof ArrayStepUpChallengeStore ? 'paritychalchkarray00001' : 'paritychalchkredis00001',
                \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::Totp,
                '00112233445566778899aabbccddeeff',
                null,
                'checkout',
                null,
                'post_solve_step_up_required',
                self::BASE_NOW,
                600,
                5,
                null,
                null,
                $sessionId,
                false,
                false,
                null,
                $checkoutDemand,
            );
            // The demand stands before its challenge: admission is the
            // only door into the store for a demand-bound challenge, and
            // it refuses a demand that is not there yet. Each challenge
            // answers its own demand, the session, scope and principal
            // identity the admission and the completion both judge. The
            // demand is minted under the lineage its completion will
            // present (the session binding here): the completion is held
            // to the stored lineage, so the history identity is fixed
            // when the demand is raised.
            $store->createDemand(StepUpDemand::mint($checkoutDemand, 'checkout', $binding, null, null, self::BASE_NOW, 600, \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind::None, '', null, null, false, null, null, null, $binding), 600);
            $store->createAdmittedChallenge($totp, 600);
            $email = \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::begin(
                $store instanceof ArrayStepUpChallengeStore ? 'paritychalemlarray0001' : 'paritychalemlredis0001',
                \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind::EmailOtp,
                '00112233445566778899aabbccddeeff',
                null,
                'login',
                null,
                'post_solve_step_up_required',
                self::BASE_NOW,
                600,
                5,
                str_repeat('a', 64),
                null,
                $sessionId,
                false,
                false,
                null,
                $loginDemand,
            );
            $store->createDemand(StepUpDemand::mint($loginDemand, 'login', $binding, null, null, self::BASE_NOW, 600, \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind::None, '', null, null, false, null, null, null, $binding), 600);
            $store->createAdmittedChallenge($email, 600);

            $answers = [];
            $answers['before'] = [
                $store->completedFactorOf($binding, null, 'checkout', self::BASE_NOW),
                $store->completedFactorOf($binding, null, 'login', self::BASE_NOW),
            ];
            $totpDone = $store->completeFactor($totp->id, $checkoutDemand, $binding, self::BASE_NOW, $totp->sessionHash, 'checkout', $binding);
            $answers['afterTotp'] = [
                $totpDone !== null,
                $store->completedFactorOf($binding, null, 'checkout', self::BASE_NOW),
                $store->completedFactorOf($binding, null, 'login', self::BASE_NOW),
            ];
            $emailDone = $store->completeFactor($email->id, $loginDemand, $binding, self::BASE_NOW + 10, $email->sessionHash, 'login', $binding);
            $answers['afterEmail'] = [
                $emailDone !== null,
                $store->completedFactorOf($binding, null, 'checkout', self::BASE_NOW + 10),
                $store->completedFactorOf($binding, null, 'login', self::BASE_NOW + 10),
                $store->completedFactorOf($binding, null, 'checkout', self::BASE_NOW + 601),
                $store->completedFactorOf($binding, null, 'login', self::BASE_NOW + 601),
            ];

            return $answers;
        };

        $a = $scenario($arrayStore);
        $r = $scenario($redisStore);

        // The ladder: no history, the totp completion recorded under its
        // scope alone, then the email completion recorded under its own
        // scope without touching the checkout history. Every answer,
        // including the per-scope expiries, is identical.
        self::assertSame([null, null], $a['before']);
        self::assertSame([true, 'totp', null], $a['afterTotp']);
        self::assertSame([true, 'totp', 'email_otp', null, null], $a['afterEmail']);
        self::assertSame($a, $r, 'the scoped completion history diverged between the stores');

        // The raw Redis shape: one key per (session hash, scope) pair,
        // the scope carried as its digest, each value prefixed with the
        // stored scope. The key carries the whole history identity:
        // lineage, the principal digest (the anonymous bucket here, since
        // these demands name no principal) and the scope digest. The
        // value carries the scope, the family, the rank, the
        // authorization window and the completion stamp.
        $anon = str_repeat('0', 64);
        // The completion stamp is the Redis server clock the script reads,
        // never the caller's argument: the fake's server clock stands at
        // self::BASE_NOW for both completions, which is exactly the
        // divergence this differential exists to pin.
        foreach (['checkout' => ['totp', self::BASE_NOW], 'login' => ['email_otp', self::BASE_NOW]] as $scope => [$family, $stamp]) {
            $raw = $fake->strings['{kiwi:diff}:stepup:emdone:'.$binding.':'.$anon.':'.hash('sha256', $scope)] ?? null;
            self::assertSame($scope.'|'.$family.'|'.\BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement::rankOf($family).'|'.(self::BASE_NOW + 600).'|'.$stamp, $raw, 'the '.$scope.' marker sits under its pair key with the stored value');
        }
    }

    /**
     * The standard-lane harness: the array store on the injected clock
     * box, the Redis store over the emulated client whose server clock
     * mirrors the same box, one shared engine.
     *
     * @return array{0: StepUpStoreDifferentialHarness}
     */
    private function harness(): StepUpStoreDifferentialHarness
    {
        [$arrayStore, $redisStore, $fake, $clock] = $this->stores();

        return new StepUpStoreDifferentialHarness(
            $arrayStore,
            $redisStore,
            $fake,
            $clock,
            StepUpStoreDifferentialHarness::LANE_STANDARD,
            self::PREFIX,
            static function (bool $condition, string $message): void {
                self::assertTrue($condition, $message);
            },
        );
    }

    /**
     * @return array{0: ArrayStepUpChallengeStore, 1: RedisStepUpChallengeStore, 2: FakePredisClient, 3: \stdClass}
     */
    private function stores(): array
    {
        $clock = new \stdClass();
        $clock->now = self::BASE_NOW;
        $fake = new FakePredisClient();
        $arrayStore = new ArrayStepUpChallengeStore(static fn (): int => $clock->now);
        $redisStore = new RedisStepUpChallengeStore($fake, self::PREFIX);

        return [$arrayStore, $redisStore, $fake, $clock];
    }
}
