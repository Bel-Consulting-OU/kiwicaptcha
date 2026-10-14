<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandAdmissionRefused;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpEffectsJournal;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use PHPUnit\Framework\TestCase;

/**
 * The real-Redis differential lane of the step-up demand behaviours:
 * the array store against the Redis store backed by a live
 * redis-server (KC_REDIS_URL), never the FakePredisClient.
 *
 * The emulated lane (StepUpStoreDifferentialTest) can only see the
 * fake's reimplementation of the Lua. This lane runs the same inputs
 * against the live scripts, so a mistake shared by the Lua and its fake
 * can no
 * longer hide behind the differential.
 *
 * Every scenario drives both stores with the same inputs and asserts
 * the same observable outcome.
 *
 * The array store rides an injected clock, resynchronized to the wall
 * clock before every scenario. The Redis scripts judge their own
 * decisions on the Redis server time, which is that same wall clock.
 * The two stores therefore share one time domain without a fixture
 * boundary.
 */
final class StepUpStoreRealRedisDifferentialTest extends TestCase
{
    private const PREFIX = '{kiwi:realdiff}:stepup:';

    private const PRINCIPAL_A = '00112233445566778899aabbccddeeff';

    private const PRINCIPAL_B = 'ffeeddccbbaa99887766554433221100';

    private const SCOPE = 'checkout';

    private \Predis\Client $client;

    private ArrayStepUpChallengeStore $arrayStore;

    private RedisStepUpChallengeStore $redisStore;

    private \stdClass $clock;

    protected function setUp(): void
    {
        $url = getenv('KC_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('KC_REDIS_URL not set — real-Redis step-up differential lane skipped');
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
        $this->clock = new \stdClass();
        $this->clock->now = time();
        $this->arrayStore = new ArrayStepUpChallengeStore(fn (): int => $this->clock->now);
        $this->redisStore = new RedisStepUpChallengeStore($this->client, self::PREFIX);
        $this->sweep();
    }

    protected function tearDown(): void
    {
        if (!isset($this->client)) {
            return;
        }
        try {
            $this->sweep();
        } catch (\Throwable) {
            // a dead instance must not fail the shutdown path
        }
    }

    private function sweep(): void
    {
        $keys = $this->client->keys(self::PREFIX.'*');
        if ($keys !== []) {
            $this->client->del(...$keys);
        }
    }

    /** Resynchronize the array clock with the shared wall clock. */
    private function sync(): void
    {
        $this->clock->now = max($this->clock->now, time());
    }

    /**
     * Scenario one: createAdmittedChallenge on an absent demand. Both
     * stores must refuse with the exact typed exception, never a silent
     * failure.
     */
    public function testAnAbsentDemandRefusesAdmissionWithTheTypedRefusalOnBothStores(): void
    {
        $this->sync();
        $now = $this->clock->now;
        $refusal = static function (StepUpChallengeStore $store) use ($now): string {
            $challenge = StepUpChallenge::begin(
                StepUpChallenge::mintId(),
                StepUpChallengeKind::EmailOtp,
                self::PRINCIPAL_A,
                null,
                self::SCOPE,
                null,
                'step_up',
                $now,
                600,
                5,
                hash('sha256', 'code'),
                null,
                'sess',
                false,
                false,
                null,
                StepUpChallenge::mintId(),
            );
            try {
                $store->createAdmittedChallenge($challenge, 600);
            } catch (StepUpDemandAdmissionRefused $e) {
                return $e::class;
            }

            return 'no-refusal';
        };

        $a = $refusal($this->arrayStore);
        $r = $refusal($this->redisStore);
        self::assertSame(StepUpDemandAdmissionRefused::class, $a, 'the array store must refuse an absent demand with the typed refusal');
        self::assertSame(StepUpDemandAdmissionRefused::class, $r, 'the Redis store must refuse an absent demand with the typed refusal');
        self::assertSame($a, $r, 'the two stores disagree on the absent-demand admission refusal');
    }

    /**
     * Scenario two: two successive admissions of one open demand. Both
     * succeed, the demand's active challenge is the second, and the
     * first is no longer readable (the replace consumed it).
     */
    public function testTwoSuccessiveAdmissionsReplaceOnBothStores(): void
    {
        $this->sync();
        $now = $this->clock->now;
        $scenario = function (StepUpChallengeStore $store) use ($now): array {
            $demand = StepUpDemand::mint(StepUpChallenge::mintId(), self::SCOPE, hash('sha256', 'sess'), null, null, $now, 600);
            $store->createDemand($demand, 600);
            $first = StepUpChallenge::begin(
                StepUpChallenge::mintId(), StepUpChallengeKind::EmailOtp, self::PRINCIPAL_A, null, self::SCOPE, null, 'step_up',
                $now, 600, 5, hash('sha256', 'code-1'), null, 'sess', false, false, null, $demand->id,
            );
            $firstId = $store->createAdmittedChallenge($first, 600);
            $second = StepUpChallenge::begin(
                StepUpChallenge::mintId(), StepUpChallengeKind::EmailOtp, self::PRINCIPAL_A, null, self::SCOPE, null, 'step_up',
                $now, 600, 5, hash('sha256', 'code-2'), null, 'sess', false, false, null, $demand->id,
            );
            $secondId = $store->createAdmittedChallenge($second, 600);
            $stored = $store->readDemand($demand->id);
            $secondRead = $store->read($secondId);

            return [
                'distinct' => $firstId !== $secondId,
                'secondIsActive' => $stored?->activeChallengeId === $secondId,
                'firstUnreadable' => $store->read($firstId) === null,
                'secondReadable' => $secondRead !== null,
                'activeExpiryIsSecondExpiry' => $stored?->activeChallengeExpiresAt === $secondRead?->expiresAt,
            ];
        };

        $a = $scenario($this->arrayStore);
        $r = $scenario($this->redisStore);
        $expected = ['distinct' => true, 'secondIsActive' => true, 'firstUnreadable' => true, 'secondReadable' => true, 'activeExpiryIsSecondExpiry' => true];
        self::assertSame($expected, $a, 'the array store: the second admission replaces the first');
        self::assertSame($expected, $r, 'the Redis store: the second admission replaces the first');
        self::assertSame($a, $r, 'the two stores disagree on successive admissions');
    }

    /**
     * Scenario three: an admission whose challenge TTL would outlive the
     * demand. Both stores must store a challenge whose expiry does not
     * exceed the demand's expiry (clamped, not refused).
     */
    public function testAChallengeTtlBeyondTheDemandIsClampedOnBothStores(): void
    {
        $this->sync();
        $now = $this->clock->now;
        $scenario = function (StepUpChallengeStore $store) use ($now): array {
            $demand = StepUpDemand::mint(StepUpChallenge::mintId(), self::SCOPE, hash('sha256', 'sess'), null, null, $now, 600);
            $store->createDemand($demand, 600);
            $challenge = StepUpChallenge::begin(
                StepUpChallenge::mintId(), StepUpChallengeKind::EmailOtp, self::PRINCIPAL_A, null, self::SCOPE, null, 'step_up',
                $now, 100000, 5, hash('sha256', 'code'), null, 'sess', false, false, null, $demand->id,
            );
            $id = $store->createAdmittedChallenge($challenge, 100000);
            $stored = $store->read($id);

            return [
                'storedExpiresAt' => $stored?->expiresAt,
                'demandExpiresAt' => $demand->expiresAt,
                'doesNotOutliveDemand' => $stored !== null && $stored->expiresAt <= $demand->expiresAt,
                'equalsDemandExpiry' => $stored?->expiresAt === $demand->expiresAt,
            ];
        };

        $a = $scenario($this->arrayStore);
        $r = $scenario($this->redisStore);
        self::assertTrue($a['doesNotOutliveDemand'], 'the array store must clamp the challenge to the demand window');
        self::assertTrue($r['doesNotOutliveDemand'], 'the Redis store must clamp the challenge to the demand window');
        self::assertSame($a, $r, 'the two stores disagree on the challenge expiry clamp');
    }

    /**
     * Scenario four: the monotonic completion history. A webauthn
     * completion then a weaker email_otp completion of the same
     * (session, scope) pair must still answer webauthn on both stores.
     */
    public function testTheFactorHistoryStaysMonotonicOnBothStores(): void
    {
        $this->sync();
        $now = $this->clock->now;
        $session = hash('sha256', 'sess');
        $scope = self::SCOPE;
        $scenario = function (StepUpChallengeStore $store) use ($now, $session, $scope): array {
            $strongDemand = StepUpDemand::mint(StepUpChallenge::mintId(), $scope, $session, null, null, $now, 600);
            $store->createDemand($strongDemand, 600);
            $strong = StepUpChallenge::begin(
                StepUpChallenge::mintId(), StepUpChallengeKind::WebAuthn, self::PRINCIPAL_A, null, $scope, null, 'step_up',
                $now, 600, 5, hash('sha256', 'ceremony'), 'assertion', 'sess', false, false, null, $strongDemand->id,
            );
            $store->create($strong, 600);
            $strongDone = $store->completeFactor($strong->id, $strongDemand->id, $session, $now, $session, $scope);
            $afterStrong = $store->completedFactorOf($session, $scope, $now);

            $weakDemand = StepUpDemand::mint(StepUpChallenge::mintId(), $scope, $session, null, null, $now, 600);
            $store->createDemand($weakDemand, 600);
            $weak = StepUpChallenge::begin(
                StepUpChallenge::mintId(), StepUpChallengeKind::EmailOtp, self::PRINCIPAL_A, null, $scope, null, 'step_up',
                $now, 600, 5, hash('sha256', 'code'), null, 'sess', false, false, null, $weakDemand->id,
            );
            $store->create($weak, 600);
            $weakDone = $store->completeFactor($weak->id, $weakDemand->id, $session, $now, $session, $scope);

            return [
                'strongCompleted' => $strongDone !== null,
                'afterStrong' => $afterStrong,
                'weakCompleted' => $weakDone !== null,
                'afterWeak' => $store->completedFactorOf($session, $scope, $now),
            ];
        };

        $a = $scenario($this->arrayStore);
        $r = $scenario($this->redisStore);
        $expected = ['strongCompleted' => true, 'afterStrong' => 'webauthn', 'weakCompleted' => true, 'afterWeak' => 'webauthn'];
        self::assertSame($expected, $a, 'the array store must keep the monotonic webauthn history');
        self::assertSame($expected, $r, 'the Redis store must keep the monotonic webauthn history');
        self::assertSame($a, $r, 'the two stores disagree on the monotonic factor history');
    }

    /**
     * Scenario five: crossed session, crossed scope and an account
     * switch (a login demand for one subject completed by a challenge of
     * another). Each crossing must complete nothing on both stores, even
     * though the presented binding reproduces the challenge.
     */
    public function testCrossedSessionScopeAndAccountCompleteNothingOnBothStores(): void
    {
        $this->sync();
        $now = $this->clock->now;
        $scenario = function (StepUpChallengeStore $store) use ($now): array {
            // Crossed session: the demand names sess-a, the challenge proves sess-b.
            $demandA = StepUpDemand::mint(StepUpChallenge::mintId(), self::SCOPE, hash('sha256', 'sess-a'), null, null, $now, 600);
            $store->createDemand($demandA, 600);
            $chalA = StepUpChallenge::begin(
                StepUpChallenge::mintId(), StepUpChallengeKind::EmailOtp, self::PRINCIPAL_A, null, self::SCOPE, null, 'step_up',
                $now, 600, 5, hash('sha256', 'code-a'), null, 'sess-b', false, false, null, $demandA->id,
            );
            $store->create($chalA, 600);
            $crossedSession = $store->completeFactor($chalA->id, $demandA->id, (string) $chalA->sessionHash, $now, (string) $chalA->sessionHash, self::SCOPE);

            // Crossed scope: the demand names checkout, the challenge proves login.
            $demandB = StepUpDemand::mint(StepUpChallenge::mintId(), self::SCOPE, hash('sha256', 'sess'), null, null, $now, 600);
            $store->createDemand($demandB, 600);
            $chalB = StepUpChallenge::begin(
                StepUpChallenge::mintId(), StepUpChallengeKind::EmailOtp, self::PRINCIPAL_A, null, 'login', null, 'step_up',
                $now, 600, 5, hash('sha256', 'code-b'), null, 'sess', false, false, null, $demandB->id,
            );
            $store->create($chalB, 600);
            $crossedScope = $store->completeFactor($chalB->id, $demandB->id, (string) $chalB->sessionHash, $now, (string) $chalB->sessionHash, 'login');

            // Account switch: a login demand for PRINCIPAL_A, a challenge proving PRINCIPAL_B.
            $demandC = StepUpDemand::mint(
                StepUpChallenge::mintId(), self::SCOPE, null, null, null, $now, 600,
                StepUpOperationBindingKind::Login, hash('sha256', 'op'), null, null, false, null, null, self::PRINCIPAL_A,
            );
            $store->createDemand($demandC, 600);
            $chalC = StepUpChallenge::begin(
                StepUpChallenge::mintId(), StepUpChallengeKind::EmailOtp, self::PRINCIPAL_B, null, self::SCOPE, null, 'step_up',
                $now, 600, 5, hash('sha256', 'code-c'), null, null, false, false, null, $demandC->id,
            );
            $store->create($chalC, 600);
            $accountSwitch = $store->completeFactor($chalC->id, $demandC->id, (string) $chalC->clientSecretHash, $now, null, self::SCOPE);

            return [
                'crossedSession' => $crossedSession === null,
                'crossedScope' => $crossedScope === null,
                'accountSwitch' => $accountSwitch === null,
            ];
        };

        $a = $scenario($this->arrayStore);
        $r = $scenario($this->redisStore);
        $expected = ['crossedSession' => true, 'crossedScope' => true, 'accountSwitch' => true];
        self::assertSame($expected, $a, 'the array store must refuse every crossing');
        self::assertSame($expected, $r, 'the Redis store must refuse every crossing');
        self::assertSame($a, $r, 'the two stores disagree on the crossed session/scope/account completions');
    }

    /**
     * Scenario six: a demand record round-trip with every optional field
     * set. The record is stored via createDemand and read back; the
     * decoded record must equal the original field-by-field on both
     * stores, and after an admission both stores must stamp the same
     * active-challenge fields.
     */
    public function testADemandRecordRoundTripsIdenticallyOnBothStores(): void
    {
        $this->sync();
        $now = $this->clock->now;
        $scope = self::SCOPE;
        $session = hash('sha256', 'sess');
        $opDigest = hash('sha256', 'op-identity');
        $contentDigest = hash('sha256', 'op-content');
        $required = new FactorRequirement(FactorRequirement::WEBAUTHN, FactorRequirement::WEBAUTHN, 3);

        $base = StepUpDemand::mint(
            StepUpChallenge::mintId(), $scope, $session, 'ChainId_0000000000001', 'decision-roundtrip',
            $now, 600, StepUpOperationBindingKind::RequestBinding, $opDigest, $opDigest, $contentDigest,
            false, null, $required, self::PRINCIPAL_A,
        );
        $expected = $base->spawnChild(StepUpChallenge::mintId(), $now, 'decision-raised', null)->withEffects(
            StepUpEffectsJournal::none()
                ->withEffect(StepUpEffectsJournal::SETTLED, $now)
                ->withEffect(StepUpEffectsJournal::OUTCOME_CREDITED, $now + 1),
        );

        $read = function (StepUpChallengeStore $store) use ($expected, $now, $scope): array {
            $store->createDemand($expected, 600);
            $decoded = $store->readDemand($expected->id);
            $challenge = StepUpChallenge::begin(
                StepUpChallenge::mintId(), StepUpChallengeKind::EmailOtp, self::PRINCIPAL_A, null, $scope, null, 'step_up',
                $now, 600, 5, hash('sha256', 'code'), null, 'sess', false, false, null, $expected->id,
            );
            $store->createAdmittedChallenge($challenge, 600);
            $afterAdmission = $store->readDemand($expected->id);

            return [
                'decodedEqualsOriginal' => $decoded?->toArray() === $expected->toArray(),
                'decoded' => $decoded?->toArray(),
                'activeChallengeIdSet' => $afterAdmission?->activeChallengeId === $challenge->id,
                'activeExpiresAt' => $afterAdmission?->activeChallengeExpiresAt,
            ];
        };

        $a = $read($this->arrayStore);
        $r = $read($this->redisStore);
        self::assertTrue($a['decodedEqualsOriginal'], 'the array store must round-trip every optional demand field');
        self::assertTrue($r['decodedEqualsOriginal'], 'the Redis store must round-trip every optional demand field');
        self::assertSame($expected->toArray(), $a['decoded'], 'the array store decoded record diverges from the original');
        self::assertSame($expected->toArray(), $r['decoded'], 'the Redis store decoded record diverges from the original');
        self::assertSame($a['decoded'], $r['decoded'], 'the two stores disagree on the round-tripped demand record');
        self::assertTrue($a['activeChallengeIdSet'], 'the array store must stamp the active challenge id after an admission');
        self::assertTrue($r['activeChallengeIdSet'], 'the Redis store must stamp the active challenge id after an admission');
        self::assertSame($a['activeExpiresAt'], $r['activeExpiresAt'], 'the two stores disagree on the active-challenge expiry after an admission');
    }

    /**
     * Scenario seven: the admit script's demand rewrite. The Lua decodes
     * the demand with cjson, stamps the active challenge and re-encodes
     * it. A cjson round-trip can drop or reshape fields (a JSON null
     * becomes the cjson.null sentinel, an absent key stays absent), so
     * every field of the maximum-surface record must survive untouched
     * except the two active-challenge stamps.
     */
    public function testTheAdmitScriptPreservesEveryDemandFieldOnBothStores(): void
    {
        $this->sync();
        $now = $this->clock->now;
        $rich = $this->richDemand($now);
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(), StepUpChallengeKind::EmailOtp, self::PRINCIPAL_A, null, self::SCOPE, null, 'step_up',
            $now, 600, 5, hash('sha256', 'code'), null, 'sess-rich', false, false, null, $rich->id,
        );

        $observe = function (StepUpChallengeStore $store) use ($rich, $challenge): array {
            $store->createDemand($rich, 600);
            $store->createAdmittedChallenge($challenge, 600);
            $after = $store->readDemand($rich->id);
            $expected = $rich->toArray();
            $observed = $after?->toArray() ?? [];
            foreach (['active_challenge_id', 'active_challenge_expires_at'] as $field) {
                unset($expected[$field], $observed[$field]);
            }

            return [
                'decodable' => $after !== null,
                'allOtherFieldsEqual' => $observed === $expected,
                'observed' => $observed,
                'expected' => $expected,
                'fxSurvived' => ($after?->effects?->toArray() ?? null) === ($rich->effects?->toArray() ?? null),
                'leaseNull' => \array_key_exists('lease_until', $after?->toArray() ?? []) && $after?->leaseUntilMs === null,
                'lastSentNull' => \array_key_exists('last_sent_at', $after?->toArray() ?? []) && $after?->lastSentAt === null,
                'createdAtInt' => \is_int($after?->createdAt),
                'expiresAtInt' => \is_int($after?->expiresAt),
            ];
        };

        $a = $observe($this->arrayStore);
        $r = $observe($this->redisStore);
        self::assertTrue($a['decodable'] && $r['decodable'], 'both stores must keep the demand decodable after the admit rewrite');
        self::assertSame($a['expected'], $a['observed'], 'the array store admit rewrite changed a demand field');
        self::assertSame($r['expected'], $r['observed'], 'the Redis admit rewrite changed a demand field');
        self::assertTrue($r['fxSurvived'], 'the Redis admit rewrite dropped or reshaped the effects journal');
        self::assertTrue($r['leaseNull'], 'the Redis admit rewrite dropped or reshaped lease_until');
        self::assertTrue($r['lastSentNull'], 'the Redis admit rewrite dropped or reshaped last_sent_at');
        self::assertTrue($r['createdAtInt'] && $r['expiresAtInt'], 'the Redis admit rewrite turned a timestamp into a non-integer');
        self::assertSame($a, $r, 'the two stores disagree on the admit-rewritten demand record');

        $raw = $this->rawDemand($rich->id);
        self::assertIsArray($raw, 'the Redis demand record must stay a JSON object after the admit rewrite');
        self::assertArrayHasKey('lease_until', $raw, 'the admit rewrite dropped lease_until from the stored JSON');
        self::assertNull($raw['lease_until'], 'the admit rewrite reshaped lease_until in the stored JSON');
        self::assertArrayHasKey('last_sent_at', $raw, 'the admit rewrite dropped last_sent_at from the stored JSON');
        self::assertNull($raw['last_sent_at'], 'the admit rewrite reshaped last_sent_at in the stored JSON');
        self::assertArrayHasKey('fx', $raw, 'the admit rewrite dropped the effects journal from the stored JSON');
        self::assertNotEmpty($raw['fx'], 'the admit rewrite emptied the effects journal in the stored JSON');
    }

    /**
     * Scenario eight: the completion script's demand rewrite. The Lua
     * re-encodes the demand after moving it to completed; the record
     * must stay decodable and every field other than state/stateAt must
     * be byte-for-byte unchanged, with the effects journal intact.
     */
    public function testTheCompletionScriptPreservesEveryDemandFieldOnBothStores(): void
    {
        $this->sync();
        $now = $this->clock->now;
        $rich = $this->richDemand($now);
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(), StepUpChallengeKind::WebAuthn, self::PRINCIPAL_A, null, self::SCOPE, null, 'step_up',
            $now, 600, 5, hash('sha256', 'ceremony'), 'assertion', 'sess-rich', false, false, null, $rich->id,
        );

        $observe = function (StepUpChallengeStore $store) use ($rich, $challenge, $now): array {
            $store->createDemand($rich, 600);
            $store->create($challenge, 600);
            $done = $store->completeFactor($challenge->id, $rich->id, (string) $challenge->sessionHash, $now, (string) $challenge->sessionHash, self::SCOPE);
            $after = $store->readDemand($rich->id);
            $expected = $rich->toArray();
            $observed = $after?->toArray() ?? [];
            foreach (['state', 'state_at'] as $field) {
                unset($expected[$field], $observed[$field]);
            }

            return [
                'completed' => $done !== null,
                'decodable' => $after !== null,
                'stateCompleted' => $after?->state === StepUpDemandState::Completed,
                'allOtherFieldsEqual' => $observed === $expected,
                'observed' => $observed,
                'expected' => $expected,
                'fxSurvived' => ($after?->effects?->toArray() ?? null) === ($rich->effects?->toArray() ?? null),
                'leaseNull' => \array_key_exists('lease_until', $after?->toArray() ?? []) && $after?->leaseUntilMs === null,
                'lastSentNull' => \array_key_exists('last_sent_at', $after?->toArray() ?? []) && $after?->lastSentAt === null,
            ];
        };

        $a = $observe($this->arrayStore);
        $r = $observe($this->redisStore);
        self::assertTrue($a['completed'] && $r['completed'], 'both stores must complete the rich demand');
        self::assertTrue($a['decodable'] && $r['decodable'], 'both stores must keep the demand decodable after the completion rewrite');
        self::assertTrue($a['stateCompleted'] && $r['stateCompleted'], 'both stores must reach the completed terminal');
        self::assertSame($a['expected'], $a['observed'], 'the array store completion rewrite changed a demand field');
        self::assertSame($r['expected'], $r['observed'], 'the Redis completion rewrite changed a demand field');
        self::assertTrue($r['fxSurvived'], 'the Redis completion rewrite dropped or reshaped the effects journal');
        self::assertTrue($r['leaseNull'], 'the Redis completion rewrite dropped or reshaped lease_until');
        self::assertTrue($r['lastSentNull'], 'the Redis completion rewrite dropped or reshaped last_sent_at');
        self::assertSame($a, $r, 'the two stores disagree on the completion-rewritten demand record');

        $raw = $this->rawDemand($rich->id);
        self::assertIsArray($raw, 'the Redis demand record must stay a JSON object after the completion rewrite');
        self::assertArrayHasKey('fx', $raw, 'the completion rewrite dropped the effects journal from the stored JSON');
        self::assertNotEmpty($raw['fx'], 'the completion rewrite emptied the effects journal in the stored JSON');
        self::assertArrayHasKey('lease_until', $raw, 'the completion rewrite dropped lease_until from the stored JSON');
        self::assertNull($raw['lease_until'], 'the completion rewrite reshaped lease_until in the stored JSON');
    }

    /**
     * The maximum-surface demand: chain id, decision id, both operation
     * digests, principal pseudonym, a required-factor snapshot and a
     * non-empty effects journal, with leaseUntilMs and lastSentAt left
     * null. Built once so both stores receive a structurally identical
     * record.
     */
    private function richDemand(int $now): StepUpDemand
    {
        $opDigest = hash('sha256', 'op-identity');
        $contentDigest = hash('sha256', 'op-content');
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(), self::SCOPE, hash('sha256', 'sess-rich'), 'ChainId_0000000000001', 'decision-rich',
            $now, 600, StepUpOperationBindingKind::RequestBinding, $opDigest, $opDigest, $contentDigest,
            false, null, new FactorRequirement(FactorRequirement::WEBAUTHN, FactorRequirement::WEBAUTHN, 3), self::PRINCIPAL_A,
        );

        return $demand->withEffects(
            StepUpEffectsJournal::none()
                ->withEffect(StepUpEffectsJournal::SETTLED, $now)
                ->withEffect(StepUpEffectsJournal::OUTCOME_CREDITED, $now + 1),
        );
    }

    /** The raw stored JSON of a demand, for a byte-shape probe of the Lua rewrite. */
    private function rawDemand(string $id): ?array
    {
        $raw = $this->client->get(self::PREFIX.'emd:'.$id);

        return \is_string($raw) ? json_decode($raw, true) : null;
    }
}
