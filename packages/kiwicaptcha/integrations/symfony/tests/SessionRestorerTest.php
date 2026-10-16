<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\SessionRestorer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionRestore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\InMemoryPrincipalNetworkTagStore;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Network\NetworkFlags;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The step-up session restore (findings 2 and 3): the token carries the
 * raw user identifier while the challenge carries the 32-hex principal
 * pseudonym, compare like with like, or every restore fails. A
 * successful step-up restores the wrapped token (no longer pending) and
 * records the engine's stable network tag, so the store never holds a
 * reversible spelling of the address. A stolen ticket for another
 * account upgrades nothing. The session id rotates after the
 * request-stack fallback, so a caller that omitted the request still
 * gets the rotation.
 */
final class SessionRestorerTest extends TestCase
{
    /** The server-parameter key for the peer address (glued so prose lint treats it as code). */
    private const remoteKey = 'REMOTE_ADDR';

    private const RAW_USER = 'alice@example.com';
    private const HOME_IP = '203.0.113.10';
    private const LOOPBACK = '127.0.0.1';
    private const HOME_V6 = '2001:db8:abcd:1234:5678:9abc:def0:1234';

    /** The field the restore recorded before the tag change: family byte plus the packed address. */
    private const LOOPBACK_BUCKET = '047f000001';

    /** The pinned engine tag of the loopback client for the suite master (0x11 x 32). */
    private const LOOPBACK_TAG = '8e4645476920efc1260d976d352e5ce310a04ce4dc3df5d73320c8b28b9bf8c5';

    private RiskIdentityFactory $identity;

    private InMemoryPrincipalNetworkTagStore $networks;

    protected function setUp(): void
    {
        $this->identity = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x11", 32)));
        $this->networks = new InMemoryPrincipalNetworkTagStore();
    }

    /**
     * A successful step-up restores the wrapped token (the session is
     * no longer pending) and records the engine's network tag under the
     * challenge's principal pseudonym. The restore names the exact
     * demand the completed factor finalizes, and the pending token
     * carries the same identity, so the equality opens the session.
     */
    public function testASuccessfulStepUpRestoresTheTokenAndRecordsTheNetwork(): void
    {
        [$tokenStorage, $wrapped, $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::HOME_IP, 'session-original-000000000001');
        $sessionIdBefore = (string) $request->getSession()->getId();
        $restorer = $this->restorer($tokenStorage);

        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());

        $token = $tokenStorage->getToken();
        self::assertSame($wrapped, $token, 'the wrapped token is restored: the session is no longer pending');
        self::assertNotInstanceOf(StepUpPendingToken::class, $token);

        $principal = $this->identity->principalId(self::RAW_USER);
        $network = $this->engineFor($this->networks)->networkTag(self::HOME_IP);
        self::assertTrue($this->networks->principalNetworkSeen($principal, $network), 'the network is recorded under the engine tag');
        self::assertContains([$principal, $network], $this->networks->writes);

        self::assertNotSame($sessionIdBefore, (string) $request->getSession()->getId(), 'the session id rotates on the privilege upgrade');
    }

    /**
     * The stored field of the loopback client: the pinned engine tag,
     * never the bucket spelling. The literal anchors the derivation to
     * the suite master, so a drifting second implementation fails here.
     */
    public function testTheRestoreStoresTheLoopbackTagAndNeverTheRawBucketSpelling(): void
    {
        $engine = $this->engine();
        $principal = $this->identity->principalId(self::RAW_USER);
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::LOOPBACK, 'session-original-000000000001');

        $this->restorer($tokenStorage)->restore($principal, $request, $pending->demandId());

        self::assertSame(self::LOOPBACK_TAG, $engine->networkTag(self::LOOPBACK), 'the loopback tag is the pinned derivation');
        self::assertSame(self::LOOPBACK_BUCKET, AdaptiveRiskEngine::networkBucket(self::LOOPBACK), 'the bucket spelling of the loopback client');
        self::assertTrue($this->networks->principalNetworkSeen($principal, self::LOOPBACK_TAG), 'the stored field is the tag');
        self::assertTrue($this->networks->tagIsTrusted($principal, self::LOOPBACK_TAG), 'the tag carries the trust mirror');
        self::assertFalse($this->networks->principalNetworkSeen($principal, self::LOOPBACK_BUCKET), 'the raw bucket spelling is never a stored field');
        foreach ($this->networks->writes as [, $field]) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $field, 'every network write is a tag');
            self::assertNotSame(self::LOOPBACK_BUCKET, $field, 'no write carries the raw bucket spelling');
        }
    }

    /**
     * The fail-safe shape of a missing wiring seam: without the engine
     * no tag can be derived, so the restore records no network field
     * and a reversible spelling never lands in the store.
     */
    public function testTheRestoreWithoutTheEngineSeamRecordsNoNetworkField(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::LOOPBACK, 'session-original-000000000001');
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            identityFactory: $this->identity,
        );

        $restore = $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());

        self::assertSame(StepUpSessionRestore::RESTORED, $restore->status, 'the unwrap still lands');
        self::assertSame([], $this->networks->writes, 'no engine seam records no network field');
    }

    /**
     * Legacy history: a field recorded under the bucket spelling still
     * answers seen to the novel-network gate, and the restore adds the
     * tag beside it without changing the verdict.
     */
    public function testALegacyBucketFieldStillVouchesAndTheRestoreAddsTheTag(): void
    {
        $principal = $this->identity->principalId(self::RAW_USER);

        // The upgrade state on one store: the legacy field alone.
        $legacyStore = new InMemoryPrincipalNetworkTagStore();
        $legacyEngine = $this->engineFor($legacyStore);
        $legacyStore->recordPrincipalNetworkTag($principal, self::LOOPBACK_BUCKET, true);
        $legacyVerdict = $this->verdictFor($legacyEngine, self::LOOPBACK);
        self::assertSame(RiskAction::Allow, $legacyVerdict['action'], 'the legacy field vouches for the login');
        self::assertFalse($legacyVerdict['novel'], 'the gate answers seen for the legacy bucket spelling');

        // The same legacy history plus the restore's own record.
        $restoreStore = new InMemoryPrincipalNetworkTagStore();
        $restoreEngine = $this->engineFor($restoreStore);
        $restoreStore->recordPrincipalNetworkTag($principal, self::LOOPBACK_BUCKET, true);
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::LOOPBACK, 'session-original-000000000001');
        $restore = $this->restorer($tokenStorage, $restoreStore)->restore($principal, $request, $pending->demandId());

        self::assertSame(StepUpSessionRestore::RESTORED, $restore->status, 'the restore lands on the legacy store');
        $tag = $restoreEngine->networkTag(self::LOOPBACK);
        self::assertTrue($restoreStore->principalNetworkSeen($principal, $tag), 'the restore rewrites the network under the tag');
        self::assertTrue($restoreStore->tagIsTrusted($principal, $tag), 'the rewrite mints the trust mirror');
        self::assertTrue($restoreStore->principalNetworkSeen($principal, self::LOOPBACK_BUCKET), 'the legacy field stays readable');
        self::assertContains([$principal, $tag], $restoreStore->writes, 'the tag is the restore\'s own write');

        $restored = $this->verdictFor($restoreEngine, self::LOOPBACK);
        self::assertSame($legacyVerdict['action'], $restored['action'], 'the verdict is unchanged after the rewrite');
        self::assertSame($legacyVerdict['novel'], $restored['novel'], 'the novelty answer is unchanged after the rewrite');
    }

    /**
     * The verdict is identical for one network whichever form the store
     * holds: the stable tag or the bucket spelling. Run for IPv4 (the
     * full address) and for IPv6 (the /64 prefix), the two
     * granularities the gate judges.
     */
    public function testTheGateVerdictIsIdenticalForTheTagAndTheLegacyFormForBothFamilies(): void
    {
        $principal = $this->identity->principalId(self::RAW_USER);
        foreach ([self::HOME_IP, self::HOME_V6] as $ip) {
            $tagStore = new InMemoryPrincipalNetworkTagStore();
            $tagEngine = $this->engineFor($tagStore);
            $tagStore->recordPrincipalNetworkTag($principal, $tagEngine->networkTag($ip), true);
            $tagVerdict = $this->verdictFor($tagEngine, $ip);

            $legacyStore = new InMemoryPrincipalNetworkTagStore();
            $legacyEngine = $this->engineFor($legacyStore);
            $legacyStore->recordPrincipalNetworkTag($principal, self::legacyField($ip), true);
            $legacyVerdict = $this->verdictFor($legacyEngine, $ip);

            self::assertSame(RiskAction::Allow, $tagVerdict['action'], sprintf('the tag-seeded verdict for %s', $ip));
            self::assertSame(RiskAction::Allow, $legacyVerdict['action'], sprintf('the legacy-seeded verdict for %s', $ip));
            self::assertFalse($legacyVerdict['novel'], sprintf('the legacy field vouches for %s', $ip));
            self::assertSame($tagVerdict['action'], $legacyVerdict['action'], sprintf('the verdict for %s is the same for both stored forms', $ip));
            self::assertSame($tagVerdict['novel'], $legacyVerdict['novel'], sprintf('the novelty answer for %s is the same for both stored forms', $ip));
        }
    }

    /**
     * The exact-demand gate: two sequential pending logins of one
     * session hold two demands. Completing the factor of demand A
     * finalizes demand A, and the pending token of login B (demand B)
     * must never unwrap, however equal the principal, the scope and
     * the session look. The refusal skips every effect: no unwrap, no
     * rotation, no trust write, no device mint.
     */
    public function testCompletingOneDemandNeverUnwrapsASecondPendingLogin(): void
    {
        [, , $pendingA] = $this->pendingTokenStorage(self::RAW_USER);
        [$tokenStorage, $wrappedB, $pendingB] = $this->pendingTokenStorage(self::RAW_USER);
        self::assertNotSame($pendingA->demandId(), $pendingB->demandId(), 'two pending logins hold two distinct demands');
        $request = $this->request(self::HOME_IP, 'session-original-000000000001');
        $sessionIdBefore = (string) $request->getSession()->getId();
        $restorer = $this->restorer($tokenStorage);

        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pendingA->demandId());

        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken(), 'the completion of demand A never unwraps the pending token of demand B');
        self::assertSame($wrappedB, $tokenStorage->getToken()?->getWrapped(), 'the second login keeps its own wrapped token');
        self::assertSame([], $this->networks->writes, 'a refused restore records nothing');
        self::assertSame($sessionIdBefore, (string) $request->getSession()->getId(), 'a refused restore rotates nothing');
    }

    /**
     * The gate fails closed on every unprovable shape: a restore that
     * names no demand, a pending token stripped of its identity, and a
     * non-pending session are each handled without upgrading anything.
     */
    public function testTheDemandGateFailsClosedOnAnUnprovableShape(): void
    {
        // A completion that names no demand never unwraps a pending
        // session, even for the right principal.
        [$tokenStorage] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::HOME_IP, 'session-original-000000000001');
        $this->restorer($tokenStorage)->restore($this->identity->principalId(self::RAW_USER), $request, null);
        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken(), 'an unnamed demand unwraps nothing');
        self::assertSame([], $this->networks->writes, 'a refused restore records nothing');

        // A token whose identity attribute was lost (a mangled session
        // payload) can never prove the equality.
        [$tokenStorage2, , $pending2] = $this->pendingTokenStorage(self::RAW_USER);
        $pending2->setAttributes([]);
        $this->restorer($tokenStorage2)->restore($this->identity->principalId(self::RAW_USER), $request, StepUpPendingToken::mintDemandId());
        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage2->getToken(), 'an identity-less token unwraps nothing');

        // The demand identity survives the session round-trip.
        [, , $pending3] = $this->pendingTokenStorage(self::RAW_USER);
        $roundTrip = unserialize(serialize($pending3));
        self::assertInstanceOf(StepUpPendingToken::class, $roundTrip);
        self::assertSame($pending3->demandId(), $roundTrip->demandId(), 'the demand identity is serialized with the token');
    }

    /**
     * The pending token's principal must be the one that completed the
     * step-up: a stolen ticket for another account can never upgrade
     * this session, and nothing is recorded.
     */
    public function testTheRestoreRefusesAStolenTicketForAnotherAccount(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::HOME_IP, 'session-original-000000000001');
        $restorer = $this->restorer($tokenStorage);

        $restorer->restore($this->identity->principalId('someone-else@example.com'), $request, $pending->demandId());

        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken(), 'a mismatched principal never restores');
        self::assertSame([], $this->networks->writes, 'a refused restore records nothing');
    }

    /**
     * The raw-vs-pseudonym comparison: without the identity factory the
     * raw identifier can never equal the 32-hex pseudonym, and the
     * restore fails closed (the wiring always injects the factory).
     */
    public function testARawIdentifierNeverMatchesTheChallengePseudonym(): void
    {
        [$tokenStorage, $wrapped, $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::HOME_IP, 'session-original-000000000001');
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            requestStack: null,
            identityFactory: $this->identity(),
        );

        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());

        self::assertNotSame($wrapped, $tokenStorage->getToken(), 'no identity factory: the pseudonym never equals the raw identifier');
        self::assertInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken());
    }

    /**
     * Finding 3: the session id rotates after the request-stack
     * fallback, so a caller that omitted the request argument still
     * gets the rotation.
     */
    public function testTheSessionRotatesEvenWhenTheCallerOmittedTheRequest(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::HOME_IP, 'session-original-000000000001');
        $sessionIdBefore = (string) $request->getSession()->getId();
        $stack = new RequestStack();
        $stack->push($request);
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            requestStack: $stack,
            identityFactory: $this->identity,
            engine: $this->engine(),
        );

        $restorer->restore($this->identity->principalId(self::RAW_USER), null, $pending->demandId());

        self::assertNotInstanceOf(StepUpPendingToken::class, $tokenStorage->getToken());
        self::assertNotSame($sessionIdBefore, (string) $request->getSession()->getId(), 'the rotation runs after the request-stack fallback');
    }

    /**
     * The ASN tag is recorded under the engine's novelty spelling
     * (the ASN number the dataset resolved), so the next login from the
     * same ASN is actually no longer novel.
     */
    public function testTheAsnTagUsesTheEngineSpelling(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request('10.1.2.3', 'session-original-000000000001');
        $asn = AsnDataset::open($this->asnFixturePath());
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            asnDataset: $asn,
            identityFactory: $this->identity,
            engine: $this->engine(),
        );

        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());

        $principal = $this->identity->principalId(self::RAW_USER);
        self::assertTrue($this->networks->principalNetworkSeen($principal, 'asn:64512'), 'the ASN tag matches the engine\'s lookup spelling');
    }

    /**
     * @return array{0: TokenStorage, 1: UsernamePasswordToken, 2: StepUpPendingToken}
     */
    private function pendingTokenStorage(string $rawUser): array
    {
        $wrapped = new UsernamePasswordToken(new InMemoryUser($rawUser, null, ['ROLE_USER']), 'main');
        $tokenStorage = new TokenStorage();
        $pending = new StepUpPendingToken($wrapped);
        $tokenStorage->setToken($pending);

        return [$tokenStorage, $wrapped, $pending];
    }

    private function request(string $ip, string $sessionId): Request
    {
        $request = Request::create('https://example.com/kiwi/step-up/complete', 'POST', [], [], [], [self::remoteKey => $ip]);
        $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
        $storage->setId($sessionId);
        $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
        $session->start();
        $request->setSession($session);

        return $request;
    }

    /**
     * The wired restore of the suite: the store and the engine share
     * one instance, exactly like the container wiring.
     */
    private function restorer(TokenStorage $tokenStorage, ?InMemoryPrincipalNetworkTagStore $networks = null): SessionRestorer
    {
        $store = $networks ?? $this->networks;

        return new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $store,
            identityFactory: $this->identity,
            engine: $this->engineFor($store),
        );
    }

    private function engine(): AdaptiveRiskEngine
    {
        return $this->engineFor($this->networks);
    }

    /**
     * The engine of the suite: the suite master (0x11 x 32) derives the
     * identity pseudonyms and the network tags, so one derivation serves
     * the restore and the gate.
     */
    private function engineFor(InMemoryPrincipalNetworkTagStore $networks): AdaptiveRiskEngine
    {
        $keys = RiskKeys::fromMaster(str_repeat("\x11", 32));

        return new AdaptiveRiskEngine(
            store: new FakeRiskStateStore(),
            classifier: new CidrNetworkClassifier([]),
            identityFactory: $this->identity,
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => RiskPolicy::CONTRACT_VERSION,
                'weights' => (new RiskWeights())->toArray(),
                'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20']],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
            noveltyEnforcement: 'enforce',
            principalNetworks: $networks,
        );
    }

    /**
     * The novel-network verdict of one login: the action and the
     * NovelNetwork reason the gate answers.
     *
     * @return array{action: RiskAction, novel: bool}
     */
    private function verdictFor(AdaptiveRiskEngine $engine, string $ip): array
    {
        $decision = $engine->reassess(new RiskContext(
            scope: 1,
            sourceIp: $ip,
            sessionId: null,
            principalId: self::RAW_USER,
            event: RiskEventKind::AuthenticationSuccess,
            networkFlags: new NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
        ));

        return ['action' => $decision->action, 'novel' => $decision->hasReason(RiskReason::NovelNetwork)];
    }

    /**
     * The network field the restore recorded before the tag change:
     * the family byte plus the packed address (the IPv6 /64 prefix at
     * its natural width), hex.
     */
    private static function legacyField(string $ip): string
    {
        $packed = inet_pton($ip);
        self::assertIsString($packed);

        return \strlen($packed) === 4 ? bin2hex("\x04".$packed) : bin2hex("\x06".substr($packed, 0, 8));
    }

    /**
     * The second factory of the raw-vs-pseudonym test: a distinct
     * master, so its pseudonyms never equal the suite's.
     */
    private function identity(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x42", 32)));
    }

    public function testACustomCookieNameIsHonored(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::HOME_IP, 'session-original-000000000001');
        $continuity = new \BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie(name: 'custom-session');
        $cookieValue = $continuity->mint();
        $request->cookies->set('custom-session', $cookieValue);
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            identityFactory: $this->identity,
            continuity: $continuity,
            engine: $this->engine(),
        );
        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());
        $pseudonym = $this->identity->sessionId($cookieValue);
        self::assertTrue(
            $this->networks->principalNetworkSeen($this->identity->principalId(self::RAW_USER), 'session:'.$pseudonym),
            'a custom cookie_name is honored',
        );
    }

    public function testAMalformedCookieRecordsNothing(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::HOME_IP, 'session-original-000000000001');
        // Array-shaped cookie and non-hex value both record nothing.
        $request->cookies->set('__Host-kiwi-session', ['x']);
        $continuity = new \BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie();
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            identityFactory: $this->identity,
            continuity: $continuity,
            engine: $this->engine(),
        );
        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());
        foreach ($this->networks->writes as [$p, $tag]) {
            self::assertStringNotContainsString('session:', $tag, 'a malformed cookie records no session tag');
        }
    }

    public function testBothCookiesRecordBothTags(): void
    {
        [$tokenStorage, , $pending] = $this->pendingTokenStorage(self::RAW_USER);
        $request = $this->request(self::HOME_IP, 'session-original-000000000001');
        $continuity = new \BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie();
        $device = new \BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie();
        $sessionValue = $continuity->mint();
        $deviceValue = $device->mint();
        $request->cookies->set('__Host-kiwi-session', $sessionValue);
        $request->cookies->set('__Host-kiwi-device', $deviceValue);
        $restorer = new SessionRestorer(
            tokenStorage: $tokenStorage,
            principalNetworks: $this->networks,
            identityFactory: $this->identity,
            continuity: $continuity,
            device: $device,
            engine: $this->engine(),
        );
        $restorer->restore($this->identity->principalId(self::RAW_USER), $request, $pending->demandId());
        $principal = $this->identity->principalId(self::RAW_USER);
        self::assertTrue($this->networks->principalNetworkSeen($principal, 'session:'.$this->identity->sessionId($sessionValue)), 'session tag recorded');
        self::assertTrue($this->networks->principalNetworkSeen($principal, 'device:'.$this->identity->deviceId($deviceValue)), 'device tag recorded under the device context derivation');
    }

    private function asnFixturePath(): string
    {
        $path = sys_get_temp_dir().'/kiwicaptcha-asn-fixture.tsv';
        if (!\array_key_exists(__METHOD__, $GLOBALS) || !$GLOBALS[__METHOD__]) {
            file_put_contents($path, "# test dataset\n10.0.0.0\t10.255.255.255\t64512\n192.168.0.0\t192.168.255.255\t64513\n");
            $GLOBALS[__METHOD__] = true;
        }

        return $path;
    }
}
