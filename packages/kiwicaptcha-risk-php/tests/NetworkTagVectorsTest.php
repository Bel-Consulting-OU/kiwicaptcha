<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Network\NetworkFlags;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;
use KiwiCaptcha\Risk\Storage\RedisPrincipalNetworkTagStore;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The stored network-tag shape of the novel-network gate. The writer
 * records the stable purpose-separated tag and never the bucket
 * spelling, so the store holds no reversible encoding of the address.
 * The reader probes the tag first and the bucket spelling as the
 * legacy form on a miss, so an upgraded deployment keeps the history
 * recorded under the legacy form.
 *
 * The Rust suite (packages/kiwicaptcha-risk/src/lib.rs, mod tests)
 * pins the same five reference vectors for master 0x42 x 32, so one
 * master and one bucket derive one tag in both cores. No protocol
 * vector file pins this value; the two suites are the parity surface.
 */
final class NetworkTagVectorsTest extends TestCase
{
    private const RAW_USER = 'alice@example.com';
    private const HOME_IP = '198.51.100.42';
    private const LOOPBACK = '127.0.0.1';
    private const HOME_V6 = '2001:db8:abcd:1234:5678:9abc:def0:1234';
    private const SIBLING_V6 = '2001:db8:abcd:1234:ffff:ffff:ffff:ffff';
    private const OTHER_V6 = '2001:db8:abcd:1235::1';

    /**
     * The shared derivation vectors, master str_repeat("\x42", 32).
     * The Rust mirror pins these identical literals.
     */
    private const TAG_HOME = '0221669a302689e99be2e6f1bf3d478e66282fef0f213da4160c957ff16ccac2';
    private const TAG_LOOPBACK = 'dd9b709dd17f2084613c9883c1a260c5f3d21783d7f1d2c002f9458aae7fca60';
    private const TAG_HOME_V6 = '9b35f176530031416eaafa5cc4231c82022fc33f65e9889191c13a49f10ba927';
    private const TAG_OTHER_V6 = '3a6252639aa10f440d109fd571d53c348a25c16969fe63d1113bf82a4f577123';

    /** The legacy field spelling of the loopback client. */
    private const LEGACY_LOOPBACK = '047f000001';

    private function engine(
        ?PrincipalNetworkTagStoreInterface $networks = null,
        string $noveltyEnforcement = 'enforce',
    ): AdaptiveRiskEngine {
        $store = new class extends RiskStateStoreStub {
            public function observe(RiskObservation $observation): SignalVector
            {
                return SignalVector::fromArray([]);
            }
        };
        $keys = RiskKeys::fromMaster(str_repeat("\x42", 32));

        return new AdaptiveRiskEngine(
            store: $store,
            classifier: new CidrNetworkClassifier([]),
            identityFactory: new RiskIdentityFactory($keys),
            scorer: new RiskScorer(),
            policy: RiskPolicy::fromConfig([
                'version' => 3,
                'weights' => (new RiskWeights())->toArray(),
                'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'sha20']],
                'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            ]),
            keys: $keys,
            noveltyEnforcement: $noveltyEnforcement,
            principalNetworks: $networks,
        );
    }

    private function principalHex(): string
    {
        $identity = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x42", 32)));

        return $identity->principalId(self::RAW_USER);
    }

    private function loginContext(string $ip): RiskContext
    {
        return new RiskContext(
            scope: 1,
            sourceIp: $ip,
            sessionId: null,
            principalId: self::RAW_USER,
            event: RiskEventKind::AuthenticationSuccess,
            networkFlags: new NetworkFlags(),
            resources: new ResourcePressure(1000, 1000),
        );
    }

    public function testNetworkTagMatchesTheSharedReferenceVectors(): void
    {
        $engine = $this->engine();
        self::assertSame(self::TAG_HOME, $engine->networkTag(self::HOME_IP), 'the IPv4 tag vector');
        self::assertSame(self::TAG_LOOPBACK, $engine->networkTag(self::LOOPBACK), 'the loopback tag vector');
        self::assertSame(self::TAG_HOME_V6, $engine->networkTag(self::HOME_V6), 'the IPv6 /64 tag vector');
        self::assertSame(self::TAG_OTHER_V6, $engine->networkTag(self::OTHER_V6), 'a second /64 derives a second tag');
        self::assertSame('', $engine->networkTag('not-an-ip'), 'an unparsable address carries no tag');
    }

    public function testNetworkTagIsStablePurposeSeparatedHex(): void
    {
        $engine = $this->engine();
        $tag = $engine->networkTag(self::HOME_IP);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $tag, 'the tag is 32 raw bytes of HMAC-SHA256 as lowercase hex');
        self::assertSame($tag, $this->engine()->networkTag(self::HOME_IP), 'a second engine derives the same tag');
        self::assertSame($tag, $engine->networkTag(self::HOME_IP), 'the memoized key keeps the tag byte-stable');
        self::assertNotSame(AdaptiveRiskEngine::networkBucket(self::HOME_IP), $tag, 'the tag is not the bucket spelling');
        // The bucket spelling stays the documented legacy field form.
        self::assertSame(self::LEGACY_LOOPBACK, AdaptiveRiskEngine::networkBucket(self::LOOPBACK));
        // Two hosts of one IPv6 /64 share the tag; another /64 differs.
        self::assertSame(
            $engine->networkTag(self::HOME_V6),
            $engine->networkTag(self::SIBLING_V6),
            'the /64 granularity is preserved: siblings share the tag',
        );
        self::assertNotSame(
            $engine->networkTag(self::HOME_V6),
            $engine->networkTag(self::OTHER_V6),
            'a different /64 derives a different tag',
        );
    }

    /**
     * The writer's stored shape: an Allow records the tag with the
     * trust mirror, and the bucket spelling is never a stored field.
     */
    public function testAnAllowRecordsTheTagAndNeverTheBucket(): void
    {
        $store = new NetworkTagMemoryStore();
        $engine = $this->engine($store, 'learn');
        $decision = $engine->reassess($this->loginContext(self::LOOPBACK));
        self::assertSame(RiskAction::Allow, $decision->action, 'learn mode allows the first login');

        $principal = $this->principalHex();
        $tag = $engine->networkTag(self::LOOPBACK);
        self::assertSame(self::TAG_LOOPBACK, $tag, 'the recorded tag is the pinned loopback tag');
        self::assertTrue($store->principalNetworkSeen($principal, $tag), 'the writer records the tag');
        self::assertTrue($store->tagIsTrusted($principal, $tag), 'the record mints the trust mirror');
        self::assertFalse(
            $store->principalNetworkSeen($principal, self::LEGACY_LOOPBACK),
            'the loopback bucket spelling is never a stored field',
        );
        self::assertSame(
            [$tag],
            $store->networkTags($principal),
            'the tag is the only network field the Allow wrote',
        );
    }

    /**
     * The canonical IPv6 spelling is the family byte plus all sixteen
     * masked bytes, byte-identical with the Rust network_bucket(). The
     * historical truncated /64 spelling stays readable as a legacy
     * form.
     */
    public function testTheIpv6BucketSpellingAndItsHistoricalForm(): void
    {
        self::assertSame(
            '0620010db8abcd12340000000000000000',
            AdaptiveRiskEngine::networkBucket(self::HOME_V6),
            'the canonical /64 spelling pads the masked bytes to full width',
        );

        $store = new NetworkTagMemoryStore();
        $engine = $this->engine($store, 'enforce');
        $principal = $this->principalHex();
        $historical = '0620010db8abcd1234';
        $store->recordPrincipalNetworkTag($principal, $historical, true);

        $decision = $engine->reassess($this->loginContext(self::HOME_V6));
        self::assertSame(
            RiskAction::Allow,
            $decision->action,
            'the historical truncated /64 spelling still vouches for the login',
        );
        self::assertFalse(
            $decision->hasReason(RiskReason::NovelNetwork),
            'the gate answers seen for the historical /64 spelling',
        );
        self::assertTrue(
            $store->principalNetworkSeen($principal, $engine->networkTag(self::HOME_V6)),
            'the Allow rewrites the network under the tag',
        );
    }

    /**
     * The gate verdict is identical for one bucket whichever form the
     * store holds: the stable tag or the legacy spelling. Run for IPv4
     * and for IPv6, the two granularities the gate judges.
     */
    public function testTheGateVerdictIsIdenticalForTheTagAndTheLegacyForm(): void
    {
        foreach ([self::HOME_IP, self::HOME_V6] as $ip) {
            $seenByTag = $this->verdictFor($ip, seedTag: true);
            $seenByLegacy = $this->verdictFor($ip, seedTag: false);
            self::assertSame(
                $seenByTag['action'],
                $seenByLegacy['action'],
                sprintf('the verdict for %s is the same for both stored forms', $ip),
            );
            self::assertSame($seenByTag['novel'], $seenByLegacy['novel']);
            self::assertSame(RiskAction::Allow, $seenByLegacy['action']);
            self::assertFalse($seenByLegacy['novel'], 'the established network is not novel');
        }
    }

    /**
     * @return array{action: RiskAction, novel: bool}
     */
    private function verdictFor(string $ip, bool $seedTag): array
    {
        $store = new NetworkTagMemoryStore();
        $engine = $this->engine($store, 'enforce');
        $principal = $this->principalHex();
        $seed = $seedTag ? $engine->networkTag($ip) : AdaptiveRiskEngine::networkBucket($ip);
        $store->recordPrincipalNetworkTag($principal, $seed, true);
        $decision = $engine->reassess($this->loginContext($ip));

        return ['action' => $decision->action, 'novel' => $decision->hasReason(RiskReason::NovelNetwork)];
    }

    /**
     * The production store's stored bytes for the loopback client: the
     * hash fields are the stable tag and its trust mirror, and the
     * bucket spelling is absent. Requires RISK_REDIS_URL.
     */
    public function testRealRedisStoresTheLoopbackTagNotTheBucket(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set');
        }
        $client = RedisRiskStateStore::createClient($url);
        $store = new RedisPrincipalNetworkTagStore(
            $client,
            'nettag-'.bin2hex(random_bytes(4)),
            sessionTtlMs: 3_600_000,
            deviceTtlMs: 7_776_000_000,
            sessionCap: 32,
            deviceCap: 16,
            netCap: 64,
        );
        $engine = $this->engine($store, 'learn');
        $decision = $engine->reassess($this->loginContext(self::LOOPBACK));
        self::assertSame(RiskAction::Allow, $decision->action);

        $principal = $this->principalHex();
        $tag = $engine->networkTag(self::LOOPBACK);
        $fields = (array) $client->hgetall($store->tagKey($principal));
        self::assertArrayHasKey($tag, $fields, 'the stored field is the stable tag');
        self::assertArrayHasKey('t:'.$tag, $fields, 'the trust mirror rides the tag');
        self::assertArrayNotHasKey(self::LEGACY_LOOPBACK, $fields, 'the loopback bucket spelling is not a field');
        self::assertArrayNotHasKey('t:'.self::LEGACY_LOOPBACK, $fields);
        $client->del($store->tagKey($principal));
    }

    /**
     * The upgrade path against the production store: a field written
     * under the legacy bucket spelling still answers seen, and the next
     * Allow rewrites the network under the tag. Requires
     * RISK_REDIS_URL.
     */
    public function testRealRedisLegacyFieldKeepsTheGateAnsweringSeen(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set');
        }
        $client = RedisRiskStateStore::createClient($url);
        $store = new RedisPrincipalNetworkTagStore(
            $client,
            'nettag-legacy-'.bin2hex(random_bytes(4)),
            sessionTtlMs: 3_600_000,
            deviceTtlMs: 7_776_000_000,
            sessionCap: 32,
            deviceCap: 16,
            netCap: 64,
        );
        $principal = $this->principalHex();
        $store->recordPrincipalNetworkTag($principal, self::LEGACY_LOOPBACK, true);

        $engine = $this->engine($store, 'enforce');
        $decision = $engine->reassess($this->loginContext(self::LOOPBACK));
        self::assertSame(
            RiskAction::Allow,
            $decision->action,
            'the legacy field still vouches for the login through the production store',
        );
        self::assertFalse($decision->hasReason(RiskReason::NovelNetwork));

        $fields = (array) $client->hgetall($store->tagKey($principal));
        self::assertArrayHasKey(
            $engine->networkTag(self::LOOPBACK),
            $fields,
            'the Allow rewrites the network under the tag',
        );
        self::assertArrayHasKey(self::LEGACY_LOOPBACK, $fields, 'the legacy field stays readable');
        $client->del($store->tagKey($principal));
    }

    /**
     * The upgrade path: a field recorded under the legacy bucket
     * spelling still answers seen, and the next Allow rewrites the
     * network under the tag.
     */
    public function testLegacyBucketHistoryIsSeenAndRewrittenUnderTheTag(): void
    {
        $store = new NetworkTagMemoryStore();
        $engine = $this->engine($store, 'enforce');
        $principal = $this->principalHex();
        $store->recordPrincipalNetworkTag($principal, self::LEGACY_LOOPBACK, true);

        $decision = $engine->reassess($this->loginContext(self::LOOPBACK));
        self::assertSame(
            RiskAction::Allow,
            $decision->action,
            'the legacy field still vouches for the login under enforce mode',
        );
        self::assertFalse(
            $decision->hasReason(RiskReason::NovelNetwork),
            'the gate answers seen for the legacy bucket spelling',
        );

        $tag = $engine->networkTag(self::LOOPBACK);
        self::assertTrue(
            $store->principalNetworkSeen($principal, $tag),
            'the Allow rewrites the network under the stable tag',
        );
        self::assertTrue($store->tagIsTrusted($principal, $tag), 'the rewrite mints the trust mirror');
        self::assertContains(
            self::LEGACY_LOOPBACK,
            $store->networkTags($principal),
            'the legacy field itself stays readable until its own expiry',
        );
    }
}

/**
 * In-memory principal-network tag store: seen-ness and the trust
 * mirrors, with the network-class trust probe of the canonical script
 * (a bare-hex field counts, exactly like the net and asn classes).
 */
final class NetworkTagMemoryStore implements PrincipalNetworkTagStoreInterface
{
    /** @var array<string, array<string, true>> */
    private array $tags = [];

    /** @var array<string, array<string, true>> */
    private array $trusted = [];

    public function principalNetworkSeen(string $principalId, string $network): ?bool
    {
        return isset($this->tags[$principalId][$network]);
    }

    public function recordPrincipalNetworkTag(string $principalId, string $network, bool $trusted = false): bool
    {
        $isNew = !isset($this->tags[$principalId][$network]);
        $this->tags[$principalId][$network] = true;
        if ($trusted) {
            $this->trusted[$principalId][$network] = true;
        }

        return $isNew;
    }

    public function principalHasTrustedNetwork(string $principalId): ?bool
    {
        foreach (array_keys($this->trusted[$principalId] ?? []) as $tag) {
            $networkClass = str_starts_with($tag, 'net:')
                || str_starts_with($tag, 'asn:')
                || preg_match('/^[0-9a-f]+$/', $tag) === 1;
            if ($networkClass) {
                return true;
            }
        }

        return false;
    }

    public function tagIsTrusted(string $principalId, string $network): ?bool
    {
        return isset($this->tags[$principalId][$network]) && isset($this->trusted[$principalId][$network]);
    }

    public function forgetDevices(string $principalId): void
    {
        foreach (array_keys($this->tags[$principalId] ?? []) as $tag) {
            if (str_starts_with($tag, 'session:') || str_starts_with($tag, 'device:')) {
                unset($this->tags[$principalId][$tag]);
            }
        }
    }

    /** @return list<string> the recorded network-class fields, sorted */
    public function networkTags(string $principalId): array
    {
        $tags = [];
        foreach (array_keys($this->tags[$principalId] ?? []) as $tag) {
            if (str_starts_with($tag, 'session:') || str_starts_with($tag, 'device:')) {
                continue;
            }
            $tags[] = $tag;
        }
        sort($tags);

        return $tags;
    }
}
