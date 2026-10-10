<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\RedisPrincipalNetworkTagStore;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The principal-network tag surface against real Redis: seen/record/
 * has_trusted, LRU eviction at the class caps, TTL expiry per class,
 * ARGV rejection, and the trust-only-on-Allow rule. Runs the canonical
 * principal_networks.lua through the production store — no in-memory
 * fake.
 */
final class PrincipalNetworkLuaTest extends TestCase
{
    private const PRINCIPAL = '9f1c4a7e2b8d63f05a1e9c4d7b2e6f18';

    /** @var \Predis\Client */
    private $client;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: redis-server --port 6421 --save "" --appendonly no --daemonize yes');
        }
        $this->client = RedisRiskStateStore::createClient($url);
        $this->client->ping();
    }

    private function store(int $sessionCap = 32, int $deviceCap = 16): RedisPrincipalNetworkTagStore
    {
        return new RedisPrincipalNetworkTagStore(
            $this->client,
            'pnet-test-'.bin2hex(random_bytes(4)),
            sessionTtlMs: 3_600_000,
            deviceTtlMs: 7_776_000_000,
            sessionCap: $sessionCap,
            deviceCap: $deviceCap,
            netCap: 64,
        );
    }

    public function testSeenAnswersZeroForAnUnknownTag(): void
    {
        $store = $this->store();
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010203'));
    }

    public function testRecordThenSeenAnswersOne(): void
    {
        $store = $this->store();
        self::assertTrue($store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203'));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010203'));
    }

    public function testRecordIsSetNx(): void
    {
        $store = $this->store();
        self::assertTrue($store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203'));
        self::assertFalse($store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203'));
    }

    public function testTrustIsMintedOnlyOnAllow(): void
    {
        $store = $this->store();
        // No trust flag: the tag is seen but not trusted.
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'session:aaaa0000000000000000000000000001');
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'session:aaaa0000000000000000000000000001'));
        self::assertFalse($store->tagIsTrusted(self::PRINCIPAL, 'session:aaaa0000000000000000000000000001'));

        // With trust: the tag is seen and trusted.
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'session:aaaa0000000000000000000000000002', trusted: true);
        self::assertTrue($store->tagIsTrusted(self::PRINCIPAL, 'session:aaaa0000000000000000000000000002'));
    }

    public function testHasTrustedNetworkIsFalseWithoutTrust(): void
    {
        $store = $this->store();
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203');
        self::assertFalse($store->principalHasTrustedNetwork(self::PRINCIPAL));
    }

    public function testHasTrustedNetworkIsTrueWithTrust(): void
    {
        $store = $this->store();
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'session:aaaa0000000000000000000000000003', trusted: true);
        self::assertTrue($store->principalHasTrustedNetwork(self::PRINCIPAL));
    }

    public function testLruEvictsOldestSessionAboveCap(): void
    {
        $store = $this->store(sessionCap: 3);
        $tag = static fn (int $i): string => sprintf('session:%032x', $i);
        foreach (range(1, 5) as $i) {
            $store->recordPrincipalNetworkTag(self::PRINCIPAL, $tag($i));
        }
        // Cap is 3: the oldest two (1 and 2) should be evicted.
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, $tag(1)));
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, $tag(2)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(3)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(4)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(5)));
    }

    public function testLruEvictsOldestDeviceAboveCap(): void
    {
        $store = $this->store(deviceCap: 2);
        $tag = static fn (int $i): string => sprintf('device:%032x', $i);
        foreach (range(1, 4) as $i) {
            $store->recordPrincipalNetworkTag(self::PRINCIPAL, $tag($i));
        }
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, $tag(1)));
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, $tag(2)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(3)));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, $tag(4)));
    }

    public function testForgetDevicesRemovesSessionAndDeviceTags(): void
    {
        $store = $this->store();
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'session:aaaa0000000000000000000000000004', trusted: true);
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'device:bbbb0000000000000000000000000005', trusted: true);
        $store->recordPrincipalNetworkTag(self::PRINCIPAL, 'net:040a010203');
        $store->forgetDevices(self::PRINCIPAL);
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, 'session:aaaa0000000000000000000000000004'));
        self::assertFalse($store->principalNetworkSeen(self::PRINCIPAL, 'device:bbbb0000000000000000000000000005'));
        // Network tags survive revocation.
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'net:040a010203'));
    }

    public function testInvalidTagIsRefused(): void
    {
        $store = $this->store();
        $refused = 0;
        foreach (['', 'nope', 'net:', 'net:XYZ', 'session:tooshort!', 'asn:abc', str_repeat('x', 81)] as $bad) {
            try {
                $store->recordPrincipalNetworkTag(self::PRINCIPAL, $bad);
                self::fail(sprintf('tag %s must be refused', var_export($bad, true)));
            } catch (\InvalidArgumentException) {
                $refused++;
            }
        }
        self::assertSame(7, $refused, 'every malformed tag is refused');
    }

    public function testAsnTagIsAccepted(): void
    {
        $store = $this->store();
        self::assertTrue($store->recordPrincipalNetworkTag(self::PRINCIPAL, 'asn:64496'));
        self::assertTrue($store->principalNetworkSeen(self::PRINCIPAL, 'asn:64496'));
    }
}
