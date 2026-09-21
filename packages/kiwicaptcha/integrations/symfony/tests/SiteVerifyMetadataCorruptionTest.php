<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataCorruptException;
use PHPUnit\Framework\TestCase;

/**
 * The corrupt-persisted-state contract of the siteverify metadata.
 * A present value of the wrong type, a value outside its request
 * grammar, or an impossible chain-coordinate pair is corrupt stored
 * state and throws at decode: never silently normalized into an
 * absent field that would answer replays with emptied metadata.
 * Absent or null keys keep their legacy defaults. The Redis-backed
 * matrix proves the same verdicts hold through the real store round
 * trip, surfacing as the store's documented corrupt exception (the
 * controller's catch-all answers its retryable internal-error
 * response).
 */
final class SiteVerifyMetadataCorruptionTest extends TestCase
{
    /** @return list<array{0: string, 1: array<string, mixed>}> */
    public static function provideCorruptShapes(): array
    {
        return [
            'action as int' => ['action', ['v' => 1, 'action' => 123, 'chainId' => 123, 'chainDepth' => '2']],
            'chainId as int' => ['chainId', ['v' => 1, 'chainId' => 123]],
            'chainDepth as string' => ['chainDepth', ['v' => 1, 'chainDepth' => '2']],
            'cdata as float' => ['cdata', ['v' => 1, 'cdata' => 1.5]],
            'scope as bool' => ['scope', ['v' => 1, 'scope' => true]],
            'sitekey as array' => ['sitekey', ['v' => 1, 'sitekey' => ['x']]],
            'action outside its grammar' => ['action', ['v' => 1, 'action' => str_repeat('x', 33)]],
            'action with spaces' => ['action', ['v' => 1, 'action' => 'log in']],
            'cdata outside its grammar' => ['cdata', ['v' => 1, 'cdata' => str_repeat('x', 256)]],
            'scope outside the identifier grammar' => ['scope', ['v' => 1, 'scope' => 'not a scope!']],
            'chainDepth one' => ['chainDepth', ['v' => 1, 'chainDepth' => 1]],
            'chainDepth three' => ['chainDepth', ['v' => 1, 'chainDepth' => 3]],
            'depth without an id' => ['pair', ['v' => 1, 'chainDepth' => 2]],
            'id without depth two' => ['pair', ['v' => 1, 'chainId' => 'chain-1', 'chainDepth' => 0]],
        ];
    }

    /**
     * @dataProvider provideCorruptShapes
     */
    public function testWrongTypeOrImpossibleCombinationThrowsAtDecode(string $label, array $data): void
    {
        try {
            SiteVerifyMetadata::fromArray($data);
            self::fail("the corrupt shape '{$label}' must throw at decode");
        } catch (SiteVerifyMetadataCorruptException $e) {
            self::assertStringContainsString('metadata', $e->getMessage());
        }
    }

    public function testAbsentAndNullKeysKeepTheirLegacyDefaults(): void
    {
        // Records persisted before a field existed parse unchanged.
        $meta = SiteVerifyMetadata::fromArray(['v' => 1]);
        self::assertNull($meta);

        $withNulls = SiteVerifyMetadata::fromArray(['v' => 1, 'action' => null, 'chainId' => null, 'chainDepth' => null]);
        self::assertNull($withNulls);

        $legacy = SiteVerifyMetadata::fromArray(['action' => 'login-action', 'cdata' => 'order-77']);
        self::assertNotNull($legacy);
        self::assertSame('login-action', $legacy->action);
        self::assertSame('order-77', $legacy->cdata);
        self::assertNull($legacy->chainId);
        self::assertSame(0, $legacy->chainDepth);

        $chained = SiteVerifyMetadata::fromArray(['v' => 1, 'chainId' => 'chain-1', 'chainDepth' => 2]);
        self::assertSame('chain-1', $chained->chainId);
        self::assertSame(2, $chained->chainDepth);
    }

    public function testTheRedisRoundTripThrowsTheSameVerdictsOnRealRedis(): void
    {
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
            if (\is_string($flag) && $flag !== '' && $flag !== '0') {
                self::fail('KIWI_REQUIRE_REAL_REDIS_TESTS is set but KC_REDIS_URL is absent');
            }
            self::markTestSkipped('KC_REDIS_URL is not set');
        }
        $client = new \Predis\Client(['host' => parse_url($url, PHP_URL_HOST) ?: '127.0.0.1', 'port' => parse_url($url, PHP_URL_PORT) ?: 6379]);
        $store = new RedisSiteVerifyMetadataStore($client, 'kiwitest:meta-corrupt:'.getmypid());
        $nonce = base64_encode(random_bytes(32));

        $store->store($nonce, new SiteVerifyMetadata('login-action', 'order-77', null, null, 0, 'login'), 120);
        $read = $store->find($nonce);
        self::assertNotNull($read);
        self::assertSame('login-action', $read->action);

        // Corrupt the persisted JSON in place: wrong types and an
        // impossible chain pair both surface as the store's corrupt
        // exception, never as emptied metadata.
        $key = '{kiwitest:meta-corrupt:'.getmypid().'}:siteverify-meta:'.$nonce;
        foreach ([
            ['v' => 1, 'action' => 123, 'chainId' => 123, 'chainDepth' => '2'],
            ['v' => 1, 'chainDepth' => 2],
            ['v' => 1, 'chainId' => 'chain-9', 'chainDepth' => 0],
            ['v' => 1, 'action' => str_repeat('x', 33)],
        ] as $corrupt) {
            $client->set($key, json_encode($corrupt, JSON_THROW_ON_ERROR));
            try {
                $store->find($nonce);
                self::fail('the corrupt persisted shape must surface as the corrupt exception');
            } catch (SiteVerifyMetadataCorruptException) {
            }
        }
        $client->del([$key]);
    }
}
