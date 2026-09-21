<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\RedisNamespace;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Cross-component deployment-namespace isolation: the raw configured
 * namespace is an identity discriminator, and every key family derives
 * its Redis-safe segment from the complete original bytes. Both
 * collision classes a replacement-sanitized derivation could never
 * distinguish must keep independent budgets and disjoint key families
 * in the rate limiter (the PSR-6 and the Redis path alike) and the
 * Argon admission semaphore. The classes: namespaces differing only
 * in a separator versus an underscore (tenant/a versus tenant:a), and
 * project directories differing only in where the separator sits
 * (/a/b_c versus /a_b/c, the shape the kernel.project_dir default
 * produces).
 */
final class NamespaceIsolationTest extends TestCase
{
    /** @return list<array{0: string, 1: string}> */
    public static function provideCollidingPairs(): array
    {
        return [
            ['tenant/a', 'tenant:a'],
            ['/a/b_c', '/a_b/c'],
        ];
    }

    /**
     * @dataProvider provideCollidingPairs
     */
    public function testTheDerivationDistinguishesEveryCollidingPair(string $a, string $b): void
    {
        self::assertNotSame(RedisNamespace::derive($a), RedisNamespace::derive($b));
    }

    public function testTheDerivationRefusesTheEmptyNamespace(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        RedisNamespace::derive('');
    }

    public function testTheDerivationFallbackIsExplicit(): void
    {
        self::assertSame(RedisNamespace::derive('fallback'), RedisNamespace::deriveOr('', 'fallback'));
        self::assertSame(RedisNamespace::derive('raw'), RedisNamespace::deriveOr('raw', 'fallback'));
    }

    /**
     * @dataProvider provideCollidingPairs
     */
    public function testThePsr6RateLimiterKeepsIndependentBudgets(string $a, string $b): void
    {
        $pool = new ArrayAdapter();
        $clock = 10_000.0;
        $now = static function () use (&$clock): float {
            return $clock;
        };
        $la = new IssuanceRateLimiter(100, 60, $pool, $now, 'pepper', null, 2, $a);
        $lb = new IssuanceRateLimiter(100, 60, $pool, $now, 'pepper', null, 2, $b);

        self::assertSame(1, $la->check('198.51.100.1'));
        self::assertSame(1, $la->check('198.51.100.2'));
        self::assertSame(-1, $la->check('198.51.100.3'), 'the first namespace hits its own global cap');
        self::assertSame(1, $lb->check('198.51.100.1'), 'the colliding-before-derivation namespace keeps its own budget');
        self::assertSame(1, $lb->check('198.51.100.2'));
        self::assertSame(-1, $lb->check('198.51.100.3'), 'the second namespace now hits its own cap');
        self::assertSame(-1, $la->check('198.51.100.4'), 'the first namespace stays saturated: the state never merged');
    }

    /**
     * @dataProvider provideCollidingPairs
     */
    public function testTheSemaphoreKeyFamiliesAreDisjoint(string $a, string $b): void
    {
        $keysA = $this->acquiredKeys($a);
        $keysB = $this->acquiredKeys($b);
        self::assertNotSame([], $keysA);
        foreach ($keysB as $key) {
            self::assertNotContains($key, $keysA, 'no lease-family key of one namespace appears in the colliding namespace family');
        }
    }

    /**
     * @return list<string> every script key one scoped acquire touches
     */
    private function acquiredKeys(string $namespace): array
    {
        $client = new FakePredisClient();
        $semaphore = new RedisAdmissionSemaphore($client, 4, $namespace);
        $lease = $semaphore->acquire('login');
        self::assertNotNull($lease);
        $keys = [];
        foreach ($client->calls as [$cmd, $arguments]) {
            if ($cmd !== 'EVAL' && $cmd !== 'EVALSHA') {
                continue;
            }
            $numKeys = (int) $arguments[1];
            foreach (\array_slice($arguments, 2, $numKeys) as $key) {
                $keys[] = (string) $key;
            }
        }

        return array_values(array_unique($keys));
    }
}
