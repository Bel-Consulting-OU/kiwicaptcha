<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RedisDsnTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\TestKernel;
use KiwiCaptcha\Challenge;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * real-redis DSN integration test (CI service container: redis:7).
 *
 * Skipped unless KC_REDIS_URL is set (e.g. redis://127.0.0.1:6399). A
 * kernel wired only through the high-level redis_dsn setting must build
 * a working challenge storage, rate limiter, Argon admission and risk
 * Redis. The container's DSN-built services drive a full issuance ->
 * solve -> verification round trip, and the doctor command reports the
 * DSN-backed Redis reachable.
 */
final class RealRedisDsnIntegrationTest extends TestCase
{
    private function redisUrl(): string
    {
        $url = getenv('KC_REDIS_URL');
        if ($url === false || $url === '') {
            $url = getenv('TEST_REDIS_URL');
        }
        if ($url === false || $url === '') {
            self::markTestSkipped('KC_REDIS_URL not set — real-Redis DSN integration test skipped');
        }

        return $url;
    }

    private function solveToken(Challenge $challenge): string
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    public function testIssuanceAndVerificationRoundTripThroughTheDsnBuiltServices(): void
    {
        $kernel = new RedisDsnTestKernel('test', true, $this->redisUrl());
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        try {
            $client = $container->get('kiwi_captcha.redis.dsn');
            self::assertInstanceOf(\Predis\Client::class, $client, 'the DSN-built client is a Predis client');
            $client->flushdb();

            // The DSN-built challenge storage is a real RedisStorage over
            // the DSN client, and the issuer/verifier consume it.
            $storage = $container->get('kiwi_captcha.storage.redis_dsn');
            self::assertInstanceOf(\KiwiCaptcha\Storage\RedisStorage::class, $storage);

            $issuer = $container->get('kiwi_captcha.issuer');
            $challenge = $issuer->issue('login', '198.51.100.7');
            $this->waitOutMinDuration($challenge);
            $token = $this->solveToken($challenge);

            $verifier = $container->get('kiwi_captcha.verifier');
            $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
            $outcome = $verifier->verify($token, TestKernel::SECRET, 'login', '198.51.100.7', $nowNs);
            self::assertTrue($outcome->isOk(), sprintf('the DSN-built round trip must verify, got %s', $outcome->code()));

            // The distributed rate limiter and the Argon admission are
            // wired on the DSN client (the production guards are
            // satisfied by the DSN alone).
            self::assertTrue($container->has('kiwi_captcha.rate_limiter'), 'the atomic rate limiter is wired over the DSN client');
            self::assertTrue($container->has('kiwi_captcha.argon2_redis_semaphore'), 'the Argon admission semaphore is wired over the DSN client');
        } finally {
            $kernel->shutdown();
        }
    }

    public function testDoctorReportsTheDsnBackedRedisReachable(): void
    {
        $kernel = new RedisDsnTestKernel('test', true, $this->redisUrl());
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        try {
            $command = $container->get(KiwiCaptchaDoctorCommand::class);
            self::assertInstanceOf(KiwiCaptchaDoctorCommand::class, $command);
            $tester = new CommandTester($command);
            $tester->execute([]);

            self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'no FAIL means exit 0');
            $display = $tester->getDisplay();
            self::assertStringContainsString('[PASS] Redis reachability', $display, 'the DSN-backed client answers PING');
            self::assertStringContainsString('[PASS] Storage atomicity', $display, 'the DSN-built RedisStorage is atomic');
            self::assertStringNotContainsString('[FAIL]', $display, 'the DSN-wired kernel must not FAIL any check');
        } finally {
            $kernel->shutdown();
        }
    }

    /**
     * The core enforces the minimum solve duration with a server-measured
     * clock; tests issue and verify in the same process, so wait out the
     * floor before submitting.
     */
    private function waitOutMinDuration(Challenge $challenge): void
    {
        usleep(($challenge->minDurationMs + 10) * 1000);
    }
}
