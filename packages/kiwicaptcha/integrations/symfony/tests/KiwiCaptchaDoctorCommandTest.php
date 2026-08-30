<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailingRedisTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorRedisStorageNoWaitKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorSentinelRedisTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\TestKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Kernel-based tests of kiwicaptcha:doctor: the command runs against
 * the real container the extension wired, reports one status per check,
 * and exits non-zero when any check fails.
 */
final class KiwiCaptchaDoctorCommandTest extends TestCase
{
    private function doctor(ContainerInterface $container): CommandTester
    {
        $command = $container->get(KiwiCaptchaDoctorCommand::class);
        self::assertInstanceOf(KiwiCaptchaDoctorCommand::class, $command);

        return new CommandTester($command);
    }

    private function containerFor(\Symfony\Component\HttpKernel\Kernel $kernel): ContainerInterface
    {
        $kernel->boot();

        return $kernel->getContainer()->get('test.service_container');
    }

    public function testCommandIsRegisteredWithTheConsoleTag(): void
    {
        // The extension's load() is the single source of the registration
        // (the pattern used by every wiring test in this suite).
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', sys_get_temp_dir());
        (new KiwiCaptchaExtension())->load([['secret_key' => str_repeat('a', 32)]], $container);
        $definition = $container->getDefinition(KiwiCaptchaDoctorCommand::class);
        self::assertTrue($definition->hasTag('console.command'), 'the doctor must be registered as a console command');

        $kernel = new TestKernel('test', true);
        $kernel->boot();
        $command = $kernel->getContainer()->get('test.service_container')->get(KiwiCaptchaDoctorCommand::class);
        self::assertSame('kiwicaptcha:doctor', $command->getName());
    }

    public function testDoctorPassesOrWarnsOnTheDefaultTestKernel(): void
    {
        $tester = $this->doctor($this->containerFor(new TestKernel('test', true)));
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), 'no FAIL means exit 0');
        $display = $tester->getDisplay();

        // pass paths on the default kernel.
        self::assertStringContainsString('[PASS] Storage atomicity', $display);
        self::assertStringContainsString('[PASS] Replication topology', $display, 'the default kernel has no Redis-backed storage and no aggregate client, so the authority-boundary check passes');
        self::assertStringContainsString('[PASS] Secret key', $display);
        self::assertStringContainsString('[PASS] Keyring state', $display);
        self::assertStringContainsString('[PASS] Public origin', $display);
        self::assertStringContainsString('[PASS] Risk Redis', $display);
        self::assertStringContainsString('[PASS] Protocol floor', $display);
        self::assertStringContainsString('[PASS] Protocol-v3 writer', $display);
        self::assertStringContainsString('[PASS] Argon memory envelope', $display);
        self::assertStringContainsString('[PASS] Argon concurrency', $display);
        self::assertStringContainsString('[PASS] SiteVerify status', $display);
        self::assertStringContainsString('[PASS] Chained challenges', $display);

        // warn paths: no Redis client, no trusted proxy,
        // unverifiable CSP, dev install versions.
        self::assertStringContainsString('[WARN] Redis reachability', $display);
        self::assertStringContainsString('[WARN] Client-IP policy', $display);
        self::assertStringContainsString('[WARN] CSP compatibility', $display);
        self::assertStringContainsString('[WARN] Release versions', $display);

        self::assertStringNotContainsString('[FAIL]', $display, 'the default test kernel must not FAIL any check');
        self::assertStringContainsString('Summary: ', $display);
    }

    public function testDoctorFailsWithANonZeroExitCodeWhenRedisIsUnreachable(): void
    {
        $tester = $this->doctor($this->containerFor(new DoctorFailingRedisTestKernel('test', true)));
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'a FAIL must produce a non-zero exit code');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] Redis reachability', $display);
        self::assertStringContainsString('[FAIL] Risk Redis', $display, 'the risk Redis ping uses the same broken client');
        self::assertStringContainsString('Summary: ', $display);
    }

    public function testDoctorWarnsOnASentinelAggregateWiredClient(): void
    {
        // The replication-topology check must detect the Predis
        // Sentinel replication aggregate by client class and emit the
        // explicit authority-change contract warning with the
        // documented postures, without a live sentinel (the aggregate
        // is built lazily; the reachability check fails on PING as in
        // the failing-Redis kernel).
        $tester = $this->doctor($this->containerFor(new DoctorSentinelRedisTestKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Replication topology', $display, 'an aggregate client must warn on the replication-topology check');
        self::assertStringContainsString('SentinelReplication', $display, 'the detection must name the wired aggregate class');
        self::assertStringContainsString(
            'One-shot verification is atomic on the current Redis authority but is not guaranteed across stale-replica promotion',
            $display,
            'the WARN must carry the exact audit contract wording',
        );
        self::assertStringContainsString('fail_closed / operator_managed / best_effort', $display, 'the WARN must name the documented deployment postures');
    }

    public function testDoctorWarnsOnRedisBackedStorageWithoutTheVerifiedWaitKnob(): void
    {
        // Redis-backed storage with waitReplicas 0 is the default
        // production shape: the promotion boundary applies and the
        // check must warn with the exact audit contract wording, even
        // though the wired client is a single-node direct connection.
        $tester = $this->doctor($this->containerFor(new DoctorRedisStorageNoWaitKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Replication topology', $display, 'Redis-backed storage with waitReplicas 0 must warn on the replication-topology check');
        self::assertStringContainsString('waitReplicas 0', $display);
        self::assertStringContainsString(
            'One-shot verification is atomic on the current Redis authority but is not guaranteed across stale-replica promotion',
            $display,
            'the WARN must carry the exact audit contract wording',
        );
    }
}
