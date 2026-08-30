<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailingRedisTestKernel;
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
}
