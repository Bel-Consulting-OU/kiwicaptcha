<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorBestEffortSentinelTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorExplicitV3WriterKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailClosedClusterTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailClosedSentinelTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailClosedSingleNodeTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorFailingRedisTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorHighAbuseDecoyDeferredKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorHighAbuseV3WriterKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorNullClearedProfileV3WriterKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorOperatorManagedSentinelTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorRedisStorageNoWaitKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorRedisStorageNoWaitOperatorManagedKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorSentinelRedisTestKernel;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\DoctorV3WriterTestKernel;
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

    /**
     * Load the extension against a container holding an aggregate
     * client definition registered beforehand, the shape the
     * build-time fail_closed refusal must classify.
     *
     * @param array{0: array, 1: array} $arguments Predis constructor args
     *
     * @return \LogicException the refused-build exception
     */
    private function assertFailClosedBuildRefusal(string $serviceId, array $arguments, string $expectedClass): \LogicException
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', sys_get_temp_dir());
        $container->register($serviceId, \Predis\Client::class)
            ->setArguments($arguments)
            ->setPublic(true);
        try {
            (new KiwiCaptchaExtension())->load([[
                'secret_key' => str_repeat('a', 32),
                'replay_durability' => 'fail_closed',
                'redis_service' => $serviceId,
            ]], $container);
            self::fail(sprintf('fail_closed with an aggregate client (%s) must refuse the container build', $expectedClass));
        } catch (\LogicException $e) {
            self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage(), 'the refusal must name the posture');
            self::assertStringContainsString('pinned-primary/topology adapter', $e->getMessage(), 'the refusal must offer the pinned-primary remediation');
            self::assertStringContainsString('operator_managed', $e->getMessage(), 'the refusal must name the operator_managed alternative');
            self::assertStringContainsString('best_effort', $e->getMessage(), 'the refusal must name the best_effort alternative');

            return $e;
        }
    }

    public function testFailClosedRefusesTheSentinelAggregateAtContainerBuildTime(): void
    {
        $e = $this->assertFailClosedBuildRefusal('doctor.sentinel.redis', [[
            ['scheme' => 'tcp', 'host' => '127.0.0.1', 'port' => 6398, 'timeout' => 0.5],
        ], [
            'replication' => 'sentinel',
            'service' => 'mymaster',
        ]], 'Sentinel replication');

        self::assertStringContainsString('replication aggregate (Sentinel or master-slave)', $e->getMessage(), 'the refusal must name the aggregate class');
    }

    public function testFailClosedRefusesTheClusterAggregateAtContainerBuildTime(): void
    {
        $e = $this->assertFailClosedBuildRefusal('doctor.cluster.redis', [[
            'tcp://127.0.0.1:7001',
            'tcp://127.0.0.1:7002',
        ], [
            'cluster' => 'redis',
        ]], 'Redis Cluster');

        self::assertStringContainsString('Predis Redis Cluster aggregate', $e->getMessage(), 'the refusal must name the cluster aggregate');
    }

    public function testFailClosedRefusesTheSentinelAggregateAtKernelBoot(): void
    {
        $kernel = new DoctorFailClosedSentinelTestKernel('test', true);
        try {
            $kernel->boot();
            self::fail('fail_closed with a sentinel aggregate must refuse the kernel boot');
        } catch (\LogicException $e) {
            self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage());
            self::assertStringContainsString('pinned-primary/topology adapter', $e->getMessage());
        }
    }

    public function testFailClosedRefusesTheClusterAggregateAtKernelBoot(): void
    {
        $kernel = new DoctorFailClosedClusterTestKernel('test', true);
        try {
            $kernel->boot();
            self::fail('fail_closed with a cluster aggregate must refuse the kernel boot');
        } catch (\LogicException $e) {
            self::assertStringContainsString('replay_durability is "fail_closed"', $e->getMessage());
            self::assertStringContainsString('Predis Redis Cluster aggregate', $e->getMessage());
        }
    }

    public function testFailClosedSingleNodeCompilesAndTheDoctorPassesReplicationTopology(): void
    {
        // Single-node direct clients are fine under every posture: the
        // build accepts the wiring and the doctor reports the topology
        // check PASSing with the posture noted.
        $tester = $this->doctor($this->containerFor(new DoctorFailClosedSingleNodeTestKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Replication topology', $display, 'fail_closed with a single-node direct client must pass the topology check');
        self::assertStringContainsString('replay_durability "fail_closed"', $display, 'the PASS must note the posture');
    }

    public function testOperatorManagedSentinelAggregateCompilesAndTheDoctorPasses(): void
    {
        // operator_managed owns promotion eligibility: the build
        // accepts the aggregate and the doctor reports pass with the
        // operator contract noted, never the best_effort warn.
        $tester = $this->doctor($this->containerFor(new DoctorOperatorManagedSentinelTestKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Replication topology', $display, 'operator_managed with an aggregate must pass the topology check');
        self::assertStringContainsString('replay_durability "operator_managed"', $display);
        self::assertStringContainsString('owns promotion eligibility', $display, 'the PASS must keep the operator contract note');
        self::assertStringNotContainsString('[WARN] Replication topology', $display);
    }

    public function testBestEffortSentinelAggregateCompilesAndTheDoctorWarns(): void
    {
        // The explicit best_effort posture is the current boundary: the
        // build accepts the aggregate and the doctor keeps the warn
        // with the posture named.
        $tester = $this->doctor($this->containerFor(new DoctorBestEffortSentinelTestKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Replication topology', $display, 'best_effort with an aggregate must keep the topology WARN');
        self::assertStringContainsString('replay_durability is "best_effort"', $display, 'the WARN must name the chosen posture');
        self::assertStringContainsString('fail_closed / operator_managed / best_effort', $display);
    }

    public function testOperatorManagedRedisBackedStorageWithoutTheWaitKnobPasses(): void
    {
        // A single-node direct client under operator_managed: the
        // operator owns the authority-change contract, so the
        // waitReplicas-0 warn becomes a pass with the contract noted.
        $tester = $this->doctor($this->containerFor(new DoctorRedisStorageNoWaitOperatorManagedKernel('test', true)));
        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Replication topology', $display, 'operator_managed with Redis-backed storage at waitReplicas 0 must pass');
        self::assertStringContainsString('waitReplicas 0', $display);
        self::assertStringContainsString('operator_managed', $display);
    }

    /**
     * Seed the fake security Redis' central policy hash with a
     * `min_protocol_version` floor, the same `{kiwi:<ns>}:security-policy`
     * read the doctor's protocol-floor and protocol-v3 writer checks
     * consume through the SecurityEpochMonitor.
     */
    private function seedProtocolFloor(ContainerInterface $container, int $floor): void
    {
        $fake = $container->get(DoctorV3WriterTestKernel::FAKE_REDIS_ID);
        self::assertInstanceOf(FakePredisClient::class, $fake);
        $fake->hashes[DoctorV3WriterTestKernel::POLICY_KEY] = [
            'min_protocol_version' => (string) $floor,
        ];
    }

    public function testDoctorFailsOnHighAbuseWithAnAbsentProtocolFloor(): void
    {
        // high_abuse promises the decoy surface; without a confirmed
        // central floor the writer silently falls back to v2, so the
        // doctor must fail with the exact message and remediation and
        // exit non-zero, or an operator could ship with the decoy layer
        // inactive while the recommended deploy check passes.
        $tester = $this->doctor($this->containerFor(new DoctorHighAbuseV3WriterKernel('test', true)));
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'high_abuse with an unconfirmed floor must produce a non-zero exit code');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] Protocol-v3 writer', $display);
        self::assertStringContainsString('high_abuse requires authenticated decoy emission, but the fleet protocol floor has not been confirmed at v3.', $display, 'the FAIL must carry the exact audit message');
        self::assertStringContainsString(
            'Confirm every serving binary supports protocol v3 and raise the central security-policy min_protocol_version to 3 (the two-phase rollout, see operations.md), or explicitly set risk.decoy_v3_enabled: false to defer v3 emission while the profile stays active.',
            $display,
            'the FAIL must carry the remediation line',
        );
    }

    public function testDoctorFailsOnHighAbuseWithAFloorBelowThree(): void
    {
        $container = $this->containerFor(new DoctorHighAbuseV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode(), 'a sub-v3 floor under high_abuse must fail the deploy gate');
        $display = $tester->getDisplay();
        self::assertStringContainsString('[FAIL] Protocol-v3 writer', $display);
        self::assertStringContainsString('high_abuse requires authenticated decoy emission, but the fleet protocol floor has not been confirmed at v3.', $display);
    }

    public function testDoctorPassesOnHighAbuseWithAConfirmedV3Floor(): void
    {
        $container = $this->containerFor(new DoctorHighAbuseV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 3);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[PASS] Protocol-v3 writer', $display);
        self::assertStringContainsString('decoy surface armed and the central floor confirms protocol v3 emission', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorWarnsOnHighAbuseWithTheDecoyExplicitlyDeferred(): void
    {
        // An explicit risk.decoy_v3_enabled: false under high_abuse is
        // the documented deferral: the check must warn (exit 0), never
        // fail, so the two-phase rollout stays safe and the deploy gate
        // stays green for an explicit, informed choice.
        $container = $this->containerFor(new DoctorHighAbuseDecoyDeferredKernel('test', true));
        $this->seedProtocolFloor($container, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Protocol-v3 writer', $display);
        self::assertStringContainsString('risk.decoy_v3_enabled is explicitly false: protocol v3 emission is deferred while the profile stays active', $display);
        self::assertStringNotContainsString('[FAIL] Protocol-v3 writer', $display);
    }

    public function testDoctorWarnsOnExplicitDecoyWithoutTheHighAbuseProfile(): void
    {
        // The safe two-phase rollout: a non-high_abuse deployment with
        // an explicit writer switch and a sub-v3 floor keeps the
        // historical warn (exit 0); the doctor never auto-raises the
        // fleet floor.
        $container = $this->containerFor(new DoctorExplicitV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Protocol-v3 writer', $display);
        self::assertStringContainsString('finish the two-phase rollout before expecting decoy-armed emission', $display);
        self::assertStringNotContainsString('[FAIL]', $display);
    }

    public function testDoctorWarnsOnANullClearedProfileWithTheExplicitDecoyOverride(): void
    {
        // The profile is the lowest-precedence layer: a later layer
        // clearing the profile (protection_profile: null) plus the
        // explicit decoy override must resolve to the final processed
        // values (no high_abuse, decoy on), so the writer check warns
        // like any non-high_abuse deployment instead of failing.
        $container = $this->containerFor(new DoctorNullClearedProfileV3WriterKernel('test', true));
        $this->seedProtocolFloor($container, 2);
        $tester = $this->doctor($container);
        $tester->execute([]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        self::assertStringContainsString('[WARN] Protocol-v3 writer', $display);
        self::assertStringNotContainsString('high_abuse requires authenticated decoy emission', $display, 'a null-cleared profile must not trigger the high_abuse FAIL');
        self::assertStringNotContainsString('[FAIL]', $display);
    }
}
