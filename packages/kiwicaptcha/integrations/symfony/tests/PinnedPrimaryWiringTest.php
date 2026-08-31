<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Command\KiwiCaptchaDoctorCommand;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\AuthorityGuardedPredisClient;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The ha_authority wiring contract (docs/ha-authority.md). Under
 * "pinned_primary" the storage/limiter/risk client construction wraps
 * the runtime authority guard with the PinnedPrimaryAuthorityGuard:
 * one guard per deployment, the client decorated with the per-command
 * AuthorityGuardedPredisClient. Under "none" (the default) nothing is
 * wired and the current boundary stays byte-identical. Aggregates,
 * phpredis clients and a missing client
 * are refused at build time. The ha_safe protection profile derives
 * ha_authority pinned_primary + replay_durability operator_managed,
 * and an explicit override in any layer wins.
 */
final class PinnedPrimaryWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const PROJECT_DIR = '/tmp/kiwi-pinned-wiring';

    /**
     * @param array<int, array<string, mixed>> $layers
     */
    private function load(array $layers): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load($layers, $container);

        return $container;
    }

    private function guardDefinition(ContainerBuilder $container): array
    {
        $definition = $container->getDefinition('kiwi_captcha.ha_authority_guard');

        return [
            'class' => $definition->getClass(),
            'arguments' => $definition->getArguments(),
        ];
    }

    public function testDefaultNoneWiresNoGuardAndKeepsTheCurrentBoundary(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis'],
        ]);

        self::assertFalse($container->hasDefinition('kiwi_captcha.ha_authority_guard'), 'ha_authority defaults to none: no guard is wired');
        self::assertFalse($container->hasDefinition('kiwi_captcha.redis.authority_guarded'), 'no client decorator is wired');
        $doctorArgs = $container->getDefinition(KiwiCaptchaDoctorCommand::class)->getArguments();
        self::assertNull($doctorArgs[9] ?? null, 'the doctor receives no authority guard');
    }

    public function testPinnedPrimaryWiresTheGuardAndDecoratesTheCheckedClient(): void
    {
        $container = $this->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => ['namespace' => 'prod-eu'],
                'ha_authority' => 'pinned_primary',
            ],
        ]);

        $guard = $this->guardDefinition($container);
        self::assertSame(PinnedPrimaryAuthorityGuard::class, $guard['class'], 'the guard service is the PinnedPrimaryAuthorityGuard');
        $guardArgs = $guard['arguments'];
        self::assertInstanceOf(Reference::class, $guardArgs[0], 'the guard binds to the raw (inner) client');
        self::assertSame(
            'kiwi_captcha.redis.checked.inner',
            (string) $guardArgs[0],
            'the guard binds to the checked client\'s raw inner instance, so its INFO/pin commands never recurse through a guarded wrapper',
        );
        self::assertSame(
            'prod-eu',
            $guardArgs[1],
            'the pin key namespace is the sanitized deployment namespace, like every other bundle key',
        );
        self::assertSame(5, $guardArgs[2], 'the default reverify window is 5 seconds');

        $decorator = $container->getDefinition('kiwi_captcha.redis.authority_guarded');
        self::assertSame(AuthorityGuardedPredisClient::class, $decorator->getClass(), 'the client is wrapped with the per-command guard wrapper');
        [$guardRef, $innerRef] = $decorator->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard', (string) $guardRef, 'the wrapper consults the pinned guard');
        self::assertSame('.inner', (string) $innerRef, 'the wrapper delegates to the raw client through the decorator inner reference');
        [$decoratedId] = $decorator->getDecoratedService();
        self::assertSame('kiwi_captcha.redis.checked', $decoratedId, 'the checked client the bundle components receive is the guarded decorator');

        $doctorArgs = $container->getDefinition(KiwiCaptchaDoctorCommand::class)->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard', (string) $doctorArgs[9], 'the doctor receives the guard for the HA authority state check');
    }

    public function testPinnedPrimaryAppliesToTheDsnBuiltClientToo(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_dsn' => 'redis://127.0.0.1:6399', 'ha_authority' => 'pinned_primary'],
        ]);

        self::assertTrue($container->hasDefinition('kiwi_captcha.ha_authority_guard'), 'the DSN lane wires the guard');
        $storageClient = $container->getDefinition('kiwi_captcha.storage.redis_dsn')->getArgument(0);
        self::assertSame('kiwi_captcha.redis.checked', (string) $storageClient, 'the DSN-built storage receives the checked (decorated) client');
    }

    public function testPinnedPrimaryWiresARiskDecoratorWhenTheRiskClientIsSeparate(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('fake_redis', FakePredisClient::class);
        $container->register('fake_risk_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_risk_redis',
                    'request_binding_authority' => 'fake_redis',
                ],
                'ha_authority' => 'pinned_primary',
            ],
        ], $container);

        $riskDecorator = $container->getDefinition('kiwi_captcha.risk.redis.authority_guarded');
        self::assertSame(AuthorityGuardedPredisClient::class, $riskDecorator->getClass(), 'the separate risk client gets its own guarded wrapper');
        [$decoratedId] = $riskDecorator->getDecoratedService();
        self::assertSame('kiwi_captcha.redis.checked.risk', $decoratedId, 'the risk checked client is decorated');
        [$guardRef] = $riskDecorator->getArguments();
        self::assertSame('kiwi_captcha.ha_authority_guard', (string) $guardRef, 'the risk wrapper shares the one deployment guard');
    }

    public function testPinnedPrimaryRefusesAnAggregateClient(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('agg_redis', \Predis\Client::class)
            ->setArguments([[
                ['scheme' => 'tcp', 'host' => '127.0.0.1', 'port' => 6398],
            ], [
                'replication' => 'sentinel',
                'service' => 'mymaster',
            ]]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('ha_authority is "pinned_primary"');

        (new KiwiCaptchaExtension())->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'agg_redis', 'ha_authority' => 'pinned_primary'],
        ], $container);
    }

    public function testPinnedPrimaryRefusesAPhpredisClient(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::PROJECT_DIR);
        $container->register('php_redis', \Redis::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('phpredis \\Redis cannot be mechanically guarded');

        (new KiwiCaptchaExtension())->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'php_redis', 'ha_authority' => 'pinned_primary'],
        ], $container);
    }

    public function testPinnedPrimaryRefusesWithoutAnyRedisClient(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('no storage/limiter Redis client is wired');

        $this->load([
            ['secret_key' => self::SECRET, 'ha_authority' => 'pinned_primary'],
        ]);
    }

    public function testHaSafeProfileDerivesPinnedPrimaryAndOperatorManaged(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis', 'protection_profile' => 'ha_safe'],
        ]);

        $config = $container->getDefinition(KiwiCaptchaDoctorCommand::class)->getArgument(1);
        self::assertSame('pinned_primary', $config['ha_authority'], 'ha_safe derives ha_authority pinned_primary');
        self::assertSame('operator_managed', $config['replay_durability'], 'ha_safe derives replay_durability operator_managed');
        self::assertTrue($container->hasDefinition('kiwi_captcha.ha_authority_guard'), 'ha_safe wires the mechanical guard');
        self::assertSame('ha_safe', $config['protection_profile'], 'the visible profile stays ha_safe');
    }

    public function testAnExplicitHaAuthorityOverrideWinsOverTheHaSafeProfile(): void
    {
        $container = $this->load([
            [
                'secret_key' => self::SECRET,
                'redis_service' => 'fake_redis',
                'protection_profile' => 'ha_safe',
                'ha_authority' => 'none',
            ],
        ]);

        $config = $container->getDefinition(KiwiCaptchaDoctorCommand::class)->getArgument(1);
        self::assertSame('none', $config['ha_authority'], 'an explicit ha_authority always wins over the profile-derived default');
        self::assertFalse($container->hasDefinition('kiwi_captcha.ha_authority_guard'), 'no guard without the effective pinned_primary posture');
    }
}
