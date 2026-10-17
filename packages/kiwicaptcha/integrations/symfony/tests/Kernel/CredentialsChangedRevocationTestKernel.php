<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\InMemoryPrincipalNetworkTagStore;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * Kernel with the risk plane armed for the revocation lane. The typed
 * outcomes facade arms through the profile's marks stage. The
 * principal-network store is the in-memory spy so the test can observe
 * every forgetDevices call the credentials-changed and logout-everywhere
 * events produce.
 */
final class CredentialsChangedRevocationTestKernel extends TestKernel
{
    public function getCacheDir(): string
    {
        return parent::getCacheDir().'-credentials-revocation';
    }

    public function getLogDir(): string
    {
        return parent::getLogDir().'-credentials-revocation';
    }

    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                // The revoked-store seam: the facade and the subscriber
                // hold a Reference to this id, so replacing the
                // definition replaces what both resolve.
                $container->setDefinition(
                    'kiwi_captcha.risk.principal_networks',
                    (new Definition(InMemoryPrincipalNetworkTagStore::class))->setPublic(true),
                );
            }
        });
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'scopes' => [
                        'login' => ['id' => 10],
                    ],
                    'outcomes' => [
                        // The facade arms through the marks stage; the
                        // security auto-bridge stays out of this kernel.
                        'auto_bridge' => false,
                    ],
                ],
            ]);
        });
    }
}
