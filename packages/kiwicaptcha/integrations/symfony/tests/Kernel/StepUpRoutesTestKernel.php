<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel that registers the step-up routes the documented opt-in way: a
 * single import of the bundle's step_up.php routing resource. The
 * endpoints stay out of the bundle's default loader, so this import is
 * the deployment's explicit choice.
 */
final class StepUpRoutesTestKernel extends TestKernel
{
    public function getCacheDir(): string
    {
        return parent::getCacheDir().'-stepup-routes';
    }

    public function getLogDir(): string
    {
        return parent::getLogDir().'-stepup-routes';
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
                'router' => [
                    'resource' => '@KiwiCaptchaBundle/Resources/config/routes/step_up.php',
                ],
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
                    'step_up' => [
                        'enabled' => true,
                        'scope' => 'login',
                        'default_handler' => 'email_otp',
                        'handlers' => [
                            'email_otp' => ['enabled' => true],
                        ],
                    ],
                ],
            ]);
        });
    }
}
