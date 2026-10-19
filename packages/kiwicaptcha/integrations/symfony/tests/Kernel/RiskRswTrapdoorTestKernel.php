<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

/**
 * Kernel with the adaptive risk engine enabled over the fake Predis
 * client and a sha256 issuance baseline. The rsw time-lock trapdoor
 * pair is configured, so the adaptive rsw rung (change.md 1.4) is
 * armed — Rsw decisions issue time-lock challenges — while the
 * baseline issuance algorithm stays sha256.
 */
final class RiskRswTrapdoorTestKernel extends TestKernel
{
    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $loader->load(function (\Symfony\Component\DependencyInjection\ContainerBuilder $container): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
                'paths' => [
                    __DIR__.'/templates' => 'Test',
                ],
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'rsw_modulus_n' => \KiwiCaptcha\Tests\Support\RswFixture::MODULUS_N_B64,
                'rsw_lambda' => \KiwiCaptcha\Tests\Support\RswFixture::LAMBDA_B64,
                'rsw_t' => 10_000,
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'scopes' => [
                        'login' => ['id' => 10],
                        'signup' => ['id' => 11, 'base_risk' => 300, 'minimum' => 'sha20'],
                    ],
                ],
            ]);
        });
    }
}
