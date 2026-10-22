<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The enforce_telemetry gate in its legal standard-privacy shape:
 * collection on (minimal), enforcement on. The doctor must name the
 * client-coverage decision this combination is — every mobile/native
 * SDK solve carries {} and is rejected — as a warning row, not a
 * silent pass.
 */
final class DoctorTelemetryEnforcementKernel extends TestKernel
{
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
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
                'public_base_url' => 'https://captcha.example.com',
                'privacy_mode' => 'standard',
                'telemetry' => 'minimal',
                'enforce_telemetry' => true,
            ]);
        });
    }
}
