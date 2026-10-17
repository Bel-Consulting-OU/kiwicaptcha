<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel with privacy_mode 'standard' and independently chosen root
 * telemetry (the legacy enforcement surface) and risk.evidence.telemetry
 * (the rendered widget arm), so a test can prove the two keys are not
 * the same surface.
 */
final class TelemetrySurfaceTestKernel extends TestKernel
{
    public function __construct(
        string $environment,
        bool $debug,
        private readonly string $rootTelemetry = 'off',
        private readonly string $evidenceTelemetry = 'off',
    ) {
        parent::__construct($environment, $debug);
    }

    public function getCacheDir(): string
    {
        return parent::getCacheDir().'-telemetry-'.$this->rootTelemetry.'-'.$this->evidenceTelemetry;
    }

    public function getLogDir(): string
    {
        return parent::getLogDir().'-telemetry-'.$this->rootTelemetry.'-'.$this->evidenceTelemetry;
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $rootTelemetry = $this->rootTelemetry;
        $evidenceTelemetry = $this->evidenceTelemetry;
        $loader->load(function (ContainerBuilder $container) use ($rootTelemetry, $evidenceTelemetry): void {
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
                'privacy_mode' => 'standard',
                'telemetry' => $rootTelemetry,
                'risk' => [
                    // The risk engine stays off: the evidence arm renders
                    // under every posture, engine or not.
                    'enabled' => false,
                    'evidence' => ['telemetry' => $evidenceTelemetry],
                ],
            ]);
        });
    }
}
