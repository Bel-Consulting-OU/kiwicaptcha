<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Doctor scenario: the high_abuse protection profile with the decoy
 * surface explicitly deferred (risk.decoy_v3_enabled false overrides
 * the profile-derived true). The doctor must warn, never fail, so the
 * explicit two-phase-rollout deferral keeps the deploy gate green.
 */
final class DoctorHighAbuseDecoyDeferredKernel extends DoctorV3WriterTestKernel
{
    protected function loadKiwiCaptcha(ContainerBuilder $container): void
    {
        $container->loadFromExtension('kiwi_captcha', [
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'public_base_url' => 'https://captcha.example.com',
            'protection_profile' => 'high_abuse',
            'redis_service' => self::FAKE_REDIS_ID,
            'risk' => [
                'namespace' => 'doctor-v3',
                'redis_service' => self::FAKE_REDIS_ID,
                'decoy_v3_enabled' => false,
            ],
        ]);
    }
}
