<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\BindingMode;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The protection profile is the LOWEST-precedence configuration layer.
 * Symfony's Processor normalizes and merges every config array in stack
 * order, so the profile defaults are prepended as the first array. An
 * explicit value in any config file always wins, and a later layer
 * carrying only `protection_profile` can never inject profile defaults
 * that override explicit settings from an earlier layer. The previous
 * per-array beforeNormalization expansion made exactly that override
 * possible (a base `rate_limit: 1` + `risk.decoy_v3_enabled: false`
 * followed by a prod overlay `protection_profile: high_abuse` silently
 * became rate_limit 5 + decoy on). These multi-array tests mirror the
 * real config/packages + config/packages/prod layering and run through
 * the extension's load() with explicit multi-array stacks — the
 * single-array helper cannot see this class of bug.
 */
final class ProtectionProfileLayeringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /**
     * @param array<int, array<string, mixed>> $layers the raw config stack, lowest precedence first
     */
    private function load(array $layers): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load($layers, $container);

        return $container;
    }

    public function testExplicitBaseSettingsSurviveALaterProfileOnlyOverlay(): void
    {
        // The layering regression this test guards: base rate_limit: 1 +
        // risk.decoy_v3_enabled: false, then a prod overlay carrying
        // only protection_profile: high_abuse. The profile must behave
        // as the lowest-precedence layer: the explicit base values win,
        // while the profile's other defaults apply where no layer set
        // them.
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis', 'rate_limit' => 1, 'risk' => ['decoy_v3_enabled' => false]],
            ['protection_profile' => 'high_abuse'],
        ]);

        self::assertSame(1, $container->getParameter('kiwi_captcha.rate_limit'), 'the explicit base rate_limit=1 must survive the high_abuse overlay (rate_limit 5 is only a derived default)');
        self::assertFalse($container->getDefinition(ChallengeController::class)->getArgument('$decoyV3Enabled'), 'the explicit base risk.decoy_v3_enabled=false must survive the high_abuse overlay');
        // The profile's other defaults apply only where no layer set them.
        self::assertSame(2000, $container->getParameter('kiwi_captcha.rate_limit_global'), 'rate_limit_global stays at the high_abuse derived default (no layer set it)');
        self::assertTrue($container->hasDefinition(RiskGateway::class), 'risk.enabled stays at the high_abuse derived default (no layer set it)');
    }

    public function testAnExplicitOverrideInALaterLayerWinsOverTheBaseProfile(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis', 'protection_profile' => 'high_abuse'],
            ['rate_limit' => 100],
        ]);

        self::assertSame(100, $container->getParameter('kiwi_captcha.rate_limit'), 'an explicit later-layer rate_limit must win over the base profile default');
        self::assertTrue($container->hasDefinition(RiskGateway::class), 'the profile still fills the other risk defaults');
    }

    public function testTheLastProfileWinsAndTheEarlierProfileDefaultsAreNotApplied(): void
    {
        // Base protection_profile: high_abuse + prod protection_profile:
        // compatibility -> compatibility wins and high_abuse's defaults
        // (rate_limit 5, risk enabled, decoy on, binding nonce_ip_hmac)
        // must NOT apply.
        $container = $this->load([
            ['secret_key' => self::SECRET, 'protection_profile' => 'high_abuse'],
            ['protection_profile' => 'compatibility'],
        ]);

        self::assertSame(10, $container->getParameter('kiwi_captcha.rate_limit'), 'compatibility rate_limit (10), not high_abuse (5)');
        self::assertSame(500, $container->getParameter('kiwi_captcha.rate_limit_global'), 'compatibility rate_limit_global (500), not high_abuse (2000)');
        self::assertFalse($container->hasDefinition(RiskGateway::class), 'risk stays off (compatibility), high_abuse risk.enabled=true is NOT applied');
        self::assertFalse($container->getDefinition(ChallengeController::class)->getArgument('$decoyV3Enabled'), 'the decoy surface stays off (compatibility)');
        self::assertSame(300, $container->getDefinition('kiwi_captcha.config')->getArgument(7), 'the compatibility TTL (300 s) applies');
        self::assertSame(BindingMode::None, $container->getDefinition('kiwi_captcha.config')->getArgument('$bindingMode'), 'compatibility binding off');
    }

    public function testAnExplicitNestedRiskWeightInOneLayerWinsOverTheProfileInAnother(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis', 'protection_profile' => 'high_abuse'],
            ['risk' => ['weights' => ['replay' => 900]]],
        ]);

        $policyConfig = $container->getDefinition('kiwi_captcha.risk.policy')->getArgument(0);
        self::assertSame(900, $policyConfig['weights']['replay'], 'the explicit later-layer replay weight wins');
        self::assertSame(320, $policyConfig['weights']['bad_proof'], 'the profile still fills the weights no layer set');
        self::assertSame(340, $policyConfig['weights']['malformed'], 'the profile fills the other abuse-evidence weights');
        self::assertTrue($container->hasDefinition(RiskGateway::class), 'risk stays enabled from the profile');
    }

    public function testExplicitDecoyV3DisabledInOneLayerWinsOverHighAbuseInAnother(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis', 'protection_profile' => 'high_abuse'],
            ['risk' => ['decoy_v3_enabled' => false]],
        ]);

        self::assertFalse($container->getDefinition(ChallengeController::class)->getArgument('$decoyV3Enabled'), 'the explicit decoy_v3_enabled=false wins over the profile default true');
        self::assertTrue($container->hasDefinition(RiskGateway::class), 'the profile still enables risk');
    }

    public function testPrivacyAndBindingPolicySplitAcrossLayersEachSurvive(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'privacy_mode' => 'standard'],
            ['binding_mode' => 'none'],
        ]);

        self::assertSame('standard', $container->getParameter('kiwi_captcha.privacy_mode'), 'privacy_mode from the base layer survives');
        self::assertSame(BindingMode::None, $container->getDefinition('kiwi_captcha.config')->getArgument('$bindingMode'), 'binding_mode from the prod layer survives');
    }

    public function testHighAbuseEngagesChainingWhenTheAuthorityLivesInAnotherLayer(): void
    {
        // The chaining conditional is an extension post-step over the
        // final merged configuration: the binding authority may live in
        // any layer (the historical same-array restriction is gone).
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis', 'protection_profile' => 'high_abuse'],
            ['risk' => ['request_binding_authority' => 'app.binding_authority']],
        ]);

        self::assertTrue($container->hasDefinition(ChainedChallengeTicketService::class), 'high_abuse engages chained step-up when the final config carries the authoritative binding resolver');
    }

    public function testHighAbuseKeepsChainingOffWithoutAnyBindingAuthority(): void
    {
        // No layer wires a binding authority: the profile's chaining
        // conditional must leave chaining at its default (false), and
        // the compile-time refusal must NOT fire for a derived value.
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis', 'protection_profile' => 'high_abuse'],
            ['rate_limit' => 100],
        ]);

        self::assertFalse($container->hasDefinition(ChainedChallengeTicketService::class), 'chaining stays off without an authoritative binding anchor');
    }

    public function testAnExplicitChainingEnabledWithoutAuthorityIsStillRefusedAtCompileTime(): void
    {
        // An explicit risk.chaining.enabled=true without an authority is
        // a configuration error: the tree refuses it at compile time
        // exactly like before (never silently degraded to "no chaining").
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->load([
            ['secret_key' => self::SECRET, 'risk' => ['chaining' => ['enabled' => true]]],
        ]);
    }

    public function testExplicitChainingEnabledFalseWinsOverHighAbuseWithAnAuthority(): void
    {
        $container = $this->load([
            ['secret_key' => self::SECRET, 'redis_service' => 'fake_redis', 'protection_profile' => 'high_abuse'],
            ['risk' => ['request_binding_authority' => 'app.binding_authority', 'chaining' => ['enabled' => false]]],
        ]);

        self::assertFalse($container->hasDefinition(ChainedChallengeTicketService::class), 'an explicit chaining.enabled=false wins over the profile conditional');
    }
}
