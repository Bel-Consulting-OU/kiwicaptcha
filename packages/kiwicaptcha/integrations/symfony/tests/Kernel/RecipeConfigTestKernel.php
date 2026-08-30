<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Kernel wired with the recipe's exact config values
 * (recipes-contrib/bel-consulting/kiwicaptcha-symfony/1.0/
 * config/packages/kiwicaptcha.yaml): protection_profile + the %env()%
 * secret (declared in the recipe manifest env) + the literal public
 * origin and DSN the recipe ships. This bundle version validates the
 * origin and the DSN shape at container build time, before %env()%
 * placeholders resolve, so the recipe ships literals for those two.
 * The secret stays env-managed; the boot must prove that exact shape
 * works end to end.
 */
final class RecipeConfigTestKernel extends TestKernel
{
    /**
     * The environment variable the recipe's %env()% secret resolves
     * from (the recipe manifest writes the generated value into .env).
     */
    public const SECRET_ENV = 'KIWI_RECIPE_SMOKE_SECRET';

    public function __construct(
        string $environment,
        bool $debug,
        private readonly string $redisDsn,
    ) {
        parent::__construct($environment, $debug);
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'protection_profile' => 'balanced',
                'secret_key' => '%env('.self::SECRET_ENV.')%',
                'public_base_url' => 'https://captcha.example.com',
                'redis_dsn' => $this->redisDsn,
            ]);
        });
    }
}
