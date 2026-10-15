<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\KiwiStepUpHandlerRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorAssurance;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpHandlerInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

/**
 * A custom-only step-up deployment on a real compiled container: the
 * deployment registers exactly one custom handler and names it the
 * default, so no built-in ladder handler is available. The container
 * must not wire a factor resolver that would demand a ladder family no
 * registered handler can satisfy, while the demand finalizer resolves
 * regardless of the handler shape.
 */
final class StepUpCustomOnlyKernelTest extends TestCase
{
    private ?Kernel $kernel = null;

    protected function tearDown(): void
    {
        if ($this->kernel !== null) {
            $this->kernel->shutdown();
        }
        $this->kernel = null;
    }

    public function testACustomOnlyDeploymentWiresNoPhantomFactorResolver(): void
    {
        $kernel = $this->kernel = new class ('test', true) extends TestKernel {
            private ?string $freshCacheDir = null;

            public function getCacheDir(): string
            {
                // A unique cache directory per kernel instance, so a stale
                // compiled container from an earlier run can never answer the
                // assertions. The value is MEMOIZED: the framework derives both
                // the build directory and the container cache path from this
                // call, and a fresh value per call would make the two diverge,
                // so the container lock would be opened in a directory that was
                // never created (a PHP warning, and a hard failure under
                // failOnWarning).
                return $this->freshCacheDir ??= parent::getCacheDir().'-custom-only-'.bin2hex(random_bytes(6));
            }

            public function registerContainerConfiguration(LoaderInterface $loader): void
            {
                $loader->load(function (ContainerBuilder $container): void {
                    $container->register('fake_redis', FakePredisClient::class)->setPublic(true);
                    // The security token storage the step-up plane
                    // resolves (the invalid-reference fallback in a
                    // kernel without a firewall): a real instance.
                    $container->register('security.token_storage', TokenStorage::class)->setPublic(true);
                    $container->register('custom_step_up_handler_service', CustomOnlyStepUpHandler::class)->setPublic(true);
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
                        'risk' => [
                            'enabled' => true,
                            'redis_service' => 'fake_redis',
                            'scopes' => [
                                'login' => ['id' => 10],
                            ],
                            'step_up' => [
                                'enabled' => true,
                                'scope' => 'login',
                                'default_handler' => 'custom_only',
                                'handlers' => [
                                    'custom' => ['custom_only' => 'custom_step_up_handler_service'],
                                ],
                            ],
                        ],
                    ]);
                });
            }
        };

        try {
            $kernel->boot();
            $container = $kernel->getContainer()->get('test.service_container');

            // The custom handler is registered under its name and is
            // the configured default: the registry resolves it when no
            // name is presented.
            self::assertTrue($container->has(KiwiStepUpHandlerRegistry::class));
            /** @var KiwiStepUpHandlerRegistry $registry */
            $registry = $container->get(KiwiStepUpHandlerRegistry::class);
            self::assertSame(['custom_only'], $registry->names());
            self::assertInstanceOf(
                CustomOnlyStepUpHandler::class,
                $registry->get(null),
                'the custom handler is the configured default handler',
            );

            // The regression guard: a custom-only deployment registers no ladder
            // handler, so no factor resolver may be wired. A resolver
            // here would demand a family no registered handler can
            // satisfy.
            self::assertFalse(
                $container->has(StepUpFactorResolver::class),
                'a custom-only deployment must not wire a StepUpFactorResolver demanding a ladder family no registered handler can satisfy',
            );

            // The demand finalizer is wired regardless of the handler
            // shape and must still resolve.
            $finalizer = $container->get(StepUpDemandFinalizer::class);
            self::assertInstanceOf(StepUpDemandFinalizer::class, $finalizer);
        } finally {
            $kernel->shutdown();
        }
    }
}

/**
 * A minimal custom step-up handler: it names the custom_only factor and
 * never drives begin or complete in this kernel test, so both throw.
 */
final class CustomOnlyStepUpHandler implements StepUpHandlerInterface
{
    public function assurance(): StepUpFactorAssurance
    {
        return StepUpFactorAssurance::custom('custom_only', 1);
    }

    public function begin(Request $request, StepUpContext $context): Response
    {
        throw new \LogicException('not exercised');
    }

    public function complete(Request $request): StepUpResult
    {
        throw new \LogicException('not exercised');
    }
}
