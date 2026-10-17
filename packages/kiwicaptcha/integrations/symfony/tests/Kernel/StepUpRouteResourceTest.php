<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use PHPUnit\Framework\TestCase;

/**
 * The step-up endpoints are opt-in: the bundle's default route loader
 * does not register them, and the documented one-line import of
 * Resources/config/routes/step_up.php registers the four shipped routes
 * at their documented paths.
 */
final class StepUpRouteResourceTest extends TestCase
{
    private ?\Symfony\Component\HttpKernel\Kernel $kernel = null;

    protected function tearDown(): void
    {
        $this->kernel = null;
    }

    public function testTheDefaultRouteLoaderDoesNotShipTheStepUpEndpoints(): void
    {
        $routes = $this->routes(new TestKernel('test', true));

        foreach (['kiwi_step_up_begin', 'kiwi_step_up_complete', 'kiwi_step_up_email_begin', 'kiwi_step_up_email_complete'] as $name) {
            self::assertFalse($routes->get($name) !== null, $name.' must stay out of the default loader (the import is opt-in)');
        }
    }

    public function testTheDocumentedImportRegistersTheFourStepUpRoutes(): void
    {
        $routes = $this->routes(new StepUpRoutesTestKernel('test', true));

        $expected = [
            'kiwi_step_up_begin' => '/kiwi/step-up/begin',
            'kiwi_step_up_complete' => '/kiwi/step-up/complete',
            'kiwi_step_up_email_begin' => '/kiwi/step-up/email/begin',
            'kiwi_step_up_email_complete' => '/kiwi/step-up/email/complete',
        ];
        foreach ($expected as $name => $path) {
            $route = $routes->get($name);
            self::assertNotNull($route, $name.' is registered by the documented import');
            self::assertSame($path, $route->getPath(), $name.' keeps its documented path');
        }
        self::assertSame(['GET', 'POST'], $routes->get('kiwi_step_up_begin')->getMethods());
        self::assertSame(['GET', 'POST'], $routes->get('kiwi_step_up_complete')->getMethods());
        self::assertSame(['POST'], $routes->get('kiwi_step_up_email_begin')->getMethods());
        self::assertSame(['POST'], $routes->get('kiwi_step_up_email_complete')->getMethods());
    }

    private function routes(\Symfony\Component\HttpKernel\Kernel $kernel): \Symfony\Component\Routing\RouteCollection
    {
        $this->kernel = $kernel;
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        return $container->get('router')->getRouteCollection();
    }
}
