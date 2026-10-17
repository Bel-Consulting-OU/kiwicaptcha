<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\Kernel;

/**
 * The two telemetry keys are distinct surfaces. The root `telemetry` key
 * is the legacy enforcement switch read by enforce_telemetry; the widget
 * container's data-kiwi-telemetry mode follows risk.evidence.telemetry.
 * A root-only change must not alter the rendered attribute.
 */
final class TelemetrySurfaceTest extends TestCase
{
    public function testRootTelemetryDoesNotChangeTheRenderedWidgetMode(): void
    {
        $html = $this->render(new TelemetrySurfaceTestKernel('test', true, 'full', 'off'));

        self::assertStringContainsString(
            'data-kiwi-telemetry="off"',
            $html,
            'root telemetry full must not arm the widget evidence arm',
        );
        self::assertStringNotContainsString('data-kiwi-telemetry="full"', $html);
    }

    public function testRiskEvidenceTelemetryDrivesTheRenderedWidgetMode(): void
    {
        $html = $this->render(new TelemetrySurfaceTestKernel('test', true, 'off', 'full'));

        self::assertStringContainsString(
            'data-kiwi-telemetry="full"',
            $html,
            'risk.evidence.telemetry is the key that reaches the rendered widget mode',
        );
    }

    private function render(Kernel $kernel): string
    {
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');
        $factory = $container->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['scope' => 'login']);

        return (string) $container->get('twig')->render('@Test/form.html.twig', ['form' => $form->createView()]);
    }
}
