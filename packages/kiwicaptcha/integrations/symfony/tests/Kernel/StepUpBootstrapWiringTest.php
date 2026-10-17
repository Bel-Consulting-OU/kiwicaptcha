<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpBootstrapGate;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * risk.step_up.allow_signup_bootstrap is not an inert knob: it reaches the
 * first-enrollment gate the reference handlers hold. With the default
 * false a granted signup bootstrap still cannot enroll a first time-based
 * factor (the grant is never minted); with the knob true the granted
 * session enrolls its first factor without a prior completed step-up.
 */
final class StepUpBootstrapWiringTest extends TestCase
{
    private const RAW_USER = 'new-user@example.com';

    private ?StepUpTestKernel $kernel = null;

    protected function tearDown(): void
    {
        $this->kernel = null;
    }

    public function testTheKnobDefaultsToFalseAndKeepsTheFirstEnrollmentClosed(): void
    {
        $container = $this->boot(new StepUpTestKernel('test', true));

        /** @var StepUpBootstrapGate $gate */
        $gate = $container->get(StepUpBootstrapGate::class);
        $request = $this->grantedRequest($container, $gate);
        self::assertSame([], $this->session($request)->all(), 'a disabled gate grants nothing to the session');

        /** @var TotpStepUpHandler $handler */
        $handler = $container->get(TotpStepUpHandler::class);
        $principal = $container->get('kiwi_captcha.risk.identity_factory')->principalId(self::RAW_USER);

        try {
            $handler->enroll($principal, 'sess-bootstrap-default');
            self::fail('the default false bootstrap gate must refuse a first enrollment without a completed step-up');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('needs a step-up completed in this session', $e->getMessage());
        }
    }

    public function testAllowSignupBootstrapReachesTheHandlerAndOpensTheFirstEnrollment(): void
    {
        $container = $this->boot(new StepUpTestKernel('test', true, true, true));

        /** @var StepUpBootstrapGate $gate */
        $gate = $container->get(StepUpBootstrapGate::class);
        $request = $this->grantedRequest($container, $gate);
        self::assertNotSame([], $this->session($request)->all(), 'the enabled gate minted the session-scoped grant');

        /** @var TotpStepUpHandler $handler */
        $handler = $container->get(TotpStepUpHandler::class);
        $principal = $container->get('kiwi_captcha.risk.identity_factory')->principalId(self::RAW_USER);
        $secret = $handler->enroll($principal, 'sess-bootstrap-enabled');

        self::assertMatchesRegularExpression('/^[A-Z2-7]+$/D', $secret, 'the bootstrap enrollment minted the sealed time-based secret');
        self::assertTrue($handler->isEnrolled($principal), 'the factor is enrolled after the bootstrap grant');
        self::assertSame([], $this->session($request)->all(), 'the grant is single-use and consumed by the enrollment');
    }

    private function boot(StepUpTestKernel $kernel): ContainerInterface
    {
        $this->kernel = $kernel;
        $kernel->boot();

        return $kernel->getContainer()->get('test.service_container');
    }

    /**
     * A signup request with a session, pushed as the current request the
     * gate falls back to, and granted the one-time bootstrap for the raw
     * identifier.
     */
    private function grantedRequest(ContainerInterface $container, StepUpBootstrapGate $gate): Request
    {
        $request = Request::create('/signup');
        $request->setSession(new Session(new MockArraySessionStorage()));
        /** @var RequestStack $stack */
        $stack = $container->get('request_stack');
        $stack->push($request);
        $gate->grant($request, self::RAW_USER);

        return $request;
    }

    private function session(Request $request): Session
    {
        $session = $request->getSession();
        \assert($session instanceof Session);

        return $session;
    }
}
