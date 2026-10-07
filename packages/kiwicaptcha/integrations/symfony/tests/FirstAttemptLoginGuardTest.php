<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Risk\LoginDecisionGate;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The first-attempt gate (P0-1): a LoginSuccessEvent runs the engine
 * pipeline with the principal id, and a StepUp decision replaces the
 * success response so the session is never granted.
 */
final class FirstAttemptLoginGuardTest extends TestCase
{
    private function identity(): RiskIdentityFactory
    {
        return new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x11", 32)));
    }

    private function request(): Request
    {
        return Request::create('https://example.com/login', 'POST', [], [], [], ['REMOTE_ADDR' => '203.0.113.10']);
    }

    /** A duck-typed LoginSuccessEvent: the class is optional at runtime. */
    private function event(): object
    {
        $request = $this->request();
        $user = new class {
            public function getUserIdentifier(): string
            {
                return 'user-42';
            }
        };

        return new class ($request, $user) {
            private ?object $response = null;

            public function __construct(private readonly Request $request, private readonly object $user)
            {
            }

            public function getRequest(): Request
            {
                return $this->request;
            }

            public function getUser(): object
            {
                return $this->user;
            }

            public function setResponse(object $response): void
            {
                $this->response = $response;
            }

            public function getResponse(): ?object
            {
                return $this->response;
            }
        };
    }

    private function decision(RiskAction $action): RiskDecision
    {
        return new RiskDecision(
            score: 100,
            action: $action,
            reasons: [],
            policyVersion: 3,
            globalLevel: 0,
            decisionId: 'd-1',
        );
    }

    private function stubGateway(?RiskDecision $result, bool $throw = false): LoginDecisionGate
    {
        return new class ($result, $throw) implements LoginDecisionGate {
            public function __construct(private readonly ?RiskDecision $result, private readonly bool $throw)
            {
            }

            public function loginDecision(string $scope, string $ip, ?string $session = null, ?string $principal = null, ?string $idempotencyKey = null): ?RiskDecision
            {
                if ($this->throw) {
                    throw new \RuntimeException('redis down');
                }

                return $this->result;
            }
        };
    }

    public function testAStepUpDecisionReplacesTheSuccessResponse(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway($this->decision(RiskAction::StepUp)), $this->identity(), '1', '/kiwi/step-up/begin');

        $event = $this->event();
        $guard->onLoginSuccess($event);

        $response = method_exists($event, 'getResponse') ? $event->getResponse() : null;
        self::assertNotNull($response, 'a StepUp decision must replace the success response');
        self::assertSame(302, $response->getStatusCode());
        self::assertStringContainsString('/kiwi/step-up/begin', (string) $response->headers->get('Location'));
    }

    public function testAnAllowDecisionLeavesTheLoginIntact(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway($this->decision(RiskAction::Allow)), $this->identity(), '1');

        $event = $this->event();
        $guard->onLoginSuccess($event);

        $response = method_exists($event, 'getResponse') ? $event->getResponse() : null;
        self::assertNull($response, 'an Allow decision must not touch the success response');
    }

    public function testAGatewayErrorNeverBreaksAuthentication(): void
    {
        $guard = new FirstAttemptLoginGuard($this->stubGateway(null, true), $this->identity(), '1');

        $event = $this->event();
        $guard->onLoginSuccess($event);

        $response = method_exists($event, 'getResponse') ? $event->getResponse() : null;
        self::assertNull($response, 'a risk backend failure logs and allows');
    }
}
