<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpBootstrapGate;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The first-factor bootstrap gate (finding 5): a single-use,
 * session-scoped grant bound to the principal the application verified
 * out of band. Never a bare request attribute — anyone can set one of
 * those. The marker is consumed on the first matching enrollment; a
 * wrong principal or a replay answers false.
 */
final class StepUpBootstrapGateTest extends TestCase
{
    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    public function testTheGrantIsSingleUseAndSessionScoped(): void
    {
        $gate = new StepUpBootstrapGate(true);
        $request = $this->request('grant-session-00000000000000001');
        $gate->grant($request, self::PRINCIPAL);

        self::assertTrue($gate->allowsFirstEnrollment($request, self::PRINCIPAL), 'the granted session may enroll');
        self::assertFalse($gate->allowsFirstEnrollment($request, self::PRINCIPAL), 'the grant is one-time: a second attempt is refused');

        // Another session of the same principal: never (session-scoped).
        $other = $this->request('grant-session-00000000000000002');
        self::assertFalse($gate->allowsFirstEnrollment($other, self::PRINCIPAL));
    }

    public function testTheGrantIsBoundToThePrincipal(): void
    {
        $gate = new StepUpBootstrapGate(true);
        $request = $this->request('grant-session-00000000000000001');
        $gate->grant($request, self::PRINCIPAL);

        self::assertFalse(
            $gate->allowsFirstEnrollment($request, 'ffeeddccbbaa99887766554433221100'),
            'a grant for one principal never authorizes another',
        );
        // The refusal does not consume the grant: the right principal
        // can still use it.
        self::assertTrue($gate->allowsFirstEnrollment($request, self::PRINCIPAL));
    }

    /**
     * The old free-form marker (a request attribute anyone could set)
     * is never accepted, with or without a grant().
     */
    public function testABareRequestAttributeIsNeverAccepted(): void
    {
        $gate = new StepUpBootstrapGate(true);
        $request = $this->request('grant-session-00000000000000001');
        $request->attributes->set('_kiwi_signup_bootstrap', true);

        self::assertFalse($gate->allowsFirstEnrollment($request, self::PRINCIPAL));
    }

    public function testADisabledGateGrantsAndAllowsNothing(): void
    {
        $gate = new StepUpBootstrapGate(false);
        $request = $this->request('grant-session-00000000000000001');
        $gate->grant($request, self::PRINCIPAL);

        self::assertFalse($gate->allowsFirstEnrollment($request, self::PRINCIPAL));
    }

    public function testAGrantWithoutASessionSticksToNothing(): void
    {
        $gate = new StepUpBootstrapGate(true);
        $request = Request::create('https://example.com/signup');
        $gate->grant($request, self::PRINCIPAL);

        self::assertFalse($gate->allowsFirstEnrollment($request, self::PRINCIPAL));
    }

    public function testAnUngrantedOrUnstatedPrincipalIsRefused(): void
    {
        $gate = new StepUpBootstrapGate(true);
        $request = $this->request('grant-session-00000000000000001');
        $gate->grant($request, self::PRINCIPAL);

        self::assertFalse($gate->allowsFirstEnrollment($request), 'no principal presented: refused');
        self::assertFalse($gate->allowsFirstEnrollment($request, ''), 'an empty principal presented: refused');
    }

    private function request(string $sessionId): Request
    {
        $request = Request::create('https://example.com/signup', 'POST');
        $storage = new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage();
        $storage->setId($sessionId);
        $session = new \Symfony\Component\HttpFoundation\Session\Session($storage);
        $session->start();
        $request->setSession($session);

        return $request;
    }
}
