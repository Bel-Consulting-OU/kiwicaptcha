<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Event\KiwiCredentialsChangedEvent;
use BelConsulting\KiwiCaptchaBundle\EventSubscriber\KiwiCredentialsChangedSubscriber;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\InMemoryPrincipalNetworkTagStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * The claims-registry revocation lane, on a booted container. The
 * credentials-changed subscriber is registered as a kernel event
 * subscriber. Both application moments (a credential change and the
 * logout-everywhere attribute) reach the outcomes facade's store
 * revocation with the correctly derived principal pseudonym.
 */
final class CredentialsChangedRevocationTest extends TestCase
{
    private const RAW_USER = 'alice@example.com';

    private ?CredentialsChangedRevocationTestKernel $kernel = null;

    protected function tearDown(): void
    {
        $this->kernel = null;
    }

    public function testTheCredentialChangeAndLogoutEverywhereEventsRevokeTheStore(): void
    {
        $this->kernel = new CredentialsChangedRevocationTestKernel('test', true);
        $this->kernel->boot();
        $container = $this->kernel->getContainer()->get('test.service_container');

        self::assertTrue($container->has(KiwiCredentialsChangedSubscriber::class), 'the revocation subscriber is registered');
        /** @var InMemoryPrincipalNetworkTagStore $store */
        $store = $container->get('kiwi_captcha.risk.principal_networks');
        $principal = $container->get('kiwi_captcha.risk.identity_factory')->principalId(self::RAW_USER);
        $dispatcher = $container->get('event_dispatcher');

        $dispatcher->dispatch(new KiwiCredentialsChangedEvent(self::RAW_USER));
        self::assertSame([$principal], $store->forgotten, 'the credentials-changed event revokes the derived principal devices');

        // A plain logout carries no revocation.
        $plain = new LogoutEvent(Request::create('/logout'), $this->token());
        $dispatcher->dispatch($plain);
        self::assertSame([$principal], $store->forgotten, 'a logout without the everywhere attribute leaves device trust intact');

        // The sign-out-everywhere moment: the application sets the
        // request attribute before triggering logout.
        $request = Request::create('/logout');
        $request->attributes->set(KiwiCredentialsChangedSubscriber::LOGOUT_EVERYWHERE_ATTRIBUTE, true);
        $dispatcher->dispatch(new LogoutEvent($request, $this->token()));
        self::assertSame([$principal, $principal], $store->forgotten, 'the logout-everywhere attribute revokes the same principal devices');
    }

    private function token(): UsernamePasswordToken
    {
        return new UsernamePasswordToken(new InMemoryUser(self::RAW_USER, null, ['ROLE_USER']), 'main', ['ROLE_USER']);
    }
}
