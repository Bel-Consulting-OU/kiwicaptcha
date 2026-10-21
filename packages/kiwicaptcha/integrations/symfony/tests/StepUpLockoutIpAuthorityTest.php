<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpLockoutGuard;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * The stateless step-up network budget resolves through the canonical
 * client IP issuance and risk bind (ClientIpResolver), never the
 * framework's independent getClientIp() answer. Under a configured
 * Kiwi trust list the raw framework call lets a client rotate its own
 * lockout bucket through X-Forwarded-For, or key into another context,
 * while the challenge record stays bound to the socket peer.
 */
final class StepUpLockoutIpAuthorityTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function guard(ClientIpResolver $resolver): StepUpLockoutGuard
    {
        return new StepUpLockoutGuard(new ArrayStepUpChallengeStore(), clientIpResolver: $resolver);
    }

    private function statelessBegin(string $forwardedFor): Request
    {
        $request = Request::create('https://example.com/kiwi/step-up/begin');
        $request->headers->set('X-Forwarded-For', $forwardedFor);

        return $request;
    }

    public function testUnderDirectModeTheSocketPeerIsTheOnlyNetworkIdentity(): void
    {
        $resolver = new ClientIpResolver(mode: ClientIpResolver::MODE_DIRECT);
        $guard = $this->guard($resolver);

        // Two requests behind different claimed forwards, one socket
        // peer: the budget key is the peer, so XFF rotation can never
        // mint a fresh bucket.
        $a = $guard->contextKeyOf($this->statelessBegin('203.0.113.9'));
        $b = $guard->contextKeyOf($this->statelessBegin('198.18.0.1'));

        self::assertSame($a, $b, 'direct mode: the claimed forward never rotates the budget key');
        self::assertSame('net:'.hash('sha256', '127.0.0.1'), $a, 'the key is the socket peer, exactly the bound identity');
    }

    public function testUnderTrustedProxyModeTheResolvedClientDrivesTheKey(): void
    {
        $resolver = new ClientIpResolver(
            mode: ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES,
            trustedProxies: ['127.0.0.1/32'],
        );
        $guard = $this->guard($resolver);

        // The peer is a trusted edge: the right-to-left walk answers the
        // real client, and the budget key follows IT — the same address
        // the issuance binding and the risk source pseudonym book.
        $a = $this->statelessBegin('203.0.113.9');
        $b = $this->statelessBegin('198.18.0.1');
        $keyA = $guard->contextKeyOf($a);
        $keyB = $guard->contextKeyOf($b);

        self::assertNotSame($keyA, $keyB, 'a trusted proxy walk: distinct clients are distinct budgets');
        self::assertSame('net:'.hash('sha256', $resolver->resolve($a)), $keyA, 'the key hashes the resolver answer — the issuance authority');
        self::assertSame('net:'.hash('sha256', $resolver->resolve($b)), $keyB, 'the key hashes the resolver answer — the issuance authority');
    }

    public function testAmbiguousForwardingFailsClosedToTheSharedAnonymousBucket(): void
    {
        $resolver = new ClientIpResolver(
            mode: ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES,
            trustedProxies: ['127.0.0.1/32'],
            rejectAmbiguousForwarding: true,
        );
        $guard = $this->guard($resolver);

        // A trusted peer sending both forwarding headers at once: the
        // canonical client is indeterminate. The key must degrade (the
        // same empty-identity degradation the demand finalizer applies),
        // never throw out of the guard and never trust one of the two
        // answers.
        $request = $this->statelessBegin('203.0.113.9');
        $request->headers->set('Forwarded', 'for=198.51.100.7');

        self::assertSame('net:anonymous', $guard->contextKeyOf($request), 'ambiguity degrades to the shared bucket, fail closed');
    }

    public function testAStartedSessionStillOwnsTheKeyRegardlessOfNetwork(): void
    {
        $resolver = new ClientIpResolver(mode: ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, trustedProxies: ['127.0.0.1/32']);
        $guard = $this->guard($resolver);

        $storage = new MockArraySessionStorage();
        $storage->setId('0123456789abcdef0123456789abcdef');
        $session = new Session($storage);
        $session->start();
        $request = $this->statelessBegin('203.0.113.9');
        $request->setSession($session);

        self::assertSame(
            'sess:'.hash('sha256', '0123456789abcdef0123456789abcdef'),
            $guard->contextKeyOf($request),
            'the started session keeps precedence; the network bucket is the stateless fallback only'
        );
    }

    public function testTheContainerWiresTheCanonicalResolverIntoTheLockoutGuard(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'risk' => [
                'enabled' => true,
                'redis_service' => 'fake_redis',
                'namespace' => 'ip-authority-test',
                'scopes' => ['login' => ['id' => 10]],
                'step_up' => [
                    'enabled' => true,
                    'scope' => 'login',
                    'default_handler' => 'email_otp',
                    'handlers' => ['email_otp' => ['enabled' => true]],
                ],
            ],
        ]], $container);

        $definition = $container->getDefinition(StepUpLockoutGuard::class);
        $resolverArg = $definition->getArgument('$clientIpResolver');
        self::assertInstanceOf(Reference::class, $resolverArg, 'the guard receives the canonical resolver');
        self::assertSame(ClientIpResolver::class, (string) $resolverArg, 'the exact service issuance and risk resolve through');
    }
}
