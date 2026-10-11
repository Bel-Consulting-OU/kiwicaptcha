<?php

declare(strict_types=1);

/**
 * rt.wire.php — the kernel-side wire plane of the campaign drivers.
 * Drives the booted product kernel over its real HTTP surface with
 * $kernel->handle(Request::create(...)), carrying one cookie jar per
 * actor. Nothing here knows how the risk engine works: the outcome
 * classification is the wire contract itself.
 *
 *   - POST /login_check with bad credentials fails the firewall
 *     (redirect back to the login page): the product's own failure
 *     lane, whose outcome bridge records a real authentication
 *     failure;
 *   - POST /login_check with good credentials either grants a session
 *     (the /account probe answers 200 = an Allow) or withholds it
 *     (the probe is refused or bounced to the login page = the
 *     first-attempt gate demands a step-up, or denies);
 *   - the step-up plane is completed through the product's own
 *     controller, the exact drive the bundle's own full-journey kernel
 *     test performs (the session plane deliberately never persists a
 *     pending token for the firewall to re-load), with the code the
 *     application's delivery channel carried (the captured OTP or the
 *     enrolled TOTP secret);
 *   - the continuity plane is established through the product's own
 *     challenge endpoint (which mints the continuity cookie) and the
 *     completed step-up (whose restore binds the session, the device,
 *     the network and the ASN under the principal).
 */

namespace KiwiRt;

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpCode;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockFileSessionStorage;
use Symfony\Component\HttpKernel\Kernel;

final class RtWire
{
    public function __construct(private readonly Kernel $kernel)
    {
    }

    /** The last enrollment failure, for the driver's fatal reports. */
    public string $lastEnrollError = '';

    /**
     * One kernel round trip: build the request for the actor (its
     * cookie jar, its source address), run it through the kernel, fold
     * the response cookies back into the jar.
     */
    public function handle(string $method, string $uri, array $post = [], ?RtActor $actor = null): Response
    {
        $cookies = $actor?->cookies ?? [];
        $request = Request::create(
            'https://captcha.example.com' . $uri,
            $method,
            $post,
            $cookies,
            [],
            ['REMOTE_ADDR' => $actor?->ip ?? '127.0.0.1'],
        );
        $response = $this->kernel->handle($request);
        if ($actor !== null) {
            foreach ($response->headers->getCookies() as $cookie) {
                $actor->cookies[$cookie->getName()] = $cookie->getValue();
            }
        }

        return $response;
    }

    /**
     * One full login attempt. Returns the wire outcome:
     *   'allow'    — the session was granted (/account answers 200);
     *   'withheld' — the session was withheld (the probe is refused or
     *                bounced to the login page: the pending step-up
     *                token is not fully authenticated, exactly the
     *                first-attempt gate's wire answer for StepUp/Deny);
     *   'invalid'  — the firewall refused the credentials (the
     *                product's failure lane);
     *   'http:<code>' — anything else (an error the driver surfaces).
     *
     * The pending token the login response leaves in the token storage
     * is captured onto the actor before the probe (the probe's own
     * firewall pass resets the storage): the pending state is what the
     * product's own login response issued, and only a completed factor
     * upgrades it.
     */
    public function login(RtActor $actor, string $username, string $password): string
    {
        $response = $this->handle('POST', '/login_check', [
            'username' => $username,
            'password' => $password,
        ], $actor);
        $status = $response->getStatusCode();
        if ($status === 500) {
            return 'http:500';
        }
        if ($status !== 401 && $status !== 302) {
            return 'http:' . $status;
        }
        $location = (string) $response->headers->get('Location');
        if ($status === 302 && str_contains($location, '/login')) {
            return 'invalid';
        }
        $actor->pending = $this->currentPending();
        $probe = $this->handle('GET', '/account', [], $actor);
        $probeStatus = $probe->getStatusCode();
        if ($probeStatus === 200) {
            $actor->pending = null;

            return 'allow';
        }

        return $probeStatus === 403 || $probeStatus === 302 ? 'withheld' : 'http:' . $probeStatus;
    }

    /**
     * Whether the actor currently carries a granted (fully
     * authenticated) session.
     */
    public function hasSession(RtActor $actor): bool
    {
        return $this->handle('GET', '/account', [], $actor)->getStatusCode() === 200;
    }

    /**
     * Mint the continuity plane: the application provisions its own
     * continuity cookie through the product's own ContinuityCookie
     * (mint + cookie builder) — the same class the challenge endpoint
     * uses on the issuance response. The cookie value names the risk
     * session the engine later binds; the binding itself stays a
     * product write (the step-up restore records the session, device,
     * network and ASN tags). The establish phase does not farm
     * challenge issuances: issuance is the deployment's priced
     * resource and the campaign's establish volume is baseline
     * population, not challenge traffic.
     */
    public function mintContinuity(RtActor $actor): bool
    {
        $continuity = $this->kernel->getContainer()->get(\BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie::class);
        \assert($continuity instanceof \BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie);
        $request = Request::create(
            'https://captcha.example.com/login',
            'GET',
            [],
            $actor->cookies,
            [],
            ['REMOTE_ADDR' => $actor->ip],
        );
        $cookie = $continuity->cookie($request, $continuity->mint());
        $actor->cookies[$cookie->getName()] = (string) $cookie->getValue();

        return $actor->continuityCookie() !== '';
    }

    /**
     * Complete the pending step-up through the product's own step-up
     * controller: the begin and complete requests run the real
     * StepUpController over real, session-carrying requests — the same
     * drive the bundle's own full-journey kernel test performs, because
     * the session plane never persists a pending token for the firewall
     * to re-load. A succeeded completion runs the session restorer,
     * which binds the network, ASN and the presented identities under
     * the principal. $codeSource resolves the delivered code for the
     * pending principal: an email-otp capture read or a computed TOTP.
     */
    public function completeStepUp(RtActor $actor, string $handler, \Closure $codeSource): bool
    {
        if ($actor->pending === null) {
            return false;
        }
        $container = $this->kernel->getContainer();
        $controller = $container->get(StepUpController::class);
        \assert($controller instanceof StepUpController);
        $stack = $container->get('request_stack');
        \assert($stack instanceof \Symfony\Component\HttpFoundation\RequestStack);
        $tokenStorage = $container->get('security.token_storage');

        // The actor's browser session: the real file-backed session the
        // actor's cookie addresses (the same store the kernel's session
        // factory writes), carried through both step-up requests.
        $session = $this->actorSession($actor);
        $session->set(FirstAttemptLoginGuard::class . ':pending', true);

        $ok = false;
        $deviceMint = null;
        $beginRequest = $this->actorRequest($actor, '/step-up/begin?mode=json&handler=' . urlencode($handler));
        $beginRequest->setSession($session);
        $stack->push($beginRequest);
        try {
            $this->setPending($tokenStorage, $actor->pending);
            $begin = $controller->begin($beginRequest);
if ($begin->getStatusCode() !== 200) {
                return false;
            }
            $document = json_decode((string) $begin->getContent(), true);
            if (!\is_array($document) || !isset($document['challenge'])) {
                return false;
            }
            $code = $codeSource($actor);
if ($code === null || $code === '') {
                return false;
            }
            // The session id the completion binds to (the restorer may
            // migrate it on success; the enrollment credit records the
            // bound one).
            $actor->completedSessionId = $session->getId();
            $completeRequest = $this->actorRequest($actor, '/step-up/complete?mode=json&handler=' . urlencode($handler), 'POST', [
                'kiwi_step_up_ticket' => (string) $document['challenge'],
                'kiwi_step_up_code' => (string) $code,
            ]);
            $completeRequest->setSession($session);
            $stack->push($completeRequest);
            try {
                $this->setPending($tokenStorage, $actor->pending);
                $complete = $controller->complete($completeRequest);
                $ok = $complete->getStatusCode() === 200
                    && (\is_array($verdict = json_decode((string) $complete->getContent(), true)))
                    && ($verdict['status'] ?? null) === 'succeeded';
                if (getenv('KIWI_RT_DEBUG')) {
                    fwrite(STDERR, '[wire] complete=' . $complete->getStatusCode() . ' ' . substr((string) $complete->getContent(), 0, 140) . "\n");
                }
                // The restore staged the fresh device value for the
                // response subscriber; the browser receives its cookie
                // on the completion response, so the actor's jar takes
                // it here through the product's own cookie builder.
                $mint = $completeRequest->attributes->get(FirstAttemptLoginGuard::DEVICE_MINT_ATTRIBUTE);
                if (\is_string($mint) && $mint !== '') {
                    $deviceMint = $this->deviceCookie($completeRequest, $mint);
                }
            } finally {
                $stack->pop();
            }
        } finally {
            $stack->pop();
        }
        // The session may have migrated on the privilege upgrade: keep
        // the actor's cookie in step and persist the session state.
        $session->save();
        $actor->cookies['MOCKSESSID'] = $session->getId();
        if ($deviceMint !== null) {
            foreach ($deviceMint as $name => $value) {
                $actor->cookies[$name] = $value;
            }
        }
        // The pending state is spent either way; the storage carries
        // the restored token after a success.
        $actor->pending = null;

        return $ok;
    }

    /** The email-otp code source: the captured delivery of this actor's principal. */
    public function capturedCode(): \Closure
    {
        return function (RtActor $actor): ?string {
            $raw = $this->pendingPrincipal($actor);
            if ($raw === null) {
                return null;
            }
            // The delivery channel keys the code by the challenge's
            // principal pseudonym; the pending token carries the raw
            // identifier, so convert like the controller does.
            $factory = $this->kernel->getContainer()->get('kiwi_captcha.risk.identity_factory');
            \assert($factory instanceof \KiwiCaptcha\Risk\RiskIdentityFactory);
            $principal = $factory->principalId($raw);
            $capture = $this->kernel->getContainer()->get(RtCodeCapture::class);
            \assert($capture instanceof RtCodeCapture);

            return $capture->lastCodeByPrincipal[$principal] ?? null;
        };
    }

    /** The totp code source: the RFC 6238 value of the enrolled secret. */
    public function totpCode(): \Closure
    {
        return function (RtActor $actor): ?string {
            $token = $this->pendingPrincipal($actor);
            if ($token === null || !isset($actor->totpSecrets[$token])) {
                return null;
            }
            $raw = TotpCode::base32Decode($actor->totpSecrets[$token]);
            if ($raw === null) {
                return null;
            }

            return TotpCode::at($raw, TotpCode::stepOf(time()));
        };
    }

    /**
     * The pending principal's raw identifier: the pending token the
     * actor carries from its withheld login.
     */
    public function pendingPrincipal(RtActor $actor): ?string
    {
        $token = $actor->pending;
        if ($token === null) {
            return null;
        }
        $pending = FirstAttemptLoginGuard::unwrapIfPending($token);
        if ($pending === $token) {
            return null;
        }

        return $pending->getUserIdentifier();
    }

    /**
     * Enroll the TOTP factor for the actor's pending principal through
     * the product's own provisioning surface (the first enrollment is
     * authorized by the email-otp step-up this session just completed).
     */
    public function enrollTotp(RtActor $actor): ?string
    {
        $raw = $this->pendingPrincipal($actor) ?? $this->grantedPrincipal($actor);
        if ($raw === null) {
            return null;
        }
        $factory = $this->kernel->getContainer()->get('kiwi_captcha.risk.identity_factory');
        \assert($factory instanceof \KiwiCaptcha\Risk\RiskIdentityFactory);
        $principal = $factory->principalId($raw);
        $handler = $this->kernel->getContainer()->get(TotpStepUpHandler::class);
        \assert($handler instanceof TotpStepUpHandler);
        // The completion credit records the session id of the session
        // it credited; the restore migrates that session on success, so
        // try the bound id and the migrated one (the two spellings the
        // browser holds).
        foreach (array_unique([$actor->completedSessionId, $actor->session()]) as $session) {
            if ($session === null || $session === '') {
                continue;
            }
            try {
                $secret = $handler->enroll($principal, $session);
            } catch (\Throwable $e) {
                $this->lastEnrollError = get_class($e) . ': ' . $e->getMessage();

                continue;
            }
            $actor->totpSecrets[$raw] = $secret;

            return $secret;
        }

        return null;
    }

    /**
     * The granted principal the token storage currently carries (the
     * restored token after a completed step-up), or null.
     */
    public function grantedPrincipal(RtActor $actor): ?string
    {
        $token = $this->tokenStorage()->getToken();
        if ($token === null || $token instanceof \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken) {
            return null;
        }
        try {
            $id = $token->getUserIdentifier();
        } catch (\Throwable) {
            return null;
        }

        return $id !== '' ? $id : null;
    }

    /**
     * Register the outcome bridge's security-event handlers on the
     * kernel's event dispatcher. Symfony routes some security events
     * through per-firewall dispatchers that a plain global subscriber
     * never sees; the deployment's own composition registers the
     * handlers it needs exactly like any other explicit listener, so
     * the bridge's CheckPassport / LoginFailure / LoginSuccess lanes
     * observe the real authentication flow.
     */
    public function listenSecurityEvents(): void
    {
        $dispatcher = $this->kernel->getContainer()->get('event_dispatcher');
        \assert($dispatcher instanceof \Symfony\Component\EventDispatcher\EventDispatcherInterface);
        $bridge = $this->kernel->getContainer()->get(\BelConsulting\KiwiCaptchaBundle\EventSubscriber\KiwiOutcomeBridgeSubscriber::class);
        \assert($bridge instanceof \BelConsulting\KiwiCaptchaBundle\EventSubscriber\KiwiOutcomeBridgeSubscriber);
        foreach (\BelConsulting\KiwiCaptchaBundle\EventSubscriber\KiwiOutcomeBridgeSubscriber::getSubscribedEvents() as $event => $handlers) {
            // The subscriber shape: event => [method] or [method,
            // priority], or a list of those pairs.
            $pairs = isset($handlers[0]) && \is_string($handlers[0]) ? [$handlers] : (array) $handlers;
            foreach ($pairs as $handler) {
                $method = \is_array($handler) ? ($handler[0] ?? null) : $handler;
                if (\is_string($method) && method_exists($bridge, $method)) {
                    $dispatcher->addListener($event, [$bridge, $method]);
                }
            }
        }
    }

    /**
     * The pending token currently left on the token storage by the
     * last request, or null.
     */
    public function currentPending(): ?object
    {
        $token = $this->tokenStorage()->getToken();
        if ($token === null) {
            return null;
        }
        $pending = FirstAttemptLoginGuard::unwrapIfPending($token);

        return $pending === $token ? null : $token;
    }

    /**
     * The unique id of a minted step-up challenge (the driver uses the
     * product's own minting only where it provisions its own flows).
     */
    public function mintedChallengeId(): string
    {
        return StepUpChallenge::mintId();
    }

    private function setPending(object $tokenStorage, object $pending): void
    {
        \assert($tokenStorage instanceof \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface);
        $tokenStorage->setToken($pending);
    }

    /**
     * The device cookie the response subscriber would have issued,
     * built by the product's own cookie builder.
     *
     * @return array<string, string> cookie name => value
     */
    private function deviceCookie(Request $request, string $value): array
    {
        $device = $this->kernel->getContainer()->get(\BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie::class);
        \assert($device instanceof \BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie);
        $cookie = $device->cookie($request, $value);

        return [$cookie->getName() => (string) $cookie->getValue()];
    }

    /** The actor's file-backed session (created from its cookie id). */
    private function actorSession(RtActor $actor): Session
    {
        $storage = new MockFileSessionStorage(
            sys_get_temp_dir() . '/kiwi-rt-d35-sessions',
        );
        if ($actor->session() !== '') {
            $storage->setId($actor->session());
        }

        $session = new Session($storage);
        // Started: a session-bound challenge binds to this id, the
        // browser-faithful shape (an unstarted session mints a
        // stateless client-secret challenge instead).
        $session->start();

        return $session;
    }

    /** A request carrying the actor's cookies and source address. */
    private function actorRequest(RtActor $actor, string $uri, string $method = 'GET', array $post = []): Request
    {
        return Request::create(
            'https://captcha.example.com' . $uri,
            $method,
            $post,
            $actor->cookies,
            [],
            ['REMOTE_ADDR' => $actor->ip],
        );
    }

    private function tokenStorage(): \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface
    {
        $storage = $this->kernel->getContainer()->get('security.token_storage');
        \assert($storage instanceof \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface);

        return $storage;
    }
}

/**
 * One actor: a cookie jar (the browser state), a fixed source address,
 * the TOTP enrollments it provisioned and the pending token its last
 * withheld login left in place.
 */
final class RtActor
{
    /** @var array<string, string> */
    public array $cookies = [];

    /** @var array<string, string> raw principal => base32 TOTP secret */
    public array $totpSecrets = [];

    /** The pending step-up token carried from the withheld login (or null). */
    public ?object $pending = null;


    /** The session id the last completed step-up was bound to. */
    public ?string $completedSessionId = null;

    public function __construct(public readonly string $ip)
    {
    }

    /** The session id this actor's cookie jar addresses (or ''). */
    public function session(): string
    {
        foreach ($this->cookies as $name => $value) {
            if (str_contains($name, 'SESSID') || str_contains($name, 'sess')) {
                return (string) $value;
            }
        }

        return '';
    }

    /** The continuity cookie value the actor currently carries (or ''). */
    public function continuityCookie(): string
    {
        foreach ($this->cookies as $name => $value) {
            if (str_starts_with($name, '__Host-kiwi') && $name !== '__Host-kiwi_device') {
                return (string) $value;
            }
        }

        return $this->cookies['kiwi-session'] ?? '';
    }
}
