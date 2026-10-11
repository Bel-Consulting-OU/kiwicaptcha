<?php

declare(strict_types=1);

/**
 * rt.kernel.php — the red-team product kernel. A REAL Symfony kernel:
 * FrameworkBundle + SecurityBundle + KiwiCaptchaBundle, the
 * abuse_first protection profile, a form_login firewall over the
 * deployment's own user source, the step-up plane (email OTP bootstraps
 * the first factor, TOTP is the enrolled authenticator) and a protected
 * /account route. Nothing about the risk engine is constructed here:
 * the kernel's own extension builds every service, and the campaigns
 * drive the result through $kernel->handle(Request::create(...)) —
 * the same HTTP surface a real deployment serves.
 *
 * The container carries ZERO overrides: no definition is replaced,
 * removed or aliased. The campaign measurement contract is "the
 * product as shipped"; a missing seam is a boot failure, never a
 * silently absent dependency. The one compiler pass only widens
 * service visibility so the driver can read measurement state back
 * (the same pass every Symfony kernel test ships); visibility is not
 * wiring.
 *
 * The application side of the deployment (the parts a real
 * integration supplies and the bundle deliberately does not):
 *   - the leaked-list user source (RtLeakedListUserProvider) — the
 *     campaign's account table, the way any app plugs its own user
 *     database into the security firewall;
 *   - the login and account controllers — the login form and the
 *     protected page any app would render;
 *   - the step-up code sender capture (RtCodeCapture) — the
 *     application-bound delivery channel of the email OTP handler;
 *     a real deployment delivers mail, the harness captures it.
 *
 * Every risk-relevant decision, store write and history record is the
 * product's own.
 */

namespace KiwiRt;

use BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

require_once __DIR__ . '/rt-risk-prelude.php';

/** The shared kernel class name the campaigns report as the driver. */
const RT_KERNEL_CLASS = 'KiwiRt\\RtCampaignKernel';

/**
 * The campaign ASN fixture: the local IP-to-ASN dataset the deployment
 * would ship. The home ISP is 10.0.0.0/8 -> ASN 64496, the attacker
 * egress is 45.0.0.0/8 -> ASN 64500. This is environment routing data
 * (every deployment supplies its own), not risk state.
 */
function rtAsnFixture(): string
{
    static $path = null;
    if ($path !== null && is_file($path)) {
        return $path;
    }
    $path = sys_get_temp_dir() . '/kiwi-rt-asn-' . (getenv('KIWI_RT_SEED') ?: '0x6b776d74') . '.tsv';
    file_put_contents($path, "# kiwi-rt campaign ASN dataset\n10.0.0.0\t10.255.255.255\t64496\n45.0.0.0\t45.255.255.255\t64500\n");

    return $path;
}

/**
 * The campaign's account table: the leaked-list shape the D3.5
 * campaign measures. Account i is `acct-<sha256('d35-acct|i')>` and
 * its true password is drawn from the corpus with the campaign's LCG,
 * so the user source and the driver derive identical tables from the
 * seed without materializing 100k users in the compiled container.
 * This is application data (the deployment's user database), not risk
 * state.
 */
final class RtD35Accounts
{
    /** The account name of leaked-list row i. */
    public static function name(int $index): string
    {
        return 'acct-' . hash('sha256', 'd35-acct|' . $index);
    }

    /** Index of an account name, or null when the name is not in the list. */
    public static function indexOf(string $name): ?int
    {
        if (!str_starts_with($name, 'acct-')) {
            return null;
        }
        static $reverse = null;
        if ($reverse === null) {
            $reverse = [];
            for ($a = 0, $n = self::rows(); $a < $n; $a++) {
                $reverse[self::name($a)] = $a;
            }
        }

        return $reverse[$name] ?? null;
    }

    /** The account's true password (the leaked list's working rows). */
    public static function passwordOf(int $index): string
    {
        static $passwords = null;
        if ($passwords === null) {
            $passwords = [];
            $handle = fopen(__DIR__ . '/d35.passwordlist.txt', 'rb');
            if ($handle === false) {
                throw new RuntimeException('the leaked-list corpus is missing at d35.passwordlist.txt');
            }
            while (($line = fgets($handle)) !== false) {
                $line = rtrim($line, "\r\n");
                if ($line === '' || $line[0] === '#') {
                    continue;
                }
                $passwords[$line] = true;
            }
            fclose($handle);
            // Numeric corpus lines become int array keys: cast back so
            // every password answers as its literal string.
            $passwords = array_map('strval', array_keys($passwords));
        }

        return $passwords[self::lcgAt($index) % count($passwords)];
    }

    /** Declared row count (KIWI_RT_D35_ROWS, floored like the campaign). */
    public static function rows(): int
    {
        return max(1000, (int) (getenv('KIWI_RT_D35_ROWS') ?: 100000));
    }

    /** The campaign's LCG, advanced $index times from the shared seed. */
    private static function lcgAt(int $index): int
    {
        $seedHex = hash('sha256', 'kiwi-rt-d35|' . (getenv('KIWI_RT_SEED') ?: '0x6b776d74'));
        $lcg = unpack('q', substr(hash('sha512', $seedHex, true), 0, 8))[1] & 0x7FFFFFFF;
        $lcg |= 1;
        for ($i = 0; $i <= $index; $i++) {
            $lcg = ($lcg ^ ($lcg >> 12)) & 0x7FFFFFFF;
            $lcg = ($lcg ^ ($lcg << 25)) & 0x7FFFFFFF;
            $lcg = ($lcg ^ ($lcg >> 27)) & 0x7FFFFFFF;
        }

        return $lcg;
    }
}

/**
 * The deployment's user source over the leaked list. Any Symfony
 * application supplies its own provider; this one answers the list's
 * accounts with their true passwords and refuses everyone else.
 */
final class RtLeakedListUserProvider implements UserProviderInterface
{
    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        $index = RtD35Accounts::indexOf($identifier);
        if ($index === null) {
            throw new UserNotFoundException(sprintf('no account "%s" in the leaked list', $identifier));
        }

        return new InMemoryUser($identifier, RtD35Accounts::passwordOf($index), ['ROLE_USER']);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return $class === InMemoryUser::class || is_subclass_of($class, InMemoryUser::class);
    }
}

/**
 * The login page: a minimal form_login target rendering the two
 * parameter fields the firewall reads. A real deployment renders its
 * own page; the harness needs the fields and nothing else.
 */
final class RtLoginPageController
{
    public function login(): Response
    {
        return new Response(
            '<!doctype html><html><body><form method="post" action="/login_check">'
            . '<input type="text" name="username"><input type="password" name="password">'
            . '<button type="submit">sign in</button></form></body></html>',
            Response::HTTP_OK,
            ['Content-Type' => 'text/html'],
        );
    }
}

/**
 * The protected page: the resource a stolen session is after. The
 * firewall's access_control demands IS_AUTHENTICATED_FULLY, so a
 * pending (step-up withheld) token answers 403 and a granted one 200.
 */
final class RtAccountPageController
{
    public function account(): Response
    {
        return new Response('account ok', Response::HTTP_OK, ['Content-Type' => 'text/plain']);
    }
}

/**
 * The application-bound OTP delivery channel: the deployment's own
 * mailer seam. The harness captures the last code per principal so the
 * driver can complete the email-otp step-up exactly like an inbox
 * would.
 */
final class RtCodeCapture implements \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCodeSenderInterface
{
    /** @var array<string, string> principal pseudonym => last delivered code */
    public array $lastCodeByPrincipal = [];

    public function send(string $code, \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext $context, int $ttlSecs): void
    {
        $this->lastCodeByPrincipal[$context->principalPseudonym] = $code;
    }
}

/**
 * The application's principal resolver: the deployment's own answer to
 * "which principal does this request carry" (the bundle's contract for
 * the step-up controller). Any Symfony application registers one; this
 * one reads the security token storage, the shape the bundle's own
 * integration documents.
 */
final class RtPrincipalResolver implements \BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface
{
    public function __construct(private readonly \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface $tokenStorage)
    {
    }

    public function resolve(\Symfony\Component\HttpFoundation\Request $request, string $scope): ?string
    {
        $user = $this->tokenStorage->getToken()?->getUser();
        if ($user instanceof \Symfony\Component\Security\Core\User\UserInterface) {
            $id = $user->getUserIdentifier();

            return $id !== '' ? $id : null;
        }

        return null;
    }
}

/**
 * The deployment's logger: captures the risk gateway's internal
 * diagnostics so a driver failure prints the decision context instead
 * of a bare deny. A real application wires its own logger; the
 * extension resolves it by the "logger" alias.
 */
final class RtArrayLogger extends \Psr\Log\AbstractLogger
{
    /** @var list<string> */
    public static array $lines = [];

    public function log($level, string|\Stringable $message, array $context = []): void
    {
        unset($context);
        self::$lines[] = sprintf('%s %s', (string) $level, (string) $message);
        if (\count(self::$lines) > 500) {
            self::$lines = \array_slice(self::$lines, -500);
        }
    }
}

/**
 * The application's CheckPassport observer: feeds the outcome bridge
 * the claimed identifier of the login attempt (the request attribute
 * its LoginFailure lane reads). The deployment owns the login flow,
 * so the deployment supplies the flow's context; on this Symfony line
 * the CheckPassportEvent carries no request, so the main request comes
 * off the kernel's request stack.
 */
final class RtOutcomeTargetListener
{
    private const TARGET_ATTRIBUTE = '_kiwi_outcome_target';
    private const USER_BADGE_CLASS = 'Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge';

    public function __construct(private readonly \Symfony\Component\HttpFoundation\RequestStack $requestStack)
    {
    }

    public function onCheckPassport(object $event): void
    {
        try {
            $request = $this->requestStack->getMainRequest();
            if ($request === null || !method_exists($event, 'getPassport')) {
                return;
            }
            $passport = $event->getPassport();
            $badge = \is_object($passport) && method_exists($passport, 'getBadge')
                ? $passport->getBadge(self::USER_BADGE_CLASS)
                : null;
            if (!\is_object($badge) || !method_exists($badge, 'getUserIdentifier')) {
                return;
            }
            $id = $badge->getUserIdentifier();
            if (\is_string($id) && $id !== '') {
                $request->attributes->set(self::TARGET_ATTRIBUTE, $id);
            }
        } catch (\Throwable) {
            // never break the authentication flow
        }
    }
}

/**
 * The kernel. abuse_first, form_login over the leaked list, TOTP and
 * email OTP enabled, /account behind IS_AUTHENTICATED_FULLY, the risk
 * engine on the real Redis. Zero container overrides.
 */
final class RtCampaignKernel extends Kernel
{
    public function __construct()
    {
        parent::__construct('test', false);
    }

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new SecurityBundle(),
            new KiwiCaptchaBundle(),
        ];
    }

    protected function build(ContainerBuilder $container): void
    {
        // Visibility only: no definition is replaced, removed or
        // aliased (container_overrides stays 0). The driver reads
        // measurement state (store level, target state, policy) and
        // the application seams it itself registered.
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                foreach ([
                    'kiwi_captcha.risk.store',
                    'kiwi_captcha.risk.policy',
                    'kiwi_captcha.risk.identity_factory',
                    'kiwi_captcha.risk.principal_networks',
                    'security.token_storage',
                    \BelConsulting\KiwiCaptchaBundle\Controller\StepUpController::class,
                    RtCodeCapture::class,
                ] as $id) {
                    if ($container->hasDefinition($id)) {
                        $container->getDefinition($id)->setPublic(true);
                    } elseif ($container->hasAlias($id)) {
                        $container->getAlias($id)->setPublic(true);
                    }
                }
            }
        });
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $redisUrl = (string) getenv('KIWI_RT_RISK_REDIS_URL');
            if ($redisUrl === '') {
                throw new InvalidConfigurationException('KIWI_RT_RISK_REDIS_URL is not set: the kernel boots the real risk engine on real Redis');
            }

            // The deployment's own Redis client, user source and pages.
            $container->register('rt_redis', \Predis\Client::class)
                ->setArguments([$redisUrl])
                ->setPublic(true);
            $container->register(RtLeakedListUserProvider::class)->setPublic(true);
            $container->register(RtLoginPageController::class)->setPublic(true);
            $container->register(RtAccountPageController::class)->setPublic(true);
            $container->register(RtCodeCapture::class)->setPublic(true);
            // The outcome bridge's request context: on this Symfony
            // line CheckPassportEvent carries no request, so the
            // deployment supplies the claimed identifier itself (the
            // attribute the bridge's LoginFailure lane reads), the
            // integration work the bundle documents as application
            // side. Registered on the firewall's event dispatcher,
            // where the security events are delivered.
            $container->register('rt.outcome_target', RtOutcomeTargetListener::class)
                ->setArguments([new \Symfony\Component\DependencyInjection\Reference('request_stack')])
                ->setPublic(true)
                ->addTag('kernel.event_listener', ['dispatcher' => 'security.event_dispatcher.main', 'event' => \Symfony\Component\Security\Http\Event\CheckPassportEvent::class, 'method' => 'onCheckPassport', 'priority' => 2048]);
            $container->register('logger', RtArrayLogger::class)->setPublic(true);
            $container->setAlias('Psr\\Log\\LoggerInterface', 'logger')->setPublic(true);
            // The step-up controller's principal resolver: the
            // application's own (the bundle refuses to guess it).
            $container->register(\BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface::class, RtPrincipalResolver::class)
                ->setArguments([new \Symfony\Component\DependencyInjection\Reference('security.token_storage')])
                ->setPublic(true);

            $sessionDir = sys_get_temp_dir() . '/kiwi-rt-d35-sessions';
            if (!is_dir($sessionDir)) {
                mkdir($sessionDir, 0700, true);
            }

            $container->loadFromExtension('framework', [
                'secret' => 'rt-kernel-secret-0123456789abcdef',
                'test' => true,
                'router' => ['resource' => __DIR__ . '/rt.kernel.routes.php'],
                'session' => [
                    // The mock-file factory: real file-backed sessions
                    // addressed by the session cookie (the cookie-jar
                    // model), without PHP's native session_start header
                    // contract, which a kernel-driven worker cannot meet.
                    'storage_factory_id' => 'session.storage.factory.mock_file',
                    'handler_id' => null,
                    'save_path' => $sessionDir,
                    'cookie_secure' => true,
                    'cookie_samesite' => 'lax',
                ],
                'php_errors' => ['log' => true],
            ]);

            $container->loadFromExtension('security', [
                'password_hashers' => [
                    'Symfony\Component\Security\Core\User\InMemoryUser' => 'plaintext',
                ],
                'providers' => [
                    'leaked_list' => ['id' => RtLeakedListUserProvider::class],
                ],
                'firewalls' => [
                    'main' => [
                        'pattern' => '^/',
                        'lazy' => true,
                        'form_login' => [
                            'login_path' => 'rt_login',
                            'check_path' => 'rt_login_check',
                            'username_parameter' => 'username',
                            'password_parameter' => 'password',
                            'enable_csrf' => false,
                        ],
                    ],
                ],
                'access_control' => [
                    ['path' => '^/account', 'roles' => 'IS_AUTHENTICATED_FULLY'],
                ],
            ]);

            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => 'rt-d35-secret-0123456789abcdefgh',
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                // The abuse posture is the shipped profile, not a
                // driver-built matrix: every derived default (novelty
                // enforcement, weights, scope minimums) comes from the
                // bundle's own ProtectionProfileDefaults.
                'protection_profile' => 'abuse_first',
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'rt_redis',
                    'asn' => ['dataset_path' => rtAsnFixture()],
                    'scopes' => [
                        'login' => ['id' => 1, 'target_field' => 'username'],
                    ],
                    'outcomes' => [
                        'auto_bridge' => true,
                        'scope' => 'login',
                        'trust_gate' => 'fail_closed',
                    ],
                    'step_up' => [
                        'enabled' => true,
                        'scope' => 'login',
                        // email OTP bootstraps the first enrollment,
                        // TOTP is the enrolled authenticator after it.
                        'default_handler' => 'email_otp',
                        'hmac_secret' => 'rt-d35-stepup-hmac-secret-0123456789abcdef',
                        'begin_path' => '/step-up/begin',
                        'complete_path' => '/step-up/complete',
                        'handlers' => [
                            'email_otp' => ['enabled' => true, 'sender' => RtCodeCapture::class],
                            'totp' => ['enabled' => true],
                        ],
                    ],
                ],
            ]);
        });
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/kiwi-rt-kernel-' . md5(RT_KERNEL_CLASS . (string) RtD35Accounts::rows()) . '/' . $this->environment;
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/kiwi-rt-kernel-logs';
    }
}
