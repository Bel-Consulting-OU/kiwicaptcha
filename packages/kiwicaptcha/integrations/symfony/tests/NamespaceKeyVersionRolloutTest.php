<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\RedisNamespace;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainRedisFake;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The namespace-key-version rollout: switching an existing deployment
 * to the digest derivation is an explicit, acknowledged migration, and
 * the state that can revoke or block something is never abandoned by
 * the cutover.
 *
 * The scenario is the deployment the migration exists for. The legacy
 * namespace holds the emergency revocation
 * (`{kiwi:<legacy>}:security-policy` with min_policy_epoch 7) and an
 * open chain obligation, while the new namespace is empty. The
 * application is still configured with policy_version 6 and boots on
 * namespace_key_version 2 with the drained-migration acknowledgment.
 *
 * The test proves the three properties the rollout must have:
 * readiness never admits the epoch-6 node, verification never falls
 * back to epoch 6, and ticketless issuance can never restart stage 1
 * while the legacy obligation is open.
 */
final class NamespaceKeyVersionRolloutTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** The raw configured discriminator both key versions derive from. */
    private const RAW = '/srv/kiwi-prod';

    /** The application's risk.policy_version at the cutover. */
    private const CONFIGURED_EPOCH = 6;

    /** The central emergency revocation that must survive. */
    private const CENTRAL_EPOCH = 7;

    private static function legacyNamespace(): string
    {
        return RedisNamespace::derive(self::RAW, RedisNamespace::VERSION_LEGACY);
    }

    private static function digestNamespace(): string
    {
        return RedisNamespace::derive(self::RAW, RedisNamespace::VERSION_DIGEST);
    }

    public function testTheTwoDerivationsOfTheDeploymentDiffer(): void
    {
        // The cutover is real: the digest namespace is not the legacy
        // segment, so the state written before the migration lives under
        // a different key family and the dual-read is what carries it.
        self::assertSame('_srv_kiwi-prod', self::legacyNamespace(), 'the legacy derivation sanitizes the separator bytes');
        self::assertNotSame(self::legacyNamespace(), self::digestNamespace());
    }

    public function testTheDigestKeyVersionRequiresTheDrainedMigrationAcknowledgment(): void
    {
        // The digest version changes every key family at once, so the
        // bundle refuses it without the explicit acknowledgment.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::RAW);
        $container->register('fake_redis', FakePredisClient::class);
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/namespace_migration/');
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'redis_service' => 'fake_redis',
            'namespace_key_version' => RedisNamespace::VERSION_DIGEST,
            'risk' => ['namespace' => self::RAW],
        ]], $container);
    }

    public function testTheDigestRolloutWiresTheRawNamespaceAndVersionIntoEveryConsumer(): void
    {
        $container = $this->loadContainer([
            'secret_key' => self::SECRET,
            'redis_service' => 'fake_redis',
            'namespace_key_version' => RedisNamespace::VERSION_DIGEST,
            'namespace_migration' => 'drained',
            'risk' => [
                'namespace' => self::RAW,
                'chaining' => ['enabled' => true],
                'request_binding_authority' => 'binding.authority',
            ],
            'ha_authority' => 'pinned_primary',
        ]);

        // The security-epoch monitor: raw namespace + configured version
        // (the monitor derives the digest key and dual-reads the legacy
        // segment internally).
        $monitor = $container->getDefinition(SecurityEpochMonitor::class)->getArguments();
        self::assertSame(self::RAW, $monitor[2], 'the monitor receives the raw namespace');
        self::assertSame(RedisNamespace::VERSION_DIGEST, $monitor['$namespaceKeyVersion'] ?? null, 'the monitor receives the configured key version');

        // The readiness probe: same raw namespace + version.
        $health = $container->getDefinition(KiwiHealthController::class)->getArguments();
        self::assertSame(self::RAW, $health[2], 'the readiness probe receives the raw namespace');
        self::assertSame(RedisNamespace::VERSION_DIGEST, $health['$namespaceKeyVersion'] ?? null, 'the readiness probe receives the configured key version');

        // The chain store: raw namespace + version (it derives the
        // primary tag and dual-reads the legacy segment for obligations
        // and chain records).
        $chain = $container->getDefinition(RedisChainedChallengeStateStore::class)->getArguments();
        self::assertSame(self::RAW, $chain[1], 'the chain store receives the raw namespace');
        self::assertSame(RedisNamespace::VERSION_DIGEST, $chain[4] ?? null, 'the chain store receives the configured key version');

        // The authority pin: the guard is the single derivation boundary
        // and receives the raw namespace + version (never a derived
        // value).
        $guard = $container->getDefinition('kiwi_captcha.ha_authority_guard.storage')->getArguments();
        self::assertSame(self::RAW, $guard[1], 'the guard receives the raw namespace');
        self::assertSame(RedisNamespace::VERSION_DIGEST, $guard[5] ?? null, 'the guard receives the configured key version');
        $direct = new PinnedPrimaryAuthorityGuard(new FakePredisClient(), self::RAW, 5, 'storage', null, RedisNamespace::VERSION_DIGEST);
        self::assertSame(
            '{kiwi:'.self::digestNamespace().'}:authority:pin:storage',
            $direct->pinKey(),
            'the digest pin key is derived exactly once from the raw namespace',
        );
    }

    public function testTheLegacySecurityPolicyRevocationSurvivesTheNamespaceCutover(): void
    {
        // Old namespace: the emergency revocation. New namespace: empty.
        $client = new FakePredisClient();
        $client->hashes['{kiwi:'.self::legacyNamespace().'}:security-policy'] = [
            SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD => (string) self::CENTRAL_EPOCH,
        ];
        self::assertArrayNotHasKey('{kiwi:'.self::digestNamespace().'}:security-policy', $client->hashes, 'the new namespace starts empty');

        // Verification: the effective epoch is the merged floor (7), never
        // the freshly started process's configured epoch (6). A node that
        // read only the digest key would serve max(6, 0) = 6 and accept
        // the revoked epoch-6 challenges.
        $monitor = new SecurityEpochMonitor(
            new Verifier(new ArrayStorage()),
            $client,
            self::RAW,
            self::CONFIGURED_EPOCH,
            1,
            null,
            60,
            RedisNamespace::VERSION_DIGEST,
        );
        self::assertSame(
            [
                '{kiwi:'.self::digestNamespace().'}:security-policy',
                '{kiwi:'.self::legacyNamespace().'}:security-policy',
            ],
            $monitor->policyKeys(),
            'the digest rollout consults the digest key first, then the legacy segment',
        );
        self::assertSame(self::CENTRAL_EPOCH, $monitor->currentEpoch(), 'the legacy revocation raises the effective epoch to 7');
        self::assertSame(self::CENTRAL_EPOCH, $monitor->observedMax(), 'the observed max carries the legacy revocation');

        // Readiness: the epoch-6 node is not admitted. A node that read
        // only the digest key would answer 200.
        $controller = new KiwiHealthController(
            self::SECRET,
            $client,
            self::RAW,
            self::CONFIGURED_EPOCH,
            null,
            0,
            null,
            16384,
            [],
            null,
            false,
            1,
            1,
            RedisNamespace::VERSION_DIGEST,
        );
        $response = $controller->ready();
        self::assertSame(503, $response->getStatusCode(), 'the epoch-6 node must not be admitted while the legacy floor is 7');
        $body = json_decode((string) $response->getContent(), true);
        self::assertStringContainsString(
            'security_policy_incompatible:min_policy_epoch_'.self::CENTRAL_EPOCH,
            (string) ($body['reason'] ?? ''),
            'the readiness reason names the legacy revocation',
        );
    }

    public function testThePolicyFloorsMergeConservativelyAcrossBothNamespaces(): void
    {
        // A mixed state: the legacy policy declares the strongest
        // protocol and execution floors, the digest policy the strongest
        // epoch. The merged read takes the maximum of every floor — an
        // absent field in one namespace never weakens the other's.
        $client = new FakePredisClient();
        $client->hashes['{kiwi:'.self::legacyNamespace().'}:security-policy'] = [
            SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD => '3',
            SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD => '4',
            SecurityEpochMonitor::MIN_EXECUTION_VERSION_FIELD => '2',
        ];
        $client->hashes['{kiwi:'.self::digestNamespace().'}:security-policy'] = [
            SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD => '5',
            SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD => '2',
        ];

        $monitor = new SecurityEpochMonitor(
            new Verifier(new ArrayStorage()),
            $client,
            self::RAW,
            1,
            1,
            null,
            60,
            RedisNamespace::VERSION_DIGEST,
        );
        self::assertSame(5, $monitor->currentEpoch(), 'the strongest epoch wins');
        self::assertSame(4, $monitor->minProtocolVersion(), 'the strongest protocol floor wins');
        self::assertSame(2, $monitor->minExecutionVersion(), 'the strongest execution floor wins');

        // A corrupt field in either namespace leaves the combined read
        // unconfirmed: the protocol/execution floors are never armed off
        // a possibly-weaker read.
        $client->hashes['{kiwi:'.self::legacyNamespace().'}:security-policy'][SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD] = '4x';
        $corrupt = new SecurityEpochMonitor(
            new Verifier(new ArrayStorage()),
            $client,
            self::RAW,
            1,
            1,
            null,
            60,
            RedisNamespace::VERSION_DIGEST,
        );
        self::assertNull($corrupt->minProtocolVersion(), 'a corrupt legacy floor keeps the merged protocol floor unconfirmed');
        self::assertSame(5, $corrupt->currentEpoch(), 'the confirmed epoch fields still merge');
    }

    public function testTheOpenChainObligationSurvivesTheNamespaceCutover(): void
    {
        // Old namespace: an open chain obligation (a stage-2 obligation
        // already issued before the cutover). New namespace: empty.
        $fake = new ChainRedisFake();
        $legacyStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_LEGACY);
        $legacyService = new ChainedChallengeTicketService($legacyStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        $requirement = $legacyService->requireStage2(
            base64_encode(random_bytes(32)),
            'login',
            'txn-rollout',
            self::CONFIGURED_EPOCH,
            RiskAction::Argon32,
            $fake->clockSecs() + 300,
        );
        $obligationId = $legacyService->obligationIdFor('login', 'txn-rollout', self::CONFIGURED_EPOCH);
        self::assertSame($requirement->chainId, $legacyStore->obligationChainId($obligationId), 'the legacy obligation is open before the cutover');
        foreach (array_keys($fake->strings) as $key) {
            self::assertStringNotContainsString('{kiwi:'.self::digestNamespace().'}', (string) $key, 'the new namespace starts empty');
        }

        // Boot the upgraded node: the digest store consults the digest
        // namespace first and the legacy segment second.
        $digestStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        self::assertSame($requirement->chainId, $digestStore->obligationChainId($obligationId), 'the obligation written before the cutover stays visible');
        self::assertNotNull($digestStore->read($requirement->chainId), 'the chain record written before the cutover stays readable');

        $digestService = new ChainedChallengeTicketService($digestStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        $found = $digestService->findOpenRequirement('login', 'txn-rollout', self::CONFIGURED_EPOCH);
        self::assertNotNull($found, 'a ticketless request must see the open obligation, never restart stage 1');
        self::assertSame($requirement->chainId, $found->chainId);

        // The transition on the legacy-only record fails closed: the
        // reservation answers missing, so the controller cannot issue a
        // fresh unchained stage-1 challenge behind the open obligation.
        self::assertSame(
            ChainReservationResult::Missing,
            $digestService->reserveStage2($requirement->chainId, bin2hex(random_bytes(16))),
            'a transition on the legacy record fails closed instead of restarting the transaction',
        );
    }

    public function testTheLegacyAuthorityPinIsMigratedInsteadOfOrphaned(): void
    {
        $client = new FakePredisClient();
        $legacyKey = '{kiwi:'.self::legacyNamespace().'}:authority:pin:storage';
        $digestKey = '{kiwi:'.self::digestNamespace().'}:authority:pin:storage';
        $client->strings[$legacyKey] = 'primary|run-42';

        $guard = new PinnedPrimaryAuthorityGuard($client, self::RAW, 5, 'storage', null, RedisNamespace::VERSION_DIGEST);
        self::assertSame('primary|run-42', $guard->state()['pinned'], 'the legacy pin is adopted by the digest-version guard');
        self::assertSame('primary|run-42', $client->strings[$digestKey] ?? null, 'the legacy pin is explicitly migrated to the digest pin key');
        self::assertSame('primary|run-42', $client->strings[$legacyKey] ?? null, 'the legacy pin is left in place, never destroyed');

        // An existing digest pin always wins: the migration only adopts a
        // legacy pin when the primary pin is absent.
        $client->strings[$digestKey] = 'primary|run-43';
        $guard2 = new PinnedPrimaryAuthorityGuard($client, self::RAW, 5, 'storage', null, RedisNamespace::VERSION_DIGEST);
        self::assertSame('primary|run-43', $guard2->state()['pinned'], 'an existing digest pin is authoritative');
        self::assertSame('primary|run-43', $client->strings[$digestKey]);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function loadContainer(array $config): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::RAW);
        $container->register('fake_redis', FakePredisClient::class);
        $container->register('binding.authority', \stdClass::class);
        (new KiwiCaptchaExtension())->load([$config], $container);

        return $container;
    }
}
