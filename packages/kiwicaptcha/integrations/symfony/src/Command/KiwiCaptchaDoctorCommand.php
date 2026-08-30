<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Command;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Security\ExpectedOrigin;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyStore;
use Composer\InstalledVersions;
use KiwiCaptcha\AtomicDeleteIfPendingInterface;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\Config;
use KiwiCaptcha\ConsumedStateReadableInterface;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\StorageInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Production-environment doctor: validates the wiring the extension
 * built from the processed configuration and reports one status (pass,
 * warn or fail) per check. A failed check makes the command exit
 * non-zero, so a deploy gate can run kiwicaptcha:doctor and refuse a
 * broken environment.
 *
 * Every check is evaluated against the container's actual services and
 * the effective (profile-derived) configuration. A check that cannot be
 * evaluated reports warn, never a made-up pass: for example the CSP of
 * the application pages cannot be inspected from the CLI, so the CSP
 * check states the documented requirements and warns that they stay
 * unverified.
 *
 * No HTTP context is required; the command runs under a plain console
 * kernel boot.
 */
final class KiwiCaptchaDoctorCommand extends Command
{
    /**
     * The protocol set this binary can emit and verify: v1 (legacy),
     * v2 (canonical, unarmed) and v3 (decoy-armed). Mirrors the core
     * verifier's accepted protocol range.
     */
    private const SUPPORTED_PROTOCOL_MAX = 3;

    /**
     * The SLO safety margin (ms) between the Argon admission lease and
     * the declared maximum verification runtime, mirroring the
     * extension's lease-safety margin: the lease must outlive the
     * runtime by at least this margin.
     */
    private const ARGON_LEASE_SAFETY_MARGIN_MS = 5000;

    /**
     * The core's browser-solvable Argon2id memory ceiling (KiB). The
     * core constructor enforces the same bound inline.
     */
    private const ARGON_MEMORY_CEILING_KIB = 65536;

    /**
     * @param array<string, mixed> $config the effective processed
     *        configuration (profile-derived defaults included), the
     *        same array the extension consumed
     */
    public function __construct(
        private readonly string $environment,
        private readonly array $config,
        private readonly StorageInterface $storage,
        private readonly Config $coreConfig,
        private readonly SecurityEpochMonitor $epochMonitor,
        private readonly \Redis|\Predis\Client|null $redis,
        private readonly \Predis\Client|null $riskRedis,
        private readonly ?ChainedChallengeStateStore $chainStore,
        private readonly ?SiteVerifyIdempotencyStore $siteVerifyIdempotencyStore,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('kiwicaptcha:doctor')
            ->setDescription('Validates the KiwiCaptcha production environment');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $profile = $this->config['protection_profile'] ?? null;
        $output->writeln(sprintf(
            'KiwiCaptcha doctor for environment %s (protection profile %s)',
            $this->environment,
            $profile === null ? 'none' : $profile,
        ));
        $output->writeln('');

        $checks = [
            'Storage atomicity' => $this->checkStorage(),
            'Redis reachability' => $this->checkRedis($this->redis, 'storage/limiter Redis'),
            'Replication topology' => $this->checkReplicationTopology(),
            'Secret key' => $this->checkSecret(),
            'Keyring state' => $this->checkKeyring(),
            'Public origin' => $this->checkPublicOrigin(),
            'Client-IP policy' => $this->checkClientIpPolicy(),
            'Risk Redis' => $this->checkRiskRedis(),
            'Protocol floor' => $this->checkProtocolFloor(),
            'Protocol-v3 writer' => $this->checkV3Writer(),
            'Argon memory envelope' => $this->checkArgonEnvelope(),
            'Argon concurrency' => $this->checkArgonConcurrency(),
            'CSP compatibility' => $this->checkCsp(),
            'SiteVerify status' => $this->checkSiteVerify(),
            'Chained challenges' => $this->checkChaining(),
            'Release versions' => $this->checkVersions(),
        ];

        $passed = 0;
        $warnings = 0;
        $failed = 0;
        foreach ($checks as $name => [$status, $detail]) {
            $output->writeln(sprintf('[%s] %s: %s', $status, $name, $detail));
            if ($status === 'PASS') {
                ++$passed;
            } elseif ($status === 'WARN') {
                ++$warnings;
            } else {
                ++$failed;
            }
        }

        $output->writeln('');
        $output->writeln(sprintf(
            'Summary: %d passed, %d warnings, %d failed',
            $passed,
            $warnings,
            $failed,
        ));

        return $failed > 0 ? Command::FAILURE : Command::SUCCESS;
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkStorage(): array
    {
        $class = \get_class($this->storage);
        if (!$this->storage instanceof AtomicStorageInterface) {
            if (\in_array($this->environment, ['test', 'dev'], true)) {
                return ['WARN', sprintf('%s is not atomic (in-memory semantics, allowed in %s only)', $class, $this->environment)];
            }

            return ['FAIL', sprintf('production requires an atomic storage backend (AtomicStorageInterface); %s is not atomic', $class)];
        }
        if (($this->config['risk']['siteverify_secrets'] ?? []) !== []) {
            $recoveryCapable = $this->storage instanceof \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyRecoveryCapableStorageInterface
                || ($this->storage instanceof ConsumedStateReadableInterface
                    && $this->storage instanceof OperationIdentityAwareStorageInterface
                    && $this->storage instanceof AtomicDeleteIfPendingInterface);
            if (!$recoveryCapable) {
                return ['FAIL', sprintf('SiteVerify is configured but %s cannot recover committed outcomes (missing the identity-aware consume or delete-if-pending capability)', $class)];
            }

            return ['PASS', sprintf('atomic and SiteVerify recovery-capable (%s)', $class)];
        }

        return ['PASS', sprintf('atomic storage (%s)', $class)];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkRedis(\Redis|\Predis\Client|null $client, string $label): array
    {
        if ($client === null) {
            return ['WARN', sprintf('%s not wired: rate limits and Argon admission fall back to in-process semantics', $label)];
        }
        try {
            $client->ping();

            return ['PASS', sprintf('%s answers PING', $label)];
        } catch (\Throwable $e) {
            return ['FAIL', sprintf('%s does not answer PING: %s', $label, $e->getMessage())];
        }
    }

    /**
     * The authority-change replay contract, posture-aware. Redis
     * failover topologies (Predis Sentinel or master-slave replication
     * aggregates and Redis Cluster aggregates) route commands through
     * promotion machinery, and the verified-WAIT barrier is refused on
     * them at construction, so waitReplicas stays 0 and the deployment
     * has no cross-authority replay guarantee. The deployment declares
     * its posture in replay_durability. best_effort (the default)
     * accepts the documented stale-promotion boundary and keeps the
     * replication-topology warn. operator_managed passes: the operator
     * owns promotion eligibility (replication gating, catch-up rules, a
     * promotion-eligibility gate on the failover manager) and
     * acknowledges the invariant. fail_closed is refused at container
     * build time when an HA aggregate client is wired, so a doctor that
     * observes that combination is itself a broken wiring. A
     * Redis-backed storage with waitReplicas 0 is the same boundary on
     * a single-node direct connection. The warn is the best_effort
     * acknowledgment; the other postures pass with the operator
     * contract noted. See docs/redis-topologies.md and
     * docs/ha-authority.md.
     *
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkReplicationTopology(): array
    {
        $posture = (string) ($this->config['replay_durability'] ?? 'best_effort');
        $aggregate = $this->predisAggregateLabel($this->redis, 'storage/limiter Redis')
            ?? $this->predisAggregateLabel($this->riskRedis, 'risk Redis');
        if ($aggregate !== null) {
            if ($posture === 'operator_managed') {
                return ['PASS', sprintf('%s — replay_durability "operator_managed": the operator owns promotion eligibility (replication gating / catch-up rules) and acknowledges the stale-promotion boundary (see docs/ha-authority.md).', $aggregate)];
            }
            if ($posture === 'fail_closed') {
                return ['FAIL', sprintf('%s — replay_durability "fail_closed" must never reach the doctor: the extension refuses this combination at container build time (a LogicException naming the posture and the remediation). A doctor that observes it means the wiring is broken.', $aggregate)];
            }

            return ['WARN', sprintf('%s — One-shot verification is atomic on the current Redis authority but is not guaranteed across stale-replica promotion. replay_durability is "best_effort": the deployment accepts the documented stale-promotion boundary. Choose and document the deployment posture (fail_closed / operator_managed / best_effort, see docs/redis-topologies.md).', $aggregate)];
        }
        if ($this->storage instanceof \KiwiCaptcha\Storage\RedisStorage) {
            $waitReplicas = (int) ($this->config['risk']['redis']['wait_replicas'] ?? 0);
            if ($waitReplicas <= 0) {
                if ($posture === 'operator_managed' || $posture === 'fail_closed') {
                    return ['PASS', sprintf('Redis-backed storage (%s) with waitReplicas 0 under replay_durability "%s": single-node direct client, %s', \get_class($this->storage), $posture, $posture === 'operator_managed' ? 'the operator owns the authority-change contract (promotion eligibility gated; see docs/ha-authority.md)' : 'the deployment keeps automatic failover out of the security-Redis contract (see docs/redis-topologies.md)')];
                }

                return ['WARN', sprintf('Redis-backed storage (%s) with waitReplicas 0 (the risk.redis wait_replicas knob) — One-shot verification is atomic on the current Redis authority but is not guaranteed across stale-replica promotion. replay_durability is "best_effort": the deployment accepts the documented stale-promotion boundary (see docs/redis-topologies.md).', \get_class($this->storage))];
            }

            return ['PASS', sprintf('Redis-backed storage (%s) with the verified-WAIT barrier (waitReplicas %d): acked writes reach every configured replica before success', \get_class($this->storage), $waitReplicas)];
        }

        return ['PASS', sprintf('no Redis-backed storage and no aggregate client: one-shot atomicity is per-authority and no promotion boundary applies (replay_durability "%s")', $posture)];
    }

    /**
     * Describe a wired client when it is a Predis replication or
     * cluster aggregate (the failover topologies), null otherwise.
     * The classification mirrors the core VerifiedWaitGuard, so a
     * deployment the barrier refuses is exactly the deployment this
     * check warns on.
     *
     * @return string|null null for a single-node direct connection
     */
    private function predisAggregateLabel(\Redis|\Predis\Client|null $client, string $label): ?string
    {
        if (!$client instanceof \Predis\Client) {
            return null;
        }
        $connection = $client->getConnection();
        if ($connection instanceof \Predis\Connection\Replication\ReplicationInterface) {
            return sprintf('%s is a Predis replication aggregate (%s): Sentinel or master-slave failover', $label, \get_class($connection));
        }
        if ($connection instanceof \Predis\Connection\Cluster\ClusterInterface) {
            return sprintf('%s is a Predis Redis Cluster aggregate (%s)', $label, \get_class($connection));
        }

        return null;
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkSecret(): array
    {
        $secret = $this->config['secret_key'];
        $length = \strlen($secret);
        if ($length < 16) {
            return ['FAIL', sprintf('secret_key is %d bytes; the core refuses secrets under 16 bytes', $length)];
        }
        $normalized = strtolower($secret);
        if (preg_match('/^(change|replace|your|example|sample|test)[-_]?/', $normalized) === 1
            || \in_array($normalized, ['secret', 'kiwi-secret', 'kiwi_secret', 'kiwicaptcha', 'changeme', 'changeme123'], true)
            || preg_match('/^(.)\1+$/', $secret) === 1
        ) {
            return ['WARN', sprintf('%d-byte secret looks like a placeholder or has no entropy; use a fresh random value', $length)];
        }

        return ['PASS', sprintf('%d-byte secret, no obvious placeholder shape', $length)];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkKeyring(): array
    {
        $kid = $this->config['kid'];
        $historical = $this->config['secrets_by_kid'];
        $revoked = $this->config['revoked_kids'];
        if (\in_array($kid, $revoked, true)) {
            return ['FAIL', sprintf('current kid %d is revoked: every issued challenge would fail verification', $kid)];
        }
        foreach (\array_keys($historical) as $historicalKid) {
            if ((int) $historicalKid === $kid) {
                return ['FAIL', sprintf('current kid %d also appears in secrets_by_kid: the verifier would select the wrong secret', $kid)];
            }
            if ((int) $historicalKid > $kid) {
                return ['FAIL', sprintf('historical kid %d exceeds the current kid %d: a future key would extend the rollback guard', (int) $historicalKid, $kid)];
            }
        }
        if ($kid > 1 && $historical === []) {
            return ['WARN', sprintf('kid %d has no historical secrets: verification of older records falls back to the legacy any-kid path', $kid)];
        }
        $note = sprintf(
            'kid %d, %d historical secret(s), %d revoked',
            $kid,
            \count($historical),
            \count($revoked),
        );
        if ($kid === 1 && $historical === [] && $revoked === []) {
            return ['PASS', $note.' (single-key ring, no rotation)'];
        }

        return ['PASS', $note];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkPublicOrigin(): array
    {
        $publicBaseUrl = $this->config['public_base_url'];
        if ($publicBaseUrl === null) {
            if (\in_array($this->environment, ['test', 'dev'], true)) {
                return ['WARN', 'public_base_url not set: allowed outside production; the expected origin derives from the request Host'];
            }

            return ['WARN', 'public_base_url not set: the expected origin derives from the request Host header; set a canonical https origin in production'];
        }
        $violation = ExpectedOrigin::publicBaseUrlViolation($publicBaseUrl);
        if ($violation !== null) {
            return ['WARN', sprintf('public_base_url "%s" %s', $publicBaseUrl, $violation)];
        }

        return ['PASS', sprintf('canonical origin %s from server config', $publicBaseUrl)];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkClientIpPolicy(): array
    {
        $mode = $this->config['risk']['client_ip_mode'];
        $proxies = $this->config['risk']['trusted_proxies'];
        if ($mode === 'direct') {
            return ['PASS', 'direct mode: the socket peer is authoritative'];
        }
        if ($mode === 'symfony_trusted_proxies' && $proxies === []) {
            return ['WARN', 'no trusted proxy is configured: forwarding headers are ignored, so behind a reverse proxy every client shares the proxy IP (per-source limits and risk attribution collapse)'];
        }
        if ($mode === 'symfony_trusted_proxies') {
            return ['PASS', sprintf('%d trusted proxy CIDR(s); forwarding headers honored only from them', \count($proxies))];
        }

        return ['WARN', 'symfony_global mode inherits the process-global trusted-proxy state; verify it matches this deployment'];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkRiskRedis(): array
    {
        if (!($this->config['risk']['enabled'] ?? false)) {
            return ['PASS', 'risk engine disabled'];
        }
        if ($this->riskRedis === null) {
            return ['FAIL', 'risk is enabled but no risk Redis client is wired (the extension refuses this at compile time; the wiring is broken)'];
        }

        return $this->checkRedis($this->riskRedis, 'risk Redis');
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkProtocolFloor(): array
    {
        $this->epochMonitor->refresh();
        if ($this->epochMonitor->isStale()) {
            return ['FAIL', 'the central security-policy read is stale: verification fails closed until the policy Redis answers again'];
        }
        $floor = $this->epochMonitor->minProtocolVersion();
        if ($floor === null) {
            return ['PASS', 'no central min_protocol_version floor confirmed; the binary\'s own configuration is authoritative'];
        }
        if ($floor > self::SUPPORTED_PROTOCOL_MAX) {
            return ['FAIL', sprintf('central floor demands protocol %d but this binary supports up to %d; readiness would refuse this node', $floor, self::SUPPORTED_PROTOCOL_MAX)];
        }

        return ['PASS', sprintf('central floor %d within the supported set 1..%d', $floor, self::SUPPORTED_PROTOCOL_MAX)];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkV3Writer(): array
    {
        // The effective (processed) values: the profile is the
        // lowest-precedence layer, so an explicit override in any
        // config file, including a null-cleared profile, is already
        // reflected here.
        $profile = $this->config['protection_profile'] ?? null;
        $decoyEnabled = (bool) ($this->config['risk']['decoy_v3_enabled'] ?? false);
        if ($profile === 'high_abuse' && !$decoyEnabled) {
            // Under high_abuse the profile-derived default is true, so
            // an effective false can only be an explicit deferral: the
            // operator chose the profile and consciously deferred v3
            // emission, which the check records as a warning, never a
            // fail (the two-phase rollout stays safe and the deploy
            // gate stays green for an explicit, documented choice).
            return ['WARN', 'high_abuse promises the decoy surface, but risk.decoy_v3_enabled is explicitly false: protocol v3 emission is deferred while the profile stays active'];
        }
        if (!$decoyEnabled) {
            return ['PASS', 'protocol v2 emission (decoy surface off)'];
        }
        $this->epochMonitor->refresh();
        $floor = $this->epochMonitor->minProtocolVersion();
        if ($floor !== null && $floor >= 3) {
            return ['PASS', 'decoy surface armed and the central floor confirms protocol v3 emission'];
        }
        if ($profile === 'high_abuse') {
            return ['FAIL', 'high_abuse requires authenticated decoy emission, but the fleet protocol floor has not been confirmed at v3. Confirm every serving binary supports protocol v3 and raise the central security-policy min_protocol_version to 3 (the two-phase rollout, see operations.md), or explicitly set risk.decoy_v3_enabled: false to defer v3 emission while the profile stays active.'];
        }

        return ['WARN', 'decoy surface armed but the central floor is below 3 or unconfirmed: issuance falls back to protocol v2; finish the two-phase rollout before expecting decoy-armed emission'];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkArgonEnvelope(): array
    {
        $violations = [];
        $algorithm = (string) $this->config['algorithm'];
        if ($this->coreConfig->mKib > self::ARGON_MEMORY_CEILING_KIB) {
            $violations[] = sprintf('argon_m_kib %d exceeds the %d KiB browser-solvable ceiling', $this->coreConfig->mKib, self::ARGON_MEMORY_CEILING_KIB);
        }
        if ($this->coreConfig->t > Config::MAX_ARGON_T) {
            $violations[] = sprintf('argon_t %d exceeds the issuance ceiling %d', $this->coreConfig->t, Config::MAX_ARGON_T);
        }
        if ($this->coreConfig->targetBits > Config::MAX_SHA_TARGET_BITS) {
            $violations[] = sprintf('difficulty_bits %d exceeds %d', $this->coreConfig->targetBits, Config::MAX_SHA_TARGET_BITS);
        }
        if ($this->coreConfig->argon2TargetBits > Config::MAX_ARGON2_TARGET_BITS) {
            $violations[] = sprintf('argon2_difficulty_bits %d exceeds %d', $this->coreConfig->argon2TargetBits, Config::MAX_ARGON2_TARGET_BITS);
        }
        if ($this->coreConfig->ttlSecs > Config::MAX_TTL_SECS) {
            $violations[] = sprintf('challenge_ttl_secs %d exceeds %d', $this->coreConfig->ttlSecs, Config::MAX_TTL_SECS);
        }
        if ($algorithm === 'argon2id') {
            if ($this->coreConfig->t < 3) {
                $violations[] = sprintf('argon2id requires t >= 3 (got %d)', $this->coreConfig->t);
            }
            if ($this->coreConfig->p !== 1) {
                $violations[] = sprintf('argon2id requires p == 1 (got %d)', $this->coreConfig->p);
            }
            if ($this->coreConfig->mKib < 8 * $this->coreConfig->p) {
                $violations[] = sprintf('argon2id requires m_kib >= 8 * p (got m_kib %d, p %d)', $this->coreConfig->mKib, $this->coreConfig->p);
            }
        }
        if ($violations !== []) {
            return ['FAIL', implode('; ', $violations)];
        }

        return ['PASS', sprintf(
            'm_kib %d, t %d, p %d, sha %d bits, argon2 %d bits, ttl %d s: within the core ceilings',
            $this->coreConfig->mKib,
            $this->coreConfig->t,
            $this->coreConfig->p,
            $this->coreConfig->targetBits,
            $this->coreConfig->argon2TargetBits,
            $this->coreConfig->ttlSecs,
        )];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkArgonConcurrency(): array
    {
        $global = $this->config['argon2_max_concurrent_verifications'];
        $perTenant = $this->config['argon2_max_per_tenant']
            ?? ($global > 0 ? max(1, $global - 1) : null);
        if ($global > 0 && $perTenant !== null && $perTenant >= $global) {
            return ['FAIL', sprintf('effective per-scope cap %d is not below the global cap %d', $perTenant, $global)];
        }
        $lease = $this->config['argon2_lease_ms'];
        $runtime = $this->config['argon2_max_verification_runtime_ms'];
        if ($lease <= $runtime + self::ARGON_LEASE_SAFETY_MARGIN_MS) {
            return ['FAIL', sprintf('argon2_lease_ms %d must exceed argon2_max_verification_runtime_ms %d by the %d ms margin', $lease, $runtime, self::ARGON_LEASE_SAFETY_MARGIN_MS)];
        }
        if ($global === 0) {
            return ['PASS', sprintf('unlimited concurrency; lease %d ms outlives the %d ms runtime SLO by the margin', $lease, $runtime)];
        }

        return ['PASS', sprintf('global cap %d, per-scope %d; lease %d ms outlives the %d ms runtime SLO by the margin', $global, $perTenant, $lease, $runtime)];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkCsp(): array
    {
        return ['WARN', 'the page CSP cannot be verified from the CLI; ensure script-src allows the widget (nonce or unsafe-inline) plus wasm-unsafe-eval, style-src covers the inline styles, worker-src blob: covers the Argon worker, and connect-src covers the challenge API (see getting-started.md Content-Security-Policy)'];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkSiteVerify(): array
    {
        $secrets = $this->config['risk']['siteverify_secrets'] ?? [];
        if ($secrets === []) {
            return ['PASS', 'disabled (no siteverify secrets configured)'];
        }
        if ($this->siteVerifyIdempotencyStore === null) {
            return ['FAIL', 'SiteVerify is configured but the idempotency store is not wired'];
        }
        $storeClass = \get_class($this->siteVerifyIdempotencyStore);
        if (!str_contains($storeClass, 'RedisSiteVerifyIdempotencyStore')) {
            if (\in_array($this->environment, ['test', 'dev'], true)) {
                return ['WARN', sprintf('%d secrets, but the idempotency store is in-memory (%s): dev-only semantics', \count($secrets), $storeClass)];
            }

            return ['FAIL', sprintf('%d secrets, but the idempotency store is in-memory (%s): the one-success contract needs a shared backend', \count($secrets), $storeClass)];
        }

        return ['PASS', sprintf('%d secret(s), Redis-backed idempotency store', \count($secrets))];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkChaining(): array
    {
        if (!($this->config['risk']['chaining']['enabled'] ?? false)) {
            return ['PASS', 'disabled'];
        }
        if ($this->chainStore === null) {
            return ['FAIL', 'chained challenges are enabled but the chain state store is not wired'];
        }
        $storeClass = \get_class($this->chainStore);
        if (!str_contains($storeClass, 'RedisChainedChallengeStateStore')) {
            return ['WARN', sprintf('chain state is in-memory (%s): dev-only semantics, no cross-worker transaction obligation', $storeClass)];
        }

        return ['PASS', sprintf('chain state Redis-backed (%s), authoritative binding wired', $storeClass)];
    }

    /**
     * @return array{0: string, 1: string} [status, detail]
     */
    private function checkVersions(): array
    {
        if (!\class_exists(InstalledVersions::class)) {
            return ['WARN', 'composer/installed-versions unavailable: bundle and core versions cannot be compared'];
        }
        $bundle = InstalledVersions::isInstalled('bel-consulting/kiwicaptcha-symfony')
            ? InstalledVersions::getPrettyVersion('bel-consulting/kiwicaptcha-symfony')
            : null;
        $core = InstalledVersions::isInstalled('kiwicaptcha/kiwicaptcha-php')
            ? InstalledVersions::getPrettyVersion('kiwicaptcha/kiwicaptcha-php')
            : null;
        if ($bundle === null || $core === null) {
            return ['WARN', sprintf('installed versions unresolvable (bundle %s, core %s)', $bundle ?? '?', $core ?? '?')];
        }
        if (str_starts_with($bundle, 'dev-') || str_starts_with($core, 'dev-')) {
            return ['WARN', sprintf('dev install: bundle %s with core %s; the composer constraint governs compatibility', $bundle, $core)];
        }
        $bundleMajor = (int) explode('.', $bundle)[0];
        $coreMajor = (int) explode('.', $core)[0];
        if ($bundleMajor !== $coreMajor) {
            return ['FAIL', sprintf('bundle %s and core %s are on different major versions', $bundle, $core)];
        }

        return ['PASS', sprintf('bundle %s with core %s (same major version)', $bundle, $core)];
    }
}
