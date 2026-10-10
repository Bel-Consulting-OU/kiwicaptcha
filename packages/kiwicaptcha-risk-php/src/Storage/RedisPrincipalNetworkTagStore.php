<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\DeploymentNamespace;
use Predis\Client;

/**
 * Production principal-network tag store over Redis, backed by the
 * canonical `principal_networks.lua` script. This is the only
 * production implementation of {@see PrincipalNetworkTagStoreInterface};
 * the in-memory fixtures in tests are named fakes and never wired into
 * the container.
 *
 * The hash key is `pnet:{kiwi:<ns>}:<principal_hex>`. Each tag
 * (`net:<hex>`, `asn:<decimal>`, `session:<hex>`, `device:<hex>`) is a
 * hash field whose value is the last-use ms (Redis TIME, never a client
 * clock). Trust is a `t:` prefixed mirror field, minted only on an Allow
 * or a completed step-up.
 *
 * Error contract: any Redis failure throws {@see RiskStoreException},
 * so the engine follows its existing fail-closed path. The store never
 * returns "not seen" on error (which would read as "novel" and price
 * users out without a signal) and never "seen" (which would fail open).
 */
final class RedisPrincipalNetworkTagStore implements PrincipalNetworkTagStoreInterface
{
    /** Per-principal cap on session tags. */
    public const DEFAULT_SESSION_CAP = 32;
    /** Per-principal cap on device tags. */
    public const DEFAULT_DEVICE_CAP = 16;
    /** Per-principal cap on network and ASN tags. */
    public const DEFAULT_NET_CAP = 64;

    /** Session-tag TTL in ms (2x a 15-30 minute continuity cookie). */
    public const DEFAULT_SESSION_TTL_MS = 3_600_000;
    /** Device-tag TTL in ms (90 days). */
    public const DEFAULT_DEVICE_TTL_MS = 7_776_000_000;
    /** Network/ASN tag TTL in ms (400 days). */
    public const DEFAULT_NET_TTL_MS = 34_560_000_000;

    private readonly string $namespace;
    private string $scriptSha = '';

    /**
     * Production store over Redis.
     *
     * @param Client $client
     * @param string $namespace
     * @param int $sessionTtlMs
     * @param int $deviceTtlMs
     * @param int $sessionCap
     * @param int $deviceCap
     * @param int $netCap
     * @param int $namespaceKeyVersion
     */
    public function __construct(
        private readonly Client $client,
        string $namespace = 'd',
        private readonly int $sessionTtlMs = self::DEFAULT_SESSION_TTL_MS,
        private readonly int $deviceTtlMs = self::DEFAULT_DEVICE_TTL_MS,
        private readonly int $sessionCap = self::DEFAULT_SESSION_CAP,
        private readonly int $deviceCap = self::DEFAULT_DEVICE_CAP,
        private readonly int $netCap = self::DEFAULT_NET_CAP,
        int $namespaceKeyVersion = DeploymentNamespace::VERSION_LEGACY,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Risk namespace must be non-empty and free of braces');
        }
        if ($sessionTtlMs < 1 || $deviceTtlMs < 1) {
            throw new \InvalidArgumentException('Tag TTLs must be positive');
        }
        if ($sessionCap < 1 || $deviceCap < 1 || $netCap < 1) {
            throw new \InvalidArgumentException('Tag caps must be positive');
        }
        $this->namespace = DeploymentNamespace::derive($namespace, $namespaceKeyVersion);
    }

    /** The hash key of one principal's tag set. */
    public function tagKey(string $principalId): string
    {
        self::assertPrincipal($principalId);

        return "pnet:{kiwi:{$this->namespace}}:{$principalId}";
    }

    public function principalNetworkSeen(string $principalId, string $network): ?bool
    {
        $this->assertTag($network);
        try {
            $result = $this->runScript([$this->tagKey($principalId)], ['seen', $network]);

            return (int) $result === 1;
        } catch (\Throwable $e) {
            throw new RiskStoreException('principal network seen probe failed: '.$e->getMessage(), 0, $e);
        }
    }

    public function recordPrincipalNetworkTag(string $principalId, string $network, bool $trusted = false): bool
    {
        $this->assertTag($network);
        [$class, $ttlMs, $cap] = $this->classOf($network);
        try {
            $result = $this->runScript(
                [$this->tagKey($principalId)],
                ['record', $network, (string) $ttlMs, (string) $cap, $trusted ? '1' : '0'],
            );

            return (int) $result === 1;
        } catch (\Throwable $e) {
            throw new RiskStoreException('principal network record failed: '.$e->getMessage(), 0, $e);
        }
    }

    public function principalHasTrustedNetwork(string $principalId): ?bool
    {
        // Any trusted tag counts: probe the principal's own hash for a
        // `t:` field. The script's has_trusted needs a specific tag; the
        // interface's hasTrustedNetwork is the "any" variant. A non-empty
        // hash with at least one `t:` field answers true.
        try {
            $key = $this->tagKey($principalId);
            $all = $this->client->hgetall($key);
            if (!\is_array($all) || $all === []) {
                return false;
            }
            foreach (array_keys($all) as $field) {
                if (str_starts_with((string) $field, 't:')) {
                    return true;
                }
            }

            return false;
        } catch (\Throwable $e) {
            throw new RiskStoreException('principal trusted-network probe failed: '.$e->getMessage(), 0, $e);
        }
    }

    public function tagIsTrusted(string $principalId, string $network): ?bool
    {
        $this->assertTag($network);
        try {
            $result = $this->runScript([$this->tagKey($principalId)], ['has_trusted', $network]);

            return (int) $result === 1;
        } catch (\Throwable $e) {
            throw new RiskStoreException('tag trust probe failed: '.$e->getMessage(), 0, $e);
        }
    }

    /** Deletes every session and device tag for a principal (revocation). */
    public function forgetDevices(string $principalId): void
    {
        self::assertPrincipal($principalId);
        try {
            $key = $this->tagKey($principalId);
            $all = $this->client->hgetall($key);
            if (!\is_array($all) || $all === []) {
                return;
            }
            $fields = [];
            foreach (array_keys($all) as $field) {
                $field = (string) $field;
                if (str_starts_with($field, 'session:') || str_starts_with($field, 'device:')
                    || str_starts_with($field, 't:session:') || str_starts_with($field, 't:device:')) {
                    $fields[] = $field;
                }
            }
            if ($fields !== []) {
                $this->client->hdel($key, ...$fields);
            }
        } catch (\Throwable $e) {
            throw new RiskStoreException('forget devices failed: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * @return array{0: string, 1: int, 2: int} class name, TTL ms, cap
     */
    private function classOf(string $tag): array
    {
        if (str_starts_with($tag, 'session:')) {
            return ['session', $this->sessionTtlMs, $this->sessionCap];
        }
        if (str_starts_with($tag, 'device:')) {
            return ['device', $this->deviceTtlMs, $this->deviceCap];
        }

        return ['net', self::DEFAULT_NET_TTL_MS, $this->netCap];
    }

    private function runScript(array $keys, array $args)
    {
        $script = self::loadScript();
        $sha = $this->scriptSha !== '' ? $this->scriptSha : $this->loadSha($script);
        $callArgs = [];
        foreach ($args as $a) {
            $callArgs[] = (string) $a;
        }
        try {
            return $this->client->evalsha($sha, \count($keys), ...$keys, ...$callArgs);
        } catch (\Throwable) {
            // NOSCRIPT: reload and retry once.
            $this->scriptSha = $this->loadSha($script);

            return $this->client->evalsha($this->scriptSha, \count($keys), ...$keys, ...$callArgs);
        }
    }

    private function loadSha(string $script): string
    {
        $sha = $this->client->script('LOAD', $script);
        if (!\is_string($sha) || $sha === '') {
            throw new RiskStoreException('SCRIPT LOAD returned no sha');
        }
        $this->scriptSha = $sha;

        return $sha;
    }

    private static function loadScript(): string
    {
        $path = dirname(__DIR__, 2) . '/resources/principal_networks.lua';
        if (!is_file($path)) {
            throw new \RuntimeException(
                sprintf('Cannot locate the bundled script at resources/principal_networks.lua (resolved from %s)', __DIR__),
            );
        }
        $script = @file_get_contents($path);
        if ($script === false) {
            throw new \RuntimeException(sprintf('Cannot read the bundled script at %s', $path));
        }

        return $script;
    }

    private static function assertPrincipal(string $principalId): void
    {
        if (!preg_match('/^[0-9a-f]{1,64}$/', $principalId)) {
            throw new \InvalidArgumentException('principalId must be a lowercase hex pseudonym of at most 64 chars');
        }
    }

    private static function assertTag(string $tag): void
    {
        if (preg_match('/^(net|session|device):[0-9a-f]{1,64}$/', $tag)) {
            return;
        }
        if (preg_match('/^asn:[0-9]{1,10}$/', $tag)) {
            return;
        }
        // Bare hex: the engine's networkBucket() spelling (no prefix).
        if (preg_match('/^[0-9a-f]{2,68}$/', $tag)) {
            return;
        }
        throw new \InvalidArgumentException('tag must match net|session|device:<hex>, asn:<decimal>, or bare hex');
    }
}
