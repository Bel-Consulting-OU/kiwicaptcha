<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Authority;

/**
 * The pinned-primary authority guard (docs/ha-authority.md): pins the
 * serving authority identity on first use and refuses every
 * subsequent use when the authority changed.
 *
 * Pin store: one Redis key in the same security-Redis namespace,
 * `{kiwi:<ns>}:authority:pin`, holding "role|run_id". The pin is
 * write-once (`SET ... NX`). The first use of a guard that has never
 * seen a pin establishes it from the connected server's `INFO`
 * identity (the role and run_id of the pinned node), and every later
 * check compares the serving identity against the pin. Any change
 * (a promotion to a stale replica, a restarted primary with a new
 * run_id, a pointed-at replica) raises the typed
 * {@see PinnedAuthorityRefusalException} naming the pinned vs
 * observed identity and the remediation. The remediation is explicit:
 * quiesce the deployment, delete the pin key, and let the next first
 * use re-pin after a deliberate authority change.
 *
 * Missing-pin semantics (documented choice): auto-pin on first use.
 * A fresh guard pins the first authority it can verify. Once the
 * guard has established or observed the pin in-process, a pin that
 * disappears (a failover to a node that never received the pin key)
 * is a refusal, and the guard refuses instead of re-pinning. The
 * deployment can only re-pin explicitly, exactly the operation a
 * stale-promotion recovery must not perform automatically. An
 * authority that cannot be verified (the `INFO` read fails, the pin
 * cannot be read) is a refusal too: the guard can only fail closed,
 * never fail open.
 *
 * Check window: the verification result is cached in-process for
 * `reverifySecs` (default 5). Within the window, subsequent checks
 * return without any round trip, so the `INFO` probe costs one round
 * trip per window per process, not one per operation. The pin key
 * itself is compared inside the same cached verification.
 *
 * Topology contract: the guard refuses automatic-failover aggregates
 * (Predis Sentinel, replication and cluster connections). A pinned
 * authority is a single node, and an aggregate can change the
 * serving node under the client. That change is exactly what this
 * guard detects at the deployment boundary; it is not routed around.
 * The bundle refuses aggregates under `ha_authority: pinned_primary`
 * at container build time; the constructor check is the same
 * classification at runtime.
 */
final class PinnedPrimaryAuthorityGuard implements AuthorityTransitionGuard
{
    private readonly string $pinKey;

    /**
     * The identity ("role|run_id") this process established or last
     * observed as pinned, or null before the first verification. Once
     * non-null, a missing pin key is a refusal (never a silent re-pin).
     */
    private ?string $establishedIdentity = null;

    /** hrtime(true) of the last successful verification, or null. */
    private ?int $lastVerifiedAt = null;

    private ?string $lastVerifiedIdentity = null;

    /**
     * @param \Predis\Client|\Redis $client        the bound authority
     *        client. Its `INFO` identity reads and its pin-key
     *        reads/writes go through this client, never through the
     *        passed client of {@see assertServeEligible()}. A guarded
     *        wrapper would otherwise recurse into its own check.
     * @param string                $namespace     the deployment
     *        namespace, sanitized to [A-Za-z0-9_.-] before it is
     *        embedded in the pin key. Matches every other bundle key.
     * @param int                   $reverifySecs  the verification cache
     *        window in seconds; 0 disables the cache (every check
     *        re-verifies, the test-mode and doctor-mode behavior)
     */
    public function __construct(
        private readonly \Predis\Client|\Redis $client,
        string $namespace = 'kiwicaptcha',
        private readonly int $reverifySecs = 5,
    ) {
        if ($reverifySecs < 0) {
            throw new \InvalidArgumentException(sprintf('reverifySecs must be >= 0, got %d', $reverifySecs));
        }
        $sanitized = preg_replace('/[^A-Za-z0-9_.-]/', '_', $namespace) ?: 'kiwi';
        $this->pinKey = sprintf('{kiwi:%s}:authority:pin', $sanitized);
        if ($client instanceof \Predis\Client) {
            $this->assertClientNotAggregate($client);
        }
    }

    /**
     * The pin key in the security-Redis namespace, named in every
     * refusal message so the operator can re-pin deliberately.
     */
    public function pinKey(): string
    {
        return $this->pinKey;
    }

    /**
     * The guard's observable state for the doctor: armed (a pin is
     * established and was verified), the pinned identity, the last
     * verified identity and the age of the last verification.
     *
     * @return array{armed: bool, pinned: ?string, lastVerified: ?string, lastCheckedAgoSecs: ?int}
     */
    public function state(): array
    {
        $pinned = $this->establishedIdentity;
        if ($pinned === null) {
            try {
                $raw = $this->readPin();
                if (\is_string($raw) && $raw !== '') {
                    $pinned = $raw;
                }
            } catch (\Throwable) {
                $pinned = null;
            }
        }

        return [
            'armed' => $pinned !== null && $this->lastVerifiedAt !== null,
            'pinned' => $pinned,
            'lastVerified' => $this->lastVerifiedIdentity,
            'lastCheckedAgoSecs' => $this->lastVerifiedAt === null
                ? null
                : (int) floor((hrtime(true) - $this->lastVerifiedAt) / 1_000_000_000),
        ];
    }

    public function assertServeEligible(mixed $client): void
    {
        if (!$client instanceof \Predis\Client && !$client instanceof \Redis) {
            throw new PinnedAuthorityRefusalException(
                'pinned_primary authority check refused: the client about to serve is not a Redis client ('.get_debug_type($client).') — the pinned-primary guard cannot verify an authority it cannot read.',
                $this->establishedIdentity,
            );
        }
        if ($client instanceof \Predis\Client) {
            $this->assertClientNotAggregate($client);
        }
        // Cached verification: within the window the pin was verified
        // and no round trip is needed; outside it, the identity is
        // re-read and compared against the pin.
        if ($this->lastVerifiedAt !== null
            && (hrtime(true) - $this->lastVerifiedAt) < $this->reverifySecs * 1_000_000_000
        ) {
            return;
        }
        $observed = $this->readIdentity();
        $observedIdentity = $this->formatIdentity($observed);
        $pinned = $this->readPin();
        if ($pinned === null) {
            if ($this->establishedIdentity !== null) {
                throw new PinnedAuthorityRefusalException(
                    sprintf(
                        'pinned_primary authority check refused: the pinned identity is missing — the deployment was pinned to %s (key %s), but the key is gone now. A promotion to a node that never received the pin would present exactly this state, so the guard refuses instead of re-pinning. Re-pin explicitly after a deliberate authority change: quiesce the deployment, delete %s, and let the next first use pin the new authority (see docs/ha-authority.md).',
                        $this->establishedIdentity,
                        $this->pinKey,
                        $this->pinKey,
                    ),
                    $this->establishedIdentity,
                    $observedIdentity,
                );
            }
            // First use: auto-pin the observed authority (write-once).
            $pinned = $this->establishPin($observedIdentity);
            if ($pinned === null) {
                throw new PinnedAuthorityRefusalException(
                    sprintf(
                        'pinned_primary authority check refused: the pin could not be established (key %s) — the concurrent first use and the re-read raced. Re-pin explicitly after a deliberate authority change (see docs/ha-authority.md).',
                        $this->pinKey,
                    ),
                    null,
                    $observedIdentity,
                );
            }
            $this->establishedIdentity = $pinned;
            $this->cacheVerified($pinned);

            return;
        }
        if ($pinned !== $observedIdentity) {
            throw new PinnedAuthorityRefusalException(
                $this->mismatchMessage($pinned, $observedIdentity),
                $pinned,
                $observedIdentity,
            );
        }
        $this->establishedIdentity = $pinned;
        $this->cacheVerified($pinned);
    }

    private function cacheVerified(string $identity): void
    {
        $this->lastVerifiedIdentity = $identity;
        $this->lastVerifiedAt = hrtime(true);
    }

    /**
     * The stale-promotion refusal: names the pinned vs observed
     * identity and the remediation.
     */
    private function mismatchMessage(string $pinned, string $observed): string
    {
        return sprintf(
            'pinned_primary authority REFUSED: the serving authority changed — pinned %s, observed %s (key %s). A promotion to a stale replica or a restarted primary with a new run_id presents exactly this identity change, so the guard refuses every durability-critical transition. Re-pin explicitly after a deliberate authority change: quiesce the deployment, delete %s, and let the next first use pin the new authority (see docs/ha-authority.md).',
            $pinned,
            $observed,
            $this->pinKey,
            $this->pinKey,
        );
    }

    /**
     * Write the pin once (SET NX): the first use that wins establishes
     * it; a concurrent first use reads the winner's pin and compares.
     * Returns the effective pin, or null when the pin could neither be
     * written nor re-read (a raced loss — fail closed).
     */
    private function establishPin(string $identity): ?string
    {
        $written = $this->setNx($this->pinKey, $identity);
        if ($written) {
            return $identity;
        }
        $existing = $this->readPin();

        return \is_string($existing) && $existing !== '' ? $existing : null;
    }

    /**
     * The pinned identity from the pin key, or null when absent or
     * unreadable (an unreadable store is a refusal, never a pass).
     */
    private function readPin(): ?string
    {
        try {
            $raw = $this->client->get($this->pinKey);

            return \is_string($raw) && $raw !== '' ? $raw : null;
        } catch (\Throwable) {
            return null;
        }
    }

    private function setNx(string $key, string $value): bool
    {
        if ($this->client instanceof \Predis\Client) {
            return $this->client->set($key, $value, 'NX') === 'OK';
        }

        return (bool) $this->client->set($key, $value, ['nx' => true]);
    }

    /**
     * The serving authority identity: the role and run_id of the
     * connected server, from `INFO replication` (falling back to
     * `INFO server` for the run_id on Redis builds that omit it from
     * the replication section). An identity that cannot be read is a
     * refusal: unverifiable means stale.
     *
     * @return array{role: string, run_id: string}
     *
     * @throws PinnedAuthorityRefusalException when the identity cannot
     *                                         be established
     */
    private function readIdentity(): array
    {
        try {
            if ($this->client instanceof \Predis\Client) {
                $replication = $this->client->info('replication');
                $role = $this->fieldOf($replication, 'role');
                $runId = $this->fieldOf($replication, 'run_id');
                if ($runId === null) {
                    $server = $this->client->info('server');
                    $runId = $this->fieldOf($server, 'run_id');
                }
            } else {
                $replication = $this->client->info('replication');
                $role = $this->fieldOf($replication, 'role');
                $runId = $this->fieldOf($replication, 'run_id');
                if ($runId === null) {
                    $runId = $this->fieldOf($this->client->info('server'), 'run_id');
                }
            }
        } catch (\Throwable $e) {
            throw new PinnedAuthorityRefusalException(
                sprintf(
                    'pinned_primary authority REFUSED: the serving authority cannot be verified — reading the server identity failed: %s. An unverifiable authority is treated as stale, never passed. Check the security Redis and re-pin explicitly after a deliberate authority change (see docs/ha-authority.md).',
                    $e->getMessage(),
                ),
                $this->establishedIdentity,
            );
        }
        if (!\is_string($role) || $role === '' || !\is_string($runId) || $runId === '') {
            throw new PinnedAuthorityRefusalException(
                sprintf(
                    'pinned_primary authority REFUSED: the serving authority identity is incomplete — the server reported role %s, run_id %s. An unverifiable authority is treated as stale, never passed (see docs/ha-authority.md).',
                    \is_string($role) && $role !== '' ? $role : '(none)',
                    \is_string($runId) && $runId !== '' ? $runId : '(none)',
                ),
                $this->establishedIdentity,
            );
        }

        return ['role' => $role, 'run_id' => $runId];
    }

    /**
     * One field of an `INFO` section. Predis returns the parsed
     * section array, either flat ("role", "run_id") or nested under
     * the section name ("Replication" => ["role", "run_id"]); phpredis
     * may return a raw "key:value" section string, which is parsed
     * line by line.
     *
     * @param mixed $section
     */
    private function fieldOf(mixed $section, string $field): ?string
    {
        if (\is_array($section)) {
            $value = $section[$field] ?? null;
            if (!\is_string($value) || $value === '') {
                foreach ($section as $nested) {
                    if (\is_array($nested)) {
                        $value = $nested[$field] ?? null;
                        if (\is_string($value) && $value !== '') {
                            return $value;
                        }
                    }
                }
            }

            return \is_string($value) && $value !== '' ? $value : null;
        }
        if (\is_string($section)) {
            foreach (explode("\r\n", $section) as $line) {
                if (preg_match('/^'.preg_quote($field, '/').':(.*)$/', $line, $m) === 1) {
                    $value = trim($m[1]);

                    return $value !== '' ? $value : null;
                }
            }
        }

        return null;
    }

    /**
     * @param array{role: string, run_id: string} $identity
     */
    private function formatIdentity(array $identity): string
    {
        return $identity['role'].'|'.$identity['run_id'];
    }

    /**
     * A pinned authority is a single node: a Predis replication or
     * cluster aggregate can change the serving node under the client,
     * so the guard refuses it outright.
     */
    private function assertClientNotAggregate(\Predis\Client $client): void
    {
        $connection = $client->getConnection();
        if ($connection instanceof \Predis\Connection\Replication\ReplicationInterface
            || $connection instanceof \Predis\Connection\Cluster\ClusterInterface
        ) {
            throw new PinnedAuthorityRefusalException(
                sprintf(
                    'pinned_primary authority REFUSED: the client is a %s aggregate (%s) — automatic failover can change the serving node under the client, which is exactly the authority change the pin exists to detect at the deployment boundary. Wire a direct single-node client (standalone connection with retries disabled) for pinned_primary (see docs/ha-authority.md).',
                    $connection instanceof \Predis\Connection\Cluster\ClusterInterface ? 'cluster' : 'replication',
                    \get_class($connection),
                ),
            );
        }
    }
}
