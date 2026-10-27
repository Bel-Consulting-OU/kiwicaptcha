<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Symfony\Component\Serializer\SerializerInterface;

/**
 * The durable credential registry of the WebAuthn step-up handler: the
 * credential store the ceremonies resolve credentials through. One
 * record per enrolled credential, keyed by the credential id's hash and
 * tagged with the principal pseudonym, so the assertion ceremony can
 * list a principal's allowed credentials and the counter check can hold
 * the per-credential sign counter.
 *
 * The registry rides the risk Redis under the step-up namespace, the
 * same protection boundary as every other security-side state of this
 * plane. Records carry the credential's public material and counters,
 * never a raw identifier: the user handle of a record is the principal
 * pseudonym the contexts carry anyway.
 *
 * The class exists (and is only wired) when the web-auth/webauthn-lib
 * package is installed: the {@see CredentialRecord} shape and the
 * library serializer live there.
 */
final class WebAuthnCredentialRegistry
{
    private const KEY_PREFIX = 'credential:';

    /** The per-principal index key fragment (the pseudonym's hash). */
    private const INDEX_PREFIX = 'principal:';

    /**
     * The one-time-backfill marker (`<prefix>` + this suffix). Value:
     * the Unix time of the last full walk (an age-less `1` from an
     * earlier build is restamped on first sight). While the marker is
     * younger than {@see self::INDEX_DUAL_READ_SECS}, lookups also run
     * the bounded reconcile walk: a pre-index node can still write an
     * un-indexed credential during a rolling upgrade, and index-only
     * reads would hide it until the marker lapsed. Past the horizon
     * the index is authoritative and no walk runs — a missing index
     * set is then a genuinely credential-less principal. Public so the
     * tests can pin the steady-state path.
     */
    public const BACKFILL_MARKER = 'credential:index-initialized';

    /** The marker's lifetime: the rolling-upgrade heal window. */
    private const BACKFILL_MARKER_TTL_SECS = 604_800;

    /**
     * The fleet-wide reconcile cadence inside the dual-read window:
     * one bounded cursor walk per TTL at most, regardless of how many
     * authentications run meanwhile.
     */
    private const RECONCILE_LOCK_TTL_SECS = 300;

    /**
     * How long after a backfill (or marker restamp) lookups keep
     * reconciling against the keyspace: the rolling-upgrade window in
     * which a pre-index node may still write credentials without
     * maintaining the index. Long enough for any real deploy overlap;
     * after it, the index alone decides.
     */
    public const INDEX_DUAL_READ_SECS = 86_400;

    /**
     * The atomic counter-rollback CAS: read, compare and write as ONE
     * server-side transaction. A client-side GET-then-SETEX races —
     * two valid concurrent assertions both read the stored counter,
     * both pass the comparison, and the later write rewinds the
     * persisted counter (6 then 5 lands 5), exactly the rollback the
     * sign counter exists to expose. Redis serializes script
     * executions, so the final counter is always the maximum that was
     * ever written. Replies: 1 written, 0 refused (stored counter
     * strictly higher). An unreadable prior record keeps the
     * documented fail-open (no counter to defend without a readable
     * prior).
     */
    private const SAVE_SCRIPT = <<<'LUA'
local existing = redis.call('GET', KEYS[1])
local incoming = tonumber(ARGV[3])
if existing then
  local ok, decoded = pcall(cjson.decode, existing)
  if ok and type(decoded) == 'table' and type(decoded['counter']) == 'number' then
    if incoming < decoded['counter'] then
      return 0
    end
  end
end
redis.call('SETEX', KEYS[1], tonumber(ARGV[1]), ARGV[2])
-- The principal index mutates inside the SAME transaction: a crash
-- between credential write and index write can no longer strand an
-- enrolled credential outside its allow-list. ARGV[5] == '1' carries
-- a non-empty user handle (the index is keyed by principal).
if ARGV[5] == '1' then
  redis.call('SADD', KEYS[2], KEYS[1])
  redis.call('EXPIRE', KEYS[2], tonumber(ARGV[4]))
end
return 1
LUA;

    private readonly SerializerInterface $serializer;

    public function __construct(
        private readonly \Predis\ClientInterface $redis,
        private readonly string $prefix,
        private readonly int $ttlSecs = 31_536_000,
        ?SerializerInterface $serializer = null,
        private readonly int $indexDualReadSecs = self::INDEX_DUAL_READ_SECS,
    ) {
        $this->serializer = $serializer ?? (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        $json = $this->redis->get($this->key($publicKeyCredentialId));
        if (!\is_string($json) || $json === '') {
            return null;
        }
        try {
            $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
        } catch (\Throwable) {
            // An unreadable record is no credential: the ceremony answers
            // unknown-credential instead of trusting broken bytes.
            return null;
        }

        return $record instanceof CredentialRecord ? $record : null;
    }

    /**
     * The enrolled credentials of a principal, or NULL when the answer
     * cannot be trusted yet. The handler's strongest-factor decisions
     * need three states, not two:
     *
     *  - a non-empty list: the principal has keys (normal flows);
     *  - an empty list: KNOWN credential-less (index authoritative, or
     *    this caller just completed the reconcile walk itself);
     *  - null: UNKNOWN during the migration window — the index may be
     *    stale because a pre-index node can still write, and another
     *    reader holds the reconcile cadence. Unknown never authorizes
     *    a first-key bootstrap and never claims the account is
     *    key-less; the caller answers a retryable refusal instead.
     *
     * The discovery is the principal's own index set — one bounded
     * read of the members of this principal, never a keyspace-wide
     * scan, except the single cadence-locked reconcile below. The
     * batch holds only this principal's records, so the steady state
     * is two round trips whatever the deployment's total credential
     * count.
     *
     * @return list<CredentialRecord>|null
     */
    public function registeredCredentialsOf(string $principalPseudonym): ?array
    {
        $marker = $this->redis->get($this->prefix.self::BACKFILL_MARKER);
        if ($marker === null) {
            // Fresh install (or lapsed marker): this call runs the one
            // full walk, so its answer is fresh by construction.
            $this->backfillIndexes();

            return $this->readIndexFor($principalPseudonym);
        }
        $dualRead = false;
        $raw = (string) $marker;
        if ($raw === '1' || !ctype_digit($raw)) {
            // Age-less marker from an earlier build: restamp it so the
            // upgrade horizon closes a full dual-read window after
            // this node first sees it, then treat the window as open.
            $this->redis->setex(
                $this->prefix.self::BACKFILL_MARKER,
                self::BACKFILL_MARKER_TTL_SECS,
                (string) \time(),
            );
            $dualRead = true;
        } elseif (\time() < (int) $raw + $this->indexDualReadSecs) {
            $dualRead = true;
        }
        if ($dualRead) {
            $list = $this->readIndexFor($principalPseudonym);
            // Inside the window this caller also tries the fleet cadence
            // when the index is empty (unknown → walk or UNKNOWN) AND
            // when it is non-empty (a partial index from a pre-index
            // write of a SECOND key must still heal). One walk per lock
            // TTL fleet-wide either way; losers of a non-empty lookup
            // still serve the index — found keys are always trustworthy
            // for the strongest-factor floor, and the gap closes on the
            // next winning claim.
            if ($this->claimReconcileLock()) {
                $this->reconcileIndexes();

                return $this->readIndexFor($principalPseudonym);
            }
            if ($list !== []) {
                return $list;
            }
            // The index says empty but another reader is reconciling:
            // a pre-index write may exist. UNKNOWN, never [].
            return null;
        }
        // Past the window: the index is authoritative.
        return $this->readIndexFor($principalPseudonym);
    }

    /**
     * The principal's records from the index (one SMEMBERS plus the
     * batched record reads): empty array means the index has no
     * members for this principal.
     *
     * @return list<CredentialRecord>
     */
    private function readIndexFor(string $principalPseudonym): array
    {
        $members = $this->redis->smembers($this->indexKey($principalPseudonym));
        if (!\is_array($members) || $members === []) {
            return [];
        }
        $keys = [];
        foreach ($members as $member) {
            if (\is_string($member) && $member !== '') {
                $keys[] = $member;
            }
        }
        if ($keys === []) {
            return [];
        }
        $values = $this->readBatch($keys);
        $found = [];
        foreach ($values as $json) {
            if (!\is_string($json) || $json === '') {
                continue;
            }
            try {
                $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
            } catch (\Throwable) {
                continue;
            }
            if (!$record instanceof CredentialRecord || $record->userHandle !== $principalPseudonym) {
                continue;
            }
            $found[] = $record;
        }

        return $found;
    }

    /**
     * The one-time cursor walk that builds every principal's index
     * from the records already on the server: pre-index installs and
     * the rolling-upgrade heal window. The walk uses a bounded count
     * per iteration, so it never blocks Redis the way a full-keyspace
     * scan does. Each record lands in its own principal's set; the set
     * add is idempotent, so a concurrent save that indexed the same
     * record changes nothing. The marker then pins the steady state:
     * a missing index means a credential-less principal.
     */
    private function backfillIndexes(): void
    {
        $this->reconcileIndexes();
        $this->redis->setex(
            $this->prefix.self::BACKFILL_MARKER,
            self::BACKFILL_MARKER_TTL_SECS,
            (string) \time(),
        );
    }

    /**
     * The bounded cursor walk without stamping the marker: the
     * reconcile leg of a dual-read lookup (and the walk half of a
     * fresh backfill). Idempotent index adds only — a record an old
     * node wrote without SADDing it lands in its principal's set here.
     */
    private function reconcileIndexes(): void
    {
        $pattern = $this->prefix.self::KEY_PREFIX.'*';
        $membersByIndex = [];
        $cursor = '0';
        $collect = [];
        $flush = function () use (&$membersByIndex, &$collect): void {
            if ($collect === []) {
                return;
            }
            $chunk = $collect;
            $collect = [];
            $values = $this->readBatch($chunk);
            foreach ($chunk as $i => $key) {
                $json = $values[$i] ?? null;
                if (!\is_string($json) || $json === '') {
                    continue;
                }
                try {
                    $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
                } catch (\Throwable) {
                    continue;
                }
                if (!$record instanceof CredentialRecord || $record->userHandle === '') {
                    continue;
                }
                $membersByIndex[$this->indexKey((string) $record->userHandle)][] = $key;
            }
        };
        do {
            $reply = $this->redis->scan($cursor, ['MATCH' => $pattern, 'COUNT' => 200]);
            if (!\is_array($reply)) {
                break;
            }
            $cursor = isset($reply[0]) ? (string) $reply[0] : (string) ($reply['cursor'] ?? '0');
            $keys = $reply[1] ?? ($reply['keys'] ?? []);
            if (\is_array($keys)) {
                foreach ($keys as $key) {
                    if (\is_string($key) && $key !== '') {
                        $collect[] = $key;
                    }
                }
            }
            if (\count($collect) >= 500) {
                $flush();
            }
        } while ($cursor !== '0' && $cursor !== '');
        $flush();
        foreach ($membersByIndex as $indexKey => $members) {
            foreach ($members as $member) {
                $this->redis->sadd($indexKey, $member);
            }
            $this->redis->expire($indexKey, $this->ttlSecs);
        }
    }

    /**
     * Try to claim the fleet-wide reconcile slot (SET NX EX). True:
     * this caller runs the bounded walk; false: another reader holds
     * the cadence (or one ran within the TTL) — serve the index read
     * immediately instead of scanning the keyspace.
     */
    private function claimReconcileLock(): bool
    {
        $lockKey = $this->prefix.'credential:reconcile-lock';
        try {
            $ok = $this->redis->set($lockKey, '1', ['NX', 'EX' => self::RECONCILE_LOCK_TTL_SECS]);
        } catch (\Throwable) {
            // A lock failure must not take authentication down: the
            // index read below still answers (and the window's heal
            // runs on the next successful claim or the marker lap).
            return false;
        }

        return $ok !== null;
    }

    /** The index set of one principal: members are the record keys. */
    private function indexKey(string $principalPseudonym): string
    {
        return $this->prefix.self::INDEX_PREFIX.hash('sha256', $principalPseudonym);
    }

    public function saveCredentialSource(CredentialRecord $record): void
    {
        $key = $this->key($record->publicKeyCredentialId);
        // The rollback guard runs inside the write (see the save-script constant):
        // the read-compare-write is one Lua transaction, never a
        // GET followed by a SETEX another writer can interleave. The
        // registry's redis seam is the Predis client interface, so the
        // script runs through its EVAL command shape directly.
        $hasPrincipal = $record->userHandle !== '' ? '1' : '0';
        $indexKey = $record->userHandle !== ''
            ? $this->indexKey((string) $record->userHandle)
            : $key; // unused placeholder key when no principal carries it
        $written = $this->redis->eval(
            self::SAVE_SCRIPT,
            2,
            $key,
            $indexKey,
            (string) $this->ttlSecs,
            (string) $this->serializer->serialize($record, 'json'),
            (string) $record->counter,
            (string) $this->ttlSecs,
            $hasPrincipal,
        );
        if ((int) $written !== 1) {
            return;
        }
        // The principal index add + TTL refresh live inside the script:
        // credential write and allow-list membership are one atomic
        // transition, so an interrupted save can never strand an
        // enrolled credential outside its own principal's index.
    }

    private function key(string $credentialId): string
    {
        return $this->prefix.self::KEY_PREFIX.hash('sha256', $credentialId);
    }

    /**
     * The values of the given keys as one pipelined batch. The batch
     * queues one GET per key in the key order and answers one response
     * per queued command in that same order, so the caller filters the
     * values it already holds.
     *
     * A response list that is not an array is no record set: the lookup
     * answers with no credential rather than reading the keys one at a
     * time, which keeps the batched call shape the only read path.
     *
     * @param list<string> $keys
     *
     * @return list<mixed>
     */
    private function readBatch(array $keys): array
    {
        $responses = $this->redis->pipeline(static function ($pipe) use ($keys): void {
            foreach ($keys as $key) {
                $pipe->get($key);
            }
        });

        return \is_array($responses) ? array_values($responses) : [];
    }
}
