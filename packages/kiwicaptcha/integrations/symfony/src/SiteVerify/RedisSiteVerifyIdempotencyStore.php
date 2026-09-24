<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

use BelConsulting\KiwiCaptchaBundle\Risk\PersistedJsonLuaPredicate;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor;
use BelConsulting\KiwiCaptchaBundle\RedisNamespace;

/**
 * Redis-backed atomic idempotency store.
 *
 * Key: `{kiwi:<namespace>}:siteverify-idem:<backend_id>:<uuid>`
 * Value: JSON schema v2, exactly `{v, response_hash,
 * remoteip_fingerprint, binding, state: pending|complete, owner, result,
 * lease_expires_at}`. The exact predicate is
 * {@see SiteVerifyIdempotencyRecordSchema}, mirrored in Lua by
 * {@see SiteVerifyIdempotencyLuaPredicate}.
 * TTL: bounded, the caller passes the window. Every read and transition
 * requires the key to carry a lifetime. A present key without a TTL
 * (`persist`, a bad restore, a foreign writer) is corrupt state. It
 * fails closed with {@see SiteVerifyIdempotencyCorruptException} and
 * zero mutations. A cached siteverify success is authorization-bearing
 * recovery state, so a persistent key would convert a 300-second replay
 * window into unbounded replay authority.
 *
 * The claim is a single Lua script, atomic even under concurrency.
 * `owner` is a random per-request token so only the owning request can
 * finalize; a stale retry can never overwrite a completed outcome. The
 * claim binds the canonicalized remoteip pseudonym and the canonical
 * transaction binding's keyed equality digest alongside the response
 * hash. The controller derives both with purpose-separated HMACs. The
 * entry carries no raw address and no raw binding: Redis persistence,
 * AOF history or forensic snapshots can outlive the logical TTL. A
 * retry with the same key but a different pseudonym or binding digest
 * is a conflict. A changed remoteip or transaction context can
 * materially change the verification outcome, and no entry may be
 * joined or reused across them. A legacy record (the shape
 * written before schema versioning, no `v` member) is recognized
 * read-only: stored() can still serve its completed result for the
 * record's bounded remaining TTL, but no transition ever claims,
 * renews, takes over or finalizes it. The owner's lease
 * (`lease_expires_at`, set from the server clock via redis TIME at
 * claim creation) is configurable (`leaseSeconds`, default
 * {@see SiteVerifyIdempotencyStore::LEASE_SECONDS}) and bounds how long
 * a crashed owner blocks the key. After expiry an atomic takeover
 * transfers ownership to a waiter. The lease length itself protects a
 * live owner mid-verification; no process-global timer is involved.
 *
 * Every Lua transition executes through the guarded
 * {@see RedisSecurityCommandExecutor} seam (docs/ha-authority.md): the
 * finalize is the security-final transition (the zero-stale lane forces
 * the pinned-primary authority revalidation immediately before the
 * write), and the claim/takeover/renew are ordinary mutations.
 */
final class RedisSiteVerifyIdempotencyStore implements SiteVerifyIdempotencyStore
{
    private const PREFIX = 'siteverify-idem:';

    private readonly RedisSecurityCommandExecutor $lua;

    /**
     * The atomic live-record read used by stored(): existence and key
     * lifetime are obtained in the same script, so only a lifetime-bearing
     * record can ever be returned. Absent -> the Lua boolean false;
     * present without a lifetime -> 'corrupt'; live -> the raw JSON.
     */
    private const READ_LIVE_LUA = PersistedJsonLuaPredicate::LUA . <<<'LUA'
local existing = readLivePersistedKey(KEYS[1])
if existing == 'corrupt' then
  return 'corrupt'
end
return existing
LUA;

    private const CLAIM_LUA = PersistedJsonLuaPredicate::LUA . SiteVerifyIdempotencyLuaPredicate::LUA . <<<'LUA'
local key = KEYS[1]
local response_hash = ARGV[1]
local owner = ARGV[2]
local ttl = tonumber(ARGV[3])
local lease_seconds = tonumber(ARGV[4])
local fingerprint = ARGV[5]
local binding = ARGV[6]
-- redis TIME returns bulk strings; tonumber makes the arithmetic explicit.
local now = tonumber(redis.call('TIME')[1])
local existing = readLivePersistedKey(key)
if existing == 'corrupt' then
  return 'corrupt'
end
if existing == false then
  redis.call('SET', key, cjson.encode({ v = 2, response_hash = response_hash, remoteip_fingerprint = fingerprint, binding = binding, state = 'pending', owner = owner, result = cjson.null, lease_expires_at = now + lease_seconds }), 'EX', ttl)
  return 'claimed'
end
local rec = decodeUniqueObject(existing)
if rec == nil then
  return 'corrupt'
end
local schema = classifyIdempotencyRecord(rec)
if schema == nil then
  return 'corrupt'
end
-- The legacy shape (written by the immediately preceding release, no `v`
-- member) is read-only: no transition ever claims, renews, takes over or
-- finalizes it. The preceding release already bound the full operation
-- identity (response_hash, remoteip_fingerprint, binding) and compared
-- all three before answering, so an EXACT retry of its own record is
-- recognized — a completed legacy record replays the cached response
-- through stored(), and an in-flight legacy pending record reports the
-- non-authoritative pending state (the waiter keeps reading; takeover
-- refuses until it expires). Any missing or differing identity component
-- stays a conflict; truly underspecified legacy records (a missing
-- fingerprint/binding, or an even older writer) conflict exactly as
-- before.
if schema == 'legacy' then
  local identity_complete = type(rec.response_hash) == 'string'
    and type(rec.remoteip_fingerprint) == 'string'
    and type(rec.binding) == 'string'
    and rec.response_hash == response_hash
    and rec.remoteip_fingerprint == fingerprint
    and rec.binding == binding
  if identity_complete then
    if rec.state == 'complete' then
      return 'complete_same'
    end
    if rec.state == 'pending' then
      return 'pending_same'
    end
  end
  return 'conflict'
end
if rec.response_hash ~= response_hash or rec.remoteip_fingerprint ~= fingerprint or rec.binding ~= binding then
  return 'conflict'
end
if rec.state == 'complete' then
  return 'complete_same'
end
return 'pending_same'
LUA;

    private const TAKEOVER_LUA = PersistedJsonLuaPredicate::LUA . SiteVerifyIdempotencyLuaPredicate::LUA . <<<'LUA'
local key = KEYS[1]
local owner = ARGV[1]
local response_hash = ARGV[2]
local fingerprint = ARGV[3]
local lease_seconds = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local binding = ARGV[6]
local now = tonumber(redis.call('TIME')[1])
local existing = readLivePersistedKey(key)
if existing == 'corrupt' then
  return 'corrupt'
end
if existing == false then
  return 'still_pending'
end
local rec = decodeUniqueObject(existing)
if rec == nil then
  return 'corrupt'
end
local schema = classifyIdempotencyRecord(rec)
if schema == nil then
  return 'corrupt'
end
-- The legacy shape is read-only: a takeover never takes ownership of a
-- record no transition may finalize.
if schema == 'legacy' then
  return 'still_pending'
end
if rec.state ~= 'pending' then
  return 'still_pending'
end
if rec.response_hash ~= response_hash then
  return 'still_pending'
end
-- The remoteip fingerprint is bound in the record: a takeover with a
-- DIFFERENT fingerprint is refused (defense-in-depth — the claim
-- already enforces it, but the store enforces the complete identity
-- itself).
if rec.remoteip_fingerprint ~= fingerprint then
  return 'still_pending'
end
-- The canonical transaction binding is bound in the record too: a
-- takeover under a different transaction context is refused, so the
-- crash-recovery identity can never cross transaction boundaries.
if rec.binding ~= binding then
  return 'still_pending'
end
local lease_expires_at = rec.lease_expires_at
if lease_expires_at >= now then
  return 'still_pending'
end
rec.owner = owner
rec.lease_expires_at = now + lease_seconds
redis.call('SET', key, cjson.encode(rec), 'EX', ttl)
return 'took_over'
LUA;

    private const RENEW_LUA = PersistedJsonLuaPredicate::LUA . SiteVerifyIdempotencyLuaPredicate::LUA . <<<'LUA'
local key = KEYS[1]
local owner = ARGV[1]
local lease_seconds = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local now = tonumber(redis.call('TIME')[1])
local existing = readLivePersistedKey(key)
if existing == 'corrupt' then
  return 'corrupt'
end
if existing == false then
  return 0
end
local rec = decodeUniqueObject(existing)
if rec == nil then
  return 'corrupt'
end
if classifyIdempotencyRecord(rec) ~= 'v2' then
  return 0
end
if rec.state ~= 'pending' or rec.owner ~= owner then
  return 0
end
rec.lease_expires_at = now + lease_seconds
redis.call('SET', key, cjson.encode(rec), 'EX', ttl)
return 1
LUA;

    private const FINALIZE_LUA = PersistedJsonLuaPredicate::LUA . SiteVerifyIdempotencyLuaPredicate::LUA . <<<'LUA'
local key = KEYS[1]
local owner = ARGV[1]
local response_hash = ARGV[2]
local result = ARGV[3]
local ttl = tonumber(ARGV[4])
local existing = readLivePersistedKey(key)
if existing == 'corrupt' then
  return 'corrupt'
end
if existing == false then
  return 0
end
local rec = decodeUniqueObject(existing)
if rec == nil then
  return 'corrupt'
end
if classifyIdempotencyRecord(rec) ~= 'v2' then
  return 0
end
-- The finalize must authorize the state, the current owner token AND
-- the response hash bound in the record: only a PENDING v2 claim owned
-- by this exact request may become complete, so a refused finalize (a
-- taken-over claim, a stale owner, a vanished key, a different
-- response, a legacy record) is a hard FALSE the caller treats exactly
-- like an ownership loss — a locally computed result is never returned
-- as authoritative after a refused finalize.
if rec.state ~= 'pending' then
  return 0
end
if rec.owner ~= owner or rec.response_hash ~= response_hash then
  return 0
end
rec.state = 'complete'
rec.owner = cjson.null
rec.lease_expires_at = cjson.null
rec.result = cjson.decode(result)
redis.call('SET', key, cjson.encode(rec), 'EX', ttl)
return 1
LUA;

    /**
     * The encoded deployment namespace inside the `{kiwi:<ns>}` hash
     * tag, derived from the raw configured discriminator.
     */
    private readonly string $namespace;

    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        string $namespace = 'kiwicaptcha',
        private readonly int $leaseSeconds = self::LEASE_SECONDS,
        private readonly int $waitReplicas = 0,
        private readonly int $waitTimeoutMs = 100,
        int $namespaceKeyVersion = RedisNamespace::VERSION_LEGACY,
    ) {
        // The RAW discriminator is derived here, so the idempotency
        // entries live under the deployment namespace: two deployments
        // sharing one Redis instance can never replay each other's
        // completed results, even with identical secrets and security
        // contexts (the backend id does not carry the namespace).
        $this->namespace = RedisNamespace::deriveOr($namespace, 'kiwicaptcha', $namespaceKeyVersion);
        $this->refuseVerifiedWaitOnUnsupportedPredisClients();
        $this->lua = new RedisSecurityCommandExecutor($redis);
    }

    public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
    {
        // The canonical writer-input rule: a non-canonical claim identity
        // would mint a record every later boundary must treat as corrupt,
        // so it is refused before any write.
        SiteVerifyIdempotencyRecordSchema::assertCanonicalClaimIdentity($responseHash, $remoteipFingerprint, $binding);
        $owner = bin2hex(random_bytes(16));
        $lease = $leaseSeconds ?? $this->leaseSeconds;
        $result = $this->lua->executeMutation(self::CLAIM_LUA, $this->key($backendId, $idempotencyKey), [$responseHash, $owner, max(1, $ttlSeconds), $lease, $remoteipFingerprint, $binding ?? '']);

        if ((string) $result === 'corrupt') {
            // Corrupted security state is a server fault, never a client
            // conflict: the typed fail-closed exception (the controller
            // answers the 503) instead of a 400 blaming the caller.
            throw new SiteVerifyIdempotencyCorruptException('the siteverify idempotency record is structurally corrupt');
        }
        $claim = match ((string) $result) {
            'claimed' => IdempotencyClaim::Claimed,
            'pending_same' => IdempotencyClaim::PendingSame,
            'complete_same' => IdempotencyClaim::CompleteSame,
            default => IdempotencyClaim::Conflict,
        };

        // The verified-WAIT durability barrier applies to the NEW claim
        // write only: the read-only outcomes (pending_same,
        // complete_same, conflict) never WAIT.
        if ($claim === IdempotencyClaim::Claimed && $this->waitReplicas > 0) {
            $this->waitAndVerify('the siteverify idempotency claim');
        }

        return [$claim, $claim === IdempotencyClaim::Claimed ? $owner : null];
    }

    public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
    {
        // The same canonical writer-input rule as the claim: a takeover
        // under a non-canonical identity can never adopt a claim.
        SiteVerifyIdempotencyRecordSchema::assertCanonicalClaimIdentity($responseHash, $remoteipFingerprint, $binding);
        $owner = bin2hex(random_bytes(16));
        // The takeover Lua already receives the lease via ARGV[4]; pass
        // the per-call override so the fixed configured lease is
        // maintained across the takeover (null = the configured lease —
        // the controller always passes null; the lease is never derived
        // from a token's remaining validity).
        $result = $this->lua->executeMutation(self::TAKEOVER_LUA, $this->key($backendId, $idempotencyKey), [$owner, $responseHash, $remoteipFingerprint, $leaseSeconds ?? $this->leaseSeconds, max(1, $ttlSeconds), $binding ?? '']);

        $takeover = match ((string) $result) {
            'took_over' => IdempotencyClaim::TookOver,
            'corrupt' => throw new SiteVerifyIdempotencyCorruptException('the siteverify idempotency record is structurally corrupt'),
            default => IdempotencyClaim::StillPending,
        };

        // The verified-WAIT barrier applies to the successful takeover
        // write only: a lost takeover write after a promotion would leave
        // different nodes with different concepts of who owns the logical
        // redemption. still_pending never WAITs.
        if ($takeover === IdempotencyClaim::TookOver && $this->waitReplicas > 0) {
            $this->waitAndVerify('the siteverify idempotency takeover');
        }

        return [$takeover, $takeover === IdempotencyClaim::TookOver ? $owner : null];
    }

    public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
    {
        // The one canonical provider-response validator: a non-canonical
        // shape refuses the write, so only shapes a cached read can
        // re-validate ever reach the stored record.
        SiteVerifyResult::validate($canonicalResponse);
        $payload = (string) json_encode($canonicalResponse, JSON_THROW_ON_ERROR);
        $result = $this->lua->executeSecurityFinal(self::FINALIZE_LUA, $this->key($backendId, $idempotencyKey), [$owner, $responseHash, $payload, max(1, $this->retentionTtl($idempotencyKey))]);
        if ((string) $result === 'corrupt') {
            // A lifetime-stripped or structurally impossible record is
            // corrupt security state: the typed fail-closed exception
            // (the controller answers the 503), zero mutation.
            throw new SiteVerifyIdempotencyCorruptException('the siteverify idempotency record is structurally corrupt');
        }
        $finalized = (int) $result === 1;
        // The verified-WAIT durability barrier applies to the successful
        // finalize only: the completed state must survive a promotion.
        if ($finalized && $this->waitReplicas > 0) {
            $this->waitAndVerify('the siteverify idempotency finalize');
        }

        return $finalized;
    }

    public function renew(string $backendId, string $idempotencyKey, string $owner): bool
    {
        $result = $this->lua->executeMutation(self::RENEW_LUA, $this->key($backendId, $idempotencyKey), [$owner, $this->leaseSeconds, max(1, $this->retentionTtl($idempotencyKey))]);
        if ((string) $result === 'corrupt') {
            // The lifetime-stripped / structurally impossible record is
            // corrupt security state: the typed fail-closed exception
            // (the controller answers the 503), zero mutation.
            throw new SiteVerifyIdempotencyCorruptException('the siteverify idempotency record is structurally corrupt');
        }
        $renewed = (string) $result === '1';
        // A lost renewal write after a promotion would resurrect an older
        // (expired) lease state; the barrier applies to the successful
        // renewal only.
        if ($renewed && $this->waitReplicas > 0) {
            $this->waitAndVerify('the siteverify idempotency renewal');
        }

        return $renewed;
    }

    public function leaseSeconds(): int
    {
        return $this->leaseSeconds;
    }

    public function stored(string $backendId, string $idempotencyKey): ?array
    {
        // The atomic live read: existence and key lifetime in one script,
        // so a PERSISTed (lifetime-stripped) record can never be
        // classified as live authorization-bearing cached state.
        $raw = $this->lua->executeRead(self::READ_LIVE_LUA, $this->key($backendId, $idempotencyKey), []);
        if ($raw === false || $raw === null) {
            return null;
        }
        if ($raw === 'corrupt') {
            throw new SiteVerifyIdempotencyCorruptException('the idempotency record carries no Redis key lifetime');
        }
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        try {
            $rec = \KiwiCaptcha\Storage\StrictJson::decodeObject($raw, 8192);
            if ($rec === null) {
                throw new SiteVerifyIdempotencyCorruptException('the idempotency record is not a clean JSON object (malformed, oversized or carrying a semantic duplicate key)');
            }
        } catch (\JsonException $e) {
            // Corrupt security state is never transformed into "nothing
            // here": a malformed idempotency record maps to the typed
            // fail-closed exception (the controller answers the 503).
            throw new SiteVerifyIdempotencyCorruptException('the idempotency record is malformed', 0, $e);
        }
        if (!\is_array($rec)) {
            throw new SiteVerifyIdempotencyCorruptException('the idempotency record is not an object');
        }
        SiteVerifyIdempotencyRecordSchema::validate($rec);
        if (($rec['state'] ?? '') === 'complete') {
            if (!\is_array($rec['result'] ?? null)) {
                throw new SiteVerifyIdempotencyCorruptException('the completed idempotency record has no result');
            }
            // A completed result is authorization-bearing cached state:
            // the canonical-response validator ran on the read too (inside
            // the schema validation), so a corrupted persisted result (a
            // shape no conforming finalize could have written) fails
            // closed as the typed corrupt exception instead of becoming a
            // cached success.
            // Failed-barrier replay guard: the finalize that wrote this
            // completed record may have landed on the primary with its
            // WAIT failing. Returning the stored success read-only would
            // hand the caller a success a promotion could lose — the
            // barrier is re-established before the acceptance (a shortfall
            // throws and the caller answers the 503).
            if ($this->waitReplicas > 0) {
                $this->establishReplicationFence('the siteverify stored-success acceptance');
            }

            return $rec['result'];
        }

        return null;
    }

    private function retentionTtl(string $idempotencyKey): int
    {
        // finalize and renew do not know the original TTL; keep a
        // conservative bounded window so completed entries are readable for
        // retries.
        return 300;
    }

    private function key(string $backendId, string $idempotencyKey): string
    {
        return sprintf('{kiwi:%s}:%s%s:%s', $this->namespace, self::PREFIX, $backendId, $idempotencyKey);
    }
    public function establishReplicationFence(string $what): void
    {
        if ($this->waitReplicas <= 0) {
            return;
        }
        $fenceKey = '{kiwi:'.$this->namespace.'}:siteverify-idem:replication-fence';
        $token = bin2hex(random_bytes(16));
        if ($this->redis instanceof \Redis) {
            $ok = $this->redis->set($fenceKey, $token, ['PX' => 60_000]);
        } else {
            $ok = $this->redis->setex($fenceKey, 60, $token);
        }
        if ($ok === false || $ok === null) {
            throw new \KiwiCaptcha\Storage\ReplicaWaitException(sprintf('the replication fence write failed after %s', $what));
        }
        $this->waitAndVerify($what);
    }

    private function waitAndVerify(string $what): void
    {
        if ($this->redis instanceof \Redis) {
            $acked = $this->redis->rawCommand('WAIT', $this->waitReplicas, $this->waitTimeoutMs);
        } else {
            $acked = $this->redis->executeRaw(['WAIT', $this->waitReplicas, $this->waitTimeoutMs]);
        }
        if ($acked === false || $acked === null) {
            throw new \KiwiCaptcha\Storage\ReplicaWaitException(sprintf(
                'Redis WAIT failed after %s (waitReplicas=%d, timeout=%dms)',
                $what,
                $this->waitReplicas,
                $this->waitTimeoutMs,
            ));
        }
        if ((int) $acked < $this->waitReplicas) {
            throw new \KiwiCaptcha\Storage\ReplicaWaitException(sprintf(
                'Redis WAIT acknowledged %d of %d requested replicas after %s',
                (int) $acked,
                $this->waitReplicas,
                $what,
            ));
        }
    }

    private function refuseVerifiedWaitOnUnsupportedPredisClients(): void
    {
        \KiwiCaptcha\VerifiedWaitGuard::refuseUnsupported($this->redis, $this->waitReplicas, 'RedisSiteVerifyIdempotencyStore');
    }

}
