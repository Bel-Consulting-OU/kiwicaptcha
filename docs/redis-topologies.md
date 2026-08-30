# Redis topologies: the verified topology contract

This document records what the redis topology contract is and how it is
verified mechanically. The security Redis (challenge storage, replay
guards, admission leases, risk state) is a trusted control-plane
component; the topology it runs on is part of its security posture.
The claims below were exercised against real local topologies, not
inferred: a three-master Redis Cluster, and a master plus replica plus
sentinel failover. The suites that run them are
`packages/kiwicaptcha-php/tests/RedisClusterTopologyTest.php` and
`packages/kiwicaptcha-php/tests/RedisSentinelFailoverTest.php`, gated
on the shared real-Redis env (`KC_REDIS_URL` or `TEST_REDIS_URL`), the
same gate every real-Redis suite uses.

## Redis Cluster: the single-slot invariants

A Redis Cluster routes every command by hash slot, and a multi-key Lua
script is refused with a cross-slot error unless all of its keys share
one slot. The storage layer is Cluster-safe by construction because of
two deliberate invariants, both verified on a live three-master
cluster (no replicas) with all 16384 slots assigned:

- Every storage transition is a single-key Lua script. The challenge
  record lives under one key; issuance (plain `SET`), the pending to
  consumed transition, the pending to cancelled transition, the
  deterministic-result commit, the terminal delete-if-pending
  deletion and the resume-derivation claim, release and
  claim-clearing commit all touch exactly that one key. The resume
  claim is embedded in the record's runtime envelope (`resume_owner`
  and `resume_until`), never a second key, so the claim transitions
  stay single-slot. The full lifecycle (issuance, verification,
  consume, commit, claim, release, delete-if-pending, cancel) runs on
  the cluster without any cross-slot error; a second key would trip
  either the client-side same-slot check or the server's cross-slot
  refusal.

- The argon admission semaphore's auxiliary keys are deliberately
  co-slotted with the lease key. The lease key is
  `kiwicaptcha:argon2:leases:<namespace>` (untagged), and the
  saturation counter and per-scope set are
  `{kiwicaptcha:argon2:leases:<namespace>}:sem:waiters` and
  `{kiwicaptcha:argon2:leases:<namespace>}:<sha256(scope)>`. The hash
  tag inside the braces is exactly the lease key string, so all three
  keys of the acquire script hash to the lease key's slot. The suite
  asserts this with the server's own `CLUSTER KEYSLOT` answer on the
  cluster masters (the slot of every composed key equals the lease
  key's slot) and cross-checks it against the canonical CRC-16
  computation, whose reference vector (`123456789` to `0x31C3`) is
  pinned in the test. The same slot equality holds for an untagged
  key whose string is the tag of the tagged keys, which is exactly
  this construction; a naive reader expecting every key to carry
  braces would flag it, so the assertion is done against the server,
  not by inspection.

Two Predis client caveats are real and documented here because they
shape deployments:

- The Predis cluster aggregate refuses keyless commands (they have no
  slot): `PING`, `SCRIPT`, `WAIT`. The storage's per-script warm-up
  is a keyless `SCRIPT LOAD`; the topology suite pre-loads every Lua
  body on every master over a plain per-node connection and seeds the
  storage's sha cache (the server's sha is the sha1 of the body,
  verified per node), after which the transitions are the genuine
  single-key `evalsha` calls. A deployment on a cluster must warm the
  scripts per node the same way, or use a client whose warm-up is
  routable.

- The verified WAIT barrier is refused on a cluster client at
  construction when `waitReplicas > 0` (`VerifiedWaitGuard`): a
  keyless WAIT has no slot to route by, and even a slot-faked WAIT
  would measure the wrong node. `waitReplicas` must stay 0 on a
  cluster; the single-slot Lua transitions are atomic per record
  regardless, which is the cluster's durability and atomicity story.

The risk engine's state script has its own family-wide hash tag
(`{kiwi:<deployment>}`), asserted by the risk package's
`ClusterKeyslotTest`; the challenge storage and the admission
semaphore are the components covered by the suites named above.

## Redis Sentinel: the failover contract

A Sentinel topology (master, replicas, sentinel nodes) serves reads
and writes through the current primary. The verified contract,
exercised on a live master plus replica plus sentinel (quorum 1,
`down-after-milliseconds` 500):

- The store fails closed during an outage. When the primary is killed,
  every operation on a store pointed at it raises a typed connection
  error (the Predis connection exceptions), and no operation returns a
  value that could be mistaken for success. There is no silent
  fallback to a stale view and no fabricated outcome while the
  authority is gone.

- The promotion boundary is the documented async-replication boundary.
  A record consumed on the primary may reappear as pending on a
  promoted replica that never received the consume; the observable
  contract is what the suites assert: a vanished or rolled-back
  record resolves as missing or pending-fresh, and a committed
  verification result is never replayed from a replica that never
  received it. Concretely, after the sentinel promotes the stale
  replica: the rolled-back record reads pending with a null
  `consumed_result` and no consumed state (a fresh consume returns
  `consumedNow` with no result, never a replayed authorization), and
  the record whose commit vanished reads as missing.

- The verified WAIT barrier is refused on a Predis Sentinel aggregate
  at construction when `waitReplicas > 0` (`VerifiedWaitGuard`): WAIT
  is connection-affine, and the aggregate's failure retry would
  execute the WAIT on a replacement connection whose write offset is
  empty, proving nothing about the original write. `waitReplicas`
  must stay 0 on a sentinel aggregate.

The stale-promotion window is exercised deterministically: real
async lag on a loopback topology is normally microseconds, so the
suite manufactures the stale view on the replica (local writes with
`replica-read-only` off, restored immediately after), then kills the
primary and lets the sentinel promote. The failover itself completes
in a couple of seconds; the suite bounds every wait and skips cleanly
when the local redis-server build lacks sentinel support.

Replay-safe promotion is a deployment invariant, not an automatic
property of the failover: operators must either set the verified WAIT
threshold to cover every eligible failover target during the challenge
lifetime (standalone topology), or gate promotion eligibility so a
lagging replica can never be elected (`min-replicas-to-write` style
replication gating, or a consensus design). Pair this with
`ttl_margin_secs` beyond token validity plus clock skew and failover
margin, and with `maxmemory-policy noeviction` on the security Redis:
an evicted or expired consumed-state guard re-enables replay.

## Deployment guidance: which topology each guard assumes

| Topology | Verified WAIT (`wait_replicas > 0`) | Single-slot Lua | Failure posture |
|----------|------------------------------------|-----------------|-----------------|
| Standalone Redis | Supported (phpredis direct, or standalone Predis with command retries disabled) | Trivially single-node | Typed errors on outage; WAIT barrier raises `ReplicaWaitException` on a shortfall |
| Redis Cluster | Refused at construction; keep 0 | Every transition is one key; semaphore keys co-slotted | Typed errors on node outage; per-key atomicity preserved across slot owners |
| Sentinel / master-slave | Refused at construction; keep 0 | Trivially single-node | Fail closed on primary outage; promotion boundary documented above |

The verified WAIT is durability hardening, not consensus: even an
acknowledged write can be lost under some failover and persistence
patterns, and Redis states that WAIT does not make it a strongly
consistent store. Deployments that require acknowledged writes that
can never vanish must back the security state with a consensus-capable
store instead. The one-shot semantics (the atomic pending to consumed
transition) hold per Redis authority on every topology above; they do
not hold across an authority change unless the promotion contract is
the hardened one.
