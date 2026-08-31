# Redis topologies: the verified topology contract

This document records what the redis topology contract is and how it is
verified mechanically. The security Redis (challenge storage, replay
guards, admission leases, risk state) is a trusted control-plane
component; the topology it runs on is part of its security posture.
The claims below were exercised against real local topologies, not
inferred: a three-master Redis Cluster (the Cluster routing/atomicity
compatibility fixture), and a master plus replica plus sentinel
failover (the Sentinel HA fixture). The suites that run them are
`packages/kiwicaptcha-php/tests/RedisClusterTopologyTest.php` and
`packages/kiwicaptcha-php/tests/RedisSentinelFailoverTest.php`, gated
on the shared real-Redis env (`KC_REDIS_URL` or `TEST_REDIS_URL`), the
same gate every real-Redis suite uses.

## Redis Cluster: routing and atomicity compatibility

This fixture is **Cluster routing/atomicity compatibility**, not
"Cluster HA verification": it boots three masters with no replicas, so
no failover, promotion or replica-side durability is exercised at all.
Redis Cluster's high-availability behavior (automatic failover,
replica promotion) is a separate deployment concern that this fixture
deliberately does not claim to verify. What the fixture verifies is
routing and per-record atomicity: a Redis Cluster routes every command
by hash slot, and a multi-key Lua script is refused with a cross-slot
error unless all of its keys share one slot. The storage layer is
Cluster-safe by construction because of two deliberate invariants,
both verified on a live three-master cluster (no replicas) with all
16384 slots assigned:

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

## Authority-change replay durability: the deployment posture

The core contract, stated once and repeated by `kiwicaptcha:doctor`:

> One-shot verification is atomic on the current Redis authority but
> is not guaranteed across stale-replica promotion.

The atomic pending-to-consumed transition holds per Redis authority.
A promotion can move the authority to a replica that never received
the consume, the commit or the terminal delete-if-pending deletion,
and that stale view can re-enable replay. Whether the deployment
accepts that boundary is an explicit posture decision; the doctor
warns on every Redis HA wiring (a Predis Sentinel, master-slave or
Cluster aggregate client) and on every Redis-backed storage with
`waitReplicas` 0, naming the documented postures below.

The posture is now a first-class configuration switch, not just a
documented choice: the `replay_durability` option (`fail_closed`,
`operator_managed` or `best_effort`, default `best_effort`) declares
it, and the extension and the doctor enforce the declared posture.
The doctor's "Replication topology" check is posture-aware: an HA
aggregate under `best_effort` keeps the WARN; under
`operator_managed` it reports PASS with the operator contract noted;
under `fail_closed` the doctor is unreachable, because the extension
refuses the container build. The design record for the replay-safe
authority abstraction lives in docs/ha-authority.md.

The three documented postures:

- **fail_closed**: the deployment guarantees the one-shot contract
  across an authority change, or refuses to serve when it cannot.
  On a standalone authority this is the verified WAIT barrier
  (`waitReplicas > 0` with the threshold covering every eligible
  failover target, `ReplicaWaitException` on a shortfall), or a
  consensus-capable store for the security state. On an HA aggregate
  the bundle refuses to run at all: the extension refuses the
  container build with a LogicException naming the posture and the
  remediation (provide a pinned-primary/topology adapter, or choose
  `operator_managed` / `best_effort`), because the barrier itself is
  refused on the aggregate (WAIT is connection-affine; see the
  Sentinel section above). Single-node direct clients are fine under
  this posture.
- **operator_managed**: the deployment accepts async replication but
  contracts that a stale replica can never be elected. Promotion
  eligibility is gated (`min-replicas-to-write` style replication
  gating, a promotion-eligibility gate on the failover manager, or a
  consensus design whose semantics are actually guaranteed), and the
  window is sized against the challenge lifetime plus `ttl_margin_secs`
  plus clock skew and failover margin. The doctor reports PASS and
  keeps the operator contract noted.
- **best_effort**: the deployment documents that a stale-replica
  promotion can re-enable replay of a consumed or burned challenge,
  and accepts the residual window (for example a low-value surface
  with compensating controls elsewhere). This is the default posture,
  and the doctor's WARN is the acknowledgment that the boundary is
  accepted.

The doctor's WARN on the exact wording above is the deployment
posture prompt: it is not a failed check, and the deployment chooses
and documents one of these three postures. A single-node direct
connection without replicas passes the check with the
authority-boundary contract noted; a failover topology without one of
the postures is exactly the case the WARN names.

## Deployment guidance: which topology each guard assumes

| Topology | Verified WAIT (`wait_replicas > 0`) | Single-slot Lua | Failure posture |
|----------|------------------------------------|-----------------|-----------------|
| Standalone Redis | Supported (phpredis direct, or standalone Predis with command retries disabled) | Trivially single-node | Typed errors on outage; WAIT barrier raises `ReplicaWaitException` on a shortfall |
| Redis Cluster | Refused at construction; keep 0 | Every transition is one key; semaphore keys co-slotted | Typed errors on node outage; per-key atomicity preserved across slot owners |
| Sentinel / master-slave | Refused at construction; keep 0 | Trivially single-node | Fail closed on primary outage; promotion boundary documented above |

Each posture's requirements under the `replay_durability` switch:

| Posture | Topology requirements | Doctor result |
|---------|----------------------|---------------|
| `best_effort` (default) | The current boundary: single-authority atomicity; the stale-promotion window documented and accepted by the deployment | HA aggregate: WARN with the posture named; single-node direct: PASS |
| `operator_managed` | The operator owns promotion eligibility: replication gating, catch-up rules, or a promotion-eligibility gate on the failover manager; the window sized against challenge lifetime plus `ttl_margin_secs` plus clock skew and failover margin | HA aggregate: PASS with the operator contract noted; single-node direct: PASS |
| `fail_closed` | No automatic failover reliance: the extension refuses the container build when a Predis Sentinel/Cluster aggregate client is wired (LogicException naming the posture and the remediation); standalone authorities may use the verified WAIT barrier; single-node direct clients are always accepted | HA aggregate: unreachable (the build is refused); single-node direct: PASS |
| `operator_managed` + `ha_authority: pinned_primary` (the `ha_safe` profile) | A direct single-node Predis client (aggregates and phpredis are refused at build under pinned_primary); the PinnedPrimaryAuthorityGuard pins the serving authority on first use (`{kiwi:<ns>}:authority:pin`) and refuses on any change, so the operator contract is mechanically enforced | "HA authority": PASS when armed and stable; FAIL on a changed authority or an unarmed guard (see docs/ha-authority.md) |

The verified WAIT is durability hardening, not consensus: even an
acknowledged write can be lost under some failover and persistence
patterns, and Redis states that WAIT does not make it a strongly
consistent store. Deployments that require acknowledged writes that
can never vanish must back the security state with a consensus-capable
store instead. The one-shot semantics (the atomic pending to consumed
transition) hold per Redis authority on every topology above; they do
not hold across an authority change unless the deployment chooses and
documents one of the [authority-change replay durability
postures](#authority-change-replay-durability-the-deployment-posture)
above.
