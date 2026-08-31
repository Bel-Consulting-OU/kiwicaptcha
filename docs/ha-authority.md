# HA authority: the replay-safe authority transition abstraction

This document is the design record for the replay-safe high-availability
authority posture, and the specification of the real pinned-primary
adapter that ships with the bundle. It sits next to redis-topologies.md,
which records the verified topology contract of the current Redis
boundary. The two documents answer different questions.
redis-topologies.md states what the bundle verifies mechanically today.
This document states the abstraction the replay-safe HA posture is
built on, why the abstraction is the right seam, what the adapter
surface looks like, and which parts of the roadmap are already real
product capability.

## The requirement

> A state transition acknowledged as security-final can never disappear
> merely because the serving authority changed.

The pending-to-consumed transition is atomic on the current Redis
authority, and the verified-WAIT barrier hardens the standalone
authority against replica lag. Neither property survives an authority
change on its own. When failover promotes a replica that never received
the consume, the consumed record can reappear as pending, and the
transition that the application was already told about is gone. The
same holds for every final disposition: a returned Deny, a committed
deterministic result, a terminal delete-if-pending deletion, and a
chain obligation. The requirement is about the acknowledgement, not
about the write: once the bundle has told the caller that a state
transition is final, no later authority change may make that statement
retroactively false.

The current deployment boundary accepts this window as documented
posture (replay_durability "best_effort"), and the operator_managed
posture contracts that promotion eligibility is gated so a stale
replica can never be elected. Neither posture makes the invariant
automatic. The HA profile changes that: it is the deployment where the
invariant is guaranteed by the adapter the bundle speaks to, not by
the operator's failover policy alone.

## Why the authority is the right seam

Every durability-critical component in the bundle (RedisStorage, the
Siteverify idempotency store, the outstanding accounting, the chain
state store, the post-solve disposition store) shares one shape: an
atomic single-key transition on the serving Redis authority, optionally
strengthened by the verified-WAIT barrier. The VerifiedWaitGuard
centralizes the WAIT topology classification through the canonical
authority-safety classifier (AuthoritySafetyClassifier): standalone
connections with retries disabled are supported, and Predis replication
aggregates, cluster clients, and retry-enabled connections are refused
at construction. The classifier is the shared classification the HA
profile reuses: a client that the VerifiedWaitGuard refuses for WAIT is
exactly a client whose authority can change under the bundle.

The authority transition is therefore the single seam where replay
safety can be made unconditional. The bundle already refuses to fake
durability on aggregates (waitReplicas stays 0 and the doctor warns).
The HA profile does the opposite side of the same coin: instead of
refusing the topology, it hands the authority-transition guarantee to
an adapter the deployment provides, and it refuses to run without one
under the fail_closed posture.

## The canonical authority-safety classifier

One classifier in the kiwicaptcha php core
(`KiwiCaptcha\AuthoritySafetyClassifier`) is the single authority
verdict every surface shares. It judges the actual constructed client
instance, never a definition shape:

- a Predis replication aggregate (Sentinel or master-slave) or a Redis
  Cluster aggregate is **Unsafe**: commands route through promotion
  machinery, so the serving node can change under the client;
- a single-node direct connection with client-side reconnect retries
  enabled is **Unsafe**: the retry wrapper can re-execute a
  durability-critical mutation on a replacement connection whose write
  offset is empty;
- a single-node direct connection with retries disabled is **Safe**: the
  serving authority is the one node, and it cannot change under the
  client;
- every uninspectable shape (an opaque product, a custom-factory
  result, a non-Redis abstraction, a client whose connection cannot be
  read) is **Unknown**.

The verified-WAIT guard refuses Unsafe; the bundle's fail_closed
runtime classifier and the pinned-primary guard refuse Unsafe and
Unknown (unknown is unsafe until proven safe under those postures).

## The adapter seam: real today

The seam is the `AuthorityTransitionGuard` interface
(`BelConsulting\KiwiCaptchaBundle\Security\Authority`), with two real
implementations:

```php
interface AuthorityTransitionGuard
{
    public function assertServeEligible(mixed $client, bool $securityFinal = false): void;
}
```

- **RuntimeAuthorityClassifier** (the default, wired under every
  posture): classifies the actual constructed client instance through
  the canonical core classifier. Under replay_durability "fail_closed"
  it refuses an automatic-failover aggregate (Predis
  Sentinel/master-slave replication, Redis Cluster), a retry-enabled
  direct connection, and an uninspectable client at service
  construction, with the typed LogicException naming the posture, the
  classification and the remediation. Under operator_managed and
  best_effort every classification serves and the doctor carries the
  deployment contract. Every Redis-backed service (storage, rate
  limit, Argon admission, risk state) is constructed through a
  checked-client wrapper that runs this guard with the actual instance.
- **PinnedPrimaryAuthorityGuard** (the pinned-primary adapter, wired
  under `ha_authority: pinned_primary`): pins the serving authority
  identity through an explicit operator bootstrap and refuses every
  subsequent use when the authority changed. This is the mechanical
  enforcement that makes replay_durability "operator_managed" a real
  contract instead of an operator promise.

### The pinned-primary adapter: semantics

Pin store: one Redis key per distinct authority in the same
security-Redis namespace, `{kiwi:<ns>}:authority:pin:storage` for the
storage/limiter authority and `{kiwi:<ns>}:authority:pin:risk` for a
distinct risk authority, each holding "role|run_id". The pin is
write-once (`SET ... NX`):

- **The production runtime never auto-pins.** A guard with no pin and
  no expected identity refuses every check with the typed
  `PinnedAuthorityRefusalException` naming the
  `kiwicaptcha:ha-initialize` command. An operator records the initial
  authority pin deliberately, after quiescing a deliberate authority
  change. A stale-promotion recovery must never be able to pin the
  promoted authority automatically, so the bootstrap is always an
  explicit operator operation.

- **`kiwicaptcha:ha-initialize` records the pin.** The command reads
  the serving authority identity (`INFO` role + run_id) and writes the
  pin key write-once for every wired authority. It refuses when a pin
  already exists unless `--force` is given: re-pinning is a deliberate
  operation that must follow a deployment quiesce (the drain procedure
  below). It refuses when the configured `ha_authority_expected`
  identity disagrees with the connected server.

- **Every later use re-verifies.** The serving identity is compared
  against the pin: the role must equal the pinned role and the run_id
  must equal the pinned run_id. Any change (a promotion to a stale
  replica, a restarted primary with a new run_id, a pointed-at
  replica, a re-pointed endpoint) raises the typed
  `PinnedAuthorityRefusalException` naming the pinned vs observed
  identity and the remediation. The refusal contract is deliberately
  strict: the guard can only fail closed, never fail open, and an
  unverifiable authority (the `INFO` read fails, the pin cannot be
  read) is treated as stale.

- **Expected identity replaces the pin.** The optional
  `ha_authority_expected` configuration carries an operator-provisioned
  identity ("role|run_id", the same shape as the pin value). Two forms
  are accepted. The scalar string form applies one identity to every
  authority. The per-authority map form applies a different identity
  to each authority
  (`{"storage": "master|...", "risk": "master|..."}`) — the contract
  for a deployment whose storage Redis and risk Redis are different
  servers, because one scalar run_id cannot describe two authorities.
  When only one Redis is used, the storage entry covers the shared
  authority, and an authority without an entry falls back to the pin
  key. When set, the guard compares the serving authority against it
  instead of the pin key: the configuration IS the pin, and an
  immutable-identity deployment can skip the Redis pin entirely. The
  pin key may still exist (the initialize command writes it to match),
  but the comparison target is the operator-provisioned value.

- **Missing-pin semantics: refusal after establishment, never a
  re-pin.** Once the guard has established or observed the pin
  in-process, a pin that disappears (a failover to a node that never
  received the pin key) is a `REFUSAL`, never a silent re-pin. The
  deployment can only re-pin through `kiwicaptcha:ha-initialize`,
  exactly the operation a stale-promotion recovery must not perform
  automatically.

Check window and connection generation: the verification result is
cached in-process per CONNECTION OBJECT for
`ha_authority_reverify_secs` (default 5). The cache key is
`spl_object_id($connection)`, so a reconnect that replaces the
connection object invalidates the cache and the next check
re-verifies. Within the window every non-security-final check serves
without a round trip, so the `INFO` probe costs one round trip per
window per process per connection, not one per operation. A smaller
window detects an authority change sooner; a larger window costs less
`INFO` traffic.

Zero-stale security-final: the bundle components execute their Lua
through the typed `RedisSecurityCommandExecutor` seam, which declares
one of three lanes for every script: `executeRead` (read-only),
`executeMutation` (a non-final write, e.g. a claim or a lease
renewal) and `executeSecurityFinal` (the security-final transition).
The store declares the lane at the call site; no comment-marker
heuristic is involved. The security-final lane forces the
pinned-primary guard to re-verify the authority immediately before
the write, bypassing the verification window regardless of the
command shape. A security-final transition can therefore never
execute on a changed authority inside a stale window. The window
applies to ordinary reads and non-final writes only. The guarded
client wrapper routes the seam's declared lane through every command
it intercepts (both `EVAL` and `EVALSHA`). A plain `EVAL` executed
without the seam is an unknown mutating script: security-final by
default, so it is re-validated immediately, never served inside the
window (fail closed). The wrapper still classifies the core
RedisStorage's `EVALSHA` writes by the script body it recorded at
`SCRIPT LOAD` time (the storage consume, delete-if-pending, cancel,
commit and resume-claim transitions), and an `EVALSHA` whose script
was never seen is security-final too.

### The pinned-primary adapter: wiring

Under `ha_authority: pinned_primary` the extension:

1. refuses the container build when the storage/limiter/risk client is
   a Predis Sentinel/Cluster aggregate, a phpredis `\Redis` client, or
   unresolvable at build time. An aggregate can change the serving
   node under the client, and a phpredis client cannot be intercepted
   per command; both would silently defeat the pin, so both are
   refused, never unguarded;
2. wires one `PinnedPrimaryAuthorityGuard` service per distinct Redis
   authority (`kiwi_captcha.ha_authority_guard.storage` and, for a
   distinct risk client, `kiwi_captcha.ha_authority_guard.risk`), each
   bound to its own raw client, so its own `INFO` reads and pin-key
   operations never pass through a guarded wrapper (no recursion);
3. decorates the storage/limiter/risk checked client with
   `AuthorityGuardedPredisClient`, which consults the guard before
   every command, including the verified-WAIT `executeRaw`, the
   core storage's `EVALSHA` writes and the seam's declared
   security-final lanes, so a durability-critical transition can
   never execute on a changed authority;
4. passes the guards to the doctor, whose "HA authority" check audits
   every distinct authority and fails the deploy gate on a changed
   authority, an uninitialized deployment, or an unarmed guard;
5. wires `kiwicaptcha:ha-initialize` with every guard, so the operator
   records the initial authority pins through the one documented
   command.

The wiring composes with the fail_closed checked-client seam: the
runtime classifier still runs at construction under every posture, and
the pinned guard adds the per-command verification on top.

### The re-pin (drain) procedure

An authority change is a deliberate deployment operation. The
procedure:

1. quiesce the deployment (stop issuing and verifying; finish or
   redirect in-flight verifications);
2. perform the deliberate authority change (promote the new primary,
   restore the new node, re-point the endpoint);
3. delete the stale pin key(s)
   (`{kiwi:<ns>}:authority:pin:storage`, `{kiwi:<ns>}:authority:pin:risk`
   for a distinct risk authority) on the new authority, or keep them
   when the new authority replicated the old state and the change is a
   restarted run_id;
4. run `kiwicaptcha:ha-initialize --force` after the quiesce to record
   the new authority identity (the `--force` overwrite exists exactly
   for this deliberate re-pin; without it an existing pin is refused);
5. run `kiwicaptcha:doctor` and confirm the "HA authority" check
   passes armed before resuming traffic.

The refusal messages name this procedure, so a deploy gate that
observes a changed authority carries the exact remediation.

### The doctor contract

- `ha_authority: none` (the default): `PASS` with the posture noted;
  the authority-change contract is governed by replay_durability
  alone.
- `ha_authority: pinned_primary`, every guard armed and stable: `PASS`
  stating exactly what the guard enforces: per-authority pins (one
  guard and one pin per distinct Redis authority), zero-stale
  security-final transitions (every consume/commit/chain/
  idempotency-finalize re-verifies the authority before the write,
  never inside the verification window), connection-generation cache
  invalidation (a reconnect that replaces the connection object
  re-verifies), and the operator-initialized bootstrap (the runtime
  never auto-pins; `kiwicaptcha:ha-initialize` records the pin).
- `ha_authority: pinned_primary`, any authority changed: `FAIL` with
  the guard's exact refusal (pinned vs observed identity + the re-pin
  remediation) — the deploy gate refuses to pass a deployment whose
  authority moved.
- `ha_authority: pinned_primary`, uninitialized (no pin, no
  `ha_authority_expected`): `FAIL` naming `kiwicaptcha:ha-initialize`
  and the never-auto-pins contract.
- `ha_authority: pinned_primary`, guard not wired (a broken wiring):
  `FAIL`.
- protection_profile "ha_safe" with an explicit `ha_authority: none`
  override: `FAIL` — the profile's mechanical promise cannot silently
  weaken.

## The deployment posture switch

The posture is first-class configuration. `replay_durability`
(`fail_closed`, `operator_managed`, `best_effort`, default
`best_effort`) declares the authority-change contract;
`ha_authority` (`none`, `pinned_primary`, default `none`) declares
whether the bundle mechanically enforces a pinned serving authority.
The `ha_safe` protection profile derives
`replay_durability: operator_managed` + `ha_authority: pinned_primary`
and mirrors balanced everywhere else: one line of configuration turns
the operator contract into a bundle-enforced guarantee.

| Posture | What the bundle does | Doctor result |
|---------|----------------------|---------------|
| `best_effort` (default) | The current boundary: single-authority atomicity; the stale-promotion window documented and accepted | HA aggregate or retry-enabled direct: WARN with the posture named; single-node direct: PASS |
| `operator_managed` | The operator owns promotion eligibility (replication gating, catch-up rules, a promotion-eligibility gate on the failover manager); the bundle does not enforce it | HA aggregate or retry-enabled direct: PASS with the operator contract noted; single-node direct: PASS |
| `fail_closed` | The extension refuses the container build when an HA aggregate client is wired; the runtime authority-transition guard refuses an aggregate, a retry-enabled client, or an uninspectable client at service construction | HA aggregate: unreachable (the build is refused); single-node direct: PASS |
| `operator_managed` + `pinned_primary` (the `ha_safe` profile) | The PinnedPrimaryAuthorityGuard pins each distinct serving authority through `kiwicaptcha:ha-initialize` and refuses on any change; every storage/limiter/risk command is preceded by the pin check, with zero-stale security-final writes | "HA authority" PASS when armed and stable; FAIL on a changed authority, an uninitialized deployment, or an unarmed guard |
| `best_effort` + `pinned_primary` | The same mechanical guard, with the weaker replay_durability contract for the parts of the boundary the pin does not cover | "HA authority" PASS when armed and stable; the replication-topology check keeps its best_effort note |

The pin makes `operator_managed` a real contract: the operator still
owns promotion eligibility, but the bundle now refuses to serve on a
changed authority instead of trusting the promotion policy alone. The
pinned_primary guard can be combined with any replay_durability
posture; under `ha_safe` the profile derives the operator_managed
combination, and the doctor FAILs if the profile's derived
pinned_primary was explicitly overridden away.

## Design options

Five designs satisfy the requirement; they differ in where the
guarantee comes from and what the deployment must operate.

**Topology-specific pinned-primary durability adapter (REAL).** The
pinned-primary adapter described above: pins the deployment to one
primary identity per distinct authority, refuses every use on a
changed authority, and verifies the serving authority before every
durability-critical transition through the per-command guarded client,
with the zero-stale security-final lane and the connection-generation
cache. It is specific to the topology (a direct single-node Predis
client) but generic across the bundle components, since every
component speaks the same atomic-transition language.

**Failover-manager integration enforcing promotion eligibility
(roadmap).** The adapter consults the failover manager (sentinel, a
Kubernetes controller, a managed-service API) before every transition
and refuses when the serving authority is not the eligible authority.
A replica that is behind the acknowledged write offset, still catching
up, or outside the replication-gating window can never be elected. The
promotion-eligibility rule is the operator's, the enforcement is the
adapter's. This is the operator_managed posture made mechanical by the
failover machinery itself, and it composes with the pinned-primary
adapter: the pin is the deployment's own record, the failover manager
is the infrastructure's.

**Consensus-backed security-state storage (roadmap).** The security
state (the consumed guards, the deterministic results, the
dispositions) lives in a consensus-capable store whose acknowledged-
write contract survives node changes. Redis stays the hot path for
issuance and verification; only the security-final transitions ride
the consensus store. This is the strongest guarantee and the most
operationally distinct design.

**A strongly consistent datastore adapter (roadmap).** The bundle
speaks to a datastore whose reads and writes are strongly consistent
by design (one of the managed databases that document linearizable
semantics), and the adapter maps the atomic single-key transition
language onto its primitives. The replay guarantee comes from the
datastore, not from the bundle.

**An explicit quorum/authority-generation protocol (roadmap).** Every
security transition carries an authority generation, and every
verification requires a quorum of the authority set to agree on the
current generation before a transition is acknowledged. The protocol
is explicit about who may serve what; a promoted node outside the
current generation is stale by definition, not by catch-up luck.

## Roadmap

Redis stays the hot path. The bundle will not replace the Redis
authority with another store for the common case: Redis is the
performance and operational center of the deployment, and the atomic
single-key Lua transitions are the language every component already
speaks. The roadmap keeps Redis for issuance, verification, rate
limits, risk state, and the ordinary security state, and introduces
the authority guard as the durability front door.

What is real now:

- the canonical authority-safety classifier
  (`AuthoritySafetyClassifier`) in the php core, shared by the
  verified-WAIT guard, the runtime classifier and the pinned-primary
  guard;
- the `AuthorityTransitionGuard` interface and the runtime classifier
  (`RuntimeAuthorityClassifier`), wired into every Redis-backed
  service construction under every posture, with the fail_closed
  refusal surface (aggregates, retry-enabled connections and
  uninspectable clients);
- the pinned-primary adapter (`PinnedPrimaryAuthorityGuard` +
  `AuthorityGuardedPredisClient` + the typed
  `RedisSecurityCommandExecutor` seam), wired under
  `ha_authority: pinned_primary` with per-authority pin stores in the
  security Redis namespace, the reverify window keyed on the
  connection object, the zero-stale security-final lane, the explicit
  operator bootstrap (`kiwicaptcha:ha-initialize`, never an auto-pin)
  and the `ha_authority_expected` operator-provisioned identity
  (scalar shorthand or the per-authority map).
- the `ha_safe` protection profile deriving the
  operator_managed + pinned_primary combination.
- the doctor's "HA authority" check auditing every distinct authority
  and failing the deploy gate on a changed authority, an uninitialized
  deployment, or an unarmed guard.

What stays on the roadmap:

- failover-manager integration enforcing promotion eligibility (the
  sentinel/Kubernetes/managed-service adapter);
- consensus-backed security-state storage and the strong-datastore
  adapter for deployments that prefer the guarantee from the store
  itself;
- the quorum/authority-generation protocol.

Every step keeps the current boundary byte-identical until the
operator opts in: with `ha_authority: none` (the default) no guard is
wired and the behavior is unchanged.
