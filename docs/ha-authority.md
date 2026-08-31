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
centralizes the WAIT topology classification: standalone connections
with retries disabled are supported, and Predis replication aggregates,
cluster clients, and retry-enabled connections are refused at
construction. The guard is the shared classification the HA profile
reuses: a client that the VerifiedWaitGuard refuses for WAIT is
exactly a client whose authority can change under the bundle.

The authority transition is therefore the single seam where replay
safety can be made unconditional. The bundle already refuses to fake
durability on aggregates (waitReplicas stays 0 and the doctor warns).
The HA profile does the opposite side of the same coin: instead of
refusing the topology, it hands the authority-transition guarantee to
an adapter the deployment provides, and it refuses to run without one
under the fail_closed posture.

## The adapter seam: real today

The seam is the `AuthorityTransitionGuard` interface
(`BelConsulting\KiwiCaptchaBundle\Security\Authority`), with two real
implementations:

```php
interface AuthorityTransitionGuard
{
    /**
     * Refuse to serve when the client's authority-transition semantics
     * are unsafe under the deployment posture.
     */
    public function assertServeEligible(mixed $client): void;
}
```

- **RuntimeAuthorityClassifier** (the default, wired under every
  posture): classifies the actual constructed client instance. Under
  replay_durability "fail_closed" it refuses an automatic-failover
  aggregate (Predis Sentinel/master-slave replication, Redis Cluster)
  and an uninspectable client at service construction, with the typed
  LogicException naming the posture, the classification and the
  remediation. Under operator_managed and best_effort every
  classification serves and the doctor carries the deployment
  contract. Every Redis-backed service (storage, rate limit, Argon
  admission, risk state) is constructed through a checked-client
  wrapper that runs this guard with the actual instance.
- **PinnedPrimaryAuthorityGuard** (the pinned-primary adapter, wired
  under `ha_authority: pinned_primary`): pins the serving authority
  identity on first use and refuses every subsequent use when the
  authority changed. This is the mechanical enforcement that makes
  replay_durability "operator_managed" a real contract instead of an
  operator promise.

### The pinned-primary adapter: semantics

Pin store: one Redis key in the same security-Redis namespace,
`{kiwi:<ns>}:authority:pin`, holding "role|run_id". The pin is
write-once (`SET ... NX`):

- **First use pins.** A guard that has never seen a pin establishes it
  from the connected server's identity: the role and run_id of the
  node, read via `INFO`. On builds that omit the run_id from the
  replication section, the server section is the fallback. The first
  verified use of the deployment therefore records the authority that
  served it.

- **Every later use re-verifies.** The serving identity is compared
  against the pin: the role must equal the pinned role and the run_id
  must equal the pinned run_id. Any change (a promotion to a stale
  replica, a restarted primary with a new run_id, a pointed-at
  replica) raises the typed `PinnedAuthorityRefusalException` naming
  the pinned vs observed identity and the remediation. The refusal
  contract is deliberately strict: the guard can only fail closed,
  never fail open, and an unverifiable authority (the `INFO` read
  fails, the pin cannot be read) is treated as stale.

- **Missing-pin semantics: auto-pin on first use, refusal after
  establishment.** A fresh guard pins the first authority it can
  verify. Once the guard has established or observed the pin
  in-process, a pin that disappears (a failover to a node that never
  received the pin key) is a `REFUSAL`, never a silent re-pin. The
  deployment can only re-pin explicitly, exactly the operation a
  stale-promotion recovery must not perform automatically.

- **Re-pin after a deliberate authority change:** quiesce the
  deployment, delete `{kiwi:<ns>}:authority:pin`, and let the next
  first use pin the new authority. The refusal message names this
  procedure.

Check window: the verification result is cached in-process for
`ha_authority_reverify_secs` (default 5). Within the window every
check serves without a round trip, so the `INFO` probe costs one round
trip per window per process, not one per operation. A smaller window
detects an authority change sooner; a larger window costs less `INFO`
traffic.

### The pinned-primary adapter: wiring

Under `ha_authority: pinned_primary` the extension:

1. refuses the container build when the storage/limiter/risk client is
   a Predis Sentinel/Cluster aggregate, a phpredis `\Redis` client, or
   unresolvable at build time. An aggregate can change the serving
   node under the client, and a phpredis client cannot be intercepted
   per command; both would silently defeat the pin, so both are
   refused, never unguarded;
2. wires one `PinnedPrimaryAuthorityGuard` service
   (`kiwi_captcha.ha_authority_guard`) bound to the raw storage/limiter
   client, so its own `INFO` reads and pin-key operations never pass
   through a guarded wrapper (no recursion);
3. decorates the storage/limiter/risk checked client with
   `AuthorityGuardedPredisClient`, which consults the guard before
   every command, including the verified-WAIT `executeRaw`, so a
   durability-critical transition can never execute on a changed
   authority;
4. passes the guard to the doctor, whose "HA authority" check reports
   the pinned identity, the last verification and the posture, and
   fails the deploy gate on a changed authority or an unarmed guard.

The wiring composes with the fail_closed checked-client seam: the
runtime classifier still runs at construction under every posture, and
the pinned guard adds the per-command verification on top.

### The doctor contract

- `ha_authority: none` (the default): `PASS` with the posture noted;
  the authority-change contract is governed by replay_durability
  alone.
- `ha_authority: pinned_primary`, guard armed and stable: `PASS`,
  "pinned-primary guard armed: pinned <role|run_id>, last verified
  ...; replay_durability ... is now mechanically enforced". The first
  doctor run after a deployment performs a verification, so it pins
  the authority and reports the armed state.
- `ha_authority: pinned_primary`, authority changed: `FAIL` with the
  guard's exact refusal (pinned vs observed identity + the re-pin
  remediation) — the deploy gate refuses to pass a deployment whose
  authority moved.
- `ha_authority: pinned_primary`, guard unarmed (not wired, no pin
  established, or the pin cannot be read): `FAIL`.
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
| `best_effort` (default) | The current boundary: single-authority atomicity; the stale-promotion window documented and accepted | HA aggregate: WARN with the posture named; single-node direct: PASS |
| `operator_managed` | The operator owns promotion eligibility (replication gating, catch-up rules, a promotion-eligibility gate on the failover manager); the bundle does not enforce it | HA aggregate: PASS with the operator contract noted; single-node direct: PASS |
| `fail_closed` | The extension refuses the container build when an HA aggregate client is wired; the runtime authority-transition guard refuses an aggregate or uninspectable client at service construction | HA aggregate: unreachable (the build is refused); single-node direct: PASS |
| `operator_managed` + `pinned_primary` (the `ha_safe` profile) | The PinnedPrimaryAuthorityGuard pins the serving authority on first use and refuses on any change; every storage/limiter/risk command is preceded by the pin check | "HA authority" PASS when armed and stable; FAIL on a changed authority or an unarmed guard |
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
primary identity, refuses every use on a changed authority, and
verifies the serving authority before every durability-critical
transition through the per-command guarded client. It is specific to
the topology (a direct single-node Predis client) but generic across
the bundle components, since every component speaks the same
atomic-transition language.

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

- the `AuthorityTransitionGuard` interface and the runtime classifier
  (`RuntimeAuthorityClassifier`), wired into every Redis-backed
  service construction under every posture, with the fail_closed
  refusal surface.
- the pinned-primary adapter (`PinnedPrimaryAuthorityGuard` +
  `AuthorityGuardedPredisClient`), wired under
  `ha_authority: pinned_primary` with the pin store in the security
  Redis namespace, the reverify window, the auto-pin-on-first-use
  semantics and the explicit re-pin procedure.
- the `ha_safe` protection profile deriving the
  operator_managed + pinned_primary combination.
- the doctor's "HA authority" check reporting the guard state and
  failing the deploy gate on a changed authority or an unarmed guard.

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
