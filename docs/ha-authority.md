# HA authority: the replay-safe authority transition abstraction

This document is the design record for the replay-safe high-availability
authority posture. It sits next to redis-topologies.md, which records
the verified topology contract of the current Redis boundary. The two
documents answer different questions. redis-topologies.md states what
the bundle verifies mechanically today. This document states the
abstraction the replay-safe HA profile is built on, why the abstraction
is the right seam, and what the adapter surface looks like.

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

## Design options

Five designs satisfy the requirement; they differ in where the
guarantee comes from and what the deployment must operate.

**Topology-specific pinned-primary durability adapter.** A client
wrapper that pins the deployment to one primary identity, refuses
automatic reconnection to a different node, and verifies the serving
authority before every durability-critical transition. The adapter is
specific to the topology (sentinel, cluster, or a managed Redis
service) but generic across the bundle components, since every
component speaks the same atomic-transition language. This is the
smallest adapter that satisfies the requirement for a given topology.

**Failover-manager integration enforcing promotion eligibility.** The
adapter consults the failover manager (sentinel, a Kubernetes
controller, a managed-service API) before every transition and refuses
when the serving authority is not the eligible authority. A replica
that is behind the acknowledged write offset, still catching up, or
outside the replication-gating window can never be elected. The
promotion-eligibility rule is the operator's, the enforcement is the
adapter's. This is the operator_managed posture made mechanical.

**Consensus-backed security-state storage.** The security state (the
consumed guards, the deterministic results, the dispositions) lives in
a consensus-capable store whose acknowledged-write contract survives
node changes. Redis stays the hot path for issuance and verification;
only the security-final transitions ride the consensus store. This is
the strongest guarantee and the most operationally distinct design.

**A strongly consistent datastore adapter.** The bundle speaks to a
datastore whose reads and writes are strongly consistent by design
(one of the managed databases that document linearizable semantics),
and the adapter maps the atomic single-key transition language onto
its primitives. The replay guarantee comes from the datastore, not
from the bundle.

**An explicit quorum/authority-generation protocol.** Every security
transition carries an authority generation, and every verification
requires a quorum of the authority set to agree on the current
generation before a transition is acknowledged. The protocol is
explicit about who may serve what; a promoted node outside the current
generation is stale by definition, not by catch-up luck.

The roadmap picks the adapter seam (options one and two compose into
the HA profile) while keeping options three to five as the documented
escape hatches for deployments that want the guarantee from the store
itself.

## The adapter seam

The seam is a small interface the bundle depends on, with a null
adapter for the current boundary. The authority-transition guard:

```php
interface AuthorityTransitionGuard
{
    /**
     * Refuse to serve when the current authority cannot be verified
     * as the eligible authority for security-final transitions.
     * A stale or unknown authority must refuse, never pass.
     */
    public function verifyAuthority(string $scope): void;

    /**
     * Promotion eligibility: whether the serving authority may be
     * elected after a failure, given the writes this deployment
     * considers security-critical. The default is false: an
     * unguarded authority change is never eligible.
     */
    public function promotionEligible(string $scope): bool;

    /**
     * The authority identity this deployment is pinned to, when the
     * adapter pins. Null means no pinned identity and therefore no
     * authority-change guarantee from this adapter.
     */
    public function pinnedAuthorityId(): ?string;
}
```

The guard is consulted on both sides of a security-final transition.
Before the transition, verifyAuthority refuses a stale or unknown
authority, so a failed-over node cannot acknowledge new transitions.
After the transition, the acknowledged outcome is recorded against the
authority identity, so a later promotion to a different identity is
detected and the deployment can refuse to serve the resurrected state
instead of replaying it. The refusal contract is deliberately strict:
the guard can only fail closed, never fail open, and an unverifiable
authority is treated as stale.

The wiring mirrors the VerifiedWaitGuard's shared classification. The
bundle keeps one guard instance per deployment scope, and every
durability-critical component calls it before its atomic transition.
Under replay_durability "best_effort" and "operator_managed" the guard
may be the operator's own implementation or absent. Under
"fail_closed" the extension refuses the build when an HA aggregate
client is wired without an adapter the build can prove is
pinned-primary (the exact refusal names the posture and the
remediation). Single-node direct clients are fine under every posture,
because their authority never changes.

## Roadmap

Redis stays the hot path. The bundle will not replace the Redis
authority with another store for the common case: Redis is the
performance and operational center of the deployment, and the atomic
single-key Lua transitions are the language every component already
speaks. The roadmap keeps Redis for issuance, verification, rate
limits, risk state, and the ordinary security state, and introduces
the authority guard as the durability front door.

The HA profile is the flagship addition of that roadmap. The profile
wires the pinned-primary adapter (or the failover-manager
integration) automatically, turns replay_durability to "fail_closed"
by default, and makes the doctor's replication topology check report
the authority contract as a verified property instead of a documented
acceptance. The profile is where the first-class HA authority posture
becomes a supported product surface rather than an
operator-assembled invariant.

The concrete steps, in order. The guard interface ships behind the
existing wiring (null adapter, zero behavior change). The
pinned-primary adapter for the sentinel and cluster topologies ships
with the HA profile. The doctor learns the adapter's verification
state. The consensus-backed and strong-datastore options stay
documented escape hatches for deployments that prefer the guarantee
from the store itself. Every step keeps the current boundary
byte-identical until the operator opts in.
