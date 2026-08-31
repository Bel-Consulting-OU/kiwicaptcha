# Performance analysis

## Scope and environment

This document records the measured performance baselines of the
KiwiCaptcha php-core and Symfony bundle paths, the hot paths of each
lifecycle, where the next 100x of headroom would have to come from, and
which budgets should gate merges. It is evidence from the benchmark
harness, not a plan presented as results. Every number below was
measured on 2026-08-30 on a local Apple silicon Mac (PHP 8.5.4, Redis
8.10.0 at redis://127.0.0.1:6399, loopback) with the working tree at
HEAD b3ddc978, and the core and bundle suites were validated on the
same day under PHP 8.2.33 with the same loopback Redis. The recorded
values live in the machine-readable record
`packages/kiwicaptcha/tools/perf-baselines.json`, the single source of
truth; the tables in this document are the regenerated view of that
record, not independent copies.

## The machine-readable baseline record

`packages/kiwicaptcha/tools/perf-baselines.json` is the one place where
the measured numbers live. Each timing tool accepts `--baseline-out
<file>` and merges its own measured section into that file: the
widget-driver and challenge-response budgets, the serial SHA-256 and
Argon2id numbers (`bench`), the risk-enabled controller numbers
(`bench_risk`), the concurrent load numbers (`load`), the verified-WAIT
single-authority numbers (`wait`) and the primary+replica numbers
(`wait_replica`). The merge is section-scoped and atomic, so running
the tools in sequence after a deliberate change regenerates the record
in place, and the CI timing steps never write it (they keep their
current continue-on-error behavior; only a clean local machine updates
the record by hand).

The regeneration command on a clean local machine with Redis reachable
at the loopback URL:

```bash
cd packages/kiwicaptcha/tools
KC_REDIS_URL=redis://127.0.0.1:6399 php perf-bench.php --all --baseline-out perf-baselines.json
php perf-bench-risk.php --baseline-out perf-baselines.json
KC_REDIS_URL=redis://127.0.0.1:6399 php perf-bench-risk.php --redis --baseline-out perf-baselines.json
KC_REDIS_URL=redis://127.0.0.1:6399 php perf-load.php --all --baseline-out perf-baselines.json
KC_REDIS_URL=redis://127.0.0.1:6399 php perf-wait.php --baseline-out perf-baselines.json
KC_REDIS_URL=redis://127.0.0.1:6399 php perf-wait-replica.php --baseline-out perf-baselines.json
```

The widget-driver and challenge-response sizes are the measured
budgets of perf-budget.sh (the raw/gzip/brotli byte counts of the three
identical widget-driver copies and the issued challenge-response JSON);
they are recorded in the `budgets` section of the record, and the CAPS
the script enforces live in that same `budgets` section. The shell
script reads the caps from the JSON at run time, so the record is the
single hard-budget authority and the script compiles no duplicate
constants. The concurrent modes (perf-bench-risk.php `--redis` and
perf-load.php) are re-run twice and the conservative of the two runs is
kept; the environment block of the record names the machine, the PHP
and Redis versions and the recording date, and is adjusted when the
recording machine changes.

## Measurement tools

- `packages/kiwicaptcha/tools/perf-bench.php` measures serial issuance
  and verification latency for the SHA-256 array path, the SHA-256 real
  Redis path and the Argon2id admission path.
- `packages/kiwicaptcha/tools/perf-bench-risk.php` measures the
  bundle's risk-enabled ChallengeController issuance path, in-memory by
  default and concurrently against real Redis in `--redis` mode (8
  forked worker processes, each with its own DSN-built Predis client).
- `packages/kiwicaptcha/tools/perf-load.php` measures concurrent load
  against real Redis with 8 worker processes, per phase and per
  operation: concurrent issuance, concurrent verification of
  pre-issued tokens, and a mixed issue-solve-verify pipeline. Its
  `--risk` variant still prints a loud note and exits, because the
  php-core vendor carries no `KiwiCaptcha\Risk` classes; the
  risk-enabled concurrent path is covered by perf-bench-risk.php
  `--redis`, which CI runs in the perf-budget job.
- `packages/kiwicaptcha-php/tests/RedisConcurrencyLoadTest.php` is a
  correctness-under-load suite against real Redis. It asserts the
  exactly-one-success contract under 4-way contention and spot-checks
  the Redis command count per lifecycle with a counting client.
- `packages/kiwicaptcha/tools/perf-wait.php` measures the
  verified-WAIT barrier round trip on a single Redis authority: WAIT
  acknowledges 0 replicas there, so every barrier write fails closed
  after the wait timeout (the shortfall/fail-closed path, the upper
  bound of the barrier cost).
- `packages/kiwicaptcha/tools/perf-wait-replica.php` boots a real
  local primary plus replica (WAIT 1 confirms the sync) and measures
  the successful-acknowledgment path of the same barrier: issuance,
  consume and commit with the replica acked, the replication-lag
  distribution, and the shortfall behavior on the same fixture when
  the replica is stopped.

The browser-side lab is separate: `tools/client-perf/` drives the
browser fixture over the real SHA-256 and Argon2id ladders (the Argon
rung measured at the real adaptive-risk envelope, m=16384 KiB, target
8) across the inline/files and cold/warm matrix, with per-cell
transferred bytes, cache-hit loads, lazy runtime fetch and repeat
navigation. Its tiers are desktop CPU-throttled emulation: the
recorded numbers are desktop-emulation evidence, never a low-end
mobile claim, and the physical-device procedure in that lab's README
is the release boundary. The two labs are deliberately separate: this
document measures the server paths, the client lab measures the
browser paths.

## Measured baselines

The serial benchmarks (p50/p95 in milliseconds, from the `bench` and
`bench_risk` sections of the record, measured on the recording day):

| path | issuance p50 | issuance p95 | verification p50 | verification p95 |
|---|---|---|---|---|
| SHA-256 array storage | 0.010 | 0.023 | 0.012 | 0.042 |
| SHA-256 Redis storage | 0.094 | 0.143 | 0.334 | 0.488 |
| Argon2id admission | 0.028 | 0.033 | 66.121 | 86.366 |
| risk-enabled controller issuance (in-memory) | 0.048 | 0.053 | n/a | n/a |

The concurrent load benchmark (8 workers x 100, p50/p95 in
milliseconds, throughput in operations per second over the concurrent
window, from the `load` section, the conservative of two consecutive
runs):

| phase | p50 | p95 | throughput |
|---|---|---|---|
| concurrent issuance | 0.133 | 0.298 | 9854 |
| concurrent verification | 0.757 | 1.168 | 5443 |
| mixed-pipeline issuance | 0.194 | 0.460 | 3961 combined |
| mixed-pipeline verification | 0.666 | 1.121 | 3961 combined |

The risk-enabled real-Redis concurrent path (8 workers x 100 through
the DSN-built client, from `bench_risk.redis_concurrent`, the
conservative of two consecutive runs):

| mode | p50 | p95 | throughput |
|---|---|---|---|
| risk-enabled concurrent issuance | 1.290 | 1.916 | 3538 req/s |

The verified-WAIT single-authority fixture (perf-wait.php, 100
iterations per phase, from the `wait` section): pre-issue reference p50
0.082 ms p95 0.097 ms; baseline consume p50 0.086 ms p95 0.097 ms and
commit p50 0.068 ms p95 0.082 ms; barrier consume p50 101.123 ms p95
202.271 ms and commit p50 101.122 ms p95 202.211 ms, every
durability-critical write raising `ReplicaWaitException`; raw WAIT 0
p50 0.091 ms p95 0.101 ms and raw WAIT 1 p50 101.133 ms p95 201.724 ms
with reply 0 on the single node. The p95 deltas of the barrier over the
baseline are +202.174 ms (consume) and +202.129 ms (commit). The
server's WAIT check granularity can land an unsatisfied WAIT at up to
twice the configured timeout, so the single-authority delta is the
configured timeout plus up to one granularity period; a real replica
that acks answers in milliseconds, so this delta is the upper bound of
the production fixture.

The primary+replica fixture (perf-wait-replica.php, 100 iterations per
phase, from the `wait_replica` section, a loopback primary with one
acked replica):

| operation | baseline p50 / p95 | ack p50 / p95 | p95 delta |
|---|---|---|---|
| issuance | 0.069 / 0.156 | 0.144 / 0.222 | +0.066 |
| consume | 0.105 / 0.175 | 0.141 / 0.250 | +0.074 |
| commit | 0.074 / 0.139 | 0.131 / 0.237 | +0.098 |

The replication-lag distribution on the same fixture: raw WAIT 1 after
a fence write p50 0.066 ms p95 0.167 ms, master-write to
replica-visible p50 0.106 ms p95 0.275 ms. The shortfall phase on the
same fixture (replica stopped) repeats the single-authority result:
raw WAIT 1 replies 0, consume p50 101.044 ms p95 202.066 ms and commit
p50 101.047 ms p95 202.085 ms, every write raising
`ReplicaWaitException`. The single-node perf-wait.php delta and this
shortfall delta agree, because both are the same unsatisfied-WAIT path;
the ack-phase numbers are the production replication topology the
single-node fixture cannot produce.

The deterministic budgets (from the `budgets` section, measured by
perf-budget.sh on the recording day): every widget-driver copy is
142,140 bytes raw, 40,395 bytes gzip and 34,119 bytes brotli, against
caps of 160,000 / 50,000 / 45,000 bytes; the same budgets section also
records the measured raw bytes of the other three widget assets (the
Argon worker at 19,491 bytes, the wasm glue runtime at 92,340 bytes
and the widget stylesheet at 13,863 bytes, each byte-identical across
the three copies); the challenge-response JSON
(decoy armed, the wire shape of the bundle's /challenge response) is
1,014-1,045 bytes for sha256 and 1,025-1,046 bytes for argon2id (the
grammar-composed name length varies the size between issuances),
against the 4,096-byte cap. The byte fields of the budgets section
were re-recorded on 2026-08-31 against the current widget assets
(the eager-import removal), and perf-budget.sh verifies the
recorded raw_bytes EQUAL the current measured bytes (an equality gate,
not just cap compliance), so a drifted record fails the budget job.
The caps are read by the shell from the record at run time; the record
is the single hard-budget authority.

## Ordinary-bootstrap target

The widget-driver byte caps (160,000 raw / 50,000 gzip / 45,000 brotli,
perf-budget.sh) are the guardrail: a regression there fails the perf
budget job. They are not the goal. The Argon worker split removed the
embedded worker source from the driver (the wasm glue carries it for the
inline compatibility tier; files mode fetches the versioned
`worker.<hash>.js` asset lazily), so the ordinary bootstrap — the bytes a
plain SHA-256 page downloads before any memory-hard challenge — targets
**sub-30 KB compressed** (gzip or brotli). The recorded driver sizes in
the `budgets` section reflect the current bytes and are re-baselined on
the next clean recording; the caps stay unchanged.

Remaining lazy candidates that would shrink the bootstrap further, not
yet split:

- the provider-migration compatibility loader — the external `/api.js`
  path ships the full glue and driver eagerly for migrated pages;
- the advanced risk-triggered modules — the decoy/polymorphism and
  client-context evidence machinery, loaded only when a risk-elevated
  challenge arrives.

## Hot paths per lifecycle

Issuance against Redis is one round trip. `RedisStorage::store()` is a
single SET with the TTL riding the command, so a challenge costs one
round trip plus the record build and the HMAC sign. Under 8 concurrent
workers the p95 stays near 0.30 ms and the instance sustains about
9,900 issuances per second.

Verification against Redis is three round trips. The runtime-state
snapshot is one GET, the atomic consume is one EVALSHA over the fused
Lua transition, and the deterministic result commit is a second
EVALSHA. The SHA-256 re-derivation (about 256 hashes at the 8-bit
target) runs locally and costs a fraction of a millisecond. The p95
under 8 concurrent workers is near 1.17 ms, with a throughput of about
5,400 verifications per second. The RedisConcurrencyLoadTest counting
client pins this shape: issuance must be exactly one SET and the
happy-path verification exactly GET, EVALSHA, EVALSHA, with the script
bodies cached.

Argon2id verification is the same three round trips plus the
memory-hard derivation. The 64 MiB t=3 profile costs about 66-86 ms, so
verification p95 moves from 0.5 ms to 86 ms. The admission gate bounds
how many derivations run at once, which is what protects the instance
from piling every concurrent verification onto one CPU.

The risk engine adds a small per-request cost on the issuance path.
The in-memory controller-level measurement of 0.048 ms p50 sits
between the plain array issuance (0.010 ms) and the Redis issuance
(0.094 ms), because the risk store is in-memory in that bench. The
real-Redis concurrent mode measures the full production shape: 8
workers through the DSN-built Predis client, risk state and challenge
storage both on Redis, p50 1.290 ms p95 1.916 ms at about 3,500
requests per second, in the same band as the plain concurrent issuance
plus the risk engine's own Redis round trips. The engine's own
signal-vector and scoring work is the cheap part; the expensive risk
paths live in the chained-challenge and post-solve Redis stores, which
are per-event writes on the verify path, not the issuance path.

## Where the next 100x lives

The single dominant cost is the Argon2id derivation. Verification moves
from 0.4-0.5 ms to 66-86 ms when the challenge profile switches from
SHA-256 to the memory-hard profile, a 150-200x jump. The derivation is
the wall by design: the whole point of the profile is to make automated
solving expensive. 100x headroom on the Argon2id path cannot come from
code tuning; it can only come from concurrency control (admission
gates that keep derivations bounded), hardware that accelerates the
hash, or from serving the deterministic result from the committed state
instead of re-deriving.

The three verification round trips are the next lever. They are cheap
at local RTT (about 0.3-0.5 ms serial), but they are sequential and
they are the entire Redis hot path. Cutting the consume and the commit
into one script would save one round trip, but the commit depends on
the derivation result, so the fusion is only possible when the
derivation is cheap or when the storage layer derives. Pipelining the
three trips is unsafe for the one-shot contract, because the consume
transition must complete before the proof check. The counting-client
assertion in RedisConcurrencyLoadTest is the regression guard for this
shape.

Durability amplification is the hidden multiplier. With
`waitReplicas > 0`, every durability-critical write pays the fresh
fence write plus a WAIT, which turns one issuance round trip into
three. The contract is correct and fail-closed, and the cost only
appears in replicated deployments, where it should be budgeted as a
deployment property, not a code regression.

The measured WAIT numbers are honest about which path they exercise.
`tools/perf-wait.php` runs against the single-node service only: on a
single authority WAIT acknowledges 0 replicas, so every barrier write
fails closed with `ReplicaWaitException` after the wait timeout
(recorded p50 about 101 ms, p95 about 202 ms at the 100 ms store
timeout), and the reported deltas are the shortfall/fail-closed path,
the upper bound of the barrier cost. `tools/perf-wait-replica.php`
boots a real local primary plus replica (WAIT 1 confirms the sync)
and measures the successful-acknowledgment numbers on the same
`RedisStorage` barrier: with the replica acked, issuance p50 0.144 ms
p95 0.222 ms, consume p50 0.141 ms p95 0.250 ms and commit p50 0.131
ms p95 0.237 ms, against a no-barrier baseline of 0.069-0.105 ms p50
(p95 deltas between +0.066 ms and +0.098 ms); the same fixture also
records the replication-lag distribution (master-write to
replica-visible p50 0.106 ms p95 0.275 ms on loopback) and re-verifies
the shortfall path by stopping the replica. The single-node shortfall
delta and the replica-fixture shortfall delta agree, because both are
the same unsatisfied-WAIT path; the ack-phase numbers are the
production replication topology the single-node fixture cannot produce.
Neither fixture gates on timing; the numbers above are the recorded
baselines of 2026-08-30 in the machine-readable record.

The risk engine is not the bottleneck. At 0.053 ms p95 per in-memory
issuance it is inside the noise of one Redis round trip, and the
real-Redis concurrent mode lands in the same band as the plain
concurrent issuance. A 100x on the bundle path would have to come from
the Redis round trips underneath the engine, not from the engine
itself.

## Which budgets should gate

The deterministic byte budgets of perf-budget.sh must stay gating. The
widget-driver raw, gzip and brotli caps and the challenge-response JSON
cap are byte measurements with zero runner noise; a regression there is
a fact, not a statistic. The caps are defined once, in the `budgets`
section of packages/kiwicaptcha/tools/perf-baselines.json, and the
shell script reads them from that record at run time, so there is no
second authority that could drift. The recorded sizes (142,140 / 40,395
/ 34,119 bytes and a 1,014-1,046-byte challenge response) leave 11-24%
headroom under the caps, so a legitimate addition lands inside them and
an accidental bloating regression trips them.

The timing ratchets must stay advisory. All three timing tools
(perf-bench.php, perf-bench-risk.php and perf-load.php) gate on a 3x
p95 ratchet against a recorded baseline, and all three are documented
as noisy-runner-tolerant on purpose. A shared CI runner can stall a
single worker or iteration without any code regression, so a hard
latency gate would flake the merge lane. The right promotion path is a
dedicated quiet runner for a p50 gate, never a p95 gate on a shared
runner; the end state for that runner is described in the next
section. The manual hard-ratchet benchmark job (the workflow_dispatch
perf-latency job) sets $KIWI_STRICT_BASELINE=1, which turns a missing
timing-baseline leaf into a hard failure: a hard-ratchet run with no
baseline is not a hard ratchet. The noisy CI timing steps in the
perf-budget job never set the flag and keep the note degradation.

The deterministic command-count assertions belong in the gating set. The
RedisConcurrencyLoadTest lifecycle check runs against real Redis in the
env-gated suites, is bounded (4 workers x 25 challenges) and asserts an
exact command shape. It is the strongest hot-path regression signal the
suite has, because it catches a round-trip regression deterministically
where a timing ratchet can only whisper.

## The dedicated hard-latency-runner end state

The end state for a latency gate that can block merges is a dedicated,
isolated runner, and the honest current status is that it does not
exist yet.

The desired end state:

- A fixed CPU class and an isolated runner: a dedicated machine or a
  pinned runner class with no co-tenants, so run-to-run variance comes
  from the measurement, not from the neighbor. The CPU class is fixed,
  never a "latest" label.
- Pinned PHP and Redis: the exact PHP patch version and the exact Redis
  version and build, on loopback, matching the versions the suite is
  validated on.
- Warm-up before measurement: the workloads already discard warmup
  iterations; the runner additionally settles the CPU governor, the
  page cache and the connection pools before the measured window
  starts.
- p50/p90/p95 distributions: the runner records the full percentile
  distribution of every phase (the harness reports p50/p95 today; p90
  and the spread between them are the variance signal), so a single
  outlier sample is visible instead of hiding inside a point p95.
- Variance limits: a run whose within-run spread exceeds a bound (for
  example the p95/p50 ratio or the inter-quartile range) is rejected
  and re-run, because a noisy window cannot produce a trustworthy
  comparison.
- Base-commit comparison: every change is benchmarked against the base
  commit on the same runner in the same session, so the comparison is
  distribution against distribution, never a point value against a
  stale absolute threshold.
- A statistically meaningful threshold: the regression test compares
  the two distributions (a percentile confidence interval or a
  distribution test with a minimum sample size), not a single p95
  against a multiple of a recorded number.
- Blocking only on confident regressions: the gate blocks only when
  the distribution shift is both statistically significant and above a
  practical significance bound (for example a double-digit percentage
  at p95). An ambiguous result fails loudly but does not block; a
  confident regression blocks.

The honest current status:

- The latency signal today is the manually dispatched benchmark job
  (workflow_dispatch only, a shared GitHub-hosted runner, the same
  timing steps without continue-on-error). It is not a merge gate: it
  is skipped on every push and pull_request, it is not a
  protected-main required context, and the release workflow does not
  consult it.
- The ratchets in the timing tools are advisory by design: a 3x p95
  against the recorded baseline, documented as noisy-runner-tolerant,
  so a shared runner stall never flakes a merge. The manual job sets
  $KIWI_STRICT_BASELINE=1, so a missing timing-baseline leaf fails
  that job even though a measured regression only signals: a
  hard-ratchet run with no baseline is not a hard ratchet.
- The only hard latency-adjacent gates are the deterministic ones: the
  perf-budget.sh byte caps and the RedisConcurrencyLoadTest command
  count. Until a dedicated runner exists, treat 3x-p95 failures as
  signals, not blockers, and do not claim a latency gate that is not
  there.

## What this analysis does not measure

The load numbers come from one host and one local Redis, so they are
relative evidence, not capacity planning. The Argon2id path was not
measured under concurrent load, because the derivation cost makes a
multi-worker latency distribution dominated by CPU contention rather
than by the Redis path; the serial bench and the admission gate bound
it. The perf-load.php `--risk` variant is not measured, because the
php-core vendor does not carry the risk classes; the risk-enabled
concurrent path is measured instead by perf-bench-risk.php `--redis`
(the real bundle wiring, 8 workers, recorded in the
`bench_risk.redis_concurrent` section), which CI runs on every push.
The replicated deployment numbers above come from the loopback
primary+replica fixture (perf-wait-replica.php), one host and one
local topology: they are evidence of the acked-WAIT cost on a quiet
loopback, not capacity planning for a production replica set, and the
shortfall numbers remain the fail-closed behavior, not a steady-state
cost.
