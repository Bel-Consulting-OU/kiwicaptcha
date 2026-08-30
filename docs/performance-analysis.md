# Performance analysis

## Scope and environment

This document records the measured performance baselines of the
KiwiCaptcha php-core and Symfony bundle paths, the hot paths of each
lifecycle, where the next 100x of headroom would have to come from, and
which budgets should gate merges. It is evidence from the benchmark
harness, not a plan presented as results. Every number below was
measured on 2026-08-30 on a local Mac (PHP 8.5.4, Redis 8.10 at
redis://127.0.0.1:6399) with the working tree at HEAD e86ad5c.

The measurement tools:

- `packages/kiwicaptcha/tools/perf-bench.php` measures serial issuance
  and verification latency for the SHA-256 array path, the SHA-256 real
  Redis path and the Argon2id admission path. Its recorded baselines
  live in the script header.
- `packages/kiwicaptcha/tools/perf-bench-risk.php` measures the
  bundle's risk-enabled ChallengeController issuance path.
- `packages/kiwicaptcha/tools/perf-load.php` measures concurrent load
  against real Redis with 8 worker processes, per phase and per
  operation: concurrent issuance, concurrent verification of
  pre-issued tokens, and a mixed issue-solve-verify pipeline. Its
  recorded baselines live in the script header.
- `packages/kiwicaptcha-php/tests/RedisConcurrencyLoadTest.php` is a
  correctness-under-load suite against real Redis. It asserts the
  exactly-one-success contract under 4-way contention and spot-checks
  the Redis command count per lifecycle with a counting client.

## Measured baselines

The serial benchmarks (p50/p95 in milliseconds, per the recorded
baselines of the scripts, which are the conservative of the runs on the
recording day):

| path | issuance p50 | issuance p95 | verification p50 | verification p95 |
|---|---|---|---|---|
| SHA-256 array storage | 0.010 | 0.026 | 0.011 | 0.037 |
| SHA-256 Redis storage | 0.063 | 0.107 | 0.240 | 0.408 |
| Argon2id admission | 0.032 | 0.043 | 79.077 | 83.331 |
| risk-enabled controller issuance | 0.047 | 0.065 | n/a | n/a |

The concurrent load benchmark (8 workers x 100, p50/p95 in
milliseconds, throughput in operations per second over the concurrent
window):

| phase | p50 | p95 | throughput |
|---|---|---|---|
| concurrent issuance | 0.097 | 0.177 | 10303 |
| concurrent verification | 0.544 | 0.880 | 6463 |
| mixed-pipeline issuance | 0.127 | 0.307 | 4433 combined |
| mixed-pipeline verification | 0.458 | 0.944 | 4433 combined |

The risk-enabled load variant of perf-load.php is absent from the
record: the php-core vendor carries no `KiwiCaptcha\Risk` classes, so
the variant prints a loud note and exits. The bundle's risk-enabled
controller path is measured by perf-bench-risk.php instead, and that
path sits at 0.047 ms p50 / 0.065 ms p95 per issuance, roughly the cost
of one Redis round trip on top of the plain issuance.

## Hot paths per lifecycle

Issuance against Redis is one round trip. `RedisStorage::store()` is a
single SET with the TTL riding the command, so a challenge costs one
round trip plus the record build and the HMAC sign. Under 8 concurrent
workers the p95 stays near 0.18 ms and the instance sustains about
10,000 issuances per second.

Verification against Redis is three round trips. The runtime-state
snapshot is one GET, the atomic consume is one EVALSHA over the fused
Lua transition, and the deterministic result commit is a second
EVALSHA. The SHA-256 re-derivation (about 256 hashes at the 8-bit
target) runs locally and costs a fraction of a millisecond. The p95
under 8 concurrent workers is near 0.88 ms, with a throughput of about
6,500 verifications per second. The RedisConcurrencyLoadTest counting
client pins this shape: issuance must be exactly one SET and the
happy-path verification exactly GET, EVALSHA, EVALSHA, with the script
bodies cached.

Argon2id verification is the same three round trips plus the
memory-hard derivation. The 64 MiB t=3 profile costs about 80 ms, so
verification p95 moves from 0.4 ms to 83 ms. The admission gate bounds
how many derivations run at once, which is what protects the instance
from piling every concurrent verification onto one CPU.

The risk engine adds a small per-request cost on the issuance path.
The controller-level measurement of 0.047 ms p50 sits between the plain
array issuance (0.010 ms) and the Redis issuance (0.063 ms), because
the risk store is in-memory in that bench. The engine's own
signal-vector and scoring work is the cheap part; the expensive risk
paths live in the chained-challenge and post-solve Redis stores, which
are per-event writes on the verify path, not the issuance path.

## Where the next 100x lives

The single dominant cost is the Argon2id derivation. Verification moves
from 0.4 ms to 80 ms when the challenge profile switches from SHA-256
to the memory-hard profile, a 200x jump. The derivation is the wall by
design: the whole point of the profile is to make automated solving
expensive. 100x headroom on the Argon2id path cannot come from code
tuning; it can only come from concurrency control (admission gates that
keep derivations bounded), hardware that accelerates the hash, or from
serving the deterministic result from the committed state instead of
re-deriving.

The three verification round trips are the next lever. They are cheap
at local RTT (about 0.3 ms serial), but they are sequential and they
are the entire Redis hot path. Cutting the consume and the commit into
one script would save one round trip, but the commit depends on the
derivation result, so the fusion is only possible when the derivation
is cheap or when the storage layer derives. Pipelining the three trips
is unsafe for the one-shot contract, because the consume transition
must complete before the proof check. The counting-client assertion in
RedisConcurrencyLoadTest is the regression guard for this shape.

Durability amplification is the hidden multiplier. With
`waitReplicas > 0`, every durability-critical write pays the fresh
fence write plus a WAIT, which turns one issuance round trip into
three. The contract is correct and fail-closed, and the cost only
appears in replicated deployments, where it should be budgeted as a
deployment property, not a code regression.

The risk engine is not the bottleneck. At 0.065 ms p95 per issuance it
is inside the noise of one Redis round trip. A 100x on the bundle path
would have to come from the Redis round trips underneath the engine,
not from the engine itself.

## Which budgets should gate

The deterministic byte budgets of perf-budget.sh must stay gating. The
widget-driver raw, gzip and brotli caps and the challenge-response JSON
cap are byte measurements with zero runner noise; a regression there is
a fact, not a statistic.

The timing ratchets must stay advisory. All three timing tools
(perf-bench.php, perf-bench-risk.php and perf-load.php) gate on a 3x
p95 ratchet against a recorded baseline, and all three are documented
as noisy-runner-tolerant on purpose. A shared CI runner can stall a
single worker or iteration without any code regression, so a hard
latency gate would flake the merge lane. The right promotion path is a
dedicated quiet runner for a p50 gate, never a p95 gate on a shared
runner.

The deterministic command-count assertions belong in the gating set. The
RedisConcurrencyLoadTest lifecycle check runs against real Redis in the
env-gated suites, is bounded (4 workers x 25 challenges) and asserts an
exact command shape. It is the strongest hot-path regression signal the
suite has, because it catches a round-trip regression deterministically
where a timing ratchet can only whisper.

## What this analysis does not measure

The load numbers come from one host and one local Redis, so they are
relative evidence, not capacity planning. The Argon2id path was not
measured under concurrent load, because the derivation cost makes a
multi-worker latency distribution dominated by CPU contention rather
than by the Redis path; the serial bench and the admission gate bound
it. The risk-enabled load variant of perf-load.php is not measured,
because the php-core vendor does not carry the risk classes. A
replicated deployment with `waitReplicas > 0` was not measured either;
the round-trip amplification above is derived from the storage
contract, not from a live replica bench.
