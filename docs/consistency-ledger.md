# The consistency ledger

The zero-contradiction cross-check of change.md (Part 12). Every row
resolves one potential tension: the claim, where the repo enforces it
(file and line, verified against the working tree at the time of
writing), and the check that keeps it true. A row whose reference
cannot be verified is worse than no row; a row with no enforcement
point is labelled spec-only instead of pointing at code that does not
exist. No such row remains: every claim below is enforced in the tree.

Line references were verified on this tree on 2026-10-04; the keeping
checks (tests, parity suites, lint gates, and since this week the
red-team campaigns under tools/redteam/) re-verify them on every run,
so drift fails before a reader can be misled.

## 1. Vocabulary and planes

| change.md claim | Where it is enforced | Keeping check |
| --- | --- | --- |
| 1.3 Five dispositions, one per request; the ladder is total and identical across both cores | `packages/kiwicaptcha-risk-php/src/RiskAction.php:17-25` (allow, sha16, sha18, sha20, argon16, argon32, argon64, step_up, deny); Rust twin `packages/kiwicaptcha-risk/src/action.rs:16-27` with the strictly monotonic rank at `action.rs:32-40` | Cross-language fixture parity: `packages/kiwicaptcha-risk/tests/` fixture_hash vs `packages/kiwicaptcha-risk-php/tools/fixture_hash.php` (CI compares the two hashes); red-team battery `tools/redteam/campaigns/` |
| 1.3 quarantine: pass to the app, marked, wire-indistinguishable from allow | Enforced as a decision disposition, never a ladder rung. Selection: `packages/kiwicaptcha-risk-php/src/Marks/Quarantine.php:55` (spam-only in-TTL mark set, no corroboration, no target mark) applied by the marks stage at `MarksEscalation.php:139-146` (action stays Allow, flag plus the `spam_mark_quarantine` reason at `:142-143`); the Rust twin `packages/kiwicaptcha-risk/src/quarantine.rs:53` applied at `marks.rs:327-328`. The decision flag rides Allow only (`RiskDecision.php:50`, `lib.rs:215`), later composed stages drop it on escalation (`AdaptiveRiskEngine.php:650`, `lib.rs:1954`), and the app-side hold persists with the disposition (`RedisPostSolveDispositionStore.php:957-1011`), surfaces as the `kiwi.quarantine` request attribute plus the `QuarantineMarkerInterface` hold (`KiwiCaptchaValidator.php:798-800`, `QuarantineMarkerInterface.php:37`, alias wired at `KiwiCaptchaExtension.php:2618`) | The shared corpus `protocol/risk-v1/quarantine-vectors.json` read by both cores (`QuarantineVectorsTest.php`, `tests/quarantine_vectors.rs`) pins the selection and its severity-monotonic precedence; the wire-diff harness `QuarantineWireDiffTest.php` proves byte-identical challenge responses over 2k paired marked/clean requests with the flag set for exactly the marked half |
| 1.1 The seven identity dimensions, each an HMAC pseudonym, raw values never leaving process memory | `protocol/risk-v2/identity.json` (the contract file §3.1.1 requires: dimension order, hmac contexts, granularities, epoch policies, cardinality bounds); both cores re-derive it: `packages/kiwicaptcha-risk/tests/identity_vectors.rs:29` and `packages/kiwicaptcha-risk-php/tests/IdentityVectorsParityTest.php:32` | Those two reader tests are the enforced surface (the contract file's own note records why); privacy re-drive at deployment level: `tools/redteam/campaigns/d3.14-privacy.sh` |
| 1.2 Trust polarity: attacker-controllable signals only add risk; only server-confirmed outcomes subtract | The scorer subtracts exactly two credits and nothing else: `packages/kiwicaptcha-risk-php/src/RiskScorer.php:47-48` (trustCredit, principalCredit); v2 factors purely additive (`RiskScorer.php:60-69`); the Lua channels never let a foreign presentation reduce home credit: `protocol/risk-v1/trust.lua:23-24` | Property tests: `packages/kiwicaptcha-risk-php/tests/ScoringPropertyTest.php`, `RiskPropertyTest.php`; campaign D3.5 asserts the victim is never denied from attacker evidence |

## 2. Ladder, pricing bands, hysteresis

| change.md claim | Where it is enforced | Keeping check |
| --- | --- | --- |
| 1.4 Ladder order Allow to Sha16 to Sha18 to Sha20 to Argon16/32/64 to RSW to StepUp to Deny | Ladder enumeration in `packages/kiwicaptcha-solver/src/bench.rs:76` (`pub fn ladder()`); action rank `packages/kiwicaptcha-risk/src/action.rs:32-40`; pricing bands in `packages/kiwicaptcha-risk-php/src/Pricing/PriceModel.php` (the 600 boundary shared by the argon regimes, `PriceModel.php:144`) | The bench's own ladder tests; `tools/ci/limits-parity-check.sh` pins the rung ceilings across implementations against `protocol/limits.json` |
| 0/4 Hysteresis edge margin: escalate on `action_for_score(score - 10)`, drop on `action_for_score(score + 10)` | `packages/kiwicaptcha-risk/src/hysteresis.rs:243,248`; PHP twin `packages/kiwicaptcha-risk-php/src/ScopeActionHysteresis.php:24-25` and the same margin in its application path (`:109`) | `hysteresis.rs:320` `bands_mirror_action_for_score` plus the shared hysteresis vectors (`HysteresisVectorsTest.php`, `hysteresis_vectors.rs`) |
| Part 7 value classes: low, high, critical price every scope above its abuse value | `packages/kiwicaptcha-risk-php/src/Pricing/ValueClass.php:14-17`; verdicts computed by the bench from `packages/kiwicaptcha-solver/reference-costs.json` | `kiwicaptcha-solver bench` value-class verdicts; the public table `docs/cost-to-abuse.md` (engine-generated); D3.3 pricing is the standing campaign |
| Protocol limits are one register, identical everywhere | `protocol/limits.json` (sha_max_target_bits 20, solver_max_hashes 20000000, ttl_max_secs 300, rsw bounds, min_master_bytes 32) | `tools/ci/limits-parity-check.sh` reads each implementation's constant declarations and fails on any pairwise difference |

## 3. Lifetimes: the TTL table against the constants

| change.md claim | Exact constant in code | Keeping check |
| --- | --- | --- |
| 1.1 source: 30 min fast, 24 h slow | `protocol/risk-v2/identity.json` dimensions.source.ttl_secs `{fast: 1800, slow: 86400}` | `identity_vectors.rs` + `IdentityVectorsParityTest.php` re-derive from the contract |
| 1.1 subnet: 30 min; asn: 6 h; session: 30 min; principal: 24 h; target: 24 h; agent: none | same file: subnet `ttl_secs {fast: 1800}`, asn `{fast: 21600}` (epoch window 21600), session `{fast: 1800}`, principal `{fast: 86400}`, target `{fast: 86400}`, agent `ttl_secs: null` | as above |
| Marks: long memory, 90 days | `packages/kiwicaptcha-risk-php/src/Storage/RedisRiskStateStore.php:66` `DEFAULT_MARK_TTL_SECS = 7_776_000` (90 days); Rust `packages/kiwicaptcha-risk/src/redis.rs:94` | consumed by `MarksEscalation.php:50` and `marks.rs:49`; D3.5 exercises the write and the relief decay over the real Redis marks store |
| Hysteresis memory window: 5 min | `packages/kiwicaptcha-risk/src/hysteresis.rs:126` `TTL_MS: u64 = 300_000` | hysteresis vectors |
| Outcome receipts: 5 min | `packages/kiwicaptcha-risk/src/calibration.rs:471` `RECEIPT_EXPIRE_S: u64 = 300` | calibration tests (`CalibrationTest.php`, `calibration_vectors`) |
| Escalation memory (the decoy/escalation record the evidence plane keeps): 10 min | `packages/kiwicaptcha-risk/src/escalation.rs:36` `ESCALATION_TTL_MS: u64 = 600_000` | escalation and decoy suites (`DecoyEscalationTest.php`, `decoy_escalation.lua`) |
| Outcome confirm keeps the register TTL (Part 0 item 13: KEEPTTL) | `packages/kiwicaptcha-risk-php/resources/outcome_confirm.lua:40` `redis.call('SET', KEYS[1], ..., 'KEEPTTL')` | `OutcomeConfirmKeepsTtlTest.php` |

## 4. Storage and failover claims

| change.md claim | Where it is enforced | Keeping check |
| --- | --- | --- |
| 2.3 Fail closed under uncertainty: corrupt record, unreadable store, stale policy all deny or step up | `packages/kiwicaptcha-php/src/Verifier.php:45` (a swapped record fails closed either way), `:420` (above the expected epoch accepts nothing, fail closed); the routers answer `storage_unavailable` with `ok:false` (`deploy/app/router.php` verify catch) | D3.10 matrix: eleven tamper classes against every storage backend, zero acceptance (`tools/redteam/campaigns/d3.10-infrastructure.sh`); core adversarial suites `pentest.rs`, `pentest_campaigns.rs`, `redis_verify.rs` |
| Single use is the consumed marker, not absence | `packages/kiwicaptcha-php/src/Storage/RedisStorage.php:22-29` (consumed marker retained until ttl; strict single-use under concurrency in the Lua compare-and-consume) | D3.10 retained-marker leg per backend; `redis_verify.rs:7330` (RecordNotFound, never a resurrected authorization) |
| 3.7 HA authority: a stale primary never serves security state | Sentinel refuse-on-unsafe-authority posture (`packages/kiwicaptcha/integrations/symfony` runtime AuthorityTransitionGuard, commit 679fa710) plus WAIT hardening semantics documented at `Configuration.php:1021` (WAIT is acknowledgement hardening, not consensus) | The sentinel leg of D3.10: WAIT-verified replication, promotion mid-consume, continuity, stale primary rejoins read-only and refuses writes (observed READONLY) |
| One-shot binding anti-oracle: a failed binding attempt burns the record | `deploy/app/router.php` verify handler doc and the core's cheap-phase retirement; `packages/kiwicaptcha-php/src/Verifier.php` (RequestBindingExpectation) | D3.1 class 7: wrong binding first, corrected retry second, the retry finds the record gone (asserted every run) |

## 5. The four-setting surface

| change.md claim | Where it is enforced | Keeping check |
| --- | --- | --- |
| Part 7: the whole required surface is profile, secret, store, scopes | Every SDK settings type leads with exactly these four and defaults everything else: `packages/kiwicaptcha-jvm/core/src/main/java/com/kiwicaptcha/Settings.java:15-21` (secret, store, scopes, profile default `standard`); the Symfony tree makes the rest progressive disclosure with compile-time gates only where production safety requires them (`packages/kiwicaptcha/integrations/symfony/src/DependencyInjection/Configuration.php:352`: a prod deployment requires a shared atomic store) | Doctor commands per SDK (`doctor.go`, `doctor.py`, jvm `DoctorTest.java`); the reference deployment reads the same knobs from the environment only (`deploy/app/bootstrap.php:12-13` name the audit contract; `:165-166` enforce it) |
| Issuance is server-owned; the client algorithm field never selects the profile | `deploy/app/router.php` kiwiChallenge: the request `algorithm` is validated compatibility metadata (`INVALID_ALGORITHM` 422) and the config is rebuilt from the deployment env per request | D3.1 class 9 (invalid algorithm refused); D3.12 wrong-content-type and unknown-field rows |

## 6. Zero cloud, no paid dependency

| change.md claim | Where it is enforced | Keeping check |
| --- | --- | --- |
| Part 8: no managed database, no third-party API, no paid feed anywhere | Python SDK: `dependencies = []` (`packages/kiwicaptcha-python-sdk/pyproject.toml`, pure stdlib verification); Go SDK's only `net/http` use is the integrator's own server surface (`packages/kiwicaptcha-go/middleware.go:7`), never an outbound client; the sidecar makes no outbound connections (`packages/kiwicaptcha-verifier/src/main.rs:35`); PHP's only I/O dependency is Predis to the adopter's own Redis (`deploy/app/composer.json`) | The greps above run in review; the red-team target boots every profile with no network beyond loopback (`tools/redteam/target.sh`), and the D3.14 dump scan verifies nothing the plane persists points elsewhere |
| Optional data feeds ship as free redistributable files | `protocol/asn/sample-asn.tsv` (the free dataset the ASN dimension loads from disk); `packages/kiwicaptcha-solver/reference-costs.json` (free, hand-refreshed cost anchors with provenance) | `AsnDatasetTest.php`; the bench prints the provenance and flags a stale as_of |
| Verify is always local, never a network call | The SDK contract: `verify(token)` is signature plus MAC plus the store adapter; the sidecar is a localhost service (`packages/kiwicaptcha-verifier/src/main.rs:35`) | D3.17: the same adversarial corpus through all seven SDKs with identical rejection (`tools/redteam/campaigns/d3.17-cross-sdk-parity.sh`) |

## 7. The wire contract and its parity

| change.md claim | Where it is enforced | Keeping check |
| --- | --- | --- |
| Byte-identical cross-language cores on a shared corpus (Part 2) | The canonical framing: `packages/kiwicaptcha-php/src/Issuer.php:14-21` (the `v4|...` canonical string, the MAC tail); the same framing re-derived by every SDK | Fixture-hash pair (rust example vs php tool, compared in CI); D3.12: all seven conformance runners green on `protocol/` corpora plus the node and python direct adversarial drives |
| Strict framing at the deployment edge (Part 3 enforcement plane) | `deploy/app/router.php:96-130` (the rejection order: query, canonical length, encoding, type, bounded read, duplicate keys, depth) | D3.12 parser legs assert each rejection code through the real endpoint; the proxy-chain and dual-read legs prove no desync introduces a second interpretation |
| Issuance budgets hold | The per-IP fixed-window limiter with the atomic INCR plus EXPIRE script and the epoch union (`deploy/app/router.php:493-545`, fail-closed on limiter loss) | D3.1 cap leg: budget 30, burst 40, exactly 30 issued and 10 refused with 429 |

## 8. The red-team program itself

| change.md claim | Where it is enforced | Keeping check |
| --- | --- | --- |
| 9.1 Production-equivalent targets only | `tools/redteam/target.sh`: the reference deployment router verbatim, the sentinel trio, the sqlite and filesystem adapter paths, the Rust sidecar | `tools/redteam/target.sh matrix` runs any campaign across the storage backend matrix |
| 9.1 Every finding becomes a permanent failing-first regression test | `tools/redteam/engine/triage.mjs` (two-run deterministic reproduction, hash-pinned) writing `tools/redteam/findings/` | `tools/redteam/engine/regression.mjs` replays the corpus; exit-criteria carries the corpus row |
| 10.3 Hard allowlist: the engine refuses any non-private target | `tools/redteam/engine/orchestrator.sh` `is_private` gate (exit 4 on refusal), and the model adapter resolves and refuses non-private hosts (`engine/model-adapter.mjs`) | The gate is code, not policy: no flag overrides it |
| 10.3 Prompts and seeds pinned and committed | `tools/redteam/engine/prompts/*.md`, the run seed in every ledger entry, temperature 0 in the adapter contract | The runs ledger under `tools/redteam/engine/runs/` is the auditable record; THREATS.md names the seed |

## 9. Open gaps this ledger records honestly

| change.md claim | Status |
| --- | --- |
| 3.x RSW as a first-class rung whenever a trapdoor is configured | Implemented in both cores and the solver (`PoWAlgorithm::Rsw`, rsw bounds in `protocol/limits.json`), exercised by the matrix only when the deployment configures the trapdoor pair (`deploy/app/bootstrap.php` refuses the half-set pair); the red-team profiles run the sha rung for runtime budget, so the RSW deployment leg is exercised by the cores' own rsw suites rather than the live matrix today |
| 9.5 model checking (TLA+), 24 h coverage-guided fuzzing, Toxiproxy chaos | The locally checkable rows run in `tools/redteam/exit-criteria.sh`: bounded mutation fuzz, the D4.1 coverage-guided fuzz row (RED with the blocker when cargo-fuzz targets are absent — never folded into the mutation row), TLC over the consume/commit spec, parity, the 17 campaign slots, privacy, lint, budget, contract, regression. The long-duration envelopes (24 h coverage-guided budget, k6 at 5x peak, continuous Toxiproxy chaos) are CI/infrastructure jobs this repo does not carry yet; the gate rows state the bounded substitute and its scale, and a missing target or toolchain is TOOLCHAIN-ABSENT or RED, never a silent pass |
