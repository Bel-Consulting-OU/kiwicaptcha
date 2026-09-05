# KiwiCaptcha client-performance lab (`tools/client-perf`)

A Playwright-based client benchmark that drives the browser fixture
(`tests/browser/router.php`) and measures the widget's real browser
costs per difficulty tier: SHA-256 at 16/18/20 leading zero bits,
Argon2id at the real adaptive-risk ladder (m=16384 KiB, target 4, the
round-5 retuned highest rung), the
three rsw sequential time-lock rungs (T=75,000 / 150,000 / 300,000
squarings: the default rung, the midpoint and the protocol ceiling of
the 10,000..=300,000 range), and the six ExecutionChallengeV1 cells
(execvm, execsha18, execargon, execchain, execvminline, execsha18inline —
see the execution-cells section), across the asset tiers (inline and
files). This is the calibration lab
referenced by the `RiskProfileResolver` calibration note: the highest
Argon rung and the SHA ladder must be measured on the throttled tiers,
never assumed from desktop estimates.

The tiers are desktop CPU-throttled emulation: a Playwright device
descriptor plus CDP `Emulation.setCPUThrottlingRate` on the machine
that runs the harness. CDP throttling is a coarse model of cheap
hardware, and the emulation does NOT reproduce real device thermals,
battery savers, or the real device browser's JIT/wasm behavior. These
results are desktop-emulation evidence only. They make no low-end
mobile claim. The physical-device procedure in the release section is
the only evidence that can support a mobile claim.

Host-state controls keep host drift out of the comparison. Every
configured cell (tier x difficulty x cache x assets) executes in a
seeded random order, so no cell class runs first or last by design.
Every tier runs in a fresh Chromium process, so long-running browser
degradation cannot bleed across tiers. Every repetition records
fixed-work throughput (hashes/sec, Argon derivations/sec) as a
per-cell drift probe. The results file carries a completion marker
only on a clean full run, and baseline promotion refuses anything
else. Each control is described in detail below.

## What is measured (per page load, per tier, per difficulty, per asset mode)

| Metric | Source |
|---|---|
| `solveMs` | challenge fetch start (`connecting` state) to `kiwi:verified`, p50/p95/p99 |
| `pureSolveMs` | `solving` state to `kiwi:verified` (the proof computation only) |
| `pageToVerifiedMs` | navigation start (`performance.timeOrigin`) to `kiwi:verified` |
| `bootstrapToConnectingMs` | navigation start to the challenge fetch (page + script parse/compile/eval + driver init) |
| `jsParseCompileMs` | Long Animation Frames `scripts[]` entries (parse + compile + eval per script; populated on tiers where a frame exceeds 50 ms) |
| `inlineScriptEvalMs` | isolated same-origin iframe evaluation of the exact served script text (inline DOM scripts, or the files-mode driver fetched by URL; parse + compile + eval, always populated when scripts exist) |
| `wasmCompileMs` / `wasmInstantiateMs` | `WebAssembly.compile` / `instantiate` wrappers on the main thread (for Argon2id the compile happens inside the worker and is covered by `workerStartupMs`) |
| `workerStartupMs` | Argon2id: `Worker` constructor to the driver's ready handshake (first worker message), i.e. worker script + wasm compile + handshake |
| `transferredBytes` | Resource Timing `transferSize` summed over the document and every resource (network bytes, not encoded body size) |
| `cacheHitCount` | resources served from the HTTP cache (`transferSize` 0) |
| `resourceCount` | resource entries observed for the load |
| `runtimeLazyFetchStartMs` | files-mode Argon2id: when the lazy wasm runtime fetch starts relative to navigation (the fetch happens only when a memory-hard challenge arrives) |
| `driverFetchStartMs` | files mode: when the external driver asset starts loading relative to navigation |
| `executionFetchStartMs` / `executionFetchDurationMs` | execution cells: when the lazy `execution.<sha256>.js` interpreter fetch starts relative to navigation and how long it takes. The fetch happens inside the driver's sandboxed ephemeral iframe, which is removed after the run, so the top document's resource timing never sees it; the harness captures it from the network layer (request start anchored to `performance.timeOrigin`, duration from `requestfinished`) |
| `executionVersion` | execution cells: the grammar version the cell actually exercised. Every armed repetition decodes the `execution_program` blob of its `/challenge` response (layout format/scopeLen/scope/actionLen/action/opVersion) and records the version byte; a cell row records the single unanimous decoded version. The release-baseline validator requires it to equal `protocol/execution-v1.json` `max_execution_version` (see the execution-cells section) |
| `longTaskCount` / `longTaskTotalMs` | Long Task API: main-thread blocks > 50 ms |
| `peakHeapMb` / `finalHeapMb` | `performance.memory.usedJSHeapSize` sampled every 50 ms plus the final sample |
| `domContentLoadedMs` / `loadMs` | Navigation Timing |
| `shaHashesPerSec` / `shaFixedWorkMs` | fixed-work SHA-256 loop on the page main thread under the tier's throttle: 500 hashes of the real input shape (prefix + decimal counter + salt), using the wasm chunk export the inline solver uses or the pure-JS implementation for files-mode cells (see the fixed-work section) |
| `argonDerivationsPerSec` / `argonFixedWorkMs` | fixed-work Argon2id loop inside a harness-owned worker built from the exact served runtime bytes: 3 derivations at the real envelope (m=16384 KiB, t=3, p=1), the raw solver export (see the fixed-work section) |
| `repeatNavigation` | warm cells only: one more navigation after the reps, everything cached, page-to-verified plus bytes and cache hits |

Every repetition is aggregated with p50/p95/p99/min/max/mean in the
machine-readable results.

## The matrix: inline/files x cold/warm

The fixture serves two asset shapes. Inline mode embeds the wasm glue
and the driver in the page HTML. Files mode (`?assets=files`) emits the
stylesheet and the driver as versioned SRI-linked external assets with
an immutable cache lifetime, keeps the Argon runtime lazy (fetched only
when a memory-hard challenge arrives), and dedups each asset once per
page. The execution interpreter is delivered in both tiers (the bundle
theme emits its SRI-linked `data-kiwi-execution-src` on the container
inline and files alike; the interpreter is never embedded), so an armed
inline page performs the one lazy interpreter fetch exactly like an
armed files page. The harness runs both shapes against both cache
states:

| cell | what it measures |
|---|---|
| inline / cold | every byte re-fetched, fresh context per load (first-visit inline path) |
| inline / warm | nothing external to cache (the page carries the assets), so warm ≈ connection/context reuse |
| files / cold | first visit with external assets: driver + css over the wire, no runtime on SHA |
| files / warm | the returning-user path: driver + css served from the immutable cache, runtime still lazy, only the challenge POST is paid again |

The KEY benchmark cell is **files + warm + ordinary SHA** (16-20 bits):
the returning-user experience. It must be extremely cheap. The
committed baseline records it explicitly (assets cached, zero runtime
fetch, no worker, page-to-verified under a few hundred ms on the
throttled tiers). Warm cells pre-warm the context with one discarded
navigation, so every recorded warm rep is a cache-hit load, not the
populating one.

## The rsw time-lock cells

The fixture issues an rsw challenge only when asked
(`?algorithm=rsw&rsw_t=<T>`, the mirror of an operator-armed
deployment), and the driver dispatches it to the worker, which solves
T sequential modular squarings in pure JS BigInt and reports the final
value as the proof. The rsw cells ride the same asset tiers as
Argon2id: inline mode builds the Blob worker from the glue-carried
worker source, files mode fetches the versioned worker asset, so the
matrix records the full worker solve path for both bootstraps, cold
and warm, like every other cell. The cells inherit the SHA-256 rep
count (default 50). The rungs are named `rsw75k`, `rsw150k` and
`rsw300k` after their T value. A T below 10,000 or above 300,000 is
rejected by the worker itself before any work starts
(`unsupported_rsw_params`), so the measured rungs are the protocol
ladder a deployment can actually issue.

## The ExecutionChallengeV1 cells

The fixture arms the execution dimension with `?execution=1` (the
mirror of the bundle's `risk.execution_challenge` gate): the challenge
response then carries an execution program the driver runs in a
sandboxed ephemeral iframe (the lazy `execution.<sha256>.js`
interpreter asset) and the execution digest rides the solution token.
The interpreter asset is delivered in both asset tiers: the fixture
emits its SRI-linked `data-kiwi-execution-src` on every container,
mirroring the bundle theme, so an armed
inline page performs the same single lazy interpreter fetch as an
armed files page — real inline-execution behavior, not a files-only
construct.

| difficulty key | asset tier | what it measures |
|---|---|---|
| `execvm` | files | the execution VM on an ordinary fixture-default SHA challenge (no PoW change): interpreter fetch + iframe creation + VM run + digest, isolated from difficulty cost |
| `execsha18` | files | the execution dimension on the ordinary 18-bit SHA rung |
| `execargon` | files | the execution dimension on the real-ladder Argon2id rung (m=16384 KiB, target 4) |
| `execchain` | files | the execution dimension on the chained-escalation path: the driver requests SHA-256 and the server issues the memory-hard rung at the real ladder (the lazy runtime fetch and worker startup are paid too) |
| `execvminline` | inline | the VM-only profile with an inline bootstrap (glue and driver inlined, no PoW change): the one lazy interpreter fetch + VM run against the inline page |
| `execsha18inline` | inline | the 18-bit SHA rung with an inline bootstrap |

The execution cells inherit the rep count of their PoW profile:
`execvm`, `execsha18`, `execvminline` and `execsha18inline` use the SHA
count (default 50, `--reps`), `execargon` and `execchain` the Argon
count (default 20, `--argon-reps`). The Argon-profile execution cells
stay files-tier by matrix scope; the inline-execution evidence this
matrix carries is the SHA-profile pair. Every cell records the
ordinary solve/parse/wasm/
worker/fixed-work metrics plus the interpreter fetch start and
duration, so the execution marginal cost is separable from the
difficulty cost in the same file.

### The execution cells measure the live grammar (audit finding 1)

Every armed query of the execution cells carries
`?exec_cap=<EXECUTION_MAX_VERSION>`, the `max_execution_version` of
`protocol/execution-v1.json` read once at harness start. The fixture's
simulated deployment cap otherwise defaults to its historical v3 era,
so an armed page whose driver advertises version 5 is issued a
version-3 program: without the knob the cells would benchmark the
old grammar while the product ships the manifest maximum. The version
the fixture actually issues is not assumed — every execution
repetition intercepts its `/challenge` response, decodes the issued
`execution_program` blob's grammar version byte, and records it as
`executionVersion` on the rep and on the cell row (the row records the
single unanimous decoded version; a row without a unanimous decode
carries no field). The payload methodology records the manifest
authority (`execution.maxVersion` + `execution.manifestSchema`), and
the release-baseline validator requires every execution result row to
carry the manifest maximum — evidence recorded against an older
grammar is a hard rejection. The 2026-09-05 live-grammar re-record
(`results-2026-09-05-exec-v5.json`, every rep decoding version 5)
replaced the earlier execution rows, which had been measured against
the fixture's v3 default.

## Device tiers

All seven tiers run in Chromium today. They are emulation tiers, not
device evidence (see the note above the table of what is measured).

| Tier key | Class | Emulation | CPU throttle |
|---|---|---|---|
| `low-android` | cheap/mid-range Android | Pixel 4a-class viewport (393x851, dpr 2.75, mobile UA) | 6x |
| `mid-android` | mid Android | Pixel 7-class (412x839, dpr 2.625) | 4x |
| `flagship-android` | flagship Android | Pixel 8 Pro-class (448x921, dpr 3) | 2x |
| `older-iphone` | older iPhone | iPhone 11-class (414x896, dpr 2) | 4x |
| `current-iphone` | current iPhone | iPhone 15-class (393x852, dpr 3) | 2x |
| `low-desktop` | low-end desktop | 1280x720 | 4x |
| `mainstream-desktop` | mainstream desktop | 1920x1080 | none |

`mainstream-desktop` is the only tier with no CPU throttle: it
represents the actual recording machine, the lab rig itself. It is
therefore the tier the release gate budgets (see the release-gate
section): emulation tiers are calibration signals, the unthrottled lab
tier is the one piece of evidence that describes real hardware.

## Sample sizes and percentiles

n=5 (SHA) / n=3 (Argon) cannot support a p95/p99 claim. The harness
defaults to 50 SHA-256 repetitions and 20 Argon2id repetitions per
configuration, and the documented ranges are 50-100 for SHA and 20-30
for Argon. The execution cells inherit the count of their PoW profile
(SHA-profile cells 50, Argon-profile cells 20), and the rsw cells
inherit the SHA count like every deterministic-work cell. `--samples
N` raises
both at once for a specific measurement, and `--quick` lowers them for
iteration. The results keep every repetition and the aggregated
percentiles, so a percentile's sample is visible in the same file.

A percentile is only as good as its sample: with 50 samples the p95 is
the 48th of 50 ordered points and the p99 is the maximum, so treat the
p99 of a 50-sample cell as an upper envelope, not a sharp estimate.
Raising to 100 narrows that. The committed real-ladder lab rows were
recorded at 12 SHA / 6 Argon reps per mode on 2026-09-03 (24/12 merged
across the asset modes; the files-only execution cells carry 12/6)
and at 50 reps in the 2026-09-04 focused run (100 merged), which is
why the budget file's minShaReps/minArgonReps floors are 12/6: the
floors equal the lowest real-ladder evidence count, and a future full
run at the harness defaults exceeds them. Physical sha20 evidence has
its own floor — `minSha20SamplesPhysical` (100 merged samples per
cache cell, see the release-gate section): the sha20 exhaustion
allowance must never be forced by a single observation on a small
sample. The physical procedure below
matters more
than any sample-size tweak: emulation noise is bounded, real-device
noise is not.

## Methodology: cell order, process isolation, cooldowns

The matrix is executed as ONE seeded random pass over every configured
cell (tier x difficulty x cache x assets). No cell class runs
monotonically first or last, so host drift (thermal state, memory
pressure, scheduler behavior) is not systematically attached to any
cell class. A nominally faster tier can no longer be measured
consistently earlier or later than a slower one. The seed defaults to
the wall clock and is recorded in the results file; `--seed N` makes
any order reproducible. The harness prints the full execution order
before the first cell and records it in the payload's methodology
section.

Every tier runs in a fresh Chromium process, launched for the tier and
closed when the tier's cells are done. The multi-widget scenario gets
its own fresh process too. A long-lived browser process degrades
(memory growth, renderer state, scheduler affinity), and that
degradation must not bleed from one tier into the next. Cold cells use
a fresh context per load; warm cells use one context per cell, which
the warm-cache semantics require (the context is closed with the
cell).

Between serious calibration runs, give the host a cooldown: a few idle
minutes with no browser and no background load before the next matrix,
and run the matrix only on an otherwise idle machine. Thermal and
memory state are exactly the contamination this section exists to
dilute, and the fixed-work metrics below are the drift probe that
makes residual drift visible in the results file instead of hiding
inside latency percentiles.

## Fixed-work throughput metrics

Solve latency is stochastic (nonce-search luck) and host-state
sensitive. The harness therefore records, on every repetition of every
cell, two fixed-work throughput probes that separate solver
implementation speed from luck and from host state:

| probe | what it measures |
|---|---|
| `shaHashesPerSec` | a fixed-N SHA-256 loop (default 500 hashes, `--sha-fixed-work`) on the page main thread under the tier's CPU throttle. The input shape mirrors a real challenge: prefix bytes, the decimal counter, then the salt. The loop uses the wasm chunk export (`solve_sha256_chunk`, the primitive the inline solver uses) when the glue is present on the page, and the pure-JS implementation (byte-identical to the solver's fallback) for files-mode cells, because files-mode SHA solving is pure JS by design. The chosen path is recorded per repetition as `shaFixedWorkPath`. |
| `argonDerivationsPerSec` | a fixed-N Argon2id derivation loop (default 3, `--argon-fixed-work`) at the exact adaptive-risk envelope (m=16384 KiB, t=3, p=1), measured inside a harness-owned worker built from the exact served runtime bytes (the inline DOM script, or the versioned files-mode runtime asset). The worker runs no product code; it calls the raw solver export. Recorded per repetition as `argonDerivationsPerSec` with `argonFixedWorkPath`. |

Both probes run per repetition, per cell, and are aggregated per cell
like every other metric. Because the work is fixed, the probes double
as a host-state drift probe. A cell whose hashes/sec or
derivations/sec drift from their neighbors was measured under a
different host state, and the drift is visible in the results file
instead of hiding inside latency percentiles. The harness's own
measurement traffic is marked (`kcp_fixed_work`) and excluded from the
page's transferred-bytes, cache-hit and resource accounting, so the
probes never tax the widget's page cost.

## The incomplete-run guard and baseline promotion

The results file carries a completion marker only when the run
traversed every configured cell without an error or an interrupt
(`completion.status` is `"completed"` with the marker
`kiwicaptcha.client-perf.completed.v1`). A crashed or interrupted run
writes its partial results to
`results/results-<date>-partial-<time>.json` without the marker, and
the harness exits non-zero. The partial file is evidence, never a
baseline: its own payload says it is incomplete.

Baseline promotion is an explicit, guarded step:

```sh
node tools/client-perf/client-perf.mjs --promote-baseline FILE
```

The loader refuses, with the reasons, any results file that lacks the
completion marker or that does not cover the full default matrix (all
seven tiers, all thirteen difficulties — the four ordinary cells, the
three rsw time-lock rungs, and the six execution cells — cold and
warm across each cell's asset
tiers: the files execution cells files-only and the inline execution
cells inline-only by design). It also refuses runs recorded
below the default sample sizes (50 SHA and 20 Argon repetitions) or
with a non-real argon ladder (m=16384 KiB, target 4), and runs whose
recorded `clientAssets` do not match the current release asset bytes
(see the identity contract below: the promotion is a hard fail, never
a warning). Only a clean
full run can replace `results/baseline.json`, so the committed
baseline is never overwritten by an interrupted or partial run.

## The client-asset identity contract (audit finding 2, asset bind)

Performance rows are only meaningful bound to the exact client bytes
they were measured against: a number recorded against one driver
cannot certify a release that ships another. Every payload therefore
carries a `clientAssets` block, and one module computes it for every
consumer of the client-performance authority:
`tools/client-perf/client-assets.mjs`. The fingerprint policy lives
there and nowhere else:

- **Canonical asset set.** The canonical client asset set is the
  release asset manifest
  (`packages/kiwicaptcha-wasm/release-assets.txt`, the set the
  `tools/ci/release-asset-contract.sh` carrier checks guard across the
  release workflow): `widget-driver.js`, `widget-risk.js`,
  `widget-telemetry.js`, `widget-locales.js`, `widget-compat.js`,
  `execution-interpreter.js`, `kiwicaptcha-wasm.js`, `kiwi-worker.js`
  and `widget.css`. All nine are read from
  `packages/kiwicaptcha-wasm/assets/`, the repo paths the harness
  serves.
- **Full SHA-256.** Every asset is hashed with FULL SHA-256 — 64
  lowercase hex — recorded next to its exact byte count as
  `{ "<name>": { "bytes": N, "sha256": "<64 hex>" } }`. The historical
  16-hex prefixes bound only 64 bits (two different files of the same
  length collide 1 in 2^64) and were dropped; a truncated fingerprint
  is an invalid record today.
- **Recorded at run time.** `client-perf.mjs` fingerprints the
  working tree at measurement time into every results payload;
  `sync-lab-baseline.mjs` writes the same block into the maintenance
  baseline; `merge-cells.mjs` and the release validator compare
  against it.

The identity rules bind in CI mode and in release mode alike:

- **Validator** (`tools/ci/validate-release-baseline.mjs`): a
  schema-3 payload MUST carry `clientAssets`, and whenever a payload
  carries the block it must name exactly the current canonical set
  with per-asset bytes and full sha256 equal to the current tree.
  Each difference is a hard reason — `client asset set differs from
  current release asset set` (extra or missing asset) or `client
  asset <name> does not match current bytes` (byte count or sha256).
  A committed baseline therefore fails CI the moment any client asset
  changes, until the evidence is re-bound by a fresh run recorded
  against the new bytes.
- **Baseline promotion** (`--promote-baseline`): a run recorded
  against any other bytes is REFUSED with the same reasons. The old
  warning-only behavior is gone — a promotion is a re-bind, and
  re-binding requires measuring the bytes it certifies.
- **sync-lab-baseline.mjs**: refuses to rebuild the baseline from any
  `--run` file whose recorded `clientAssets` do not match the current
  canonical set (a stale run would launder old rows under a fresh
  identity), then records the canonical block.
- **merge-cells.mjs**: before any repetition is concatenated, every
  `--run` file must have been measured against the same measurement
  context: the canonical client asset set (each run equal to the
  current release bytes), the harness schema, the Argon parameters
  (`options.argonBits`/`argonMKib`), the execution maximum
  (`options.executionMaxVersion` when payloads carry it), the
  difficulty definitions and the asset mode. Any difference throws
  `cannot merge performance runs measured against different client
  assets` with the naming detail — merging repetitions recorded
  against different bytes, ladders or grammar versions would fabricate
  a percentile over incomparable measurements.

The committed maintenance baseline was re-bound on 2026-09-05: its
identity block was regenerated from the current release asset bytes
(full sha256) with the performance rows untouched. The pre-fix state
the audit cited — the target-4 recording (2026-09-05T03:07) carried
driver 92,053 / risk 47,649 / interpreter 33,402 with 16-hex
prefixes while the current tree ships driver 99,146 / risk 31,644 /
interpreter 35,728 — is why the truncated prefixes are invalid
records and why identity is now asserted, never warned.

## Running

```sh
# Default: all seven tiers, sha16+sha18+sha20+argon2id plus the rsw
# rungs (rsw75k, rsw150k, rsw300k) plus the six execution cells
# (execvm, execsha18, execargon, execchain — files —
# and execvminline, execsha18inline — inline) at the real
# ladder (16 MiB, target 4), cold and warm, inline and files, plus the
# 3-widget page scenario. SHA-profile
# cells run 50 reps, Argon cells 20. A committed full run takes many
# hours on the recording Mac.
node tools/client-perf/client-perf.mjs

# Iteration mode (two tiers, 3 SHA / 2 Argon reps, both asset modes):
node tools/client-perf/client-perf.mjs --quick

# Specific tiers/difficulties, more repetitions, attach to a fixture
# that is already running (e.g. the playwright lane on 8085):
node tools/client-perf/client-perf.mjs \
  --tiers low-android,mainstream-desktop \
  --difficulties sha16,sha18,sha20,argon2id,rsw75k,rsw150k,rsw300k \
  --reps 100 --argon-reps 30 \
  --no-fixture --fixture-port 8085

# Raise both sample sizes at once:
node tools/client-perf/client-perf.mjs --samples 100

# Fix the randomized cell order for a reproducible run:
node tools/client-perf/client-perf.mjs --seed 20260831

# Fixed-work probe sizes (defaults: 500 SHA hashes, 3 Argon derivations):
node tools/client-perf/client-perf.mjs --sha-fixed-work 1000 --argon-fixed-work 5

# Promote a completed full-matrix run to the committed baseline
# (refuses anything without the completion marker or with partial
# coverage):
node tools/client-perf/client-perf.mjs --promote-baseline results/results-2026-09-01.json
```

The harness boots its own fixture on port 8091 by default (php `-S`
with `opcache.jit=off`, the same command the Playwright lanes use) and
tears it down on exit. Requirements: the fixture's Playwright install
(`tests/browser/node_modules`, used via `createRequire`), PHP, and a
Chromium build from `npx playwright install chromium` if the fixture's
bundled engine is absent.

Fixture knobs used by the harness (opt-in, defaults byte-identical to
the historical fixture): `?bits=`, `?argon_bits=`, `?m_kib=`,
`?algorithm=rsw&rsw_t=` (the rsw arm, T clamped to 10,000..300,000 by
the fixture) and
`?execution=1&exec_cap=<manifest max>` (the execution arm, raised to
the live grammar maximum — audit finding 1) plus `?escalate=argon`
(the chained
escalation arm) on the challenge endpoint, and `?assets=files` plus
`?widgets=N` on the widget page. The fixture clamps argon bits to
1..10 and the memory envelope to 8..65536 KiB, so the real ladder (4
bits, 16384 KiB) is permitted. The execution cells pass the real
ladder knobs to the escalated challenge exactly like the argon cell,
and the rsw cells pass their T the same way.

## Physical-run procedure (the release boundary)

Emulation tiers are calibration signals. The physical-device tiers are
the release boundary. Before a release that changes the solver, the
widget, or the difficulty ladder, run the same matrix on real devices:

1. Use a cold device for the cold-cache cells: a device that has not
   loaded the page before, so no asset or connection state leaks in.
   The warmed device cells come second, after the page has loaded at
   least once.
2. Include the battery-saver state and the thermal-throttled state on
   the Android tiers. A mid-session CPU governor drop changes the
   percentiles more than any code change, and the harness cannot see
   it.
3. Let the host cool down between runs: a few idle minutes with the
   device idle and no background load. A warm device measures a
   different machine, and the fixed-work metrics in the results file
   are the trace that shows it.
4. Run longer sequential blocks, not a burst: the first Argon solve on
   a cold device is less interesting than the tenth, because the first
   is dominated by wasm compile and cold caches. The tenth reflects
   the steady state a real user hits on a warmed phone. Thermal
   saturation is a state to measure in, not a reason to stop: report
   both the early and the saturated windows.
5. The release boundary is met when the physical-device p95 solve
   times stay within the documented budget for every tier the
   deployment targets, and no tier shows a failure rate above the
   mode's `failureRateBudgets` limit (1% per cell by default; the 2%
   sha20 allowance is only for the measured driver-exhaustion tail,
   and the physical sha20 evidence must meet `minSha20SamplesPhysical`
   so a single observation never forces the allowance). If the highest
   Argon rung is too expensive for legitimate mobile users, adjust the
   server-selected
   ladder globally or transition earlier to StepUp, never weaken the
   rung based on client-reported device capabilities (bots lie).
6. Record the physical-device rows device-indexed in the results
   payload's top-level `physical_results` object
   (`{ "<device-id>": { "<tier>:<difficulty>:<cache>:<asset-mode>":
   <row> } }`) — the shape `merge-cells.mjs --physical-index` emits
   (see the physical-authority contract below) — with the device/
   browser/OS and date carried by the qualification entry's
   `tested_at`, and every row stamped `source: "physical"` and
   `device_id` from `qualification.devices`. The emulation numbers
   alone do not constitute a release qualification.

## The release gate and the performance-qualification status

The release gate is a separate authority from the harness: the harness
only records, `tools/client-perf/release-budgets.json` declares, and
`tools/ci/validate-release-baseline.mjs` enforces. The budget file
(schema `kiwicaptcha.release-budgets/2`) carries an explicit p95 budget
row (solveMsP95 and pageToVerifiedMsP95) for every released solver mode
x every qualified tier x cold/warm, the per-mode failure-rate limits,
the physical sha20 sample floor, and a top-level `qualification`
block:

```json
{
  "status": "lab",
  "qualified_at": null,
  "harness_schema": "kiwicaptcha.client-perf/3",
  "release_tiers": [ "mainstream-desktop" ],
  "devices": [ { "id": "...", "kind": "lab", "role": "...", "tier": "mainstream-desktop", ... } ]
}
```

`status` is one of `lab` or `physical`. `lab` means the budgets are
desktop-lab evidence recorded by the harness on the rigs listed in
`devices` (the current file names the recording Mac). `physical` means
the budgets come from the physical-device procedure below, with
`qualified_at` and the device rows recorded, and the validator proves
the claim (see the physical-authority contract section).

### `qualification.release_tiers` — the declared release ladder

`release_tiers` is the explicit, ordered list of tiers the release
gate certifies. The entries must be documented harness tier keys from
the device-tier table above — never invented names. The current file
names only `mainstream-desktop`, the one tier with real-harness
evidence; the five Android/iPhone emulation tiers and `low-desktop`
are calibration signals and are not on the ladder. The extension rule:
adding a tier to `release_tiers` requires (1) the tier's p95 budget
rows for every released mode x cold/warm in the same file, (2) at
least one `kind: "physical"` device qualified on that tier, and (3)
per-device physical evidence rows in the payload's `physical_results`
for every cell of every registered physical device of that tier. The
release-required scope is the union of the budget file's `tiers` and
`qualification.release_tiers` whenever the file claims physical
qualification (so ordinary CI proves the claim) or release mode is
on; a file can never declare a release ladder that lacks p95 budgets
or measured rows.

### Failure-rate limits and the sha20 carve-out

`maxCellFailureRate` is gone. `failureRateBudgets` replaces it with
per-mode limits:

```json
{
  "failureRateBudgets": { "default": 0.01, "sha20": 0.02 },
  "minSha20SamplesPhysical": 100
}
```

- Every mode except `sha20` (sha16, sha18, argon2id, every rsw rung,
  every execution cell) inherits `default` — 1% of a cell's samples
  may fail (time out or error), not ~5%.
- `sha20` alone keeps the 2% allowance, and only for the measured
  driver-exhaustion tail: the 20-bit pure-JS files-mode search can
  exhaust the 5M-hash cap, and the committed lab evidence for that
  cell contains one such event.
- The allowance is pre-justified, never per-sample. The lab's own
  sha20 warm files-mode evidence was 1 exhaustion event in 24 merged
  samples (4.2%) — above even the 2% carve-out. That is exactly why
  lab rows are never release evidence, and why physical sha20
  certification must meet `minSha20SamplesPhysical` (100 merged
  samples per cache cell = 50 per asset mode at the harness default,
  the natural evidence depth of a schema-3 full run): with the floor,
  a single exhaustion observation is at most 1% of the evidence, so a
  small-sample accident can never force the allowance upward. The
  floor is asserted in release mode only (certification); the failure
  budgets themselves bind whenever a file claims physical
  qualification.
- Failure-rate budgets bind the physical evidence of a
  physical-qualified file. They are not asserted against lab rows: lab
  rows are never certification evidence, and a lab-status file already
  fails release certification on the status reason alone.

### Physical device registration

A physical qualification lists its devices inside `qualification`,
one entry per rig, with the full physical identity:

```json
{
  "id": "pixel-9-mainstream-01",
  "kind": "physical",
  "tier": "mainstream-desktop",
  "hardware": "Google Pixel 9 (Tensor G4)",
  "os": "Android 15",
  "browser": "Chrome 129",
  "tested_at": "2026-09-04T12:00:00.000Z",
  "battery_state": "plugged-steady"
}
```

`kind` is `lab` or `physical`; ids are unique; every device names a
harness tier. A physical entry must additionally carry non-empty
`hardware`/`os`/`browser`/`battery_state` and a parseable `tested_at`.
The recommended `battery_state` vocabulary follows the physical-run
procedure (plugged-steady, battery-steady, battery-saver,
thermal-throttled); the validator requires the field to be present and
non-empty, it does not enumerate the vocabulary.

### The two validator modes

- CI mode (the default; wired into the required "Performance budgets"
  workflow check) runs against the committed
  `results/baseline.json` on every push. It fails unless every
  release-required cell has a measured p95 under budget: coverage gaps
  and uncovered cells are hard failures, there is no notes escape for
  any release-required cell, and the payload's recorded `clientAssets`
  match the current release asset bytes (the identity contract above —
  a baseline whose assets drifted from the tree is a rejection, never
  a note). It prints the current qualification
  status line (e.g. `performance qualification status=lab —
  physical-device data required before release certification`) and
  does not fail solely on the status. Once the committed file claims
  `status: "physical"`, every physical-authority proof below binds in
  CI mode too, and the release-required scope widens to the union of
  the budget `tiers` and `qualification.release_tiers` — a malformed
  committed claim cannot survive ordinary CI and wait for release
  mode to catch it.
- Release mode (`--release` or `RELEASE_PERFORMANCE=1`) is the
  release-certification gate. It refuses to certify unless
  `qualification.status` is `"physical"` (with a qualified_at date and
  recorded devices) and the physical-authority contract below holds; a
  current-harness (schema 3) payload must additionally satisfy the
  completed-run guards (completion marker, full default matrix,
  default sample sizes, real argon ladder), the client-asset
  identity rule binds exactly as in CI mode — release certification
  never skips the proof that the rows certify the bytes they claim to
  describe — and the per-device sha20 evidence must meet
  `minSha20SamplesPhysical`. Release mode widens the
  release-required cells to the union of the budget `tiers` and
  `qualification.release_tiers`. In the committed state (status
  `lab`), release mode fails with the qualification reason and no
  other, which is the honest state: no physical-device data exists
  yet, so no release can be performance-certified.

```sh
# CI mode (the every-push check):
node tools/ci/validate-release-baseline.mjs tools/client-perf/results/baseline.json

# Release mode (must fail today with the qualification-status reason):
node tools/ci/validate-release-baseline.mjs --release tools/client-perf/results/baseline.json
```

The outstanding requirement before any release can be
performance-certified is the physical-device qualification: run the
matrix on real devices (the procedure below), record the rows in a
clean completed run, promote it, and re-record the budget rows and the
qualification block (`status: "physical"`, `qualified_at`,
`release_tiers`, the physical device rows) from the physical
measurements. Until then the gate prints status `lab` in CI and
refuses certification in release mode.

## The physical-authority contract (what "physical" must prove)

Certification is only as strong as the file's claims, so when
`qualification.status` is `"physical"` the validator proves every part
of the claim — in release mode and in CI mode alike (a committed
physical claim must hold on every push, and a physical release tier
must carry its own p95 budget rows in the same budget file):

1. **Device registration.** At least one device entry is
   `kind: "physical"` with a non-empty `id` and `tier`; the generic
   "recorded devices" shape alone proves nothing about the kind of
   device.
2. **Tier coverage.** Every tier in `qualification.release_tiers` has
   at least one physical device qualified on it. A release tier with
   no physical qualification device is a hard reason.
3. **Evidence index.** Physical evidence lives in the baseline
   payload's top-level `physical_results` object, one row per device
   and per cell:

   ```json
   {
     "physical_results": {
       "pixel-9-mainstream-01": {
         "mainstream-desktop:sha18:cold:inline": { "source": "physical", "device_id": "pixel-9-mainstream-01", "reps": [ ... ] },
         "mainstream-desktop:sha18:cold:files":  { "source": "physical", "device_id": "pixel-9-mainstream-01", "reps": [ ... ] },
         "mainstream-desktop:sha18:warm:inline": { "source": "physical", "device_id": "pixel-9-mainstream-01", "reps": [ ... ] },
         "mainstream-desktop:sha18:warm:files":  { "source": "physical", "device_id": "pixel-9-mainstream-01", "reps": [ ... ] }
       },
       "pixel-9-mainstream-02": { "mainstream-desktop:sha18:cold:inline": { "source": "physical", "device_id": "pixel-9-mainstream-02", "reps": [ ... ] } }
     }
   }
   ```

   The index keys are the per-mode result-row keys
   (`tier:difficulty:cache:assetMode`) of the device's tier. A
   physical claim without `physical_results`, an index key that does
   not name a registered `kind: "physical"` device, a row whose
   `source` is not `"physical"`, a row whose `device_id` does not
   match its index key, or a row whose cell tier differs from the
   device's qualified tier are all hard reasons. `merge-cells.mjs
   --physical-index --source physical --device-id <id>` emits this
   shape from a device's schema-3 run without folding the asset
   modes; a merged (three-part) row folds the modes and can never
   satisfy the per-mode invariant.
4. **Per-device coverage (the RELEASE invariant).** Every registered
   physical device x every released difficulty x cold/warm x every
   required asset mode of the device's tier has its own evidence row.
   A device missing a required cell is a hard reason naming the
   device and the cell: registered devices without measurements are
   never invisible, so the "worst physical device" is the worst
   among ALL qualified devices, not the worst among devices that
   happened to contribute rows.
5. **Per-device evidence quality.** Each device's own samples meet
   the generic minShaReps/minArgonReps floor and the mode's
   `failureRateBudgets` rate (failure rate over its own samples,
   timedOut or errorCount; 1.0 when it has rows but zero samples),
   computed per device per cell, never aggregated across devices —
   one healthy device can never mask a failing one. Release mode
   only: each device's sha20 cells meet `minSha20SamplesPhysical`, so
   a single exhaustion observation on a thin per-device sample never
   forces the sha20 allowance.
6. **Budget derivation from the physical rows.** For every
   release-tier cell the p95 budget is checked against the WORST
   per-device physical p95 across the qualified devices of the tier
   (each device's own rows merged across the cell's asset modes,
   worst device taken), for solveMs and pageToVerifiedMs. Budget
   compliance therefore uses the max physical p95, never one
   recording: if the budget rows were copied from a lab run or from a
   single fast device while another qualified device is slower, the
   budget fails.
7. **Freshness and chronology.** Every physical device's `tested_at`
   is within `recordAgeDays` of now (a regenerated baseline can never
   launder old measurements), never postdates
   `qualification.qualified_at` or the payload's `generated_at`, and
   `qualified_at` never precedes the newest physical `tested_at`.

A `lab` file runs none of these proofs (there is no physical claim to
prove); its CI gate is the coverage and budget-compliance rules above,
and release mode rejects it on the status reason alone. The committed
file stays `lab` with no `physical_results` until physical-device
data is recorded.

## Absolute UX ceilings and the interactive/non-interactive split (audit findings 2 and 4)

`release-budgets.json` carries an `absoluteP95Ceilings` block per
qualified tier — the absolute wall-clock p95 a release may ask an
ordinary interactive user to wait:

```json
{
  "absoluteP95Ceilings": {
    "mainstream-desktop": { "solveMsP95": 5000, "pageToVerifiedMsP95": 5000 }
  }
}
```

The committed value is 5000 ms on the mainstream-desktop tier: five
seconds of p95 solve time is the product's UX ceiling, and it is the
reason the Argon2id default was retuned from 8 to 4 target bits (the
8-bit rung measured about 16 s p95 and could never meet it). The
validator rejects a cell when its measured p95 exceeds its budget row
OR when its budget row exceeds the tier's absolute ceiling — an
inflated budget can never buy the ceiling out, and release
certification refuses a tier without an `absoluteP95Ceilings` entry.

The interactive/non-interactive classification derives from the
HARNESS difficulty profiles in `client-perf.mjs`, never from the
budgets file (audit finding 4). `execchain` is the one difficulty
declared `interactive: false`; every other profile is interactive (a
profile without the flag defaults to interactive):

```js
execchain: { label: '...', dimension: 'execution', ..., interactive: false, ... }
```

execchain models the composed chained-escalation flow (a SHA request
escalated to the memory-hard rung by the server, with the execution
dimension armed), so its p95 is not the experience of an ordinary
interactive rung a user is sent to directly: it is budgeted and
measured like every cell, but it is never counted as an ordinary
interactive release cell and is not ceiling-checked (its budget rows
may legitimately exceed 5000 ms). Every other
difficulty (sha16/18/20, argon2id, the rsw rungs, execvm, execargon,
execvminline, execsha18inline) is interactive and ceiling-subject. The
early-rounds `nonInteractiveDifficulties` field of the budgets file is
gone — it was the audit's escape hatch (it lived in the very file
whose budgets it relaxed), so its presence is now an
unknown/deprecated field the validator rejects as a hard reason:
changing only the release budgets can never change a difficulty's
interactive classification. A cell that cannot meet the ceiling
honestly must be re-measured, retuned, or explicitly classified
non-interactive in the harness profile with the rationale recorded in
the profile comment — never silently left out of the gate.

## The validator's adversarial mutation suite

`tools/ci/test-validate-release-baseline.mjs` is the validator's own
mutation corpus: it generates temporary budget/baseline fixtures in
`os.tmpdir()` and runs the validator as a subprocess against them,
asserting on exit codes AND on the specific reason substrings of the
validator's own messages. The harness constants are read out of
`client-perf.mjs` and the committed `release-budgets.json` is cloned,
so the fixtures can never drift from the harness authority. Run it
standalone (no harness install needed):

```sh
node tools/ci/test-validate-release-baseline.mjs
```

The corpus covers the complete schema-3 matrix (pass), per-mode
matrix deletions (removing only `sha18:cold:files` or only
`:inline`, or replacing both four-part rows with one three-part row),
the legacy schema-1 path, and the physical-claim negatives: lab-only
devices, missing device id, invalid tier, unknown device_id, a row
whose device belongs to another tier, an unmeasured registered
device, a 100%-failure device next to a healthy one, a one-sample
sha20 device, a p95 over budget, stale `tested_at`, a release tier
without p95 budgets, `source: "lab"` rows, and a qualification date
predating the evidence. Round 5 added the absolute-ceiling cases
(budget under the ceiling with measurements under budget passes; a
measurement over its budget rejects; a budget over the 5000 ms
absolute ceiling rejects; a 20-second inflated budget with 5 ms
measurements still rejects on the ceiling; a tier without an
absoluteP95Ceilings entry rejects in release mode) and the evidence
time-validation cases (generated_at/qualified_at/tested_at a year in
the future reject; qualified_at postdating generated_at by a day
rejects; tested_at two minutes in the future passes within the skew
allowance and six minutes rejects; a space-separated timestamp and a
non-UTC offset timestamp reject as non-canonical RFC3339). Round 6
added the live-grammar evidence cases (audit finding 1: execution
rows at the manifest maximum pass; all execution rows at version 3
reject; one exec cell below the maximum rejects naming the cell;
execution rows without `executionVersion` reject for the current
schema; non-execution SHA/Argon rows need no field) and the
classification-authority cases (audit finding 4: a budgets file
reintroducing `nonInteractiveDifficulties` rejects as
unknown/deprecated; an execchain budget above the absolute ceiling is
allowed because the harness classifies it non-interactive; argon2id
and sha20 budgets above the ceiling reject; and a budgets-only
mutation cannot flip sha20 to non-interactive — it rejects on the
deprecated field AND the still-binding interactive ceiling). The job
is wired into CI as the self-contained "Release-validator mutation

added the client-asset identity cases (the asset bind): a schema-3
payload without a `clientAssets` block rejects, an extra recorded
asset rejects on the set difference, a recorded asset missing from
the current release set rejects, a byte-count mismatch and a sha256
mismatch each reject on the per-asset reason (in CI and in
`--release` mode alike), a schema-3 payload bound to the current set
passes, and a legacy payload with a tampered identity block rejects.
The job is
wired into CI as the self-contained "Release-validator mutation

suite" job.

## Results store

- `results/results-<date>.json` is a completed run (machine-readable,
  schema `kiwicaptcha.client-perf/3`, environment + methodology +
  completion marker + tiers + options + per-cell aggregates and
  per-repetition samples). The payload records the served client
  assets as the `clientAssets` identity block (full sha256 + byte
  counts over the canonical release asset set, see the identity
  contract), so a run is attributable to the exact bytes measured and
  the validator can prove that a payload certifies the bytes the tree
  ships. A physical-device recording (or the maintenance
  payload built from one) additionally carries the top-level
  `physical_results` per-device evidence index of the physical-
  authority contract.
- `results/results-<date>-partial-<time>.json` is a crashed or
  interrupted run, written without the completion marker. It is
  evidence only and can never be promoted to baseline.
- `results/baseline.json` is the committed baseline, replaced only
  through `--promote-baseline` from a completed full-matrix run. The
  current file is the maintenance file the release gate validates: it
  started as the legacy-labelled pre-matrix recording and was
  surgically extended on 2026-09-04/05 (see the honest-status
  section).

Compare a run against the baseline by diffing the aggregated cells
(`solveMs.p95`, `transferredBytes.p50`, `pageToVerifiedMs.p95`, ...).
The harness itself never gates anything; the validator above does.

## Honest status of the committed baseline

The committed `results/baseline.json` carries the legacy pre-matrix
recording (schema 1, labelled legacy in the file itself) for the
emulation tiers, byte-for-byte. The mainstream-desktop rows were
re-recorded at the real ladder and merged per cache across the inline
and files asset modes on 2026-09-03/04: sha16/18/20 and argon2id from
the completed run `results/run-2026-09-03.json` (12 SHA / 6 Argon
reps per mode), and the execution cells plus the rsw75k/150k/300k
rungs from the focused completed run
`tools/client-perf/results/results-2026-09-04.json` (50 reps). On
2026-09-05 the argon family (argon2id, execargon, execchain) was
re-recorded at the round-5 retuned rung (target 4, 12 Argon reps per
mode) from the completed run
`tools/client-perf/results/results-2026-09-05.json` after the 8-bit
rung measured about 16 s p95 — the numbers that drove the retune and
the absolute UX ceiling. Later on 2026-09-05 the six
ExecutionChallengeV1 cells were re-recorded at the LIVE execution
grammar from the completed run
`tools/client-perf/results/results-2026-09-05-exec-v5.json` (audit
finding 1): every armed query carried `?exec_cap=5` (the
protocol/execution-v1.json manifest maximum; the earlier execution
rows measured the fixture's historical v3 default), 20 SHA-profile /
12 Argon reps per mode, every rep decoding `executionVersion` 5 from
its `/challenge` response, and the merged rows record it too — the
`release-budgets.json` execution rows were regenerated from those
measurements. The merge procedure is documented inside the payload.
This is lab evidence on the recording Mac (Apple M5 Pro,
Chromium 151), desktop-emulation tiers excluded from the qualified
scope. The physical-device procedure remains the release boundary:
emulation numbers, with or without a fresh full run, are calibration
signals, never mobile claims, and the qualification status stays
`lab` until physical-device data is recorded.

On 2026-09-05 the file was re-bound to the client-asset identity
contract (round 6): it now carries the `clientAssets` block computed
from the current release asset bytes — full sha256 over the canonical
nine-asset set (driver 99,146 / risk 31,644 / interpreter 35,728
bytes at re-bind, where the earlier target-4 recording had measured
driver 92,053 / risk 47,649 / interpreter 33,402) — with the
performance rows untouched, and every push validates that the tree
still ships those exact bytes.

## Server-side latency baselines and hosted-Redis anomalies (finding-9 note)

This repo keeps a second, server-side performance authority in
`packages/kiwicaptcha/tools/perf-baselines.json` (enforced by
`packages/kiwicaptcha/tools/perf-budget.sh` and emitted by
`--baseline-out` from the perf-bench tools), separate from this
client-side lab. The finding-9 discipline for that authority, recorded
here because this directory owns the baseline-hygiene rules:

- **Hosted-Redis risk anomalies must NEVER re-record the baseline.**
  The `bench_risk.redis_concurrent` leaf of `perf-baselines.json` is a
  fixed-host measurement: it was recorded on the dedicated local
  machine that also records every other perf baseline. A run against a
  hosted Redis service is a different host, and its numbers describe
  that host's network and tenancy, not the code. Copying them over the
  committed leaf would silently move the baseline authority onto
  noise.
- **Route anomalies through the interleaved same-host base/head
  comparator first (the fixed-host workflow).** When a change touches
  the Redis-backed risk path, run the base build and the head build on
  the SAME fixed host in interleaved order and compare the pair; only
  that comparison can separate a code signal from a host signal. A
  single noisy observation is never a reason to touch a baseline.
- **The current committed numbers are a host signal comparison, not a
  code signal.** The committed lab leaf reads p95 1.364 ms /
  4202 req/s for the concurrent real-Redis risk path; an observed
  noisy hosted-Redis run at 5.837 ms / 1166 req/s is ~4x slower, which
  is exactly the scale of hosted-network and shared-tenant variance,
  not of an application regression. Treat the hosted number as a
  prompt to run the fixed-host comparator, never as a new baseline and
  never as a release blocker by itself.
- Accordingly, `results/baseline.json` values are never re-recorded
  from hosted or anomalous runs either; this file only changes through
  the guarded `--promote-baseline` merge path from completed
  fixed-host runs.

## Notes and caveats

- The fixture serves the files-mode assets with `Cache-Control:
  public, max-age=31536000, immutable`, so the warm files-mode cells
  genuinely hit the HTTP cache. The page document itself carries no
  cache header, so the returning user re-fetches the small HTML every
  time, exactly like a real theme page.
- `jsParseCompileMs` (Long Animation Frames) populates only where a
  frame exceeds 50 ms (typically the throttled tiers); the iframe-based
  `inlineScriptEvalMs` is the always-populated parse + compile + eval
  measurement of the exact served script text.
- Argon2id runs in a worker in both modes (inline Blob worker, files
  same-origin worker); there is no main-thread Argon fallback.
  `workerStartupMs` and `runtimeLazyFetchStartMs` together describe the
  files-mode lazy path: SHA pays no runtime fetch, Argon fetches it
  once when the memory-hard challenge arrives.
- Main-thread long tasks stay near zero by design (the SHA solver
  bounds each main-thread chunk to ~10 ms wall time; Argon2id always
  runs in a worker), a measured property of the widget, verified per
  tier by the `longTask*` metrics.
- CDP CPU throttling is noisy: the same cell can vary several-fold
  between reps, more on the throttled tiers. The large sample sizes
  and the documented run procedure exist because of that, and the
  percentile read-outs must be read as distributions, never as single
  points.
- The fixed-work SHA probe measures whichever primitive the asset
  mode's main-thread solver actually uses (wasm in inline mode, pure
  JS in files mode), so its hashes/sec reflects the solver
  implementation, and the path is recorded per repetition.
- The fixed-work Argon probe uses a harness-owned worker. A production
  page whose CSP forbids Blob workers cannot host the probe; the lab
  fixture page has no CSP, and the probe is a lab measurement, not
  part of the widget.
- The execution interpreter fetch happens inside the driver's
  sandboxed ephemeral iframe, so it never appears in the top
  document's `transferredBytes`/`cacheHitCount` accounting; the cell
  records it explicitly via `executionFetchStartMs`/`DurationMs`
  (network layer), and its wire size is budgeted separately in
  `packages/kiwicaptcha/tools/perf-baselines.json`
  (`budgets.widget_execution`, enforced by perf-budget.sh).
