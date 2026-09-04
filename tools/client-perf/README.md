# KiwiCaptcha client-performance lab (`tools/client-perf`)

A Playwright-based client benchmark that drives the browser fixture
(`tests/browser/router.php`) and measures the widget's real browser
costs per difficulty tier: SHA-256 at 16/18/20 leading zero bits,
Argon2id at the real adaptive-risk ladder (m=16384 KiB, target 8), and
the six ExecutionChallengeV1 cells (execvm, execsha18, execargon,
execchain, execvminline, execsha18inline — see the execution-cells
section), across the asset tiers (inline and files). This is the
calibration lab
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
| `execargon` | files | the execution dimension on the real-ladder Argon2id rung (m=16384 KiB, target 8) |
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

## Sample sizes and percentiles

n=5 (SHA) / n=3 (Argon) cannot support a p95/p99 claim. The harness
defaults to 50 SHA-256 repetitions and 20 Argon2id repetitions per
configuration, and the documented ranges are 50-100 for SHA and 20-30
for Argon. The execution cells inherit the count of their PoW profile
(SHA-profile cells 50, Argon-profile cells 20). `--samples N` raises
both at once for a specific measurement, and `--quick` lowers them for
iteration. The results keep every repetition and the aggregated
percentiles, so a percentile's sample is visible in the same file.

A percentile is only as good as its sample: with 50 samples the p95 is
the 48th of 50 ordered points and the p99 is the maximum, so treat the
p99 of a 50-sample cell as an upper envelope, not a sharp estimate.
Raising to 100 narrows that. The physical procedure below matters more
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
seven tiers, all ten difficulties — the four ordinary cells plus the
six execution cells — cold and warm across each cell's asset tiers:
the files execution cells files-only and the inline execution cells
inline-only by design). It also refuses runs recorded
below the default sample sizes (50 SHA and 20 Argon repetitions) or
with a non-real argon ladder (m=16384 KiB, target 8). Only a clean
full run can replace `results/baseline.json`, so the committed
baseline is never overwritten by an interrupted or partial run.

## Running

```sh
# Default: all seven tiers, sha16+sha18+sha20+argon2id plus the six
# execution cells (execvm, execsha18, execargon, execchain — files —
# and execvminline, execsha18inline — inline) at the real
# ladder (16 MiB, target 8), cold and warm, inline and files, plus the
# 3-widget page scenario. SHA
# cells run 50 reps, Argon cells 20. A committed full run takes many
# hours on the recording Mac.
node tools/client-perf/client-perf.mjs

# Iteration mode (two tiers, 3 SHA / 2 Argon reps, both asset modes):
node tools/client-perf/client-perf.mjs --quick

# Specific tiers/difficulties, more repetitions, attach to a fixture
# that is already running (e.g. the playwright lane on 8085):
node tools/client-perf/client-perf.mjs \
  --tiers low-android,mainstream-desktop \
  --difficulties sha16,sha18,sha20,argon2id \
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
the historical fixture): `?bits=`, `?argon_bits=`, `?m_kib=` and
`?execution=1` (the execution arm) plus `?escalate=argon` (the chained
escalation arm) on the challenge endpoint, and `?assets=files` plus
`?widgets=N` on the widget page. The fixture clamps argon bits to
1..10 and the memory envelope to 8..65536 KiB, so the real ladder (8
bits, 16384 KiB) is permitted. The execution cells pass the real
ladder knobs to the escalated challenge exactly like the argon cell.

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
   widget's documented exhaustion bounds. If the highest Argon rung is
   too expensive for legitimate mobile users, adjust the server-selected
   ladder globally or transition earlier to StepUp, never weaken the
   rung based on client-reported device capabilities (bots lie).
6. Record the physical-device rows in the results file (or an attached
   run notes section) with the device/browser/OS and date. The
   emulation numbers alone do not constitute a release qualification.

## Results store

- `results/results-<date>.json` is a completed run (machine-readable,
  schema `kiwicaptcha.client-perf/3`, environment + methodology +
  completion marker + tiers + options + per-cell aggregates and
  per-repetition samples). The payload records the served client
  assets (driver, glue, worker, execution interpreter) with their
  sizes and sha256 prefixes, so a run is attributable to the exact
  bytes measured.
- `results/results-<date>-partial-<time>.json` is a crashed or
  interrupted run, written without the completion marker. It is
  evidence only and can never be promoted to baseline.
- `results/baseline.json` is the committed baseline, replaced only
  through `--promote-baseline` from a completed full-matrix run. The
  current file is the legacy-labelled pre-matrix recording (see the
  honest-status section below).

Compare a run against the baseline by diffing the aggregated cells
(`solveMs.p95`, `transferredBytes.p50`, `pageToVerifiedMs.p95`, ...).
The harness itself never gates anything.

## Honest status of the committed baseline

The committed `results/baseline.json` is still the legacy pre-matrix
recording (schema 1, labelled legacy in the file itself). No clean
controlled full-matrix run has completed on this machine: the real
ladder costs tens of seconds per Argon solve even unthrottled, the
throttled tiers cost more, a full run is a multi-hour job that has
crashed before finishing, and the default matrix now also carries the
four files-tier execution cells. The baseline stays legacy-labelled
until a clean full run completes and is promoted with the loader above
(the loader requires the execution cells, so a run recorded against an
earlier matrix can never be promoted). The physical-device procedure
remains the release boundary: emulation numbers, with or without a
fresh full run, are calibration signals, never mobile claims.

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
