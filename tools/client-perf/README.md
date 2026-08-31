# KiwiCaptcha client-performance lab (`tools/client-perf`)

A Playwright-based client benchmark that drives the browser fixture
(`tests/browser/router.php`) and measures the widget's real browser
costs per difficulty tier: SHA-256 at 16/18/20 leading zero bits and
Argon2id. This is the calibration lab referenced by the
`RiskProfileResolver` calibration note: the highest Argon rung and the
SHA ladder must be measured on the cheap-device tiers, never assumed
from desktop estimates.

## What is measured (per page load, per tier, per difficulty)

| Metric | Source |
|---|---|
| `solveMs` | challenge fetch start (`connecting` state) to `kiwi:verified`, p50/p95/p99 |
| `pureSolveMs` | `solving` state to `kiwi:verified` (the proof computation only) |
| `pageToVerifiedMs` | navigation start (`performance.timeOrigin`) to `kiwi:verified` |
| `bootstrapToConnectingMs` | navigation start to the challenge fetch (page + inline-script parse/compile/eval + driver init) |
| `jsParseCompileMs` | Long Animation Frames `scripts[]` entries (parse + compile + eval per script; populated on tiers where a frame exceeds 50 ms) |
| `inlineScriptEvalMs` | isolated same-origin iframe evaluation of the exact inline wasm-glue and driver sources (parse + compile + eval, always populated) |
| `wasmCompileMs` / `wasmInstantiateMs` | `WebAssembly.compile` / `instantiate` wrappers on the main thread (note: `instantiate(bytes)` includes the compile; for Argon2id the compile happens inside the worker and is covered by `workerStartupMs`) |
| `workerStartupMs` | Argon2id: `Worker` constructor to the driver's ready handshake (first worker message), i.e. worker script + wasm compile + handshake |
| `longTaskCount` / `longTaskTotalMs` | Long Task API: main-thread blocks > 50 ms. The widget deliberately bounds SHA main-thread chunks to ~10 ms wall time, so this stays near zero even on throttled tiers — a measured property, not an absence of data |
| `peakHeapMb` / `finalHeapMb` | `performance.memory.usedJSHeapSize` sampled every 50 ms plus the final sample |
| `domContentLoadedMs` / `loadMs` | Navigation Timing |

Every repetition is aggregated with p50/p95/p99/min/max/mean in the
machine-readable results.

## Device tiers

Emulation = Playwright device descriptor + CDP CPU throttling
(`Emulation.setCPUThrottlingRate`). All seven tiers run in Chromium
today (the emulation tiers are runnable now; the physical-device tiers
below are the release boundary).

| Tier key | Class | Emulation | CPU throttle |
|---|---|---|---|
| `low-android` | cheap/mid-range Android | Pixel 4a-class viewport (393x851, dpr 2.75, mobile UA) | 6x |
| `mid-android` | mid Android | Pixel 7-class (412x839, dpr 2.625) | 4x |
| `flagship-android` | flagship Android | Pixel 8 Pro-class (448x921, dpr 3) | 2x |
| `older-iphone` | older iPhone | iPhone 11-class (414x896, dpr 2) | 4x |
| `current-iphone` | current iPhone | iPhone 15-class (393x852, dpr 3) | 2x |
| `low-desktop` | low-end desktop | 1280x720 | 4x |
| `mainstream-desktop` | mainstream desktop | 1920x1080 | none |

Cold vs warm cache: a cold load runs in a fresh browser context with
the HTTP cache disabled (`Network.setCacheDisabled`); a warm load
reuses one context whose cache is enabled and already populated by the
previous repetition. The fixture page inlines all its assets, so for
this fixture the cache state mostly reflects connection/context reuse;
the mechanism stays in place for pages with external assets.

## Running

```sh
# Default: all seven tiers, sha16+sha18+sha20+argon2id, cold and warm,
# plus the 3-widget page scenario.
node tools/client-perf/client-perf.mjs

# Representative subset (the CI/quick shape):
node tools/client-perf/client-perf.mjs --quick

# Specific tiers/difficulties, more repetitions, attach to a fixture
# that is already running (e.g. the playwright lane on 8085):
node tools/client-perf/client-perf.mjs \
  --tiers low-android,mainstream-desktop \
  --difficulties sha16,sha18,sha20,argon2id \
  --reps 10 --argon-reps 5 \
  --no-fixture --fixture-port 8085

# The risk-ladder highest Argon rung (the RiskProfileResolver
# calibration target: target 8 at the fixed 16 MiB envelope):
node tools/client-perf/client-perf.mjs \
  --argon-bits 8 --argon-m-kib 16384 --argon-reps 3
```

The harness boots its own fixture on port 8091 by default (php `-S`
with `opcache.jit=off`, the same command the Playwright lanes use) and
tears it down on exit. Requirements: the fixture's Playwright install
(`tests/browser/node_modules`, used via `createRequire` — no second
install), PHP, and a Chromium build from `npx playwright install
chromium` if the fixture's bundled engine is absent.

Fixture knobs used by the harness (opt-in, defaults byte-identical to
the historical fixture): `?bits=`, `?argon_bits=`, `?m_kib=` on the
challenge endpoint (SHA target bits / Argon2id target bits / Argon2id
memory envelope) and `?widgets=N` on the widget page (multiple-widget
scenario). The default browser lanes are unaffected.

## Results store

- `results/results-<date>.json` — every run (machine-readable,
  schema `kiwicaptcha.client-perf/1`, environment + tiers + options +
  per-cell aggregates and per-repetition samples).
- `results/baseline.json` — the committed baseline (a results file
  from a recorded run, kept under version control so regressions have
  a point of comparison).

Compare a run against the baseline by diffing the aggregated cells
(`solveMs.p95`, `workerStartupMs.p95`, `pageToVerifiedMs.p95`, ...).
The harness itself never gates anything.

## Release qualification (the release boundary)

Emulation tiers are calibration/regression signals, not release
evidence: CDP CPU throttling is a coarse model of cheap hardware, and
Playwright device emulation does not reproduce real thermals, battery
savers, or the real browser's JIT/wasm behavior on those devices. The
**physical-device tiers are the release boundary**. Before a release
that changes the solver, the widget, or the difficulty ladder:

1. Run the emulation lab on this repo (`node
   tools/client-perf/client-perf.mjs`, plus the risk-rung Argon
   envelope: `--argon-bits 8 --argon-m-kib 16384`) and record the
   results file next to the baseline.
2. Repeat the same tier/difficulty matrix on physical devices:
   cheap and mid-range Android (battery-saver and thermal-throttled
   states included), flagship Android, older and current iPhone, a
   low-end desktop and a mainstream desktop, using the real browsers.
   The device UA/viewport/dpr columns of the emulation tiers define
   the physical-device matrix.
3. The release boundary is met when the physical-device p95 solve
   times stay within the documented budget for every tier the
   deployment targets, and no tier shows a failure rate above the
   widget's documented exhaustion bounds. If the highest Argon rung is
   too expensive for legitimate mobile users, adjust the server-selected
   ladder globally or transition earlier to StepUp — never weaken the
   rung based on client-reported device capabilities (bots lie).
4. Record the physical-device rows in the results file (or an
   attached run notes section) with the device/browser/OS and date;
   the emulation numbers alone do not constitute a release
   qualification.

CI posture (stated): the harness is **not wired into the protected CI
lanes** — a client benchmark under CDP throttling is too noisy and too
slow for a merge gate, and adding a job to the protected lanes would
add noise without a hard threshold to enforce. It is a **manual
release step** (this procedure), runnable on demand by a maintainer or
as a non-gating, manually dispatched CI job if the repository later
wants one. It never gates anything by itself.

## Notes and caveats

- The fixture page inlines the wasm glue and the driver, so the
  cold/warm cache difference is small for this fixture (see above);
  the multi-widget and Argon worker paths still exercise real
  cross-request machinery.
- `jsParseCompileMs` (Long Animation Frames) populates only where a
  frame exceeds 50 ms (typically the throttled tiers); the
  iframe-based `inlineScriptEvalMs` is the always-populated parse +
  compile + eval measurement of the exact served script text.
- The Argon2id tier defaults to the fixture envelope (64 KiB, t=3,
  p=1, target 4 bits) so the lab runs quickly on every machine; the
  risk-ladder envelope (16 MiB, target 8) is the release-qualification
  configuration (`--argon-bits 8 --argon-m-kib 16384`).
- Main-thread long tasks stay near zero by design (the SHA solver
  bounds each main-thread chunk to ~10 ms wall time; Argon2id always
  runs in a worker) — a measured property of the widget, verified per
  tier by the `longTask*` metrics.
