# KiwiCaptcha client-performance lab (`tools/client-perf`)

A Playwright-based client benchmark that drives the browser fixture
(`tests/browser/router.php`) and measures the widget's real browser
costs per difficulty tier: SHA-256 at 16/18/20 leading zero bits and
Argon2id at the real adaptive-risk ladder (m=16384 KiB, target 8), in
both asset modes (inline and files). This is the calibration lab
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
| `longTaskCount` / `longTaskTotalMs` | Long Task API: main-thread blocks > 50 ms |
| `peakHeapMb` / `finalHeapMb` | `performance.memory.usedJSHeapSize` sampled every 50 ms plus the final sample |
| `domContentLoadedMs` / `loadMs` | Navigation Timing |
| `repeatNavigation` | warm cells only: one more navigation after the reps, everything cached, page-to-verified plus bytes and cache hits |

Every repetition is aggregated with p50/p95/p99/min/max/mean in the
machine-readable results.

## The matrix: inline/files x cold/warm

The fixture serves two asset shapes. Inline mode embeds the wasm glue
and the driver in the page HTML. Files mode (`?assets=files`) emits the
stylesheet and the driver as versioned SRI-linked external assets with
an immutable cache lifetime, keeps the Argon runtime lazy (fetched only
when a memory-hard challenge arrives), and dedups each asset once per
page. The harness runs both shapes against both cache states:

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
for Argon. `--samples N` raises both at once for a specific
measurement, and `--quick` lowers them for iteration. The results keep
every repetition and the aggregated percentiles, so a percentile's
sample is visible in the same file.

A percentile is only as good as its sample: with 50 samples the p95 is
the 48th of 50 ordered points and the p99 is the maximum, so treat the
p99 of a 50-sample cell as an upper envelope, not a sharp estimate.
Raising to 100 narrows that. The physical procedure below matters more
than any sample-size tweak: emulation noise is bounded, real-device
noise is not.

## Running

```sh
# Default: all seven tiers, sha16+sha18+sha20+argon2id at the real
# ladder (16 MiB, target 8), cold and warm, inline and files, plus the
# 3-widget page scenario. SHA cells run 50 reps, Argon cells 20. The
# committed run took about 3 hours on the recording Mac.
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
```

The harness boots its own fixture on port 8091 by default (php `-S`
with `opcache.jit=off`, the same command the Playwright lanes use) and
tears it down on exit. Requirements: the fixture's Playwright install
(`tests/browser/node_modules`, used via `createRequire`), PHP, and a
Chromium build from `npx playwright install chromium` if the fixture's
bundled engine is absent.

Fixture knobs used by the harness (opt-in, defaults byte-identical to
the historical fixture): `?bits=`, `?argon_bits=`, `?m_kib=` on the
challenge endpoint and `?assets=files` plus `?widgets=N` on the widget
page. The fixture clamps argon bits to 1..10 and the memory envelope
to 8..65536 KiB, so the real ladder (8 bits, 16384 KiB) is permitted.

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
3. Run longer sequential blocks, not a burst: the first Argon solve on
   a cold device is less interesting than the tenth, because the first
   is dominated by wasm compile and cold caches. The tenth reflects
   the steady state a real user hits on a warmed phone. Thermal
   saturation is a state to measure in, not a reason to stop: report
   both the early and the saturated windows.
4. The release boundary is met when the physical-device p95 solve
   times stay within the documented budget for every tier the
   deployment targets, and no tier shows a failure rate above the
   widget's documented exhaustion bounds. If the highest Argon rung is
   too expensive for legitimate mobile users, adjust the server-selected
   ladder globally or transition earlier to StepUp, never weaken the
   rung based on client-reported device capabilities (bots lie).
5. Record the physical-device rows in the results file (or an attached
   run notes section) with the device/browser/OS and date. The
   emulation numbers alone do not constitute a release qualification.

## Results store

- `results/results-<date>.json` — every run (machine-readable, schema
  `kiwicaptcha.client-perf/2`, environment + methodology + tiers +
  options + per-cell aggregates and per-repetition samples). The
  payload records the served client assets (driver, glue, worker) with
  their sizes and sha256 prefixes, so a run is attributable to the
  exact bytes measured.
- `results/baseline.json` — the committed baseline (a results file
  from a recorded run, kept under version control so regressions have
  a point of comparison).

Compare a run against the baseline by diffing the aggregated cells
(`solveMs.p95`, `transferredBytes.p50`, `pageToVerifiedMs.p95`, ...).
The harness itself never gates anything.

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
