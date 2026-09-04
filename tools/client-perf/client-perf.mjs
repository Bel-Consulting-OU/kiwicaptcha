#!/usr/bin/env node
/**
 * KiwiCaptcha client-performance harness (tools/client-perf).
 *
 * A Playwright-based client benchmark that drives the browser fixture
 * (tests/browser/router.php) and measures, per difficulty tier
 * (SHA-256 16/18/20 bits, Argon2id, and the four ExecutionChallengeV1
 * cells) and per asset mode (inline vs files, the ?assets=files
 * fixture variant):
 *
 *   - solve time (challenge fetch start -> kiwi:verified) and the pure
 *     proof computation (solving state -> verified): p50/p95/p99,
 *   - page-to-verified time (navigation start -> verified),
 *   - JS parse/compile/eval time: the Long Animation Frames script
 *     entries (performance entries; the fixture inlines the wasm glue
 *     and the driver in inline mode and links them with SRI in files
 *     mode), plus the isolated same-origin iframe evaluation of the
 *     exact served script text (inline or fetched driver) when the
 *     scripts are present,
 *   - WASM compile + instantiate time (WebAssembly wrappers, main
 *     thread),
 *   - worker startup latency for Argon2id (Worker constructor -> first
 *     message, i.e. the driver's ready handshake),
 *   - main-thread blocking (Long Task API): count, total, p95,
 *   - peak JS heap (performance.memory samples + final heap),
 *   - the inline/files x cold/warm matrix: transferred bytes (Resource
 *     Timing transferSize, document + assets), cache-hit loads (warm
 *     reps reusing one populated context), the lazy Argon runtime fetch
 *     (files mode: the wasm glue is fetched only when a memory-hard
 *     challenge arrives; the fetch start is recorded), and a repeat
 *     navigation measurement after the warm reps (everything cached).
 *
 * The ExecutionChallengeV1 cells (?execution=1 armed) are: execvm (the
 * execution VM on an ordinary fixture-default SHA challenge, no PoW
 * change), execsha18 (execution + SHA-256 18 bits), execargon
 * (execution + Argon2id at the real ladder), execchain (execution +
 * chained escalation: the driver requests SHA-256, the server
 * escalates to Argon2id), and execvminline + execsha18inline: the
 * VM-only and 18-bit SHA profiles on the inline tier. The product
 * delivers the interpreter asset in both asset tiers: the bundle's
 * data-kiwi-execution-src rides the container inline and files alike,
 * and the interpreter is never embedded, only lazily fetched. An armed
 * inline page therefore performs the same single lazy interpreter
 * fetch as a files-tier one, and the fixture mirrors that delivery.
 * The interpreter asset is lazy in both tiers, so every execution cell
 * records when its single fetch starts and how long it takes
 * (executionFetchStartMs/DurationMs), alongside the ordinary
 * solve/parse/wasm/worker/fixed-work metrics. execargon and execchain
 * stay files-only by matrix scope: the inline-execution evidence this
 * matrix carries is the SHA-profile pair.
 *
 * The KEY benchmark cell is files + warm + ordinary SHA (16-20 bits):
 * the returning-user path, which must be extremely cheap (all assets
 * cached, no runtime fetch, no worker).
 *
 * Device tiers come from Playwright device emulation plus CDP CPU
 * throttling (Emulation.setCPUThrottlingRate). The tiers are desktop
 * CPU-throttled approximations of the device classes they name: CDP
 * throttling is a coarse model of cheap hardware, and the emulation
 * does NOT reproduce real thermals, battery savers, or the real
 * device's JIT/wasm behavior. This lab records desktop-emulation
 * evidence only; it makes no low-end-mobile claim. The physical-device
 * tiers described in README.md are the release boundary.
 *
 * Methodology controls against host-state contamination:
 *
 *   - CELL ORDER: every configured cell (tier x difficulty x cache x
 *     assets) is executed exactly once in a SEEDED RANDOM order, so
 *     host drift (thermal, memory, scheduler) is not systematically
 *     correlated with cell identity. The seed is a CLI option and is
 *     recorded in the results file, so any run is reproducible.
 *   - FRESH BROWSER PROCESSES: a fresh Chromium process is launched
 *     per tier (and per multi-widget scenario) and closed when the
 *     tier is done, so long-running browser degradation cannot bleed
 *     across tiers. Cold cells use a fresh context per load; warm
 *     cells use one context per cell by design (the warm-cache
 *     semantics require reuse).
 *   - FIXED-WORK THROUGHPUT: alongside the stochastic solve latency,
 *     every repetition records hashes/sec (a fixed-N SHA-256 loop on
 *     the page main thread, the same primitive the asset mode's
 *     solver actually uses) and Argon2id derivations/sec (a fixed-N
 *     derivation loop at the exact adaptive-risk envelope, m=16384
 *     KiB t=3 p=1, measured in a harness-owned worker built from the
 *     exact served runtime bytes). These separate solver
 *     implementation speed from nonce-search luck and host state, and
 *     act as a per-cell drift probe.
 *   - INCOMPLETE-RUN GUARD: the results file carries a completion
 *     marker only when the run traversed every configured cell
 *     without an error or an interrupt. A crashed or interrupted run
 *     writes its partial results WITHOUT the marker, and
 *     --promote-baseline refuses to promote any results file that
 *     lacks the marker or does not cover the full default matrix.
 *
 * Usage:
 *   node tools/client-perf/client-perf.mjs [--tiers all] [--reps 50]
 *     [--argon-reps 20] [--samples N] [--cache both] [--assets both]
 *     [--seed N] [--sha-fixed-work 500] [--argon-fixed-work 3]
 *     [--fixture-port 8091] [--out FILE]
 *   node tools/client-perf/client-perf.mjs --quick
 *   node tools/client-perf/client-perf.mjs --promote-baseline FILE
 *   node tools/client-perf/client-perf.mjs --help
 */
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import { execSync } from 'node:child_process';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const BROWSER_DIR = join(REPO_ROOT, 'tests', 'browser');
const RESULTS_DIR = join(SCRIPT_DIR, 'results');
const FIXTURE_ROUTER = join(BROWSER_DIR, 'router.php');

// Playwright lives in tests/browser/node_modules (the fixture's own
// install); the harness resolves it there so no second install is
// needed. A standalone `npm install @playwright/test` inside
// tools/client-perf would also work — the require path is tried first.
const requireFromBrowser = createRequire(join(BROWSER_DIR, 'package.json'));
let chromium;
let devices;
try {
  ({ chromium, devices } = requireFromBrowser('@playwright/test'));
} catch (e) {
  console.error(`cannot resolve @playwright/test from ${BROWSER_DIR}: ${e.message}`);
  process.exit(2);
}

const SCHEMA = 'kiwicaptcha.client-perf/3';

// The completion marker: written into the results payload ONLY when the
// run traversed every configured cell without an error or an interrupt.
// The baseline loader (--promote-baseline) refuses any results file
// that does not carry this marker with status "completed".
const COMPLETION_MARKER = 'kiwicaptcha.client-perf.completed.v1';

// Fixed-work throughput defaults (see the header comment): a fixed-N
// SHA-256 loop on the page main thread and a fixed-N Argon2id
// derivation loop at the exact adaptive-risk envelope in a harness
// worker. The SHA target is 64 leading zero bits, unreachable inside a
// few hundred hashes, so the loop measures pure hash throughput.
const FIXED_WORK_SHA_DEFAULT = 500;
const FIXED_WORK_ARGON_DEFAULT = 3;
const FIXED_WORK_SHA_TARGET_BITS = 64;
const FIXED_WORK_ARGON_T = 3;
const FIXED_WORK_ARGON_P = 1;
// The harness's own measurement traffic is marked and excluded from the
// page's resource accounting (transferred bytes, cache hits, resource
// count): a fixed-work measurement must not tax the widget's page cost.
const FIXED_WORK_MARKER = 'kcp_fixed_work=1';
const FIXED_WORK_SHA_MAX_CALLS = 10000;

const TIERS = {
  'low-android': {
    label: 'low Android (Pixel 4a-class)',
    device: 'Pixel 5',
    cpuThrottle: 6,
    fallback: {
      viewport: { width: 393, height: 851 },
      deviceScaleFactor: 2.75,
      isMobile: true,
      hasTouch: true,
      userAgent:
        'Mozilla/5.0 (Linux; Android 13; Pixel 4a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36',
    },
  },
  'mid-android': {
    label: 'mid Android (Pixel 7-class)',
    device: 'Pixel 7',
    cpuThrottle: 4,
    fallback: {
      viewport: { width: 412, height: 839 },
      deviceScaleFactor: 2.625,
      isMobile: true,
      hasTouch: true,
      userAgent:
        'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36',
    },
  },
  'flagship-android': {
    label: 'flagship Android (Pixel 8-class)',
    device: 'Pixel 8 Pro',
    cpuThrottle: 2,
    fallback: {
      viewport: { width: 448, height: 921 },
      deviceScaleFactor: 3,
      isMobile: true,
      hasTouch: true,
      userAgent:
        'Mozilla/5.0 (Linux; Android 15; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36',
    },
  },
  'older-iphone': {
    label: 'older iPhone (iPhone 11-class)',
    device: 'iPhone 11',
    cpuThrottle: 4,
    fallback: {
      viewport: { width: 414, height: 896 },
      deviceScaleFactor: 2,
      isMobile: true,
      hasTouch: true,
      userAgent:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    },
  },
  'current-iphone': {
    label: 'current iPhone (iPhone 15-class)',
    device: 'iPhone 15',
    cpuThrottle: 2,
    fallback: {
      viewport: { width: 393, height: 852 },
      deviceScaleFactor: 3,
      isMobile: true,
      hasTouch: true,
      userAgent:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    },
  },
  'low-desktop': {
    label: 'low-end desktop (4x CPU)',
    cpuThrottle: 4,
    fallback: {
      viewport: { width: 1280, height: 720 },
      deviceScaleFactor: 1,
      isMobile: false,
      userAgent:
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    },
  },
  'mainstream-desktop': {
    label: 'mainstream desktop (no throttle)',
    cpuThrottle: 1,
    fallback: {
      viewport: { width: 1920, height: 1080 },
      deviceScaleFactor: 1,
      isMobile: false,
      userAgent:
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    },
  },
};

const DIFFICULTIES = {
  sha16: {
    label: 'SHA-256, 16 leading zero bits',
    query: () => '?bits=16',
    dimension: 'sha',
    isArgon: false,
    assetModes: ['inline', 'files'],
  },
  sha18: {
    label: 'SHA-256, 18 leading zero bits',
    query: () => '?bits=18',
    dimension: 'sha',
    isArgon: false,
    assetModes: ['inline', 'files'],
  },
  sha20: {
    label: 'SHA-256, 20 leading zero bits',
    query: () => '?bits=20',
    dimension: 'sha',
    isArgon: false,
    assetModes: ['inline', 'files'],
  },
  argon2id: {
    label: 'Argon2id (m=16384 KiB, t=3, p=1, target 8)',
    query: (o) => `?algorithm=argon2id&argon_bits=${o.argonBits}&m_kib=${o.argonMKib}`,
    dimension: 'argon',
    isArgon: true,
    assetModes: ['inline', 'files'],
  },
  // The ExecutionChallengeV1 cells. The fixture arms the execution
  // dimension with ?execution=1 (the mirror of the bundle's
  // risk.execution_challenge gate); the challenge response then carries
  // an execution program the driver runs in a sandboxed ephemeral
  // iframe (the lazy execution.<sha256>.js interpreter asset) and the
  // execution digest rides the solution token. The interpreter asset
  // is delivered in both asset tiers: the bundle theme emits the
  // SRI-linked data-kiwi-execution-src on the container in inline mode
  // exactly as in files mode (the interpreter is never embedded), and
  // the fixture mirrors that — so the files-tier cells below are
  // joined by the inline-tier cells execvminline/execsha18inline. The
  // interpreter fetch is lazy in both tiers: a cell that arms execution
  // records the single fetch (network layer), a SHA-only page pays
  // zero bytes.
  execvm: {
    label: 'execution VM only (armed, fixture SHA default, no PoW change)',
    query: () => '?execution=1',
    dimension: 'execution',
    isArgon: false,
    assetModes: ['files'],
  },
  execsha18: {
    label: 'execution + SHA-256, 18 leading zero bits',
    query: () => '?execution=1&bits=18',
    dimension: 'execution',
    isArgon: false,
    assetModes: ['files'],
  },
  execargon: {
    label: 'execution + Argon2id (m=16384 KiB, t=3, p=1, target 8)',
    query: (o) => `?execution=1&algorithm=argon2id&argon_bits=${o.argonBits}&m_kib=${o.argonMKib}`,
    dimension: 'execution',
    isArgon: true,
    assetModes: ['files'],
  },
  execchain: {
    label: 'execution + chained escalation (SHA request, Argon issued at the real ladder)',
    query: (o) => `?execution=1&escalate=argon&argon_bits=${o.argonBits}&m_kib=${o.argonMKib}`,
    dimension: 'execution',
    isArgon: true,
    assetModes: ['files'],
  },
  // The inline-tier execution cells: the same SHA-profile execution
  // workloads on the ?assets=inline page (glue and driver inlined, the
  // interpreter still lazily fetched from its content-addressed route
  // when the armed challenge arrives — the product's inline execution
  // behavior, one lazy interpreter fetch per armed page). They measure
  // the interpreter fetch start/duration and the VM run against an
  // inline bootstrap instead of a files one.
  execvminline: {
    label: 'execution VM only, inline assets (armed, fixture SHA default, no PoW change)',
    query: () => '?execution=1',
    dimension: 'execution',
    isArgon: false,
    assetModes: ['inline'],
  },
  execsha18inline: {
    label: 'execution + SHA-256 18 bits, inline assets',
    query: () => '?execution=1&bits=18',
    dimension: 'execution',
    isArgon: false,
    assetModes: ['inline'],
  },
};

function parseArgs(argv) {
  const opts = {
    tiers: null, // null = all
    difficulties: ['sha16', 'sha18', 'sha20', 'argon2id', 'execvm', 'execsha18', 'execargon', 'execchain', 'execvminline', 'execsha18inline'],
    reps: 50, // SHA-256 solve repetitions per cell (the percentile-supporting default)
    argonReps: 20, // Argon2id solve repetitions per cell (memory-hard, so fewer but still percentile-supporting)
    cache: 'both', // cold | warm | both
    assets: 'both', // inline | files | both
    fixturePort: 8091,
    noFixture: false,
    php: 'php',
    out: null,
    argonBits: 8, // the real adaptive-risk ladder highest rung (not the fixture envelope default)
    argonMKib: 16384, // the real ladder envelope (16 MiB), not the 64 KiB fixture default
    multiWidget: true,
    multiWidgetReps: 3,
    quick: false,
    seed: null, // null = derive from the wall clock; recorded in the results file
    shaFixedWork: FIXED_WORK_SHA_DEFAULT,
    argonFixedWork: FIXED_WORK_ARGON_DEFAULT,
    promoteBaseline: null, // loader mode: validate + write results/baseline.json
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => argv[++i];
    switch (arg) {
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
        break;
      case '--tiers':
        opts.tiers = next().split(',').map((s) => s.trim()).filter(Boolean);
        break;
      case '--difficulties':
        opts.difficulties = next().split(',').map((s) => s.trim()).filter(Boolean);
        break;
      case '--reps':
        opts.reps = parseInt(next(), 10);
        break;
      case '--argon-reps':
        opts.argonReps = parseInt(next(), 10);
        break;
      case '--samples':
        opts.reps = parseInt(next(), 10);
        opts.argonReps = opts.reps;
        break;
      case '--cache':
        opts.cache = next();
        break;
      case '--assets':
        opts.assets = next();
        break;
      case '--fixture-port':
        opts.fixturePort = parseInt(next(), 10);
        break;
      case '--no-fixture':
        opts.noFixture = true;
        break;
      case '--php':
        opts.php = next();
        break;
      case '--out':
        opts.out = next();
        break;
      case '--argon-bits':
        opts.argonBits = parseInt(next(), 10);
        break;
      case '--argon-m-kib':
        opts.argonMKib = parseInt(next(), 10);
        break;
      case '--seed':
        opts.seed = parseInt(next(), 10);
        break;
      case '--sha-fixed-work':
        opts.shaFixedWork = parseInt(next(), 10);
        break;
      case '--argon-fixed-work':
        opts.argonFixedWork = parseInt(next(), 10);
        break;
      case '--promote-baseline':
        opts.promoteBaseline = next();
        break;
      case '--no-multi-widget':
        opts.multiWidget = false;
        break;
      case '--quick':
        opts.quick = true;
        break;
      default:
        console.error(`unknown option: ${arg}`);
        printHelp();
        process.exit(2);
    }
  }
  if (opts.quick) {
    opts.tiers = ['low-android', 'mainstream-desktop'];
    opts.reps = 3;
    opts.argonReps = 2;
    opts.cache = 'both';
    opts.assets = 'both';
  }
  return opts;
}

function printHelp() {
  console.log(`KiwiCaptcha client-performance harness

Usage:
  node tools/client-perf/client-perf.mjs [options]

Options:
  --tiers <list>          comma list of device tiers (default: all)
                          ${Object.keys(TIERS).join(', ')}
  --difficulties <list>   comma list (default:
                          sha16,sha18,sha20,argon2id,execvm,execsha18,
                          execargon,execchain,execvminline,execsha18inline)
  --reps N                SHA-256 solve repetitions per tier/difficulty/cache/assets
                          (default 50; the percentile-supporting range is 50-100)
  --argon-reps N          Argon2id repetitions per cell (default 20; range 20-30)
                          (the execution cells inherit the rep count of their PoW
                          profile: execvm, execsha18, execvminline and
                          execsha18inline use --reps, execargon and execchain use
                          --argon-reps)
  --samples N             shorthand for --reps N --argon-reps N
  --cache <cold|warm|both>  cold = fresh context per load with the HTTP
                          cache disabled; warm = one reused context with
                          the cache enabled and populated (default both)
  --assets <inline|files|both>  inline = the fixture's inlined wasm glue
                          and driver; files = the ?assets=files variant
                          (external SRI assets, lazy Argon runtime and
                          lazy execution interpreter).
                          Default both; the files execution cells
                          (execvm, execsha18, execargon, execchain) are
                          files-only and the inline execution cells
                          (execvminline, execsha18inline) inline-only by
                          design (the interpreter asset rides the
                          container in both tiers, so each tier's cells
                          measure its own bootstrap against the one
                          lazy interpreter fetch).
  --fixture-port N        fixture server port (default 8091)
  --no-fixture            attach to an already-running fixture (e.g. the
                          playwright lane on 8085)
  --php BIN               php binary for the fixture (default php)
  --argon-bits N          argon2id target bits for the argon tier (default 8,
                          the real adaptive-risk ladder highest rung)
  --argon-m-kib N         argon2id memory KiB for the argon tier (default 16384,
                          the real ladder envelope; the fixture clamps to
                          8..65536 KiB, so 16384 is permitted)
  --seed N                seed for the randomized cell execution order
                          (default: derived from the wall clock; recorded in
                          the results file so any run is reproducible)
  --sha-fixed-work N      fixed-N SHA-256 hashes for the page fixed-work loop
                          (default 500)
  --argon-fixed-work N    fixed-N Argon2id derivations for the worker
                          fixed-work loop at the real envelope m=16384 KiB
                          t=3 p=1 (default 3)
  --promote-baseline FILE validate a completed results file (completion marker
                          present, full default matrix covered, default sample
                          sizes and the real argon ladder) and write it as
                          tools/client-perf/results/baseline.json; refuses any
                          file without the marker (the incomplete-run guard)
  --no-multi-widget       skip the multiple-widget scenario
  --quick                 iteration mode: low-android + mainstream-desktop,
                          3 SHA / 2 Argon reps, cold and warm, inline and files
  --out FILE              results file (default results/results-<date>.json)
  --help                  this text

Output: machine-readable JSON (schema ${SCHEMA}) written to
  tools/client-perf/results/results-<date>.json on a completed run, or
  tools/client-perf/results/results-<date>-partial-<time>.json on a
  crashed or interrupted run (no completion marker, never promotable).
  The committed baseline lives at
  tools/client-perf/results/baseline.json and is replaced ONLY through
  --promote-baseline with a completed full-matrix run.
`);
}

function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

function summarize(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    count: sorted.length,
    min: sorted.length ? sorted[0] : null,
    max: sorted.length ? sorted[sorted.length - 1] : null,
    mean: sorted.length ? sorted.reduce((a, b) => a + b, 0) / sorted.length : null,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
  };
}

// Seeded PRNG (mulberry32) for the cell execution order: the same seed
// always yields the same order, so any run is reproducible; the default
// seed comes from the wall clock so consecutive runs interleave cells
// differently and no residual ordering bias survives.
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seededShuffle(arr, rng) {
  for (let i = arr.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
  return arr;
}

// Every configured cell (tier x difficulty x cache x assets) as one
// flat list; the run executes the list once, in seeded random order.
// A difficulty may restrict its asset modes (the files execution cells
// are files-only and the inline execution cells inline-only by
// design), intersected with the CLI --assets selection.
function buildCellList(opts, tierNames) {
  const assetModes = opts.assets === 'both' ? ['inline', 'files'] : [opts.assets];
  const caches = opts.cache === 'both' ? ['cold', 'warm'] : [opts.cache];
  const cells = [];
  for (const tier of tierNames) {
    for (const difficultyName of opts.difficulties) {
      const modes = (DIFFICULTIES[difficultyName].assetModes || ['inline', 'files']).filter(
        (m) => assetModes.includes(m),
      );
      if (modes.length === 0) continue;
      for (const cache of caches) {
        for (const assets of modes) {
          cells.push({ tier, difficulty: difficultyName, cache, assets });
        }
      }
    }
  }
  return cells;
}

function waitForHttp(url, timeoutMs) {
  return new Promise((resolvePromise) => {
    const start = Date.now();
    const tick = () => {
      fetch(url)
        .then((r) => (r.ok ? resolvePromise(true) : retry()))
        .catch(retry);
    };
    const retry = () => {
      if (Date.now() - start > timeoutMs) resolvePromise(false);
      else setTimeout(tick, 250);
    };
    tick();
  });
}

async function bootFixture(opts) {
  if (opts.noFixture) return null;
  if (!existsSync(FIXTURE_ROUTER)) {
    console.error(`fixture router not found: ${FIXTURE_ROUTER}`);
    process.exit(2);
  }
  const port = opts.fixturePort;
  const base = `http://127.0.0.1:${port}`;
  const up = await waitForHttp(base, 800);
  if (up) {
    console.log(`fixture already answering on ${base}; reusing it`);
    return null;
  }
  const child = spawn(opts.php, ['-d', 'opcache.jit=off', '-S', `127.0.0.1:${port}`, FIXTURE_ROUTER], {
    cwd: BROWSER_DIR,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (d) => {
    const s = String(d).trim();
    if (s && !s.includes('Accepted') && !s.includes('Closing')) process.stderr.write(`[fixture] ${s}\n`);
  });
  const ready = await waitForHttp(base, 20000);
  if (!ready) {
    console.error('fixture did not come up in time');
    child.kill('SIGKILL');
    process.exit(2);
  }
  return child;
}

function tierContextOptions(tierName) {
  const tier = TIERS[tierName];
  if (!tier) throw new Error(`unknown tier: ${tierName}`);
  const descriptor = devices[tier.device];
  const base = descriptor ? { ...descriptor } : { ...tier.fallback };
  return {
    ...base,
    viewport: { ...(descriptor ? descriptor.viewport : tier.fallback.viewport) },
  };
}

const INIT_SCRIPT = `
(() => {
  if (window.__kiwiPerf) return;
  window.__kiwiPerf = {
    states: [],
    verified: null,
    verifiedWidgets: {},
    errors: [],
    workers: [],
    wasm: { compile: [], instantiate: [] },
    memSamples: [],
    timeOrigin: performance.timeOrigin,
  };
  const P = window.__kiwiPerf;
  new MutationObserver((ms) => {
    for (const m of ms) {
      const el = m.target;
      if (el && el.matches && el.matches('[data-kiwi-widget]') && m.attributeName === 'data-state') {
        const container = el.closest ? el.closest('.kiwi-container') : null;
        P.states.push({ state: el.getAttribute('data-state'), t: performance.now(), widget: container ? container.id : null });
      }
    }
  }).observe(document, { subtree: true, childList: false, attributes: true, attributeFilter: ['data-state'] });
  document.addEventListener('kiwi:verified', (e) => {
    const container = e.target && e.target.closest ? e.target.closest('.kiwi-container') : null;
    const widget = container ? container.id : 'widget';
    P.verified = { t: performance.now(), widget, nonce: (e.detail && e.detail.nonce) || null };
    P.verifiedWidgets[widget] = performance.now();
  }, true);
  document.addEventListener('kiwi:error', (e) => { P.errors.push({ t: performance.now(), detail: e.detail || {} }); }, true);
  document.addEventListener('kiwi:worker-unavailable', (e) => { P.errors.push({ t: performance.now(), workerUnavailable: true }); }, true);
  const NativeWorker = window.Worker;
  if (NativeWorker && !window.__kiwiPerfWorkerWrapped) {
    window.__kiwiPerfWorkerWrapped = true;
    function PerfWorker(url, opts) {
      const w = new NativeWorker(url, opts);
      const rec = { created: performance.now(), firstMessage: null, url: String(url).slice(0, 60) };
      P.workers.push(rec);
      w.addEventListener('message', () => { if (rec.firstMessage === null) rec.firstMessage = performance.now(); });
      return w;
    }
    PerfWorker.prototype = NativeWorker.prototype;
    window.Worker = PerfWorker;
  }
  const wc = WebAssembly.compile;
  const wi = WebAssembly.instantiate;
  const wis = WebAssembly.instantiateStreaming;
  const WM = WebAssembly.Module;
  const WI = WebAssembly.Instance;
  if (wc) WebAssembly.compile = function (bytes) {
    const t0 = performance.now();
    return wc.call(this, bytes).then((r) => { P.wasm.compile.push({ ms: performance.now() - t0 }); return r; });
  };
  if (wi) WebAssembly.instantiate = function (a, b) {
    const t0 = performance.now();
    return wi.call(this, a, b).then((r) => { P.wasm.instantiate.push({ ms: performance.now() - t0 }); return r; });
  };
  if (wis) WebAssembly.instantiateStreaming = function (a, b) {
    const t0 = performance.now();
    return wis.call(this, a, b).then((r) => { P.wasm.instantiate.push({ ms: performance.now() - t0 }); return r; });
  };
  if (WM) WebAssembly.Module = function (bytes) {
    const t0 = performance.now();
    const m = new WM(bytes);
    P.wasm.compile.push({ ms: performance.now() - t0 });
    return m;
  };
  WebAssembly.Module.prototype = WM.prototype;
  if (WI) WebAssembly.Instance = function (module, imports) {
    const t0 = performance.now();
    const inst = new WI(module, imports);
    P.wasm.instantiate.push({ ms: performance.now() - t0 });
    return inst;
  };
  WebAssembly.Instance.prototype = WI.prototype;
  const lt = [];
  try {
    const obs = new PerformanceObserver((list) => {
      for (const e of list.getEntries()) lt.push({ start: e.startTime, duration: e.duration });
    });
    obs.observe({ type: 'longtask' });
    P.__longTasks = lt;
  } catch (e) { P.__longTaskError = String(e); }
  const mem = setInterval(() => {
    try { if (performance.memory) P.memSamples.push(performance.memory.usedJSHeapSize); } catch (e) {}
  }, 50);
  P.__stopMemSampling = () => clearInterval(mem);
  window.addEventListener('pagehide', () => clearInterval(mem));

  // ── Fixed-work throughput probes ────────────────────────────────────
  // hashes/sec and Argon2id derivations/sec are measured per repetition
  // (see the harness header). The SHA loop runs on the page main thread
  // under the tier's CPU throttle and uses the same primitive the
  // asset mode's solver actually uses: the wasm solve_sha256_chunk
  // export when the glue is present (inline mode), or the pure-JS
  // implementation (files mode, where the main-thread SHA solver is
  // pure JS by design). The Argon loop runs in a harness-owned worker
  // built from the exact served runtime bytes, at the exact
  // adaptive-risk envelope (m=16384 KiB, t=3, p=1).
  const BENCH_PREFIX = 'kiwicaptcha-perf-prefix-0123456789abcdef';
  const BENCH_SALT = 'kiwicaptcha-perf-salt-0123456789';
  const BENCH_TARGET_BITS = 64; // unreachable inside the fixed windows
  const benchSaltBytes = new TextEncoder().encode(BENCH_SALT);
  // The pure-JS SHA-256 below is byte-identical to the implementation
  // the driver and the worker ship (the solver's own fallback), so the
  // files-mode fixed-work loop measures the solver's implementation.
  const _bk = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  const _bh = new Uint32Array(8);
  const _bw = new Uint32Array(64);
  const _bout = new Uint8Array(32);
  let _bin = null;
  function sha256sync(data, result) {
    _bh[0] = 0x6a09e667; _bh[1] = 0xbb67ae85; _bh[2] = 0x3c6ef372; _bh[3] = 0xa54ff53a;
    _bh[4] = 0x510e527f; _bh[5] = 0x9b05688c; _bh[6] = 0x1f83d9ab; _bh[7] = 0x5be0cd19;
    const l = data.length * 8;
    const padLen = (data.length % 64 < 56) ? (56 - data.length % 64) : (120 - data.length % 64);
    const msg = new Uint8Array(data.length + padLen + 8);
    msg.set(data); msg[data.length] = 0x80;
    const view = new DataView(msg.buffer);
    view.setUint32(msg.length - 4, l, false);
    let a, b, c, d, e, f, g, hh, s0, s1, ch, maj, t1, t2;
    for (let i = 0; i < msg.length; i += 64) {
      for (let j = 0; j < 16; j += 1) _bw[j] = view.getUint32(i + j * 4, false);
      for (j = 16; j < 64; j += 1) {
        const x = _bw[j - 15]; s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        const y = _bw[j - 2]; s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        _bw[j] = (_bw[j - 16] + s0 + _bw[j - 7] + s1) | 0;
      }
      a = _bh[0]; b = _bh[1]; c = _bh[2]; d = _bh[3]; e = _bh[4]; f = _bh[5]; g = _bh[6]; hh = _bh[7];
      for (j = 0; j < 64; j += 1) {
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ch = (e & f) ^ (~e & g); t1 = (hh + s1 + ch + _bk[j] + _bw[j]) | 0;
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        maj = (a & b) ^ (a & c) ^ (b & c); t2 = (s0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      _bh[0] = (_bh[0] + a) | 0; _bh[1] = (_bh[1] + b) | 0; _bh[2] = (_bh[2] + c) | 0; _bh[3] = (_bh[3] + d) | 0;
      _bh[4] = (_bh[4] + e) | 0; _bh[5] = (_bh[5] + f) | 0; _bh[6] = (_bh[6] + g) | 0; _bh[7] = (_bh[7] + hh) | 0;
    }
    for (let i = 0; i < 8; i += 1) {
      result[i * 4] = (_bh[i] >>> 24) & 0xff; result[i * 4 + 1] = (_bh[i] >>> 16) & 0xff;
      result[i * 4 + 2] = (_bh[i] >>> 8) & 0xff; result[i * 4 + 3] = _bh[i] & 0xff;
    }
  }
  function benchShaJs(n) {
    const t0 = performance.now();
    for (let i = 0; i < n; i += 1) {
      const c = String(i);
      const total = BENCH_PREFIX.length + c.length + benchSaltBytes.length;
      if (!_bin || _bin.length !== total) _bin = new Uint8Array(total);
      for (let j = 0; j < BENCH_PREFIX.length; j += 1) _bin[j] = BENCH_PREFIX.charCodeAt(j);
      for (let k = 0; k < c.length; k += 1) _bin[BENCH_PREFIX.length + k] = c.charCodeAt(k);
      _bin.set(benchSaltBytes, BENCH_PREFIX.length + c.length);
      sha256sync(_bin, _bout);
    }
    return performance.now() - t0;
  }
  function wasmAlloc(w, bytes) {
    let ptr = 0;
    if (w.alloc) {
      ptr = w.alloc(bytes.length);
    } else if (w.__wbindgen_malloc) {
      ptr = w.__wbindgen_malloc(bytes.length, 1);
    }
    if (!ptr) return 0;
    new Uint8Array(w.memory.buffer).set(bytes, ptr);
    return ptr;
  }
  function wasmFree(w, ptr, len) {
    if (!ptr) return;
    try {
      if (w.dealloc) w.dealloc(ptr, len);
      else if (w.__wbindgen_free) w.__wbindgen_free(ptr, len, 1);
    } catch (e) {}
  }
  async function benchSha(n) {
    const started = performance.now();
    let path = null;
    const g = window.__kiwiCaptchaWasm;
    if (g && typeof g.load === 'function') {
      try {
        const w = await g.load();
        if (w && w.init_panic_hook) { try { w.init_panic_hook(); } catch (e) {} }
        if (w && typeof w.solve_sha256_chunk === 'function' && (w.alloc || w.__wbindgen_malloc)) {
          const prefix = new TextEncoder().encode(BENCH_PREFIX);
          const pp = wasmAlloc(w, prefix);
          const sp = wasmAlloc(w, benchSaltBytes);
          if (pp && sp) {
            path = 'wasm';
            let counter = 0;
            let scanned = 0;
            for (let calls = 0; calls < ${FIXED_WORK_SHA_MAX_CALLS} && scanned < n; calls += 1) {
              const win = Math.min(n - scanned, 500);
              const res = w.solve_sha256_chunk(pp, prefix.length, sp, benchSaltBytes.length, BENCH_TARGET_BITS, counter, win);
              if (typeof res !== 'number') { path = 'wasm-error'; break; }
              const done = res === -1 ? win : -res - 1;
              if (done <= 0) { path = 'wasm-stall'; break; }
              scanned += done;
              counter += done;
            }
            wasmFree(w, pp, prefix.length);
            wasmFree(w, sp, benchSaltBytes.length);
            if (path === 'wasm' && scanned < n) path = 'wasm-short';
            const ms = performance.now() - started;
            return { n: scanned, ms, hashesPerSec: ms > 0 ? scanned / (ms / 1000) : null, path };
          }
        }
      } catch (e) {
        path = null;
      }
    }
    path = 'pure-js';
    const ms = benchShaJs(n);
    return { n, ms, hashesPerSec: ms > 0 ? n / (ms / 1000) : null, path };
  }
  // The Argon fixed-work loop runs inside a harness-owned worker whose
  // source is the exact served runtime bytes plus this self-contained
  // driver (the widget driver builds its own Blob worker the same way,
  // with the same var window = self prelude). No product code runs
  // here; the measurement is the raw solver export at the real
  // envelope.
  function __kiwiArgonBenchWorker(self) {
    'use strict';
    const respond = (r) => { self.postMessage(r); };
    self.onmessage = (ev) => {
      const m = ev.data;
      const n = m.n, mKib = m.mKib, t = m.t, p = m.p, targetBits = m.targetBits;
      const g = self.__kiwiCaptchaWasm;
      if (!g || typeof g.load !== 'function') {
        respond({ n, ms: null, derivationsPerSec: null, path: 'no-glue' });
        return;
      }
      g.load().then((w) => {
        if (!w || typeof w.solve_argon2_chunk !== 'function' || !(w.alloc || w.__wbindgen_malloc)) {
          respond({ n, ms: null, derivationsPerSec: null, path: 'no-argon-export' });
          return;
        }
        const prefix = new TextEncoder().encode('kiwicaptcha-perf-prefix-0123456789abcdef');
        const salt = new TextEncoder().encode('kiwicaptcha-perf-salt-0123456789');
        const pp = w.alloc ? w.alloc(prefix.length) : w.__wbindgen_malloc(prefix.length, 1);
        const sp = w.alloc ? w.alloc(salt.length) : w.__wbindgen_malloc(salt.length, 1);
        if (!pp || !sp) {
          respond({ n, ms: null, derivationsPerSec: null, path: 'alloc-failed' });
          return;
        }
        try {
          new Uint8Array(w.memory.buffer).set(prefix, pp);
          new Uint8Array(w.memory.buffer).set(salt, sp);
          const started = performance.now();
          for (let i = 0; i < n; i += 1) {
            w.solve_argon2_chunk(pp, prefix.length, sp, salt.length, targetBits, mKib, t, p, i, 1);
          }
          const ms = performance.now() - started;
          respond({ n, ms, derivationsPerSec: ms > 0 ? n / (ms / 1000) : null, path: 'harness-worker' });
        } catch (e) {
          respond({ n, ms: null, derivationsPerSec: null, path: 'solve-error' });
        } finally {
          try {
            if (w.dealloc) { w.dealloc(pp, prefix.length); w.dealloc(sp, salt.length); }
            else if (w.__wbindgen_free) { w.__wbindgen_free(pp, prefix.length, 1); w.__wbindgen_free(sp, salt.length, 1); }
          } catch (e) {}
        }
      }).catch(() => {
        respond({ n, ms: null, derivationsPerSec: null, path: 'load-error' });
      });
    };
  }
  async function benchArgon(n, mKib, t, p) {
    let glueSrc = null;
    try {
      const g = window.__kiwiCaptchaWasm;
      if (g) {
        const scripts = document.scripts || [];
        for (let i = 0; i < scripts.length; i += 1) {
          const text = scripts[i].textContent || '';
          if (text.indexOf('var KIWI_WASM_B64') !== -1 && text.indexOf('__kiwiCaptchaWasm') !== -1) {
            glueSrc = text;
            break;
          }
        }
      }
      if (!glueSrc) {
        const el = document.querySelector('[data-kiwi-runtime-src]');
        if (el) {
          const url = el.getAttribute('data-kiwi-runtime-src');
          if (url) {
            const sep = url.indexOf('?') === -1 ? '?' : '&';
            const resp = await fetch(url + sep + '${FIXED_WORK_MARKER}', { cache: 'force-cache' });
            if (resp.ok) glueSrc = await resp.text();
          }
        }
      }
    } catch (e) {}
    if (!glueSrc) return { n, ms: null, derivationsPerSec: null, path: 'no-glue-source' };
    const workerSrc = 'var window = self;\\n' + glueSrc + '\\n(' + __kiwiArgonBenchWorker.toString() + ')(self);';
    let url = null;
    try {
      url = URL.createObjectURL(new Blob([workerSrc], { type: 'text/javascript' }));
      return await new Promise((resolve) => {
        let settled = false;
        const done = (r) => {
          if (settled) return;
          settled = true;
          try { w.terminate(); } catch (e) {}
          try { URL.revokeObjectURL(url); } catch (e) {}
          resolve(r);
        };
        // The harness worker bypasses the instrumented window.Worker
        // wrapper (the native constructor captured before wrapping), so
        // the fixed-work worker never contaminates the widget's
        // workerStartupMs measurement.
        const w = new NativeWorker(url);
        w.onmessage = (e) => done(e.data);
        w.onerror = (e) => done({ n, ms: null, derivationsPerSec: null, path: 'worker-error', reason: e && e.message ? String(e.message) : 'unknown' });
        w.postMessage({ n, mKib, t, p, targetBits: BENCH_TARGET_BITS });
        setTimeout(() => done({ n, ms: null, derivationsPerSec: null, path: 'worker-timeout' }), 60000);
      });
    } catch (e) {
      try { if (url) URL.revokeObjectURL(url); } catch (e2) {}
      return { n, ms: null, derivationsPerSec: null, path: 'worker-creation-failed' };
    }
  }
  P.benchSha = benchSha;
  P.benchArgon = benchArgon;
})();
`;

async function collectPageMetrics(page) {
  return page.evaluate(async () => {
    const P = window.__kiwiPerf || { states: [], verified: null, workers: [], wasm: { compile: [], instantiate: [] } };
    if (P.__stopMemSampling) P.__stopMemSampling();
    const longTasks = [];
    const lafScripts = [];
    let finalHeap = null;
    try { if (performance.memory) finalHeap = performance.memory.usedJSHeapSize; } catch (e) {}
    try {
      for (const e of performance.getEntriesByType('long-animation-frame')) {
        for (const s of e.scripts || []) {
          lafScripts.push({ invoker: s.invoker || '', duration: s.duration, startTime: s.startTime });
        }
      }
    } catch (e) {}
    await new Promise((resolvePromise) => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        resolvePromise();
      };
      let obs = null;
      try {
        obs = new PerformanceObserver((list) => {
          for (const e of list.getEntries()) {
            if (e.entryType === 'longtask') longTasks.push({ start: e.startTime, duration: e.duration });
            if (e.entryType === 'long-animation-frame') {
              for (const s of e.scripts || []) {
                lafScripts.push({ invoker: s.invoker || '', duration: s.duration, startTime: s.startTime });
              }
            }
          }
          finish();
        });
        obs.observe({ type: 'longtask', buffered: true });
        obs.observe({ type: 'long-animation-frame', buffered: true });
      } catch (e) {}
      setTimeout(finish, 250);
    });
    if (longTasks.length === 0 && Array.isArray(P.__longTasks) && P.__longTasks.length) {
      for (const l of P.__longTasks) longTasks.push({ start: l.start, duration: l.duration });
    }
    if (lafScripts.length === 0 && Array.isArray(P.__lafScripts) && P.__lafScripts.length) {
      for (const s of P.__lafScripts) lafScripts.push({ invoker: s.invoker, duration: s.duration, startTime: s.startTime });
    }
    const scriptEntries = [];
    try {
      for (const e of performance.getEntriesByType('script')) {
        scriptEntries.push({ invoker: e.invoker || '', duration: e.duration, startTime: e.startTime, executionStart: e.executionStart });
      }
    } catch (e) {}
    const resources = [];
    try {
      for (const e of performance.getEntriesByType('resource')) {
        // The harness's own fixed-work runtime fetch is marked
        // (kcp_fixed_work=1) and excluded from the widget's page cost:
        // a measurement must not tax the numbers it measures.
        if (e.name.indexOf('kcp_fixed_work') !== -1) continue;
        resources.push({
          name: e.name.slice(0, 120),
          startTime: e.startTime,
          duration: e.duration,
          transferSize: typeof e.transferSize === 'number' ? e.transferSize : null,
          encodedBodySize: typeof e.encodedBodySize === 'number' ? e.encodedBodySize : null,
          decodedBodySize: typeof e.decodedBodySize === 'number' ? e.decodedBodySize : null,
        });
      }
    } catch (e) {}
    const nav = performance.getEntriesByType('navigation')[0] || null;
    return {
      timeOrigin: P.timeOrigin,
      states: P.states,
      verified: P.verified,
      verifiedWidgets: P.verifiedWidgets || {},
      errors: P.errors,
      workers: P.workers,
      wasm: P.wasm,
      longTasks,
      lafScripts,
      scriptEntries,
      resources,
      memSamples: P.memSamples,
      finalHeap,
      nav: nav
        ? {
            domContentLoadedMs: nav.domContentLoadedEventEnd - nav.startTime,
            loadMs: nav.loadEventEnd - nav.startTime,
            transferSize: typeof nav.transferSize === 'number' ? nav.transferSize : null,
          }
        : null,
    };
  });
}

/**
 * Measure the page's served scripts (the wasm glue and the widget driver)
 * with the browser's own V8: each script's exact text is evaluated in an
 * isolated same-origin iframe under the active CPU throttle, and the wall
 * time from script insertion to the appended sentinel statement is the
 * script's parse + compile + eval time. In inline mode the fixture inlines
 * the scripts, so the DOM text is used; in files mode the fixture links
 * them, so the same-origin script src is fetched and evaluated. The iframe
 * is blank (no widget), so executing the driver a second time has no page
 * side effects.
 */
async function measureInlineScripts(page) {
  return page.evaluate(async () => {
    const sources = [];
    for (const s of document.querySelectorAll('script')) {
      if (s.src) {
        continue;
      }
      if (s.type && s.type !== 'text/javascript' && s.type !== 'application/javascript') continue;
      if (s.textContent.trim().length < 100) continue;
      sources.push(s.textContent);
    }
    if (sources.length === 0) {
      for (const s of document.querySelectorAll('script[src]')) {
        const url = s.src;
        if (!url) continue;
        try {
          const resp = await fetch(url);
          const text = await resp.text();
          if (text.trim().length >= 100) sources.push(text);
        } catch (e) {}
      }
    }
    if (sources.length === 0) return [];
    const iframe = document.createElement('iframe');
    iframe.setAttribute('style', 'width:1px;height:1px;position:absolute;left:-9999px;border:0');
    document.body.appendChild(iframe);
    const doc = iframe.contentDocument;
    doc.open();
    doc.write('<!DOCTYPE html><html><body></body></html>');
    doc.close();
    const results = [];
    for (const src of sources) {
      const t0 = performance.now();
      const script = doc.createElement('script');
      script.textContent = src + ';window.__kiwiPerfScriptEvalDone = performance.now();';
      doc.body.appendChild(script);
      const deadline = Date.now() + 60000;
      while (Date.now() < deadline) {
        if (doc.defaultView && doc.defaultView.__kiwiPerfScriptEvalDone !== undefined) break;
        // Synchronous spin: the script evaluation blocks this loop, so
        // the check runs immediately after the evaluation returns.
      }
      results.push({ ms: performance.now() - t0 });
      if (doc.defaultView) doc.defaultView.__kiwiPerfScriptEvalDone = undefined;
    }
    iframe.remove();
    return results;
  });
}

/**
 * Fixed-work throughput probes, measured per repetition inside the page
 * (under the tier's CPU throttle): hashes/sec via the SHA-256 loop and
 * Argon2id derivations/sec via the harness worker (see the INIT_SCRIPT
 * section that defines window.__kiwiPerf.benchSha / benchArgon). A
 * failure of either probe is recorded as nulls with its path, never an
 * exception: the cell evidence survives a broken probe.
 */
async function measureFixedWork(page, opts) {
  return page.evaluate(
    async (cfg) => {
      const P = window.__kiwiPerf || {};
      if (typeof P.benchSha !== 'function' || typeof P.benchArgon !== 'function') {
        return {
          sha: { n: cfg.shaN, ms: null, hashesPerSec: null, path: 'unavailable' },
          argon: { n: cfg.argonN, ms: null, derivationsPerSec: null, path: 'unavailable' },
        };
      }
      let sha;
      try {
        sha = await P.benchSha(cfg.shaN);
      } catch (e) {
        sha = { n: cfg.shaN, ms: null, hashesPerSec: null, path: 'failed' };
      }
      let argon;
      try {
        argon = await P.benchArgon(cfg.argonN, cfg.argonMKib, cfg.argonT, cfg.argonP);
      } catch (e) {
        argon = { n: cfg.argonN, ms: null, derivationsPerSec: null, path: 'failed' };
      }
      return { sha, argon };
    },
    {
      shaN: opts.shaFixedWork,
      argonN: opts.argonFixedWork,
      argonMKib: opts.argonMKib,
      argonT: FIXED_WORK_ARGON_T,
      argonP: FIXED_WORK_ARGON_P,
    },
  );
}

function computeMetrics(raw) {
  const firstState = (name) => {
    const hit = raw.states.find((s) => s.state === name);
    return hit ? hit.t : null;
  };
  const connecting = firstState('connecting');
  const solving = firstState('solving');
  const verifiedT = raw.verified ? raw.verified.t : null;
  const workerRec = raw.workers[0] || null;
  const longTaskDurations = (raw.longTasks || []).map((l) => l.duration);
  const lafSum = (raw.lafScripts || []).reduce((a, s) => a + s.duration, 0);
  const wasmCompile = (raw.wasm.compile || []).map((c) => c.ms);
  const wasmInstantiate = (raw.wasm.instantiate || []).map((c) => c.ms);
  const mem = raw.memSamples || [];
  const peakHeapMb = mem.length ? Math.max(...mem) / (1024 * 1024) : null;
  const resources = raw.resources || [];
  const transferred = resources.reduce((a, r) => a + (typeof r.transferSize === 'number' ? r.transferSize : 0), 0);
  const cacheHits = resources.filter((r) => typeof r.transferSize === 'number' && r.transferSize === 0).length;
  const runtimeEntry = resources.find((r) => /\/assets\/runtime\./.test(r.name) || /kiwicaptacha-wasm/.test(r.name));
  const driverEntry = resources.find((r) => /\/assets\/driver\./.test(r.name));
  const navTransfer = raw.nav && typeof raw.nav.transferSize === 'number' ? raw.nav.transferSize : 0;
  return {
    solveMs: connecting !== null && verifiedT !== null ? verifiedT - connecting : null,
    pureSolveMs: solving !== null && verifiedT !== null ? verifiedT - solving : null,
    pageToVerifiedMs: verifiedT !== null ? verifiedT : null,
    bootstrapToConnectingMs: connecting !== null ? connecting : null,
    jsParseCompileMs: lafSum > 0 ? lafSum : null,
    lafScriptCount: (raw.lafScripts || []).length,
    scriptEntryCount: (raw.scriptEntries || []).length,
    wasmCompileMs: wasmCompile.length ? wasmCompile.reduce((a, b) => a + b, 0) : null,
    wasmInstantiateMs: wasmInstantiate.length ? wasmInstantiate.reduce((a, b) => a + b, 0) : null,
    workerStartupMs: workerRec && workerRec.firstMessage !== null ? workerRec.firstMessage - workerRec.created : null,
    workerFirstMessageMs: workerRec && workerRec.firstMessage !== null ? workerRec.firstMessage : null,
    longTaskCount: longTaskDurations.length,
    longTaskTotalMs: longTaskDurations.reduce((a, b) => a + b, 0),
    longTaskMaxMs: longTaskDurations.length ? Math.max(...longTaskDurations) : null,
    peakHeapMb,
    finalHeapMb: raw.finalHeap !== null ? raw.finalHeap / (1024 * 1024) : null,
    domContentLoadedMs: raw.nav ? raw.nav.domContentLoadedMs : null,
    loadMs: raw.nav ? raw.nav.loadMs : null,
    transferredBytes: transferred + navTransfer,
    resourceTransferredBytes: transferred,
    cacheHitCount: cacheHits,
    resourceCount: resources.length,
    runtimeLazyFetchStartMs: runtimeEntry ? runtimeEntry.startTime : null,
    runtimeLazyFetchDurationMs: runtimeEntry ? runtimeEntry.duration : null,
    driverFetchStartMs: driverEntry ? driverEntry.startTime : null,
    driverFetchDurationMs: driverEntry ? driverEntry.duration : null,
    // The execution interpreter fetch is NOT visible to the top
    // document's resource timing: the driver loads it inside a
    // sandboxed ephemeral iframe that is removed after the run, so the
    // harness captures the fetch from the network layer instead (see
    // runLoad) and stamps it onto the metrics there.
    executionFetchStartMs: null,
    executionFetchDurationMs: null,
    errorCount: (raw.errors || []).length,
    errors: (raw.errors || []).map((e) => ({ t: e.t, workerUnavailable: !!e.workerUnavailable, detail: e.detail || {} })),
  };
}

async function runLoad(browser, opts, tierName, difficultyName, assetMode, warmContext, repIndex, measureFixed = true) {
  const tier = TIERS[tierName];
  const difficulty = DIFFICULTIES[difficultyName];
  const contextOptions = tierContextOptions(tierName);
  const base = `http://127.0.0.1:${opts.fixturePort}`;
  const assetsParam = assetMode === 'files' ? '&assets=files' : '';
  const url = base + '/' + difficulty.query(opts) + assetsParam;
  const cacheState = warmContext === null ? 'cold' : 'warm';
  let context = null;
  let page = null;
  let executionFetch = null;
  try {
    if (warmContext === null) {
      context = await browser.newContext(contextOptions);
    } else {
      context = warmContext;
    }
    page = await context.newPage();
    // The execution interpreter is fetched by the sandboxed ephemeral
    // iframe the driver creates per armed challenge (the iframe is
    // removed after the run, so the top document's resource timing
    // never sees the fetch). The network layer records it: the request
    // start is an epoch timestamp that anchors to the page's
    // performance.timeOrigin, and responseEnd (available at
    // requestfinished, before the iframe is removed) is the duration
    // in ms from the same baseline.
    page.on('requestfinished', (req) => {
      if (executionFetch === null && /\/assets\/execution\./.test(req.url())) {
        try {
          const t = req.timing();
          executionFetch = { epochStartMs: t.startTime, responseEndMs: t.responseEnd };
        } catch (e) {}
      }
    });
    await page.addInitScript(INIT_SCRIPT);
    const cdpSession = await context.newCDPSession(page);
    await cdpSession.send('Emulation.setCPUThrottlingRate', { rate: tier.cpuThrottle });
    if (cacheState === 'cold') {
      await cdpSession.send('Network.enable');
      await cdpSession.send('Network.setCacheDisabled', { cacheDisabled: true });
    }
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
    const isArgon = difficulty.isArgon;
    const timeoutMs = isArgon ? 300000 : 90000;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const state = await page.evaluate(() => {
        const P = window.__kiwiPerf || {};
        return { verified: !!P.verified, errors: (P.errors || []).length };
      });
      if (state.verified) break;
      if (state.errors > 0) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    await new Promise((r) => setTimeout(r, 150));
    const fixedWork = measureFixed
      ? await measureFixedWork(page, opts)
      : {
          sha: { n: opts.shaFixedWork, ms: null, hashesPerSec: null, path: 'skipped' },
          argon: { n: opts.argonFixedWork, ms: null, derivationsPerSec: null, path: 'skipped' },
        };
    const raw = await collectPageMetrics(page);
    const metrics = computeMetrics(raw);
    if (executionFetch && typeof raw.timeOrigin === 'number') {
      const startMs = executionFetch.epochStartMs - raw.timeOrigin;
      if (startMs >= 0) metrics.executionFetchStartMs = startMs;
      if (typeof executionFetch.responseEndMs === 'number' && executionFetch.responseEndMs >= 0) {
        metrics.executionFetchDurationMs = executionFetch.responseEndMs;
      }
    }
    const inlineScripts = await measureInlineScripts(page);
    metrics.inlineScriptEvalMs = inlineScripts.length ? inlineScripts.reduce((a, b) => a + b.ms, 0) : null;
    metrics.inlineScriptEvalCount = inlineScripts.length;
    metrics.inlineScriptEvalPerScriptMs = inlineScripts.map((i) => i.ms);
    metrics.shaFixedWorkN = fixedWork.sha.n;
    metrics.shaFixedWorkMs = fixedWork.sha.ms;
    metrics.shaHashesPerSec = fixedWork.sha.hashesPerSec;
    metrics.shaFixedWorkPath = fixedWork.sha.path;
    metrics.argonFixedWorkN = fixedWork.argon.n;
    metrics.argonFixedWorkMs = fixedWork.argon.ms;
    metrics.argonDerivationsPerSec = fixedWork.argon.derivationsPerSec;
    metrics.argonFixedWorkPath = fixedWork.argon.path;
    metrics.timedOut = raw.verified === null;
    metrics.difficulty = difficultyName;
    metrics.dimension = difficulty.dimension;
    metrics.execution = difficulty.dimension === 'execution';
    metrics.tier = tierName;
    metrics.cache = cacheState;
    metrics.assets = assetMode;
    metrics.rep = repIndex;
    metrics.cpuThrottle = tier.cpuThrottle;
    metrics.device = tier.device || null;
    metrics.viewport = `${contextOptions.viewport.width}x${contextOptions.viewport.height}`;
    metrics.dpr = contextOptions.deviceScaleFactor || 1;
    metrics.mobile = !!contextOptions.isMobile;
    if (!metrics.timedOut && metrics.solveMs === null && metrics.errorCount === 0) {
      metrics.notes = ['verified without a state stream'];
    }
    return metrics;
  } finally {
    if (page) await page.close().catch(() => {});
    if (warmContext === null && context) await context.close().catch(() => {});
  }
}

/**
 * The repeat-navigation measurement for a warm cell: after the reps have
 * populated the cache, one more navigation of the same URL in the same
 * context measures the fully-cached returning-user load (assets from
 * cache; only the challenge POST round trip is paid again). The result is
 * recorded as a named field on the cell, not as a solve rep.
 */
async function runRepeatNavigation(browser, opts, tierName, difficultyName, assetMode, warmContext) {
  const tier = TIERS[tierName];
  const difficulty = DIFFICULTIES[difficultyName];
  const base = `http://127.0.0.1:${opts.fixturePort}`;
  const assetsParam = assetMode === 'files' ? '&assets=files' : '';
  const url = base + '/' + difficulty.query(opts) + assetsParam;
  let page = null;
  try {
    page = await warmContext.newPage();
    await page.addInitScript(INIT_SCRIPT);
    const cdpSession = await warmContext.newCDPSession(page);
    await cdpSession.send('Emulation.setCPUThrottlingRate', { rate: tier.cpuThrottle });
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
    const isArgon = DIFFICULTIES[difficultyName].isArgon;
    const timeoutMs = isArgon ? 300000 : 90000;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const state = await page.evaluate(() => {
        const P = window.__kiwiPerf || {};
        return { verified: !!P.verified, errors: (P.errors || []).length };
      });
      if (state.verified) break;
      if (state.errors > 0) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    await new Promise((r) => setTimeout(r, 150));
    const raw = await collectPageMetrics(page);
    const m = computeMetrics(raw);
    return {
      pageToVerifiedMs: m.pageToVerifiedMs,
      domContentLoadedMs: m.domContentLoadedMs,
      loadMs: m.loadMs,
      transferredBytes: m.transferredBytes,
      cacheHitCount: m.cacheHitCount,
      resourceCount: m.resourceCount,
      timedOut: raw.verified === null,
    };
  } finally {
    if (page) await page.close().catch(() => {});
  }
}

/**
 * Run one cell: one (tier, difficulty, cache, assets) configuration.
 * The cell list is built once and executed in seeded random order by
 * the caller; each cell owns its warm context (one context per cell by
 * design) and its fresh contexts per load for cold cells. The warm
 * context is pre-warmed with one discarded load (fixed-work probes
 * skipped there) so every recorded warm rep is a cache-hit load.
 */
async function runCell(browser, opts, cell, results) {
  const { tier: tierName, difficulty: difficultyName, cache: cacheState, assets: assetMode } = cell;
  const reps = DIFFICULTIES[difficultyName].isArgon ? opts.argonReps : opts.reps;
  let warmContext = null;
  if (cacheState === 'warm') {
    warmContext = await browser.newContext(tierContextOptions(tierName));
    // Warm-cache semantics: the context is pre-warmed with one
    // discarded load before any recorded rep, so every recorded
    // warm rep is a genuinely cache-hit load (the returning-user
    // path), not the populating load. For Argon files-mode cells
    // the pre-warm also completes a solve, which fetches and
    // caches the lazy runtime and worker assets.
    try {
      await runLoad(browser, opts, tierName, difficultyName, assetMode, warmContext, -1, false);
      process.stdout.write(`  ${tierName}/${difficultyName}/${assetMode}/warm pre-warmed the context (rep 0 discarded)`);
      console.log('');
    } catch (e) {
      process.stderr.write(`  ${tierName}/${difficultyName}/${assetMode}/warm pre-warm failed: ${e.message}\n`);
    }
  }
  const samples = [];
  let repeatNav = null;
  try {
    for (let rep = 0; rep < reps; rep += 1) {
      let m;
      try {
        m = await runLoad(browser, opts, tierName, difficultyName, assetMode, cacheState === 'warm' ? warmContext : null, rep);
      } catch (e) {
        // A transient page/browser close under throttling must not
        // abort the whole matrix: the rep is recorded as a failed
        // sample and the cell continues. A cell whose samples all
        // failed still lands with its errorCount, which the
        // results language treats as a measured failure.
        process.stderr.write(`  ${tierName}/${difficultyName}/${assetMode}/${cacheState} rep ${rep + 1} failed: ${e.message}\n`);
        m = {
          tier: tierName,
          difficulty: difficultyName,
          cache: cacheState,
          assets: assetMode,
          rep,
          timedOut: true,
          errorCount: 1,
          errorMessage: String(e.message || e).slice(0, 200),
          solveMs: null,
          pureSolveMs: null,
          pageToVerifiedMs: null,
          bootstrapToConnectingMs: null,
          jsParseCompileMs: null,
          inlineScriptEvalMs: null,
          wasmCompileMs: null,
          wasmInstantiateMs: null,
          workerStartupMs: null,
          longTaskCount: 0,
          longTaskTotalMs: 0,
          longTaskMaxMs: null,
          peakHeapMb: null,
          finalHeapMb: null,
          domContentLoadedMs: null,
          loadMs: null,
          transferredBytes: null,
          cacheHitCount: null,
          resourceCount: null,
          runtimeLazyFetchStartMs: null,
          runtimeLazyFetchDurationMs: null,
          driverFetchStartMs: null,
          driverFetchDurationMs: null,
          executionFetchStartMs: null,
          executionFetchDurationMs: null,
          shaFixedWorkN: opts.shaFixedWork,
          shaFixedWorkMs: null,
          shaHashesPerSec: null,
          shaFixedWorkPath: null,
          argonFixedWorkN: opts.argonFixedWork,
          argonFixedWorkMs: null,
          argonDerivationsPerSec: null,
          argonFixedWorkPath: null,
        };
      }
      samples.push(m);
      process.stdout.write(
        `  ${tierName}/${difficultyName}/${assetMode}/${cacheState} rep ${rep + 1}/${reps}: ` +
          `solve ${m.solveMs === null ? '-' : m.solveMs.toFixed(0)} ms` +
          ` (p2v ${m.pageToVerifiedMs === null ? '-' : m.pageToVerifiedMs.toFixed(0)} ms` +
          `, tx ${m.transferredBytes} B` +
          `, cachehits ${m.cacheHitCount}` +
          `, js ${m.jsParseCompileMs === null ? '-' : m.jsParseCompileMs.toFixed(0)} ms` +
          `, wasmC ${m.wasmCompileMs === null ? '-' : m.wasmCompileMs.toFixed(0)} ms` +
          (m.workerStartupMs !== null ? `, worker ${m.workerStartupMs.toFixed(0)} ms` : '') +
          `, longtasks ${m.longTaskCount}(${m.longTaskTotalMs.toFixed(0)} ms)` +
          `, heap ${m.peakHeapMb === null ? '-' : m.peakHeapMb.toFixed(1)} MB` +
          `, sha ${m.shaHashesPerSec === null ? '-' : m.shaHashesPerSec.toFixed(0)} h/s` +
          `, argon ${m.argonDerivationsPerSec === null ? '-' : m.argonDerivationsPerSec.toFixed(2)} d/s` +
          (m.timedOut ? ' TIMED OUT' : '') +
          (m.errorCount ? ` ERRORS=${m.errorCount}` : '') +
          `)`,
      );
      console.log('');
    }
  } finally {
    if (warmContext) {
      if (cacheState === 'warm' && samples.length > 0) {
        try {
          repeatNav = await runRepeatNavigation(browser, opts, tierName, difficultyName, assetMode, warmContext);
        } catch (e) {
          process.stderr.write(`  repeat-navigation measurement failed: ${e.message}\n`);
        }
      }
      if (repeatNav) {
        process.stdout.write(
          `  repeat navigation ${tierName}/${difficultyName}/${assetMode}/warm: ` +
            `p2v ${repeatNav.pageToVerifiedMs === null ? '-' : repeatNav.pageToVerifiedMs.toFixed(0)} ms` +
            `, tx ${repeatNav.transferredBytes} B, cachehits ${repeatNav.cacheHitCount}, load ${repeatNav.loadMs === null ? '-' : repeatNav.loadMs.toFixed(0)} ms`,
        );
        console.log('');
      }
      await warmContext.close().catch(() => {});
    }
  }
  const key = `${tierName}:${difficultyName}:${cacheState}:${assetMode}`;
  const agg = { tier: tierName, difficulty: difficultyName, cache: cacheState, assets: assetMode, reps: samples };
  for (const metric of [
    'solveMs',
    'pureSolveMs',
    'pageToVerifiedMs',
    'bootstrapToConnectingMs',
    'jsParseCompileMs',
    'inlineScriptEvalMs',
    'wasmCompileMs',
    'wasmInstantiateMs',
    'workerStartupMs',
    'longTaskTotalMs',
    'longTaskMaxMs',
    'peakHeapMb',
    'domContentLoadedMs',
    'loadMs',
    'transferredBytes',
    'cacheHitCount',
    'resourceCount',
    'runtimeLazyFetchStartMs',
    'runtimeLazyFetchDurationMs',
    'driverFetchStartMs',
    'driverFetchDurationMs',
    'executionFetchStartMs',
    'executionFetchDurationMs',
    'shaHashesPerSec',
    'shaFixedWorkMs',
    'argonDerivationsPerSec',
    'argonFixedWorkMs',
  ]) {
    agg[metric] = summarize(samples.map((s) => s[metric]).filter((v) => v !== null && v !== undefined));
  }
  agg.longTaskCount = summarize(samples.map((s) => s.longTaskCount).filter((v) => v !== null));
  agg.timedOutCount = samples.filter((s) => s.timedOut).length;
  agg.errorCount = samples.filter((s) => s.errorCount > 0).length;
  if (repeatNav) {
    agg.repeatNavigation = repeatNav;
  }
  results[key] = agg;
}

async function runMultiWidget(browser, opts, results) {
  if (!opts.multiWidget) return;
  const base = `http://127.0.0.1:${opts.fixturePort}`;
  const assetModes = opts.assets === 'both' ? ['inline', 'files'] : [opts.assets];
  for (const assetMode of assetModes) {
    const assetsParam = assetMode === 'files' ? '&assets=files' : '';
    const url = `${base}/?widgets=3&bits=18${assetsParam}`;
    const samples = [];
    for (let rep = 0; rep < opts.multiWidgetReps; rep += 1) {
      const context = await browser.newContext(tierContextOptions('mainstream-desktop'));
      const page = await context.newPage();
      try {
        await page.addInitScript(INIT_SCRIPT);
        const cdpSession = await context.newCDPSession(page);
        await cdpSession.send('Emulation.setCPUThrottlingRate', { rate: 1 });
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
        const deadline = Date.now() + 120000;
        let state;
        while (Date.now() < deadline) {
          state = await page.evaluate(() => {
            const P = window.__kiwiPerf || {};
            return { verifiedCount: Object.keys(P.verifiedWidgets || {}).length, errors: (P.errors || []).length };
          });
          if (state.verifiedCount >= 3) break;
          if (state.errors > 0) break;
          await new Promise((r) => setTimeout(r, 100));
        }
        await new Promise((r) => setTimeout(r, 150));
        const fixedWork = await measureFixedWork(page, opts);
        const raw = await collectPageMetrics(page);
        const widgets = await page.evaluate(() => document.querySelectorAll('[data-kiwi-widget]').length);
        const verifiedTimes = Object.values(raw.verifiedWidgets || {});
        const lt = (raw.longTasks || []).map((l) => l.duration);
        const mem = raw.memSamples || [];
        const m = computeMetrics(raw);
        const sample = {
          widgets,
          verifiedCount: verifiedTimes.length,
          allVerifiedMs: verifiedTimes.length ? Math.max(...verifiedTimes) : null,
          firstVerifiedMs: verifiedTimes.length ? Math.min(...verifiedTimes) : null,
          spreadMs: verifiedTimes.length ? Math.max(...verifiedTimes) - Math.min(...verifiedTimes) : null,
          longTaskCount: lt.length,
          longTaskTotalMs: lt.reduce((a, b) => a + b, 0),
          peakHeapMb: mem.length ? Math.max(...mem) / (1024 * 1024) : null,
          transferredBytes: m.transferredBytes,
          cacheHitCount: m.cacheHitCount,
          resourceCount: m.resourceCount,
          shaFixedWorkN: fixedWork.sha.n,
          shaFixedWorkMs: fixedWork.sha.ms,
          shaHashesPerSec: fixedWork.sha.hashesPerSec,
          shaFixedWorkPath: fixedWork.sha.path,
          argonFixedWorkN: fixedWork.argon.n,
          argonFixedWorkMs: fixedWork.argon.ms,
          argonDerivationsPerSec: fixedWork.argon.derivationsPerSec,
          argonFixedWorkPath: fixedWork.argon.path,
          errorCount: (raw.errors || []).length,
          timedOut: verifiedTimes.length < widgets,
        };
        samples.push(sample);
        process.stdout.write(
          `  multi-widget (${widgets} widgets, sha18, ${assetMode}) rep ${rep + 1}/${opts.multiWidgetReps}: ` +
            `all-verified ${sample.allVerifiedMs?.toFixed(0)} ms, ` +
            `spread ${sample.spreadMs?.toFixed(0)} ms, ` +
            `tx ${sample.transferredBytes} B, ` +
            `longtasks ${sample.longTaskCount}(${sample.longTaskTotalMs.toFixed(0)} ms)` +
            `, heap ${sample.peakHeapMb?.toFixed(1)} MB` +
            `, sha ${sample.shaHashesPerSec === null ? '-' : sample.shaHashesPerSec.toFixed(0)} h/s` +
            `, argon ${sample.argonDerivationsPerSec === null ? '-' : sample.argonDerivationsPerSec.toFixed(2)} d/s`,
        );
        console.log('');
      } finally {
        await page.close().catch(() => {});
        await context.close().catch(() => {});
      }
    }
    results[`multi-widget:sha18:3-widgets:${assetMode}`] = {
      tier: 'mainstream-desktop',
      difficulty: 'sha18',
      widgets: 3,
      assets: assetMode,
      reps: samples,
      allVerifiedMs: summarize(samples.map((s) => s.allVerifiedMs).filter((v) => v !== null)),
      firstVerifiedMs: summarize(samples.map((s) => s.firstVerifiedMs).filter((v) => v !== null)),
      spreadMs: summarize(samples.map((s) => s.spreadMs).filter((v) => v !== null)),
      longTaskTotalMs: summarize(samples.map((s) => s.longTaskTotalMs)),
      peakHeapMb: summarize(samples.map((s) => s.peakHeapMb).filter((v) => v !== null)),
      transferredBytes: summarize(samples.map((s) => s.transferredBytes).filter((v) => v !== null)),
      shaHashesPerSec: summarize(samples.map((s) => s.shaHashesPerSec).filter((v) => v !== null)),
      argonDerivationsPerSec: summarize(samples.map((s) => s.argonDerivationsPerSec).filter((v) => v !== null)),
    };
  }
}

function environment() {
  const out = {
    os: `${os.type()} ${os.release()} (${os.arch()})`,
    machine: os.hostname(),
    node: process.version,
    cpus: os.cpus().length ? `${os.cpus().length} x ${os.cpus()[0].model.trim()}` : 'unknown',
  };
  try {
    out.php = execSync('php -v', { encoding: 'utf8' }).split('\n')[0];
  } catch (e) {
    out.php = 'unavailable';
  }
  return out;
}

/**
 * Fingerprint the served client assets at measurement time: the harness
 * measures whatever the working tree serves, so the results carry the
 * exact bytes (sha256 + sizes) they were measured against. The driver and
 * glue are edited by the delivery workstream, so this attribution is what
 * makes a re-measurement reconciliation possible.
 */
function clientAssets() {
  const assetsDir = join(REPO_ROOT, 'packages', 'kiwicaptcha-wasm', 'assets');
  const names = ['widget-driver.js', 'widget-risk.js', 'widget-telemetry.js', 'widget-compat.js', 'kiwicaptcha-wasm.js', 'kiwi-worker.js', 'execution-interpreter.js'];
  const out = {};
  for (const name of names) {
    const file = join(assetsDir, name);
    try {
      const bytes = readFileSync(file);
      out[name] = {
        bytes: bytes.length,
        sha256: createHash('sha256').update(bytes).digest('hex').slice(0, 16),
      };
    } catch (e) {
      out[name] = null;
    }
  }
  return out;
}

// ── Incomplete-run guard ─────────────────────────────────────────────
// The results payload carries the completion marker ONLY when the run
// traversed every configured cell without an error or an interrupt. A
// crashed or interrupted run writes its partial results WITHOUT the
// marker, and --promote-baseline refuses to promote any file that
// lacks it (or that does not cover the full default matrix at the
// default sample sizes and the real argon ladder).
let runCtx = null;

function resultsOutFile(opts, completed) {
  if (opts.out) return opts.out;
  const date = new Date().toISOString().slice(0, 10);
  if (completed) return join(RESULTS_DIR, `results-${date}.json`);
  const time = new Date().toISOString().slice(11, 19).replace(/:/g, '');
  return join(RESULTS_DIR, `results-${date}-partial-${time}.json`);
}

function buildPayload(opts, ctx, completion) {
  const tierNames = ctx.tierNames;
  return {
    schema: SCHEMA,
    generated_at: new Date().toISOString(),
    started_at: ctx.startedAt,
    harness: 'tools/client-perf/client-perf.mjs',
    chromium: ctx.chromiumVersion,
    environment: environment(),
    clientAssets: clientAssets(),
    completion,
    methodology: {
      note: 'desktop CPU-throttled emulation: the tiers are Playwright device descriptors plus CDP Emulation.setCPUThrottlingRate on an Apple silicon Mac. The emulation approximates the named device classes on a desktop CPU; it does NOT reproduce real device thermals, battery saver, or the real device browser JIT/wasm behavior. These numbers are desktop-emulation evidence only and make no low-end-mobile claim; the physical-device tiers described in README.md are the release boundary.',
      cellOrder: {
        strategy: 'seeded-random-shuffle',
        seed: ctx.seed,
        cells: ctx.executedOrder.map((c) => `${c.tier}:${c.difficulty}:${c.cache}:${c.assets}`),
        note: 'every configured cell is executed exactly once in a seeded random order, so host drift (thermal, memory, scheduler) is not systematically correlated with cell identity; the seed is recorded so any run is reproducible.',
      },
      processIsolation: {
        note: 'a fresh Chromium process is launched per tier (and for the multi-widget scenario) and closed when the tier is done, so long-running browser degradation cannot bleed across tiers; cold cells use a fresh context per load, warm cells one context per cell by design (the warm-cache semantics require reuse).',
      },
      fixedWork: {
        shaHashes: opts.shaFixedWork,
        shaTargetBits: FIXED_WORK_SHA_TARGET_BITS,
        argonDerivations: opts.argonFixedWork,
        argonEnvelope: { mKib: opts.argonMKib, t: FIXED_WORK_ARGON_T, p: FIXED_WORK_ARGON_P },
        note: 'fixed-work throughput is recorded per repetition and per cell: a fixed-N SHA-256 loop measured on the page main thread (the wasm chunk export the inline solver uses, or the pure-JS implementation for files-mode cells, whichever the asset mode actually solves with) and a fixed-N Argon2id derivation loop at the exact adaptive-risk envelope, measured in a harness-owned worker built from the exact served runtime bytes. These separate solver implementation speed from nonce-search luck and act as a per-cell host-state drift probe.',
      },
      cooldown: {
        note: 'between serious calibration runs, let the host cool down for a few idle minutes (no browser, no background load) and run the matrix only on an otherwise idle machine; thermal, memory and scheduler state contaminate cells, which is why the run records fixed-work throughput per cell as the drift probe.',
      },
      sampleSizes: {
        shaReps: opts.reps,
        argonReps: opts.argonReps,
        note: 'SHA-256 cells default to 50 reps and Argon2id cells to 20 reps so p95/p99 are computed over a defensible sample; --samples N raises both, --quick lowers them for iteration. The execution cells inherit the rep count of their PoW profile (execvm, execsha18, execvminline and execsha18inline use the SHA count, execargon and execchain the Argon count).',
      },
      argonLadder: {
        mKib: opts.argonMKib,
        targetBits: opts.argonBits,
        note: 'the real adaptive-risk ladder (16 MiB envelope, target 8) as chosen by the server-side RiskProfileResolver, not the fixture envelope default.',
      },
      coldWarm: {
        note: 'cold = a fresh context per load with the HTTP cache disabled, so every byte is re-fetched; warm = one reused context whose cache is enabled and populated by the first rep, so reps 2+ are cache-hit loads. The repeat-navigation field after the warm reps measures the fully-cached load.',
      },
      assets: {
        inline: 'the fixture inlines the wasm glue and the driver in the page HTML; the container still carries the SRI-linked execution interpreter attrs (data-kiwi-execution-src + integrity) in both tiers, mirroring the bundle theme, so an armed inline page lazily fetches the interpreter exactly once',
        files: 'the ?assets=files fixture variant: versioned SRI-linked external assets, page-level dedup, a lazy Argon runtime that is fetched only when a memory-hard challenge arrives, and the lazy execution interpreter that is fetched only when an armed challenge arrives',
      },
    },
    fixture: {
      router: 'tests/browser/router.php',
      port: opts.fixturePort,
      php: opts.php,
      note: 'opt-in difficulty knobs (bits/argon_bits/m_kib), the assets=files knob, and the execution arms (?execution=1 armed challenges, ?escalate=argon chained escalation); the fixture default behavior is unchanged',
    },
    tiers: Object.fromEntries(
      tierNames.map((t) => [
        t,
        { label: TIERS[t].label, device: TIERS[t].device || null, cpuThrottle: TIERS[t].cpuThrottle },
      ]),
    ),
    difficulties: Object.fromEntries(
      opts.difficulties.map((d) => [
        d,
        {
          label: DIFFICULTIES[d].label,
          dimension: DIFFICULTIES[d].dimension,
          query: DIFFICULTIES[d].query(opts),
          assetModes: DIFFICULTIES[d].assetModes || ['inline', 'files'],
        },
      ]),
    ),
    options: {
      reps: opts.reps,
      argonReps: opts.argonReps,
      cache: opts.cache,
      assets: opts.assets,
      argonBits: opts.argonBits,
      argonMKib: opts.argonMKib,
      multiWidget: opts.multiWidget,
      multiWidgetReps: opts.multiWidgetReps,
      seed: ctx.seed,
      shaFixedWork: opts.shaFixedWork,
      argonFixedWork: opts.argonFixedWork,
    },
    results: ctx.results,
  };
}

/**
 * The baseline loader (--promote-baseline FILE). Refuses, with the
 * reasons, any results file that is not a clean completed full-matrix
 * run: the completion marker must be present (the incomplete-run
 * guard), the full default matrix must be covered (all seven tiers,
 * all ten difficulties — the four ordinary cells plus the six
 * ExecutionChallengeV1 cells, of which execvm/execsha18/execargon/
 * execchain are files-only and execvminline/execsha18inline are
 * inline-only by design — cold and warm across each cell's asset
 * modes), the sample sizes must
 * meet the defaults, and the argon ladder must be the real one. Only
 * then is the file copied to results/baseline.json. The current
 * committed baseline.json stays untouched by every run; it is replaced
 * only through this loader.
 */
function promoteBaseline(file, baselinePath) {
  let payload;
  try {
    payload = JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) {
    console.error(`promote-baseline: cannot read results file ${file}: ${e.message}`);
    return false;
  }
  const reasons = [];
  if (payload.schema !== SCHEMA) {
    reasons.push(`schema ${payload.schema} is not the current ${SCHEMA}`);
  }
  const completion = payload.completion || {};
  if (completion.status !== 'completed' || completion.marker !== COMPLETION_MARKER) {
    reasons.push(
      `no completion marker (status ${JSON.stringify(completion.status)}): the incomplete-run guard refuses any run that crashed or was interrupted`,
    );
  } else {
    const have = new Set(
      Object.keys(payload.results || {}).filter((k) => k.indexOf('multi-widget') !== 0),
    );
    const expected = [];
    for (const t of Object.keys(TIERS)) {
      for (const d of Object.keys(DIFFICULTIES)) {
        const modes = DIFFICULTIES[d].assetModes || ['inline', 'files'];
        for (const c of ['cold', 'warm']) {
          for (const a of modes) {
            expected.push(`${t}:${d}:${c}:${a}`);
          }
        }
      }
    }
    const missing = expected.filter((k) => !have.has(k));
    if (missing.length) {
      reasons.push(`${missing.length} cells of the full matrix missing (e.g. ${missing.slice(0, 3).join(', ')})`);
    }
    const o = payload.options || {};
    if (!(o.reps >= 50)) reasons.push(`SHA reps ${o.reps} below the 50-sample default`);
    if (!(o.argonReps >= 20)) reasons.push(`Argon reps ${o.argonReps} below the 20-sample default`);
    if (o.cache !== 'both') reasons.push(`cache option ${o.cache} is not 'both'`);
    if (o.assets !== 'both') reasons.push(`assets option ${o.assets} is not 'both'`);
    if (o.argonMKib !== 16384) reasons.push(`argon envelope ${o.argonMKib} KiB is not the real ladder 16384`);
    if (o.argonBits !== 8) reasons.push(`argon target ${o.argonBits} is not the real ladder 8`);
  }
  if (reasons.length) {
    console.error('promote-baseline refused:');
    for (const r of reasons) console.error(`  - ${r}`);
    return false;
  }
  const cur = clientAssets();
  const rec = payload.clientAssets || {};
  for (const name of Object.keys(cur)) {
    const a = cur[name];
    const b = rec[name];
    if (b && (a.bytes !== b.bytes || a.sha256 !== b.sha256)) {
      console.warn(
        `promote-baseline: warning — ${name} differs from the measured run (${b.bytes} bytes/${b.sha256} then, ${a.bytes} bytes/${a.sha256} now); the baseline stays historical evidence of the recorded bytes`,
      );
    }
  }
  mkdirSync(dirname(baselinePath), { recursive: true });
  writeFileSync(baselinePath, JSON.stringify(payload, null, 2) + '\n');
  console.log(
    `promote-baseline: baseline written to ${baselinePath} (schema ${payload.schema}, ${Object.keys(payload.results || {}).length} cells, generated ${payload.generated_at})`,
  );
  return true;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.promoteBaseline) {
    const ok = promoteBaseline(opts.promoteBaseline, join(RESULTS_DIR, 'baseline.json'));
    process.exit(ok ? 0 : 1);
    return;
  }
  const tierNames = opts.tiers ?? Object.keys(TIERS);
  for (const t of tierNames) {
    if (!TIERS[t]) {
      console.error(`unknown tier: ${t}`);
      process.exit(2);
    }
  }
  for (const d of opts.difficulties) {
    if (!DIFFICULTIES[d]) {
      console.error(`unknown difficulty: ${d}`);
      process.exit(2);
    }
  }
  if (!['cold', 'warm', 'both'].includes(opts.cache)) {
    console.error(`invalid --cache value: ${opts.cache}`);
    process.exit(2);
  }
  if (!['inline', 'files', 'both'].includes(opts.assets)) {
    console.error(`invalid --assets value: ${opts.assets}`);
    process.exit(2);
  }

  const seed = opts.seed ?? Math.floor(Date.now());
  const cells = seededShuffle(buildCellList(opts, tierNames), mulberry32(seed));
  const fixture = await bootFixture(opts);
  const startedAt = new Date().toISOString();
  const ctx = {
    opts,
    tierNames,
    seed,
    cells,
    executedOrder: [],
    results: {},
    fixture,
    browser: null,
    chromiumVersion: null,
    startedAt,
  };
  runCtx = ctx;
  console.log(`cell execution order: seeded random (seed ${seed}, ${cells.length} cells)`);
  for (const c of cells) console.log(`  ${c.tier}:${c.difficulty}:${c.cache}:${c.assets}`);
  const completion = { status: 'interrupted', signal: null, error: null };
  try {
    for (const tierName of tierNames) {
      const tier = TIERS[tierName];
      const tierCells = cells.filter((c) => c.tier === tierName);
      // FRESH BROWSER PROCESS PER TIER: a long-lived Chromium process
      // degrades (memory growth, scheduler affinity, renderer state),
      // so the tier boundary is also a process boundary; the tier's
      // cells run in their seeded-random relative order.
      let browser = null;
      try {
        browser = await chromium.launch({ headless: true });
        ctx.browser = browser;
        if (ctx.chromiumVersion === null) {
          ctx.chromiumVersion = browser.version();
          console.log(`chromium ${ctx.chromiumVersion} (fixture ${opts.noFixture ? 'external' : 'spawned'})`);
        }
        console.log(`tier ${tierName} (${tier.label}, CPU x${tier.cpuThrottle}) — fresh process, ${tierCells.length} cells`);
        for (const cell of tierCells) {
          ctx.executedOrder.push(cell);
          await runCell(browser, opts, cell, ctx.results);
        }
      } finally {
        if (browser) {
          await browser.close().catch(() => {});
          ctx.browser = null;
        }
      }
    }
    if (opts.multiWidget) {
      let browser = null;
      try {
        browser = await chromium.launch({ headless: true });
        ctx.browser = browser;
        console.log('multi-widget scenario (fresh process)');
        await runMultiWidget(browser, opts, ctx.results);
      } finally {
        if (browser) {
          await browser.close().catch(() => {});
          ctx.browser = null;
        }
      }
    }
    completion.status = 'completed';
    completion.marker = COMPLETION_MARKER;
  } catch (e) {
    completion.status = 'failed';
    completion.error = String((e && e.message) || e);
    throw e;
  } finally {
    if (ctx.browser) await ctx.browser.close().catch(() => {});
    if (fixture) fixture.kill('SIGKILL');
    const completed = completion.status === 'completed';
    const outFile = resultsOutFile(opts, completed);
    mkdirSync(dirname(outFile), { recursive: true });
    const payload = buildPayload(opts, ctx, completion);
    writeFileSync(outFile, JSON.stringify(payload, null, 2) + '\n');
    if (completed) {
      console.log(`\nresults written to ${outFile} (completed; carries the completion marker ${COMPLETION_MARKER})`);
    } else {
      console.error(`\nrun did not complete (${completion.status}); partial results written to ${outFile} WITHOUT the completion marker — this file can never be promoted to baseline`);
    }
  }
}

process.on('SIGINT', () => {
  if (!runCtx) process.exit(130);
  const ctx = runCtx;
  if (ctx.browser && ctx.browser.process) {
    try { ctx.browser.process().kill('SIGKILL'); } catch (e) {}
  }
  if (ctx.fixture) {
    try { ctx.fixture.kill('SIGKILL'); } catch (e) {}
  }
  try {
    const outFile = resultsOutFile(ctx.opts, false);
    mkdirSync(dirname(outFile), { recursive: true });
    const payload = buildPayload(ctx.opts, ctx, { status: 'interrupted', signal: 'SIGINT', error: null });
    writeFileSync(outFile, JSON.stringify(payload, null, 2) + '\n');
    console.error(`\ninterrupted by SIGINT: partial results written to ${outFile} WITHOUT the completion marker — this file can never be promoted to baseline`);
  } catch (e) {
    console.error(`\ninterrupted by SIGINT; could not write partial results: ${e.message}`);
  }
  process.exit(130);
});

process.on('SIGTERM', () => {
  if (!runCtx) process.exit(143);
  const ctx = runCtx;
  if (ctx.browser && ctx.browser.process) {
    try { ctx.browser.process().kill('SIGKILL'); } catch (e) {}
  }
  if (ctx.fixture) {
    try { ctx.fixture.kill('SIGKILL'); } catch (e) {}
  }
  try {
    const outFile = resultsOutFile(ctx.opts, false);
    mkdirSync(dirname(outFile), { recursive: true });
    const payload = buildPayload(ctx.opts, ctx, { status: 'interrupted', signal: 'SIGTERM', error: null });
    writeFileSync(outFile, JSON.stringify(payload, null, 2) + '\n');
    console.error(`\ninterrupted by SIGTERM: partial results written to ${outFile} WITHOUT the completion marker — this file can never be promoted to baseline`);
  } catch (e) {
    console.error(`\ninterrupted by SIGTERM; could not write partial results: ${e.message}`);
  }
  process.exit(143);
});

main().then(
  () => process.exit(0),
  (e) => {
    console.error(e);
    process.exit(1);
  },
);
