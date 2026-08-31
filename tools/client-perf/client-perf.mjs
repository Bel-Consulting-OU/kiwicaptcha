#!/usr/bin/env node
/**
 * KiwiCaptcha client-performance harness (tools/client-perf).
 *
 * A Playwright-based client benchmark that drives the browser fixture
 * (tests/browser/router.php) and measures, per difficulty tier
 * (SHA-256 16/18/20 bits + Argon2id) and per asset mode (inline vs
 * files, the ?assets=files fixture variant):
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
 * Usage:
 *   node tools/client-perf/client-perf.mjs [--tiers all] [--reps 50]
 *     [--argon-reps 20] [--samples N] [--cache both] [--assets both]
 *     [--fixture-port 8091] [--out FILE]
 *   node tools/client-perf/client-perf.mjs --quick
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

const SCHEMA = 'kiwicaptcha.client-perf/2';

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
  sha16: { label: 'SHA-256, 16 leading zero bits', query: () => '?bits=16' },
  sha18: { label: 'SHA-256, 18 leading zero bits', query: () => '?bits=18' },
  sha20: { label: 'SHA-256, 20 leading zero bits', query: () => '?bits=20' },
  argon2id: {
    label: 'Argon2id (m=16384 KiB, t=3, p=1, target 8)',
    query: (o) => `?algorithm=argon2id&argon_bits=${o.argonBits}&m_kib=${o.argonMKib}`,
  },
};

function parseArgs(argv) {
  const opts = {
    tiers: null, // null = all
    difficulties: ['sha16', 'sha18', 'sha20', 'argon2id'],
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
  --difficulties <list>   comma list (default: sha16,sha18,sha20,argon2id)
  --reps N                SHA-256 solve repetitions per tier/difficulty/cache/assets
                          (default 50; the percentile-supporting range is 50-100)
  --argon-reps N          Argon2id repetitions per cell (default 20; range 20-30)
  --samples N             shorthand for --reps N --argon-reps N
  --cache <cold|warm|both>  cold = fresh context per load with the HTTP
                          cache disabled; warm = one reused context with
                          the cache enabled and populated (default both)
  --assets <inline|files|both>  inline = the fixture's inlined wasm glue
                          and driver; files = the ?assets=files variant
                          (external SRI assets, lazy Argon runtime).
                          Default both.
  --fixture-port N        fixture server port (default 8091)
  --no-fixture            attach to an already-running fixture (e.g. the
                          playwright lane on 8085)
  --php BIN               php binary for the fixture (default php)
  --argon-bits N          argon2id target bits for the argon tier (default 8,
                          the real adaptive-risk ladder highest rung)
  --argon-m-kib N         argon2id memory KiB for the argon tier (default 16384,
                          the real ladder envelope; the fixture clamps to
                          8..65536 KiB, so 16384 is permitted)
  --no-multi-widget       skip the multiple-widget scenario
  --quick                 iteration mode: low-android + mainstream-desktop,
                          3 SHA / 2 Argon reps, cold and warm, inline and files
  --out FILE              results file (default results/results-<date>.json)
  --help                  this text

Output: machine-readable JSON (schema ${SCHEMA}) written to
  tools/client-perf/results/results-<date>.json, and the committed
  baseline at tools/client-perf/results/baseline.json.
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
    errorCount: (raw.errors || []).length,
    errors: (raw.errors || []).map((e) => ({ t: e.t, workerUnavailable: !!e.workerUnavailable, detail: e.detail || {} })),
  };
}

async function runLoad(browser, opts, tierName, difficultyName, assetMode, warmContext, repIndex) {
  const tier = TIERS[tierName];
  const difficulty = DIFFICULTIES[difficultyName];
  const contextOptions = tierContextOptions(tierName);
  const base = `http://127.0.0.1:${opts.fixturePort}`;
  const assetsParam = assetMode === 'files' ? '&assets=files' : '';
  const url = base + '/' + difficulty.query(opts) + assetsParam;
  const cacheState = warmContext === null ? 'cold' : 'warm';
  let context = null;
  let page = null;
  try {
    if (warmContext === null) {
      context = await browser.newContext(contextOptions);
    } else {
      context = warmContext;
    }
    page = await context.newPage();
    await page.addInitScript(INIT_SCRIPT);
    const cdpSession = await context.newCDPSession(page);
    await cdpSession.send('Emulation.setCPUThrottlingRate', { rate: tier.cpuThrottle });
    if (cacheState === 'cold') {
      await cdpSession.send('Network.enable');
      await cdpSession.send('Network.setCacheDisabled', { cacheDisabled: true });
    }
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
    const isArgon = difficultyName === 'argon2id';
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
    const metrics = computeMetrics(raw);
    const inlineScripts = await measureInlineScripts(page);
    metrics.inlineScriptEvalMs = inlineScripts.length ? inlineScripts.reduce((a, b) => a + b.ms, 0) : null;
    metrics.inlineScriptEvalCount = inlineScripts.length;
    metrics.inlineScriptEvalPerScriptMs = inlineScripts.map((i) => i.ms);
    metrics.timedOut = raw.verified === null;
    metrics.difficulty = difficultyName;
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
    const isArgon = difficultyName === 'argon2id';
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

async function runTier(browser, opts, tierName, difficulties, results) {
  const assetModes = opts.assets === 'both' ? ['inline', 'files'] : [opts.assets];
  for (const assetMode of assetModes) {
    for (const difficultyName of difficulties) {
      const reps = difficultyName === 'argon2id' ? opts.argonReps : opts.reps;
      const caches = opts.cache === 'both' ? ['cold', 'warm'] : [opts.cache];
      for (const cacheState of caches) {
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
            await runLoad(browser, opts, tierName, difficultyName, assetMode, warmContext, -1);
            process.stdout.write(
              `  ${tierName}/${difficultyName}/${assetMode}/warm pre-warmed the context (rep 0 discarded)\n`,
            );
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
    }
  }
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
            `, heap ${sample.peakHeapMb?.toFixed(1)} MB`,
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
  const names = ['widget-driver.js', 'kiwicaptcha-wasm.js', 'kiwi-worker.js'];
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

async function main() {
  const opts = parseArgs(process.argv.slice(2));
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

  const fixture = await bootFixture(opts);
  const startedAt = new Date().toISOString();
  const results = {};

  let browser;
  let chromiumVersion = null;
  try {
    browser = await chromium.launch({ headless: true });
    chromiumVersion = browser.version();
    console.log(`chromium ${chromiumVersion} (fixture ${opts.noFixture ? 'external' : 'spawned'})`);
    for (const tierName of tierNames) {
      const tier = TIERS[tierName];
      console.log(`tier ${tierName} (${tier.label}, CPU x${tier.cpuThrottle})`);
      await runTier(browser, opts, tierName, opts.difficulties, results);
    }
    await runMultiWidget(browser, opts, results);
  } finally {
    if (browser) await browser.close().catch(() => {});
    if (fixture) fixture.kill('SIGKILL');
  }

  const outFile =
    opts.out || join(RESULTS_DIR, `results-${new Date().toISOString().slice(0, 10)}.json`);
  mkdirSync(dirname(outFile), { recursive: true });
  const payload = {
    schema: SCHEMA,
    generated_at: new Date().toISOString(),
    started_at: startedAt,
    harness: 'tools/client-perf/client-perf.mjs',
    chromium: chromiumVersion,
    environment: environment(),
    clientAssets: clientAssets(),
    methodology: {
      note: 'desktop CPU-throttled emulation: the tiers are Playwright device descriptors plus CDP Emulation.setCPUThrottlingRate on an Apple silicon Mac. The emulation approximates the named device classes on a desktop CPU; it does NOT reproduce real device thermals, battery saver, or the real device browser JIT/wasm behavior. These numbers are desktop-emulation evidence only and make no low-end-mobile claim; the physical-device tiers described in README.md are the release boundary.',
      sampleSizes: {
        shaReps: opts.reps,
        argonReps: opts.argonReps,
        note: 'SHA-256 cells default to 50 reps and Argon2id cells to 20 reps so p95/p99 are computed over a defensible sample; --samples N raises both, --quick lowers them for iteration.',
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
        inline: 'the fixture inlines the wasm glue and the driver in the page HTML',
        files: 'the ?assets=files fixture variant: versioned SRI-linked external assets, page-level dedup, and a lazy Argon runtime that is fetched only when a memory-hard challenge arrives',
      },
    },
    fixture: {
      router: 'tests/browser/router.php',
      port: opts.fixturePort,
      php: opts.php,
      note: 'opt-in difficulty knobs (bits/argon_bits/m_kib) and the assets=files knob; the fixture default behavior is unchanged',
    },
    tiers: Object.fromEntries(
      tierNames.map((t) => [
        t,
        { label: TIERS[t].label, device: TIERS[t].device || null, cpuThrottle: TIERS[t].cpuThrottle },
      ]),
    ),
    difficulties: Object.fromEntries(
      opts.difficulties.map((d) => [d, { label: DIFFICULTIES[d].label, query: DIFFICULTIES[d].query(opts) }]),
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
    },
    results,
  };

  writeFileSync(outFile, JSON.stringify(payload, null, 2) + '\n');
  console.log(`\nresults written to ${outFile}`);
  return payload;
}

main().then(
  () => process.exit(0),
  (e) => {
    console.error(e);
    process.exit(1);
  },
);
