#!/usr/bin/env node
/**
 * KiwiCaptcha client-performance harness (tools/client-perf).
 *
 * A Playwright-based client benchmark that drives the browser fixture
 * (tests/browser/router.php) and measures, per difficulty tier
 * (SHA-256 16/18/20 bits + Argon2id):
 *
 *   - solve time (challenge fetch start -> kiwi:verified) and the pure
 *     proof computation (solving state -> verified): p50/p95/p99,
 *   - page-to-verified time (navigation start -> verified),
 *   - JS parse/compile/eval time: the Long Animation Frames script
 *     entries (performance entries; the fixture inlines the wasm glue
 *     and the driver), plus the script-timing entries when the build
 *     exposes them,
 *   - WASM compile + instantiate time (WebAssembly wrappers, main
 *     thread),
 *   - worker startup latency for Argon2id (Worker constructor -> first
 *     message, i.e. the driver's ready handshake),
 *   - main-thread blocking (Long Task API): count, total, p95,
 *   - peak JS heap (performance.memory samples + final heap),
 *   - cold-cache vs warm-cache loads: a cold load runs in a fresh
 *     browser context with the HTTP cache disabled (every byte is
 *     re-fetched); a warm load reuses one context whose cache is
 *     enabled and already populated by the previous rep. Note: the
 *     fixture page inlines all its assets, so for this fixture the
 *     cache state mostly reflects connection/context reuse; the
 *     mechanism stays in place for pages with external assets (see
 *     README.md).
 *   - multiple-widget pages (the ?widgets=N fixture page).
 *
 * Device tiers come from Playwright device emulation plus CDP CPU
 * throttling (Emulation.setCPUThrottlingRate). See README.md for the
 * tier table and the release-qualification procedure (physical-device
 * tiers are the release boundary; the emulation tiers are runnable
 * now).
 *
 * Usage:
 *   node tools/client-perf/client-perf.mjs [--tiers all] [--reps 5]
 *     [--cache both] [--fixture-port 8091] [--out FILE]
 *   node tools/client-perf/client-perf.mjs --help
 */
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
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

const SCHEMA = 'kiwicaptcha.client-perf/1';

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
    label: 'Argon2id (m_kib, t=3, p=1)',
    query: (o) => `?algorithm=argon2id&argon_bits=${o.argonBits}&m_kib=${o.argonMKib}`,
  },
};

function parseArgs(argv) {
  const opts = {
    tiers: null, // null = all
    difficulties: ['sha16', 'sha18', 'sha20', 'argon2id'],
    reps: 5,
    argonReps: 3,
    cache: 'both', // cold | warm | both
    fixturePort: 8091,
    noFixture: false,
    php: 'php',
    out: null,
    argonBits: 4,
    argonMKib: 64,
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
      case '--cache':
        opts.cache = next();
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
  --reps N                solve repetitions per tier/difficulty/cache (default 5)
  --argon-reps N          repetitions for the argon2id tier (default 3)
  --cache <cold|warm|both>  cold = fresh context per load with the HTTP
                          cache disabled; warm = one reused context with
                          the cache enabled and populated (default both)
  --fixture-port N        fixture server port (default 8091)
  --no-fixture            attach to an already-running fixture (e.g. the
                          playwright lane on 8085)
  --php BIN               php binary for the fixture (default php)
  --argon-bits N          argon2id target bits for the argon tier (default 4,
                          the fixture envelope; use 8 for the risk-ladder
                          highest rung, see README release-qualification)
  --argon-m-kib N         argon2id memory KiB for the argon tier (default 64;
                          use 16384 for the risk-ladder envelope)
  --no-multi-widget       skip the multiple-widget scenario
  --quick                 low-android + mainstream-desktop, 3 reps
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
    // Long-task and long-animation-frame entries are not retained in
    // the timeline by default (longtask) or only via the buffered
    // timeline (LAF), so the collection arms buffered observers and
    // reads the retained buffers; the init-script observer lists are
    // the fallback.
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
      memSamples: P.memSamples,
      finalHeap,
      nav: nav
        ? { domContentLoadedMs: nav.domContentLoadedEventEnd - nav.startTime, loadMs: nav.loadEventEnd - nav.startTime }
        : null,
    };
  });
}

/**
 * Measure the page's inline classic scripts (the wasm glue and the
 * widget driver — the fixture inlines them) with the browser's own V8:
 * each script's exact text is evaluated in an isolated same-origin
 * iframe under the active CPU throttle, and the wall time from script
 * insertion to the appended sentinel statement is the script's
 * parse + compile + eval time. The iframe is blank (no widget), so
 * executing the driver a second time has no page side effects. This
 * complements the long-animation-frame script entries (which only
 * populate when a frame exceeds 50 ms, i.e. on throttled tiers).
 */
async function measureInlineScripts(page) {
  return page.evaluate(() => {
    const sources = [];
    for (const s of document.querySelectorAll('script')) {
      if (s.src || (s.type && s.type !== 'text/javascript' && s.type !== 'application/javascript')) continue;
      if (s.textContent.trim().length < 100) continue;
      sources.push(s.textContent);
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
      const deadline = Date.now() + 30000;
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
    errorCount: (raw.errors || []).length,
    errors: (raw.errors || []).map((e) => ({ t: e.t, workerUnavailable: !!e.workerUnavailable, detail: e.detail || {} })),
  };
}

async function runLoad(browser, opts, tierName, difficultyName, warmContext, repIndex) {
  const tier = TIERS[tierName];
  const difficulty = DIFFICULTIES[difficultyName];
  const contextOptions = tierContextOptions(tierName);
  const base = `http://127.0.0.1:${opts.fixturePort}`;
  const url = base + '/' + difficulty.query(opts);
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
      // Cold-cache semantics: the HTTP cache is disabled, so every byte
      // is re-fetched; the fresh context additionally starts with an
      // empty cache.
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

async function runTier(browser, opts, tierName, difficulties, results) {
  for (const difficultyName of difficulties) {
    const reps = difficultyName === 'argon2id' ? opts.argonReps : opts.reps;
    const caches = opts.cache === 'both' ? ['cold', 'warm'] : [opts.cache];
    for (const cacheState of caches) {
      // Cold: a fresh context per load. Warm: ONE context reused across
      // all reps of this cell, its cache enabled and populated by the
      // first rep.
      let warmContext = null;
      if (cacheState === 'warm') {
        warmContext = await browser.newContext(tierContextOptions(tierName));
      }
      const samples = [];
      try {
        for (let rep = 0; rep < reps; rep += 1) {
          const m = await runLoad(browser, opts, tierName, difficultyName, cacheState === 'warm' ? warmContext : null, rep);
          samples.push(m);
          process.stdout.write(
            `  ${tierName}/${difficultyName}/${cacheState} rep ${rep + 1}/${reps}: ` +
              `solve ${m.solveMs === null ? '-' : m.solveMs.toFixed(0)} ms` +
              ` (p2v ${m.pageToVerifiedMs === null ? '-' : m.pageToVerifiedMs.toFixed(0)} ms` +
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
        if (warmContext) await warmContext.close().catch(() => {});
      }
      const key = `${tierName}:${difficultyName}:${cacheState}`;
      const agg = { tier: tierName, difficulty: difficultyName, cache: cacheState, reps: samples };
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
      ]) {
        agg[metric] = summarize(samples.map((s) => s[metric]).filter((v) => v !== null && v !== undefined));
      }
      agg.longTaskCount = summarize(samples.map((s) => s.longTaskCount).filter((v) => v !== null));
      agg.timedOutCount = samples.filter((s) => s.timedOut).length;
      agg.errorCount = samples.filter((s) => s.errorCount > 0).length;
      results[key] = agg;
    }
  }
}

async function runMultiWidget(browser, opts, results) {
  if (!opts.multiWidget) return;
  const base = `http://127.0.0.1:${opts.fixturePort}`;
  const url = `${base}/?widgets=3&bits=18`;
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
      const sample = {
        widgets,
        verifiedCount: verifiedTimes.length,
        allVerifiedMs: verifiedTimes.length ? Math.max(...verifiedTimes) : null,
        firstVerifiedMs: verifiedTimes.length ? Math.min(...verifiedTimes) : null,
        spreadMs: verifiedTimes.length ? Math.max(...verifiedTimes) - Math.min(...verifiedTimes) : null,
        longTaskCount: lt.length,
        longTaskTotalMs: lt.reduce((a, b) => a + b, 0),
        peakHeapMb: mem.length ? Math.max(...mem) / (1024 * 1024) : null,
        errorCount: (raw.errors || []).length,
        timedOut: verifiedTimes.length < widgets,
      };
      samples.push(sample);
      process.stdout.write(
        `  multi-widget (${widgets} widgets, sha18) rep ${rep + 1}/${opts.multiWidgetReps}: ` +
          `all-verified ${sample.allVerifiedMs?.toFixed(0)} ms, ` +
          `spread ${sample.spreadMs?.toFixed(0)} ms, ` +
          `longtasks ${sample.longTaskCount}(${sample.longTaskTotalMs.toFixed(0)} ms)` +
          `, heap ${sample.peakHeapMb?.toFixed(1)} MB`,
      );
      console.log('');
    } finally {
      await page.close().catch(() => {});
      await context.close().catch(() => {});
    }
  }
  results['multi-widget:sha18:3-widgets'] = {
    tier: 'mainstream-desktop',
    difficulty: 'sha18',
    widgets: 3,
    reps: samples,
    allVerifiedMs: summarize(samples.map((s) => s.allVerifiedMs).filter((v) => v !== null)),
    firstVerifiedMs: summarize(samples.map((s) => s.firstVerifiedMs).filter((v) => v !== null)),
    spreadMs: summarize(samples.map((s) => s.spreadMs).filter((v) => v !== null)),
    longTaskTotalMs: summarize(samples.map((s) => s.longTaskTotalMs)),
    peakHeapMb: summarize(samples.map((s) => s.peakHeapMb).filter((v) => v !== null)),
  };
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
    fixture: {
      router: 'tests/browser/router.php',
      port: opts.fixturePort,
      php: opts.php,
      note: 'opt-in difficulty knobs (bits/argon_bits/m_kib) and the widgets knob; the fixture default behavior is unchanged',
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
