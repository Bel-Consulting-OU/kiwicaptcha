#!/usr/bin/env node
/**
 * Adversarial integration + binding corpus for the client-performance
 * measurement freeze (audit findings 1 and 2).
 *
 * Part 1 — binding acceptance mutations (module level): a change to any
 * benchmark-defining source must change the canonical measurement-source
 * manifest, and a run recorded against the old manifest must be refused
 * against the new one. The cases mirror the audit's required mutations:
 * an opcode-number swap with max_execution_version unchanged, a trace
 * name change, a router bits reinterpretation, an Argon fixture envelope
 * change, and the deliberate non-invalidation of the unrelated
 * qualification page (excluded from the source set).
 *
 * Part 2 — the freeze at runtime (integration, real harness): start a
 * benchmark, mutate the working tree mid-cell, and prove the run either
 * aborts as contaminated (no completion marker, status "contaminated")
 * or — for a change restored before the next cell boundary — completes
 * with the recorded manifest still describing the frozen startup bytes.
 * The fixture serves from the immutable snapshot throughout, so a
 * mid-run edit can never change the measured bytes.
 *
 * Usage:
 *   node tools/client-perf/test-measurement-freeze.mjs
 *
 * Requires: php on PATH, the PHP core vendor installed, and the
 * Playwright Chromium engine (tests/browser/node_modules + browser).
 * Exit status: 0 when every case behaved as expected, 1 otherwise.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { snapshotMeasurementSources } from './measurement-sources.mjs';
import { measurementFieldDifferences } from './measurement-context.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const HARNESS = join(SCRIPT_DIR, 'client-perf.mjs');

const FIXTURE_DIR = mkdtempSync(join(tmpdir(), 'kiwicaptcha-measure-freeze-'));
let failures = 0;
let cases = 0;

// Safety net: the runtime cases mutate real working-tree files on
// purpose, so an interrupted test must still leave the tree pristine.
const pristineByPath = new Map();
function restoreAllPristine() {
  for (const [full, bytes] of pristineByPath) {
    try {
      if (!existsSync(full) || !readFileSync(full).equals(bytes)) writeFileSync(full, bytes);
    } catch (e) {
      /* best effort on the exit path */
    }
  }
}
process.on('exit', restoreAllPristine);
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => {
    restoreAllPristine();
    process.exit(signal === 'SIGINT' ? 130 : 143);
  });
}

function ok(label) {
  cases++;
  process.stdout.write(`ok ${label}\n`);
}

function fail(label, detail) {
  cases++;
  failures++;
  process.stderr.write(`FAIL ${label}: ${detail}\n`);
}

/** A tiny temp repo carrying the files a case needs. */
function makeTempRepo(files) {
  const root = mkdtempSync(join(FIXTURE_DIR, 'repo-'));
  for (const [rel, bytes] of Object.entries(files)) {
    const full = join(root, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, bytes);
  }
  return root;
}

function sourceSnapshot(root, relPaths) {
  return snapshotMeasurementSources({
    repoRoot: root,
    filePaths: relPaths,
    treePaths: [],
    servedCopyDirs: [],
    includeAssets: false,
  });
}

/**
 * One acceptance mutation: mutate the named authority in a temp copy,
 * prove the manifest digest and the per-file entry changed, and prove a
 * field-set comparison recorded before the mutation names the authority
 * after it.
 */
function bindingCase(label, relPath, mutate) {
  const root = makeTempRepo({ [relPath]: readFileSync(join(REPO_ROOT, relPath)) });
  const before = sourceSnapshot(root, [relPath]);
  const originalBytes = readFileSync(join(root, relPath));
  const mutated = mutate(Buffer.from(originalBytes));
  if (!mutated || mutated.equals(originalBytes)) {
    fail(label, 'the mutation did not change the fixture bytes');
    return;
  }
  writeFileSync(join(root, relPath), mutated);
  const after = sourceSnapshot(root, [relPath]);
  if (before.manifestSha256 === after.manifestSha256) {
    fail(label, 'the source mutation did not change the measurement-source manifest digest');
    return;
  }
  if (before.manifest[relPath].sha256 === after.manifest[relPath].sha256) {
    fail(label, 'the source mutation did not change the per-file manifest entry');
    return;
  }
  const recorded = { sources: { manifest: before.manifest, sha256: before.manifestSha256 } };
  const current = { sources: { manifest: after.manifest, sha256: after.manifestSha256 } };
  const differences = measurementFieldDifferences(recorded, current);
  if (!differences.some((r) => r.includes(relPath))) {
    fail(label, `the field comparison did not name ${relPath}: ${JSON.stringify(differences)}`);
    return;
  }
  ok(label);
}

// 1. Swap two opcode numbers, max_execution_version unchanged.
bindingCase('opcode-number swap with an unchanged max_execution_version is rejected', 'protocol/execution-v1.json', (bytes) => {
  const text = bytes.toString('utf8');
  if (!/"max_execution_version"\s*:\s*\d+/.test(text)) throw new Error('fixture manifest has no max_execution_version');
  const swapped = text
    .replace('"ADD": 0', '"ADD": __TMP__')
    .replace('"SUB": 1', '"SUB": 0')
    .replace('"ADD": __TMP__', '"ADD": 1');
  if (swapped === text) throw new Error('the opcode entries were not found');
  return Buffer.from(swapped);
});

// 2. Trace-name change, same opcode count and same maximum version.
bindingCase('execution trace-name change is rejected', 'protocol/execution-v1.json', (bytes) => {
  const text = bytes.toString('utf8');
  const match = text.match(/"trace_names"\s*:\s*\[([^\]]*)\]/);
  if (!match) throw new Error('fixture manifest has no trace_names array');
  const first = match[1].match(/"([^"]+)"/);
  if (!first) throw new Error('fixture manifest has no trace names');
  return Buffer.from(text.replace(first[1], `${first[1]}_mutated`));
});

// 3. Router reinterpretation of the bits knob (same query string, different behavior).
bindingCase('fixture router bits reinterpretation is rejected', 'tests/browser/router.php', (bytes) => {
  const text = bytes.toString('utf8');
  const line = text.match(/\$shaBits = [^\n]+: 8;/);
  if (!line) throw new Error('fixture router has no parseable SHA bits default');
  return Buffer.from(text.replace(line[0], line[0].replace(': 8;', ': 20;')));
});

// 4. Argon fixture envelope change (the fixture's Argon target-bits default).
bindingCase('Argon fixture envelope change is rejected', 'tests/browser/router.php', (bytes) => {
  const text = bytes.toString('utf8');
  const line = text.match(/\$argonBits = [^\n]+: 4;/);
  if (!line) throw new Error('fixture router has no parseable Argon bits default');
  return Buffer.from(text.replace(line[0], line[0].replace(': 4;', ': 10;')));
});

// 5. The qualification page is deliberately EXCLUDED: editing it must
//    not invalidate a performance recording.
{
  const page = 'tests/browser/autofill-qualification.php';
  const root = makeTempRepo({
    [page]: readFileSync(join(REPO_ROOT, page)),
    'tests/browser/router.php': readFileSync(join(REPO_ROOT, 'tests/browser/router.php')),
  });
  const before = sourceSnapshot(root, ['tests/browser/router.php']);
  writeFileSync(join(root, page), Buffer.concat([readFileSync(join(root, page)), Buffer.from('\n<!-- mutated -->\n')]));
  const after = sourceSnapshot(root, ['tests/browser/router.php']);
  if (before.manifestSha256 !== after.manifestSha256) {
    fail('qualification-page edit does not invalidate the manifest', 'the excluded page changed the manifest digest');
  } else {
    ok('qualification-page edit does not invalidate the manifest');
  }
}

// ── Part 2: runtime freeze integration ──────────────────────────────

const HARNESS_ARGS = [
  '--tiers', 'mainstream-desktop',
  '--difficulties', 'sha16,sha18',
  '--reps', '3',
  '--argon-reps', '3',
  '--cache', 'cold',
  '--assets', 'inline',
  '--no-multi-widget',
];

function startHarness(label) {
  const outFile = join(FIXTURE_DIR, `${label}.json`);
  const child = spawn(process.execPath, [HARNESS, ...HARNESS_ARGS, '--out', outFile], {
    cwd: REPO_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (d) => {
    output += d;
  });
  child.stderr.on('data', (d) => {
    output += d;
  });
  return { child, outFile, getOutput: () => output };
}

function waitForFirstRep(state, timeoutMs = 180000) {
  const started = Date.now();
  return new Promise((resolvePromise, reject) => {
    const timer = setInterval(() => {
      if (/rep 1\/3:/.test(state.getOutput())) {
        clearInterval(timer);
        resolvePromise();
      } else if (state.child.exitCode !== null) {
        clearInterval(timer);
        reject(new Error(`the harness exited before the first rep (code ${state.child.exitCode})\n${state.getOutput()}`));
      } else if (Date.now() - started > timeoutMs) {
        clearInterval(timer);
        reject(new Error(`timed out waiting for the first rep\n${state.getOutput()}`));
      }
    }, 100);
  });
}

function waitForExit(state, timeoutMs = 240000) {
  return new Promise((resolvePromise, reject) => {
    if (state.child.exitCode !== null) {
      resolvePromise(state.child.exitCode);
      return;
    }
    const timer = setTimeout(
      () => reject(new Error(`timed out waiting for the harness to exit\n${state.getOutput()}`)),
      timeoutMs,
    );
    state.child.on('exit', (code) => {
      clearTimeout(timer);
      resolvePromise(code);
    });
  });
}

function readRun(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) {
    return null;
  }
}

async function runtimeCase(label, rel, { restoreAfterMs = null } = {}) {
  const full = join(REPO_ROOT, rel);
  const pristine = readFileSync(full);
  pristineByPath.set(full, pristine);
  const patch = Buffer.concat([pristine, Buffer.from(`\n/* measurement-freeze-test ${Date.now()} */\n`)]);
  const restore = () => {
    if (!existsSync(full) || !readFileSync(full).equals(pristine)) {
      writeFileSync(full, pristine);
    }
  };
  const state = startHarness(label);
  let restoreTimer = null;
  try {
    await waitForFirstRep(state);
    writeFileSync(full, patch);
    if (restoreAfterMs !== null) {
      restoreTimer = setTimeout(restore, restoreAfterMs);
    }
    const code = await waitForExit(state);
    if (restoreTimer) {
      clearTimeout(restoreTimer);
      restoreTimer = null;
    }
    const payload = readRun(state.outFile);
    const output = state.getOutput();
    if (code === 0) {
      // The change was restored before the next cell boundary (or landed
      // after the last check): the immutable snapshot still guarantees
      // the recorded manifest describes the startup bytes.
      if (!payload || payload.completion?.status !== 'completed' || !payload.completion?.marker) {
        fail(label, `exit 0 without a completed payload\n${output}`);
        return;
      }
      const frozenDriver = snapshotMeasurementSources({ snapshotRoot: null }).manifest[rel].sha256;
      const recorded = payload.measurementSources.manifest[rel].sha256;
      if (recorded !== frozenDriver) {
        fail(label, `completed run recorded ${recorded} for ${rel}, expected the frozen startup bytes ${frozenDriver}`);
        return;
      }
      ok(`${label} (completed against the immutable snapshot; the frozen bytes are the recorded identity)`);
      return;
    }
    if (!/measurement contamination/.test(output)) {
      fail(label, `non-zero exit without a contamination report (code ${code})\n${output}`);
      return;
    }
    if (!payload || payload.completion?.status !== 'contaminated' || payload.completion?.marker) {
      fail(label, `contaminated run wrote ${JSON.stringify(payload?.completion)} instead of status "contaminated" without a marker`);
      return;
    }
    ok(label);
  } finally {
    if (restoreTimer) clearTimeout(restoreTimer);
    restore();
    if (state.child.exitCode === null) state.child.kill('SIGKILL');
  }
}

await runtimeCase(
  'a persistent mid-run asset edit aborts the run as contaminated',
  'packages/kiwicaptcha-wasm/assets/widget-driver.js',
);
await runtimeCase(
  'a persistent mid-run router edit aborts the run as contaminated',
  'tests/browser/router.php',
);
await runtimeCase(
  'an asset edit restored before the next cell boundary either aborts or completes with the frozen bytes',
  'packages/kiwicaptcha-wasm/assets/widget-driver.js',
  { restoreAfterMs: 250 },
);

// ── Summary ─────────────────────────────────────────────────────────

rmSync(FIXTURE_DIR, { recursive: true, force: true });
if (failures) {
  process.stderr.write(`test-measurement-freeze: ${failures} of ${cases} cases failed\n`);
  process.exit(1);
}
process.stdout.write(`test-measurement-freeze: OK (${cases} cases)\n`);
process.exit(0);
