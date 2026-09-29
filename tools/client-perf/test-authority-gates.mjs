#!/usr/bin/env node
/**
 * Adversarial corpus for the certifiable-run authority gates
 * (round-5 audit findings 1-3):
 *
 *   1. an occupied fixture port is a hard refusal — the harness never
 *      reuses a server it does not own (an external server can serve
 *      byte-identical page and assets while reinterpreting /challenge);
 *   2. a run that attached to an external fixture (--no-fixture) is
 *      recorded as external and can never be promoted or indexed as
 *      physical evidence, even though it completed and its served-byte
 *      probes passed;
 *   3. an in-process run (owned fixture, but the harness loaded mutable
 *      working-tree source) can never be indexed as physical evidence;
 *   4. a run executed through the frozen launcher from a detached
 *      worktree of the committed bytes is certifiable, and a mutation
 *      of the working tree made while it runs never reaches the
 *      recorded identity: the payload's harness manifest hash equals
 *      the committed bytes, not the mutated ones.
 *
 * The fake-fixture case is the audit's exact scenario: the real router
 * serves the real page and assets, but the difficulty knob is
 * reinterpreted (bits=18 becomes 8). The served-byte probes cannot see
 * it; the fixture-origin gate is what refuses it.
 *
 * Usage:
 *   node tools/client-perf/test-authority-gates.mjs
 *
 * Requires: php on PATH, the PHP core vendor, the Playwright Chromium
 * engine, and a clean tracked git tree (the frozen launcher refuses
 * otherwise; this test restores every mutation it makes).
 * Exit status: 0 when every case behaved as expected, 1 otherwise.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256Hex } from './canonical-json.mjs';
import { snapshotMeasurementSources, verifyMeasurementSources } from './measurement-sources.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const HARNESS = join(SCRIPT_DIR, 'client-perf.mjs');
const LAUNCHER = join(SCRIPT_DIR, 'run-frozen.mjs');
const MERGE_CELLS = join(SCRIPT_DIR, 'merge-cells.mjs');
const BASELINE = join(SCRIPT_DIR, 'results', 'baseline.json');

const FIXTURE_DIR = mkdtempSync(join(tmpdir(), 'kiwicaptcha-authority-gates-'));
let failures = 0;
let cases = 0;

function ok(label) {
  cases++;
  process.stdout.write(`ok ${label}\n`);
}

function fail(label, detail) {
  cases++;
  failures++;
  process.stderr.write(`FAIL ${label}: ${detail}\n`);
}

function runNode(script, args, timeoutMs = 300000) {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: timeoutMs,
  });
  return { code: result.status, output: `${result.stdout || ''}${result.stderr || ''}` };
}

function readRun(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) {
    return null;
  }
}

const HARNESS_ARGS = [
  '--tiers', 'mainstream-desktop',
  '--difficulties', 'sha16',
  '--reps', '2',
  '--argon-reps', '2',
  '--cache', 'cold',
  '--assets', 'inline',
  '--no-multi-widget',
];

async function freePort() {
  return new Promise((resolvePromise) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolvePromise(port));
    });
  });
}

// ── 1. An occupied port is a hard refusal ───────────────────────────

{
  const port = await freePort();
  const blocker = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('not the fixture');
  });
  await new Promise((r) => blocker.listen(port, '127.0.0.1', r));
  const out = join(FIXTURE_DIR, 'occupied.json');
  const result = runNode(HARNESS, [...HARNESS_ARGS, '--fixture-port', String(port), '--out', out]);
  blocker.close();
  const payload = readRun(out);
  if (result.code === 0) {
    fail('occupied port: the harness must refuse', `exited 0\n${result.output}`);
  } else if (!/already occupied; refusing to reuse/.test(result.output)) {
    fail('occupied port: refusal message missing', result.output.slice(0, 600));
  } else if (payload && payload.completion && payload.completion.status === 'completed') {
    fail('occupied port: refusal wrote a completed payload', JSON.stringify(payload.completion));
  } else {
    ok('an occupied fixture port is refused, never reused');
  }
}

// ── 2. The fake fixture: real assets, cheapened bits ────────────────

let externalRun = null;
{
  const port = await freePort();
  const fakeRouter = join(FIXTURE_DIR, 'fake-router.php');
  writeFileSync(
    fakeRouter,
    `<?php
// Deliberately dishonest fixture for the authority-gates corpus: the
// real router serves the real page and every real asset, but the
// difficulty knob is reinterpreted (bits=18 becomes 8). Byte-level
// probes cannot see this; only the fixture-origin gate can.
if (isset($_GET['bits'])) { $_GET['bits'] = '8'; }
require ${JSON.stringify(join(REPO_ROOT, 'tests', 'browser', 'router.php'))};
`,
  );
  const server = spawn('php', ['-d', 'opcache.jit=off', '-S', `127.0.0.1:${port}`, fakeRouter], {
    cwd: FIXTURE_DIR,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Wait for the fake server to answer.
  const deadline = Date.now() + 10000;
  let up = false;
  while (Date.now() < deadline && !up) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(500) });
      up = res.status === 200;
    } catch (e) {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  if (!up) {
    server.kill('SIGKILL');
    fail('fake fixture: could not start', 'the fake router did not answer');
  } else {
    const out = join(FIXTURE_DIR, 'external.json');
    const result = runNode(HARNESS, [...HARNESS_ARGS, '--fixture-port', String(port), '--no-fixture', '--out', out]);
    server.kill('SIGKILL');
    const payload = readRun(out);
    if (result.code !== 0) {
      fail('fake fixture: the external run must complete for the gate test', `exited ${result.code}\n${result.output.slice(0, 600)}`);
    } else if (!payload || payload.fixture?.mode !== 'external') {
      fail('fake fixture: the run must be recorded as external', JSON.stringify(payload && payload.fixture));
    } else if (payload.completion?.status !== 'completed') {
      fail('fake fixture: the run was expected to complete', JSON.stringify(payload.completion));
    } else {
      externalRun = out;
      ok('the fake fixture is accepted as an external run (and recorded as such)');
    }
  }
}

if (externalRun) {
  // Promotion refuses it.
  const before = readFileSync(BASELINE);
  const promote = runNode(HARNESS, ['--promote-baseline', externalRun]);
  const after = readFileSync(BASELINE);
  if (!before.equals(after)) {
    // A promotion that should have been refused touched the committed
    // baseline: restore it before reporting, so the test never leaves
    // the repository altered.
    writeFileSync(BASELINE, before);
    fail('fake fixture: the refused promotion must not touch the baseline', 'baseline.json changed (restored)');
  } else if (promote.code === 0) {
    fail('fake fixture: --promote-baseline must refuse an external run', promote.output.slice(0, 600));
  } else if (!/fixture mode "external" is not owned-snapshot/.test(promote.output)) {
    fail('fake fixture: promotion refusal reason missing', promote.output.slice(0, 600));
  } else {
    ok('--promote-baseline refuses the external run (cheapened bits included)');
  }
  // Physical indexing refuses it.
  const index = runNode(MERGE_CELLS, [
    '--physical-index', '--source', 'physical', '--device-id', 'dev-authority-test',
    '--tier', 'mainstream-desktop', '--run', externalRun,
  ]);
  if (index.code === 0) {
    fail('fake fixture: --physical-index must refuse an external run', index.output.slice(0, 600));
  } else if (!/fixture\.mode "external" is not "owned-snapshot"/.test(index.output)) {
    fail('fake fixture: physical-index refusal reason missing', index.output.slice(0, 600));
  } else {
    ok('--physical-index refuses the external run (cheapened bits included)');
  }
}

// ── 3. An in-process run cannot be physical evidence ────────────────

{
  const port = await freePort();
  const out = join(FIXTURE_DIR, 'in-process.json');
  const result = runNode(HARNESS, [...HARNESS_ARGS, '--fixture-port', String(port), '--out', out]);
  const payload = readRun(out);
  if (result.code !== 0 || payload?.completion?.status !== 'completed') {
    fail('in-process run: expected a completed owned-snapshot run', `${result.code}\n${result.output.slice(0, 600)}`);
  } else if (payload.fixture?.mode !== 'owned-snapshot' || payload.harnessOrigin?.mode !== 'in-process') {
    fail('in-process run: unexpected origin fields', JSON.stringify({ fixture: payload.fixture, origin: payload.harnessOrigin }));
  } else {
    const index = runNode(MERGE_CELLS, [
      '--physical-index', '--source', 'physical', '--device-id', 'dev-authority-test',
      '--tier', 'mainstream-desktop', '--run', out,
    ]);
    if (index.code === 0) {
      fail('in-process run: --physical-index must refuse an in-process origin', index.output.slice(0, 600));
    } else if (!/harnessOrigin\.mode "in-process" is not "frozen-detached-worktree"/.test(index.output)) {
      fail('in-process run: physical-index refusal reason missing', index.output.slice(0, 600));
    } else {
      ok('an in-process run is refused as physical evidence');
    }
  }
}

// ── 4. The frozen launcher: certifiable origin + race immunity ──────

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

function startFrozen(label, args = HARNESS_ARGS) {
  const out = join(FIXTURE_DIR, `${label}.json`);
  const child = spawn(process.execPath, [LAUNCHER, ...args, '--fixture-port', String(port), '--out', out], {
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
  return { child, out, getOutput: () => output };
}

const port = await freePort();
const frozen = startFrozen('frozen');
const frozenRel = 'tools/client-perf/client-perf.mjs';
const frozenFull = join(REPO_ROOT, frozenRel);
const pristineHarness = readFileSync(frozenFull);
pristineByPath.set(frozenFull, pristineHarness);

// Wait for the first repetition, then mutate the WORKING TREE harness
// while the frozen process runs. The frozen process must keep executing
// (and recording) the committed bytes.
const firstRepDeadline = Date.now() + 180000;
let firstRep = false;
while (Date.now() < firstRepDeadline && !firstRep) {
  if (/rep 1\/2:/.test(frozen.getOutput())) firstRep = true;
  else if (frozen.child.exitCode !== null) break;
  else await new Promise((r) => setTimeout(r, 100));
}
let mutated = false;
if (!firstRep) {
  fail('frozen race: the run never reached its first repetition', frozen.getOutput().slice(0, 800));
} else {
  writeFileSync(frozenFull, Buffer.concat([pristineHarness, Buffer.from('\n/* authority-gates race mutation */\n')]));
  mutated = true;
}
const frozenExit = await new Promise((resolvePromise) => {
  if (frozen.child.exitCode !== null) resolvePromise(frozen.child.exitCode);
  else frozen.child.on('exit', (code) => resolvePromise(code));
});
const frozenPayload = readRun(frozen.out);
restoreAllPristine();

if (frozenExit !== 0 || frozenPayload?.completion?.status !== 'completed') {
  fail('frozen run: expected a clean completed run', `${frozenExit}\n${frozen.getOutput().slice(0, 800)}`);
} else if (frozenPayload.fixture?.mode !== 'owned-snapshot') {
  fail('frozen run: fixture must be owned-snapshot', JSON.stringify(frozenPayload.fixture));
} else if (frozenPayload.harnessOrigin?.mode !== 'frozen-detached-worktree') {
  fail('frozen run: harnessOrigin must be frozen-detached-worktree', JSON.stringify(frozenPayload.harnessOrigin));
} else if (!/^[0-9a-f]{40}$/.test(frozenPayload.harnessOrigin.commit || '')) {
  fail('frozen run: harnessOrigin.commit missing', JSON.stringify(frozenPayload.harnessOrigin));
} else if (mutated) {
  const committedSha = sha256Hex(pristineHarness);
  const mutatedSha = sha256Hex(Buffer.concat([pristineHarness, Buffer.from('\n/* authority-gates race mutation */\n')]));
  const recordedSha = frozenPayload.measurementSources?.manifest?.[frozenRel]?.sha256;
  if (recordedSha !== committedSha) {
    fail('frozen race: the payload must record the committed harness bytes', `recorded ${recordedSha}, committed ${committedSha}`);
  } else if (recordedSha === mutatedSha) {
    fail('frozen race: the payload recorded the mutated bytes while executing the frozen ones', 'internal inconsistency');
  } else {
    ok('a working-tree mutation during the run never reaches the frozen recorded identity');
  }
  // The race run used development options (tiny repetitions), which are
  // not eligible for physical indexing by construction. The certifiable
  // case runs a focused selection (sha16) with the REAL solver defaults,
  // which is exactly the focused-recording path: a clean run over a
  // deliberately selected subset.
  const certify = startFrozen('certify', [
    '--tiers', 'mainstream-desktop',
    '--difficulties', 'sha16',
    '--no-multi-widget',
  ]);
  const certifyExit = await new Promise((resolvePromise) => {
    certify.child.on('exit', (code) => resolvePromise(code));
  });
  const certifyPayload = readRun(certify.out);
  if (certifyExit !== 0 || certifyPayload?.completion?.status !== 'completed') {
    fail('frozen certifying run: expected a clean completed run', `${certifyExit}\n${certify.getOutput().slice(0, 800)}`);
  } else {
    const index = runNode(MERGE_CELLS, [
      '--physical-index', '--source', 'physical', '--device-id', 'dev-authority-test',
      '--tier', 'mainstream-desktop', '--run', certify.out,
    ]);
    if (index.code !== 0) {
      fail('frozen certifying run: --physical-index must accept a focused frozen run with real solver defaults', index.output.slice(0, 1200));
    } else {
      const parsed = JSON.parse(index.output);
      const device = parsed.physical_results['dev-authority-test'];
      const runs = device.source_runs;
      if (!Array.isArray(runs) || runs.length !== 1) {
        fail('frozen certifying run: the device index must record source_runs', JSON.stringify(runs));
      } else if (runs[0].completion !== 'completed' || runs[0].marker !== 'kiwicaptcha.client-perf.completed.v1') {
        fail('frozen certifying run: source_runs completion state wrong', JSON.stringify(runs[0]));
      } else if (runs[0].measurement_sources_sha256 !== certifyPayload.measurementSources.sha256) {
        fail('frozen certifying run: source_runs manifest identity wrong', JSON.stringify(runs[0]));
      } else if (!/^[0-9a-f]{64}$/.test(runs[0].run_digest || '')) {
        fail('frozen certifying run: source_runs run_digest missing', JSON.stringify(runs[0]));
      } else {
        const missingRuntime = [
          'tests/browser/node_modules/@playwright/test',
          'tests/browser/node_modules/playwright',
          'tests/browser/node_modules/playwright-core',
        ].filter((rel) => !certifyPayload.measurementSources.manifest[rel]);
        if (missingRuntime.length) {
          fail('frozen certifying run: the manifest must bind the Playwright runtime trees', missingRuntime.join(', '));
        } else {
          ok('a focused frozen run with real solver defaults is certifiable physical evidence and carries its source_runs record plus the Playwright runtime identity');
        }
      }
    }
  }

  // ── The Playwright runtime is part of the measurement identity ────
  // B/D: a modified installation is copied and hashed into a DIFFERENT
  // identity; two installations with different bytes can never share a
  // certifying context.
  {
    const pwFile = join(REPO_ROOT, 'tests', 'browser', 'node_modules', 'playwright-core', 'package.json');
    if (!existsSync(pwFile)) {
      ok('Playwright runtime absent; identity binding covered by the lockfile cases');
    } else {
      const pristinePw = readFileSync(pwFile);
      pristineByPath.set(pwFile, pristinePw);
      const frozenSnapshot = snapshotMeasurementSources({ snapshotRoot: null });
      const pristineDigest = frozenSnapshot.manifest['tests/browser/node_modules/playwright-core'].sha256;
      writeFileSync(pwFile, Buffer.concat([pristinePw, Buffer.from('\n')]));
      // The per-cell freeze check must see the changed runtime tree.
      const driftReasons = verifyMeasurementSources(frozenSnapshot);
      if (!driftReasons.some((r) => r.includes('node_modules/playwright-core'))) {
        fail('Playwright mutation: per-cell verification does not cover the runtime tree', JSON.stringify(driftReasons));
      }
      const mutated = startFrozen('pw-mutated');
      const mutatedExit = await new Promise((resolvePromise) => {
        mutated.child.on('exit', (code) => resolvePromise(code));
      });
      const mutatedPayload = readRun(mutated.out);
      restoreAllPristine();
      const restoredDigest = snapshotMeasurementSources({ snapshotRoot: null }).manifest[
        'tests/browser/node_modules/playwright-core'
      ].sha256;
      if (mutatedExit !== 0 || mutatedPayload?.completion?.status !== 'completed') {
        fail('Playwright mutation: the run must complete while binding the mutated bytes', `${mutatedExit}\n${mutated.getOutput().slice(0, 800)}`);
      } else if (restoredDigest !== pristineDigest) {
        fail('Playwright mutation: restoring the file did not restore the identity', `${restoredDigest} != ${pristineDigest}`);
      } else if (
        mutatedPayload.measurementSources.manifest['tests/browser/node_modules/playwright-core'].sha256 === pristineDigest
      ) {
        fail('Playwright mutation: a modified installation recorded the pristine identity', 'the runtime bytes are not bound');
      } else {
        ok('a modified Playwright installation is copied and hashed into a different measurement identity (B/D)');
      }
    }
  }

  // C: mutating the original installation after the frozen launch must
  // not affect the running experiment. The run spans two tiers, so the
  // second browser launch happens after the original tree is renamed
  // away: a symlinked runtime cannot survive that, the frozen copy must.
  {
    const nm = join(REPO_ROOT, 'tests', 'browser', 'node_modules');
    const movedNm = join(REPO_ROOT, 'tests', 'browser', 'node_modules.moved-authority-test');
    if (!existsSync(nm)) {
      ok('Playwright runtime absent; copy isolation covered by the launcher design');
    } else {
      const pristineDigest = snapshotMeasurementSources({ snapshotRoot: null }).manifest[
        'tests/browser/node_modules/playwright-core'
      ].sha256;
      const state = startFrozen('pw-rename', [...HARNESS_ARGS, '--tiers', 'mainstream-desktop,low-desktop']);
      const firstRepDeadline = Date.now() + 240000;
      let firstRep = false;
      while (Date.now() < firstRepDeadline && !firstRep) {
        if (/rep 1\/2:/.test(state.getOutput())) firstRep = true;
        else if (state.child.exitCode !== null) break;
        else await new Promise((r) => setTimeout(r, 100));
      }
      let moved = false;
      if (!firstRep) {
        fail('Playwright mutation: the run never reached its first repetition', state.getOutput().slice(0, 800));
      } else {
        try {
          renameSync(nm, movedNm);
          moved = true;
        } catch (e) {
          fail('Playwright mutation: cannot move the original installation', e.message);
        }
      }
      const exitCode = await new Promise((resolvePromise) => {
        if (state.child.exitCode !== null) resolvePromise(state.child.exitCode);
        else state.child.on('exit', (code) => resolvePromise(code));
      });
      if (moved) {
        try {
          renameSync(movedNm, nm);
        } catch (e) {
          fail('Playwright mutation: cannot restore the original installation', e.message);
        }
      }
      const payload = readRun(state.out);
      if (exitCode !== 0 || payload?.completion?.status !== 'completed') {
        fail('Playwright mutation: renaming the original tree after launch must not affect the frozen run', `${exitCode}\n${state.getOutput().slice(0, 800)}`);
      } else if (
        payload.measurementSources.manifest['tests/browser/node_modules/playwright-core'].sha256 !== pristineDigest
      ) {
        fail('Playwright mutation: the run executed bytes other than the frozen copy', 'recorded identity differs from the pristine tree');
      } else {
        ok('a post-launch mutation of the original installation leaves the running frozen experiment unaffected (C)');
      }
      rmSync(movedNm, { recursive: true, force: true });
    }
  }
}

// ── 5. The Composer vendor tree is not executable benchmark input ───

{
  const vendorAutoload = join(REPO_ROOT, 'packages', 'kiwicaptcha-php', 'vendor', 'autoload.php');
  if (!existsSync(vendorAutoload)) {
    ok('vendor tree absent; nothing to trap (the fixture never loads Composer)');
  } else {
    const pristineVendor = readFileSync(vendorAutoload);
    pristineByPath.set(vendorAutoload, pristineVendor);
    writeFileSync(
      vendorAutoload,
      '<?php\n// Adversarial trap for the authority corpus: if any fixture path executes\n// Composer as benchmark input, this file announces it and aborts.\nfwrite(STDERR, "VENDOR EXECUTED\\n");\nthrow new RuntimeException("vendor executed");\n',
    );
    const trapped = startFrozen('vendor-trap');
    const trappedExit = await new Promise((resolvePromise) => {
      trapped.child.on('exit', (code) => resolvePromise(code));
    });
    restoreAllPristine();
    const trappedOutput = trapped.getOutput();
    const trappedPayload = readRun(trapped.out);
    const currentSources = snapshotMeasurementSources({ snapshotRoot: null });
    if (trappedOutput.includes('VENDOR EXECUTED')) {
      fail('vendor trap: the fixture executed the altered Composer vendor tree', trappedOutput.slice(0, 800));
    } else if (trappedExit !== 0 || trappedPayload?.completion?.status !== 'completed') {
      fail('vendor trap: the run must complete while ignoring vendor', `${trappedExit}\n${trappedOutput.slice(0, 800)}`);
    } else if (trappedPayload.measurementSources.sha256 !== currentSources.manifestSha256) {
      fail(
        'vendor trap: the measurement identity changed although vendor is not executable input',
        `recorded ${trappedPayload.measurementSources.sha256}, current ${currentSources.manifestSha256}`,
      );
    } else if (Object.keys(trappedPayload.measurementSources.manifest).some((k) => k.includes('/vendor/'))) {
      fail('vendor trap: the manifest must not carry vendor entries', 'vendor path found');
    } else {
      ok('an altered Composer vendor tree is ignored entirely: the fixture loads only hashed source trees and the identity is unchanged');
    }
  }
}

// ── Summary ─────────────────────────────────────────────────────────

rmSync(FIXTURE_DIR, { recursive: true, force: true });
if (failures) {
  process.stderr.write(`test-authority-gates: ${failures} of ${cases} cases failed\n`);
  process.exit(1);
}
process.stdout.write(`test-authority-gates: OK (${cases} cases)\n`);
process.exit(0);
