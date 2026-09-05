#!/usr/bin/env node
/**
 * Adversarial mutation corpus for tools/ci/validate-release-baseline.mjs.
 *
 * The release-baseline validator is a certification parser: the
 * negative states are the important part. CI's ordinary invocation
 * (validator against the committed lab baseline) only proves today's
 * real file is accepted/rejected as expected; this suite proves the
 * validator REJECTS carefully constructed bad states (and accepts the
 * good ones), asserting on exit codes AND on the specific reason
 * substrings of the validator's own messages.
 *
 * Usage:
 *   node tools/ci/test-validate-release-baseline.mjs
 *
 * Every fixture is generated in os.tmpdir() (a fresh directory per
 * run) and the validator is executed as a subprocess exactly like the
 * CI invocation:
 *   node tools/ci/validate-release-baseline.mjs <baseline> [<budgets>] [--release]
 * The suite needs no harness install: it reads the harness constants
 * (tiers, difficulties, asset modes, default rep counts) out of
 * tools/client-perf/client-perf.mjs and clones the committed
 * release-budgets.json, exactly like the validator does, so fixtures
 * can never drift from the harness authority.
 *
 * Exit status: 0 when every mutation behaved as expected, 1 otherwise,
 * with the failing case's validator output printed.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const VALIDATOR = join(SCRIPT_DIR, 'validate-release-baseline.mjs');
const HARNESS_FILE = join(REPO_ROOT, 'tools', 'client-perf', 'client-perf.mjs');
const BUDGETS_SRC = join(REPO_ROOT, 'tools', 'client-perf', 'release-budgets.json');
const LEGACY_BASELINE_SRC = join(REPO_ROOT, 'tools', 'client-perf', 'results', 'baseline.json');

// ── Harness authority (mirror of the validator's own reads). ────────

function harnessConst(source, label, pattern) {
  const m = source.match(pattern);
  if (!m) throw new Error(`test-validate-release-baseline: cannot read the harness ${label} (pattern ${pattern}); update the suite`);
  return m[1];
}

/** Tier names and difficulty profiles ({isArgon, dimension, interactive, assetModes}) in source order. */
function harnessFacts(source) {
  const tiers = [];
  const tiersMatch = source.match(/const TIERS = \{([\s\S]*?)\n\};/);
  if (!tiersMatch) throw new Error('test-validate-release-baseline: cannot read the harness TIERS block');
  for (const line of tiersMatch[1].split('\n')) {
    const key = line.match(/^\s{2}'([a-z-]+)': \{$/);
    if (key) tiers.push(key[1]);
  }
  const difficulties = {};
  const namesMatch = source.match(/const DIFFICULTIES = \{([\s\S]*?)\n\};/);
  if (!namesMatch) throw new Error('test-validate-release-baseline: cannot read the harness DIFFICULTIES block');
  for (const line of namesMatch[1].split('\n')) {
    const key = line.match(/^\s{2}([a-zA-Z0-9]+): \{$/);
    if (key) {
      const name = key[1];
      const start = source.indexOf('\n  ' + name + ': {');
      if (start === -1) throw new Error(`test-validate-release-baseline: difficulty ${name} not found in the harness`);
      const end = source.indexOf('\n  }', start);
      const body = source.slice(start, end);
      const modesMatch = body.match(/assetModes: \[([^\]]*)\]/);
      if (!modesMatch) throw new Error(`test-validate-release-baseline: difficulty ${name} has no parseable assetModes`);
      const dimensionMatch = body.match(/dimension: '([a-z]+)'/);
      if (!dimensionMatch) throw new Error(`test-validate-release-baseline: difficulty ${name} has no parseable dimension`);
      difficulties[name] = {
        isArgon: /isArgon: true/.test(body),
        dimension: dimensionMatch[1],
        interactive: !/interactive: false/.test(body),
        assetModes: [...modesMatch[1].matchAll(/'([a-z]+)'/g)].map((m) => m[1]),
      };
    }
  }
  if (tiers.length === 0 || Object.keys(difficulties).length === 0) {
    throw new Error('test-validate-release-baseline: no tiers/difficulties parsed from the harness');
  }
  return { tiers, difficulties };
}

const HARNESS_SOURCE = readFileSync(HARNESS_FILE, 'utf8');
const SCHEMA = harnessConst(HARNESS_SOURCE, 'schema string', /const SCHEMA = '([^']+)';/);
const COMPLETION_MARKER = harnessConst(HARNESS_SOURCE, 'completion marker', /const COMPLETION_MARKER = '([^']+)';/);
const SHA_REPS_DEFAULT = parseInt(harnessConst(HARNESS_SOURCE, 'SHA rep default', /reps: (\d+), \/\/ SHA-256 solve repetitions/), 10);
const ARGON_REPS_DEFAULT = parseInt(harnessConst(HARNESS_SOURCE, 'Argon rep default', /argonReps: (\d+), \/\/ Argon2id solve repetitions/), 10);
const ARGON_BITS_DEFAULT = parseInt(harnessConst(HARNESS_SOURCE, 'argon bits default', /argonBits: (\d+), \/\/ the real adaptive-risk ladder/), 10);
const { tiers: TIERS, difficulties: DIFFICULTIES } = harnessFacts(HARNESS_SOURCE);
const CACHE_STATES = ['cold', 'warm'];
const RELEASE_TIER = 'mainstream-desktop';

// The live execution-grammar authority (audit finding 1): the suite
// reads the manifest maximum exactly like the validator, so every
// fixture row of an execution-dimension difficulty carries an
// executionVersion at the manifest maximum.
const EXECUTION_MANIFEST = JSON.parse(readFileSync(join(REPO_ROOT, 'protocol', 'execution-v1.json'), 'utf8'));
const EXECUTION_MAX_VERSION = EXECUTION_MANIFEST.max_execution_version;

// ── Fixture helpers. ────────────────────────────────────────────────

const DAY_MS = 86400000;
const MIN_MS = 60000;
const nowIso = (offsetDays = 0) => new Date(Date.now() + offsetDays * DAY_MS).toISOString();
const isoAt = (ms) => new Date(ms).toISOString();

function clone(src) {
  return JSON.parse(JSON.stringify(src));
}

/** The committed release-budgets.json as a mutable fixture base. */
function baseBudgets() {
  const budgets = clone(JSON.parse(readFileSync(BUDGETS_SRC, 'utf8')));
  return budgets;
}

/** A minimal but complete baseline payload skeleton (identity + age). */
function payloadSkeleton(schema) {
  return {
    schema,
    generated_at: nowIso(),
    chromium: 'test-chromium-0',
    environment: {
      os: 'test-os',
      machine: 'test-machine',
      cpus: '1 x test-cpu',
    },
  };
}

/** One synthetic sample: 5 ms everywhere stays under every real budget row. */
const healthySample = () => ({ solveMs: 5, pageToVerifiedMs: 5, errorCount: 0, timedOut: false });
const failingSample = () => ({ solveMs: 5, pageToVerifiedMs: 5, errorCount: 0, timedOut: true });
const slowSample = (ms) => ({ solveMs: ms, pageToVerifiedMs: ms, errorCount: 0, timedOut: false });

/** Per-mode row of the schema-3 matrix or of a device index. */
function modeRow(device, tier, difficulty, cache, mode, samples) {
  const summary = (field) => {
    const values = samples.map((s) => s[field]).filter((v) => typeof v === 'number');
    const sorted = [...values].sort((a, b) => a - b);
    return {
      count: sorted.length,
      min: sorted.length ? sorted[0] : null,
      max: sorted.length ? sorted[sorted.length - 1] : null,
      p50: sorted.length ? sorted[Math.floor((sorted.length - 1) / 2)] : null,
      p95: sorted.length ? sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(0.95 * sorted.length) - 1))] : null,
      p99: sorted.length ? sorted[sorted.length - 1] : null,
    };
  };
  const row = {
    tier,
    difficulty,
    cache,
    assets: mode,
    reps: samples,
    solveMs: summary('solveMs'),
    pageToVerifiedMs: summary('pageToVerifiedMs'),
    errorCount: samples.filter((s) => s.errorCount > 0).length,
    timedOutCount: samples.filter((s) => s.timedOut).length,
  };
  // Execution rows (audit finding 1) carry the live grammar version:
  // the validator requires every execution result row's
  // executionVersion to equal the execution manifest maximum.
  if (DIFFICULTIES[difficulty] && DIFFICULTIES[difficulty].dimension === 'execution') {
    row.executionVersion = EXECUTION_MAX_VERSION;
  }
  if (device) {
    row.source = 'physical';
    row.device_id = device;
  }
  return row;
}

/**
 * The complete schema-3 default matrix: every harness tier x
 * difficulty x cold/warm x asset mode. Only mainstream-desktop rows
 * carry repetitions (the only tier with budget rows in the committed
 * file): SHA-profile difficulties at SHA_REPS_DEFAULT, Argon profiles
 * at ARGON_REPS_DEFAULT, sha20 rows at 100 so a release-mode sha20
 * floor is satisfiable. All other rows are key presence for the
 * full-matrix guard.
 */
function fullMatrix() {
  const results = {};
  for (const tier of TIERS) {
    for (const [difficulty, profile] of Object.entries(DIFFICULTIES)) {
      for (const cache of CACHE_STATES) {
        for (const mode of profile.assetModes) {
          const required = tier === RELEASE_TIER;
          let samples = [];
          if (required) {
            const n = difficulty === 'sha20' ? 100 : profile.isArgon ? ARGON_REPS_DEFAULT : SHA_REPS_DEFAULT;
            samples = Array.from({ length: n }, healthySample);
          }
          results[`${tier}:${difficulty}:${cache}:${mode}`] = modeRow(null, tier, difficulty, cache, mode, samples);
        }
      }
    }
  }
  return results;
}

function schema3Payload(results = fullMatrix()) {
  const payload = payloadSkeleton(SCHEMA);
  payload.completion = { status: 'completed', marker: COMPLETION_MARKER };
  payload.tiers = Object.fromEntries(TIERS.map((t) => [t, { label: t }]));
  payload.difficulties = Object.fromEntries(Object.entries(DIFFICULTIES).map(([d, p]) => [d, { label: d, dimension: p.isArgon ? 'argon' : 'sha' }]));
  payload.options = {
    reps: SHA_REPS_DEFAULT,
    argonReps: ARGON_REPS_DEFAULT,
    cache: 'both',
    argonBits: ARGON_BITS_DEFAULT,
    argonMKib: 16384,
    multiWidget: false,
    assets: 'both',
  };
  payload.results = results;
  return payload;
}

/** Delete one family of per-mode rows across every tier. */
function withoutRows(payload, difficulty, cache, mode) {
  const next = clone(payload);
  for (const tier of TIERS) delete next.results[`${tier}:${difficulty}:${cache}:${mode}`];
  return next;
}

/** Drop the four-part rows of one (difficulty, cache) family and write a single three-part row instead. */
function threePartInsteadOfModes(payload, difficulty, cache) {
  const next = clone(payload);
  for (const tier of TIERS) {
    for (const mode of DIFFICULTIES[difficulty].assetModes) delete next.results[`${tier}:${difficulty}:${cache}:${mode}`];
    const merged = [];
    for (const mode of DIFFICULTIES[difficulty].assetModes) {
      const row = next.results[`${tier}:${difficulty}:${cache}:${mode}`];
      if (row && Array.isArray(row.reps)) merged.push(...row.reps);
    }
    if (merged.length === 0) merged.push(healthySample());
    const mode = DIFFICULTIES[difficulty].assetModes[0];
    next.results[`${tier}:${difficulty}:${cache}`] = modeRow(null, tier, difficulty, cache, mode, merged);
  }
  return next;
}

/** Legacy schema-1 store: the committed baseline with a fresh timestamp. */
function legacySchema1Payload() {
  const payload = clone(JSON.parse(readFileSync(LEGACY_BASELINE_SRC, 'utf8')));
  payload.generated_at = nowIso();
  return payload;
}

// ── Physical-claim fixtures. ────────────────────────────────────────

function physicalDevice(id, tier = RELEASE_TIER, opts = {}) {
  return {
    id,
    kind: 'physical',
    tier,
    hardware: opts.hardware || 'test rig hardware',
    os: opts.os || 'test-os',
    browser: opts.browser || 'test-browser',
    battery_state: opts.battery_state || 'plugged-steady',
    tested_at: opts.tested_at || nowIso(),
    ...(opts.extra || {}),
  };
}

function physicalBudgets({ devices, status = 'physical', qualifiedAt = nowIso(), releaseTiers = [RELEASE_TIER], budgets = null }) {
  const file = budgets || baseBudgets();
  file.qualification = {
    status,
    qualified_at: qualifiedAt,
    harness_schema: SCHEMA,
    release_tiers: releaseTiers,
    devices,
  };
  return file;
}

/** Sample count of a physical per-device row by difficulty. */
function deviceRepCount(difficulty) {
  if (difficulty === 'sha20') return 100;
  return DIFFICULTIES[difficulty].isArgon ? ARGON_REPS_DEFAULT : SHA_REPS_DEFAULT;
}

/**
 * The full per-device evidence index of one device: every
 * (difficulty, cache, mode) row of the device's tier keyed
 * tier:difficulty:cache:assetMode, exactly the shape merge-cells
 * --physical-index emits. sampleFor(difficulty) lets a mutation make
 * one device unhealthy (failing samples, thin sha20 samples, slow
 * p95s).
 */
function deviceIndex(deviceId, sampleFor = () => healthySample(), countFor = deviceRepCount) {
  const index = {};
  for (const [difficulty, profile] of Object.entries(DIFFICULTIES)) {
    for (const cache of CACHE_STATES) {
      for (const mode of profile.assetModes) {
        const n = countFor(difficulty);
        const samples = Array.from({ length: n }, sampleFor);
        index[`${RELEASE_TIER}:${difficulty}:${cache}:${mode}`] = modeRow(deviceId, RELEASE_TIER, difficulty, cache, mode, samples);
      }
    }
  }
  return index;
}

function physicalPayload(deviceIndexes) {
  const payload = payloadSkeleton('kiwicaptcha.client-perf/1');
  payload.results = {};
  payload.physical_results = deviceIndexes;
  return payload;
}

/** Result-row keys whose difficulty is an execution-dimension profile. */
function executionRowKeys(results) {
  return Object.keys(results).filter((k) => {
    const segments = k.split(':');
    const difficulty = segments.length >= 2 ? segments[1] : null;
    return difficulty !== null && DIFFICULTIES[difficulty] && DIFFICULTIES[difficulty].dimension === 'execution';
  });
}

// ── Subprocess harness. ─────────────────────────────────────────────

let failures = 0;
let cases = 0;
const tmpBase = mkdtempSync(join(tmpdir(), 'kc-validator-mutation-'));

function runValidator(payload, budgets, release = false) {
  const baselinePath = join(tmpBase, `baseline-${cases}.json`);
  const budgetsPath = join(tmpBase, `budgets-${cases}.json`);
  writeFileSync(baselinePath, JSON.stringify(payload));
  writeFileSync(budgetsPath, JSON.stringify(budgets));
  const args = [VALIDATOR, ...(release ? ['--release'] : []), baselinePath, budgetsPath];
  const res = spawnSync(process.execPath, args, { encoding: 'utf8' });
  return { ...res, baselinePath, budgetsPath };
}

function check(label, res, expect) {
  cases += 1;
  const text = `${res.stdout || ''}${res.stderr || ''}`;
  const okStatus = expect.status === 0 ? res.status === 0 : res.status !== 0;
  const missing = (expect.mustInclude || []).filter((s) => !text.includes(s));
  const unexpected = (expect.mustExclude || []).filter((s) => text.includes(s));
  if (okStatus && missing.length === 0 && unexpected.length === 0) {
    console.log(`PASS  ${label}`);
    return;
  }
  failures += 1;
  console.log(`FAIL  ${label}`);
  console.log(`      exit=${res.status} expected ${expect.status === 0 ? '0' : 'non-zero'}`);
  for (const s of missing) console.log(`      missing expected reason substring: ${JSON.stringify(s)}`);
  for (const s of unexpected) console.log(`      unexpected reason substring present: ${JSON.stringify(s)}`);
  const head = (res.stderr || '(no stderr)').split('\n').filter((l) => l.trim().length).slice(0, 40).join('\n      ');
  console.log(`      validator output:\n      ${head}`);
}

const pass = (label, res) => check(label, res, { status: 0 });
const reject = (label, res, mustInclude, mustExclude = []) =>
  check(label, res, { status: 1, mustInclude, mustExclude });

// ── Corpus. ─────────────────────────────────────────────────────────

// 1. Complete schema-3 matrix passes in CI mode (lab status, the
//    committed qualification state).
{
  const payload = schema3Payload();
  const budgets = baseBudgets();
  pass('complete schema-3 full matrix: CI mode accepts the clean completed run', runValidator(payload, budgets, false));
}

// 2. Removing only sha18:cold:files (inline survives) must be
//    detected as the files row of the per-mode matrix.
{
  const payload = withoutRows(schema3Payload(), 'sha18', 'cold', 'files');
  const res = runValidator(payload, baseBudgets(), false);
  reject('sha18:cold:files deleted (inline kept): reject naming the files row', res, ['sha18:cold:files'], ['sha18:cold:inline']);
}

// 3. Removing only sha18:cold:inline (files survives).
{
  const payload = withoutRows(schema3Payload(), 'sha18', 'cold', 'inline');
  const res = runValidator(payload, baseBudgets(), false);
  reject('sha18:cold:inline deleted (files kept): reject naming the inline row', res, ['sha18:cold:inline'], ['sha18:cold:files']);
}

// 4. Both four-part rows replaced by one three-part row: an aggregate
//    row can never satisfy the per-mode schema-3 matrix.
{
  const payload = threePartInsteadOfModes(schema3Payload(), 'sha18', 'cold');
  const res = runValidator(payload, baseBudgets(), false);
  reject('sha18:cold four-part rows replaced by one three-part row: schema-3 full-matrix certification rejects', res, ['full default matrix']);
}

// 5. Legacy schema-1 three-part rows stay valid through the legacy
//    path (the committed baseline shape with a fresh timestamp).
{
  const payload = legacySchema1Payload();
  pass('legacy schema-1 three-part baseline: still valid through the legacy path (CI mode)', runValidator(payload, baseBudgets(), false));
}

// 6. Mainstream-tier files row missing while its inline row exists.
{
  const payload = clone(schema3Payload());
  delete payload.results[`${RELEASE_TIER}:sha18:cold:files`];
  const res = runValidator(payload, baseBudgets(), false);
  reject('missing mainstream-desktop:sha18:cold:files row while inline exists', res, ['mainstream-desktop:sha18:cold:files']);
}

// 7. Physical status with only lab devices.
{
  const budgets = physicalBudgets({
    devices: [{
      id: 'lab-rig',
      kind: 'lab',
      tier: RELEASE_TIER,
      hardware: 'lab',
      os: 'lab',
      browser: 'lab',
      battery_state: 'plugged-steady',
      tested_at: nowIso(),
    }],
  });
  const res = runValidator(physicalPayload({}), budgets, false);
  reject('physical status with only lab devices', res, ['requires at least one kind:"physical" device']);
}

// 8. Physical device with a missing id.
{
  const device = physicalDevice('dev-a');
  delete device.id;
  const budgets = physicalBudgets({ devices: [device] });
  const res = runValidator(physicalPayload({ 'dev-a': deviceIndex('dev-a') }), budgets, false);
  reject('physical device with missing id', res, ['needs a non-empty id']);
}

// 9. Physical device with an invalid (non-harness) tier.
{
  const budgets = physicalBudgets({ devices: [physicalDevice('dev-a', 'not-a-tier')] });
  const res = runValidator(physicalPayload({ 'dev-a': deviceIndex('dev-a') }), budgets, false);
  reject('physical device with invalid tier', res, ['is not a harness tier']);
}

// 10. Physical row with an unknown device_id (index key not registered).
{
  const budgets = physicalBudgets({ devices: [physicalDevice('dev-a')] });
  const payload = physicalPayload({
    'dev-a': deviceIndex('dev-a'),
    'ghost-device': deviceIndex('ghost-device'),
  });
  const res = runValidator(payload, budgets, false);
  reject('physical row with unknown device_id', res, ['not a registered kind:"physical" device']);
}

// 11. Physical row whose device belongs to another tier (a
//     low-desktop row under a mainstream-desktop-qualified device).
{
  const budgets = physicalBudgets({ devices: [physicalDevice('dev-a', RELEASE_TIER)] });
  const index = deviceIndex('dev-a');
  index['low-desktop:sha16:cold:inline'] = modeRow('dev-a', 'low-desktop', 'sha16', 'cold', 'inline', [healthySample()]);
  const res = runValidator(physicalPayload({ 'dev-a': index }), budgets, false);
  reject('physical row whose device belongs to another tier', res, ['belongs to tier']);
}

// 12. Two registered physical devices, only one measured: the
//     unmeasured device's missing cells are hard reasons.
{
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a'), physicalDevice('dev-b')],
  });
  const res = runValidator(physicalPayload({ 'dev-a': deviceIndex('dev-a') }), budgets, false);
  reject('two registered physical devices with only one measured', res, ['physical device dev-b has no evidence row for']);
}

// 13. Device A healthy, device B 100% failures: the per-device
//     failure budget catches B, never masked by A.
{
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a'), physicalDevice('dev-b')],
  });
  const payload = physicalPayload({
    'dev-a': deviceIndex('dev-a'),
    'dev-b': deviceIndex('dev-b', failingSample),
  });
  const res = runValidator(payload, budgets, false);
  reject('device A healthy + device B 100% failures: per-device failure rate rejects', res, ['failure rate 100.0%']);
}

// 14. Device A with 100 sha20 samples, device B with one: the
//     per-device minSha20SamplesPhysical floor rejects in release
//     mode.
{
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a'), physicalDevice('dev-b')],
  });
  const countFor = (difficulty) => (difficulty === 'sha20' ? 1 : deviceRepCount(difficulty));
  const payload = physicalPayload({
    'dev-a': deviceIndex('dev-a'),
    'dev-b': deviceIndex('dev-b', healthySample, countFor),
  });
  const res = runValidator(payload, budgets, true);
  reject('device A 100 sha20 samples + device B 1 sha20 sample (release mode)', res, ['sha20 needs >=']);
}

// 15. One device's p95 above the budget: worst physical p95 must be
//     compared per device and the budget must cover the slowest.
{
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a'), physicalDevice('dev-b')],
  });
  const payload = physicalPayload({
    'dev-a': deviceIndex('dev-a'),
    'dev-b': deviceIndex('dev-b', () => slowSample(20000)),
  });
  const res = runValidator(payload, budgets, false);
  reject('device B p95 above the budget: worst physical p95 rejects', res, ['worst physical p95']);
}

// 16. Physical tested_at older than recordAgeDays (90).
{
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a', RELEASE_TIER, { tested_at: nowIso(-200) })],
  });
  const res = runValidator(physicalPayload({ 'dev-a': deviceIndex('dev-a') }), budgets, false);
  reject('physical tested_at older than recordAgeDays', res, ['days old; maximum is']);
}

// 17. Release tier with no p95 budget rows (budget tiers name another
//     tier): a committed physical claim must carry its own budgets.
{
  const budgets = physicalBudgets({ devices: [physicalDevice('dev-a')] });
  budgets.tiers = ['low-desktop'];
  budgets.budgets = { 'low-desktop': clone(baseBudgets().budgets[RELEASE_TIER]) };
  const res = runValidator(physicalPayload({ 'dev-a': deviceIndex('dev-a') }), budgets, false);
  reject('release tier with no p95 budget rows', res, ['has no budget tier']);
}

// 18. Physical row with source=lab inside the device index.
{
  const budgets = physicalBudgets({ devices: [physicalDevice('dev-a')] });
  const index = deviceIndex('dev-a');
  index[`${RELEASE_TIER}:sha16:cold:inline`].source = 'lab';
  const res = runValidator(physicalPayload({ 'dev-a': index }), budgets, false);
  reject('physical row with source=lab', res, ['source "lab" is not "physical"']);
}

// 19. Qualification date predating the evidence: qualified_at must
//     never precede the newest physical tested_at.
{
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a', RELEASE_TIER, { tested_at: nowIso(-30) })],
    qualifiedAt: nowIso(-60),
  });
  const res = runValidator(physicalPayload({ 'dev-a': deviceIndex('dev-a') }), budgets, false);
  reject('qualification date predating evidence', res, ['precedes the newest']);
}

// 20. Lab baseline: CI mode allowed, --release rejected on the status
//     reason alone.
{
  const payload = legacySchema1Payload();
  pass('lab baseline: CI mode allowed', runValidator(payload, baseBudgets(), false));
  reject('lab baseline: --release rejected on the lab qualification status', runValidator(payload, baseBudgets(), true), ['is not "physical"']);
}

// 21. Healthy physical claim: CI mode passes (proves the committed
//     physical claim is fully provable in ordinary CI) and release
//     mode certifies it (per-device sha20 floor met).
{
  const budgets = physicalBudgets({ devices: [physicalDevice('dev-a')] });
  pass('healthy physical claim (one device, every cell): CI mode proves the claim', runValidator(physicalPayload({ 'dev-a': deviceIndex('dev-a') }), budgets, false));
  pass('healthy physical claim: release mode certifies it (per-device sha20 floor met)', runValidator(physicalPayload({ 'dev-a': deviceIndex('dev-a') }), budgets, true));
}

// 22. Physical claim with an empty evidence index: the claim without
//     per-device rows is a silent gap.
{
  const budgets = physicalBudgets({ devices: [physicalDevice('dev-a')] });
  const res = runValidator(physicalPayload({}), budgets, false);
  reject('physical claim with an empty physical_results index', res, ['carries no physical_results object']);
}

// 23. Evidence rows indexed under a registered kind:"lab" device.
{
  const labDevice = physicalDevice('lab-rig');
  labDevice.kind = 'lab';
  const budgets = physicalBudgets({
    devices: [labDevice, physicalDevice('dev-a')],
  });
  const res = runValidator(physicalPayload({ 'lab-rig': deviceIndex('lab-rig') }), budgets, false);
  reject('physical_results indexed under a registered lab device', res, ['not a registered kind:"physical" device']);
}

// ── Absolute UX ceiling cases (audit finding 2, round 5). ───────────
// The committed release-budgets.json declares absoluteP95Ceilings
// (5000 ms for mainstream-desktop) and the interactive/non-interactive
// classification (execchain budgeted but never an ordinary interactive
// release cell). The argon2id cells are interactive: their budget rows
// must sit under the absolute ceiling even when measurements are below
// the budget, and a budget above the ceiling is a hard rejection.

// 24. Interactive budget under the absolute ceiling with measurements
//     under the budget: the ceiling-complete state passes in CI mode.
{
  const payload = schema3Payload();
  const budgets = baseBudgets();
  pass('absolute ceiling present + argon measurement under budget: CI mode accepts the clean run', runValidator(payload, budgets, false));
}

// 25. Interactive cell measurement above its budget row.
{
  const payload = clone(schema3Payload());
  for (const cache of CACHE_STATES) {
    for (const mode of DIFFICULTIES.argon2id.assetModes) {
      payload.results[`${RELEASE_TIER}:argon2id:${cache}:${mode}`] = modeRow(
        null, RELEASE_TIER, 'argon2id', cache, mode,
        Array.from({ length: ARGON_REPS_DEFAULT }, () => slowSample(20000))
      );
    }
  }
  const res = runValidator(payload, baseBudgets(), false);
  reject('argon2id measurement above the budget row: reject naming the measured p95', res, ['exceeds the budget'], ['absolute interactive ceiling']);
}

// 26. Interactive budget row above the absolute ceiling (measurements
//     healthy): the ceiling binds the budget, never only the
//     measurements.
{
  const payload = schema3Payload();
  const budgets = baseBudgets();
  budgets.budgets[RELEASE_TIER].argon2id.warm.solveMsP95 = 6000;
  budgets.budgets[RELEASE_TIER].argon2id.warm.pageToVerifiedMsP95 = 6000;
  const res = runValidator(payload, budgets, false);
  reject('argon2id warm budget 6000 ms above the absolute 5000 ms ceiling: reject', res, ['exceeds the absolute interactive ceiling'], ['exceeds the budget']);
}

// 27. Measurement below an inflated 20-second budget: still rejected —
//     an inflated budget can never buy the ceiling out.
{
  const payload = schema3Payload();
  const budgets = baseBudgets();
  budgets.budgets[RELEASE_TIER].argon2id.warm.solveMsP95 = 20000;
  budgets.budgets[RELEASE_TIER].argon2id.warm.pageToVerifiedMsP95 = 20000;
  const res = runValidator(payload, budgets, false);
  reject('argon2id warm budget inflated to 20 s with 5 ms measurements: still rejected on the absolute ceiling', res, ['exceeds the absolute interactive ceiling'], ['exceeds the budget']);
}

// 28. A certified tier without an absoluteP95Ceilings entry is
//     rejected in release mode (and for a committed physical claim in
//     CI): the release ladder cannot declare a tier with no absolute
//     UX ceiling.
{
  const budgets = physicalBudgets({ devices: [physicalDevice('dev-a')] });
  delete budgets.absoluteP95Ceilings;
  const res = runValidator(physicalPayload({ 'dev-a': deviceIndex('dev-a') }), budgets, true);
  reject('release mode: physical claim whose budget file lacks absoluteP95Ceilings', res, ['has no absoluteP95Ceilings entry']);
}

// ── Evidence time validation cases (audit finding 3, round 5). ──────
// Evidence timestamps (payload generated_at, qualification
// qualified_at, device tested_at) must be canonical UTC RFC3339
// (zero offset, T separator) and may not lie beyond now + 5 minutes
// (MAX_EVIDENCE_CLOCK_SKEW_MS); qualified_at may not postdate
// generated_at beyond the same skew allowance.

// 29. generated_at a year in the future.
{
  const payload = legacySchema1Payload();
  payload.generated_at = nowIso(365);
  const res = runValidator(payload, baseBudgets(), false);
  reject('generated_at now+365d: reject as beyond the clock-skew allowance', res, ['is in the future beyond the 5-minute clock-skew allowance']);
}

// 30. All three evidence timestamps a year in the future in a valid
//     chronological order: every field is rejected individually.
{
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a', RELEASE_TIER, { tested_at: nowIso(365) })],
    qualifiedAt: nowIso(365),
  });
  const payload = physicalPayload({ 'dev-a': deviceIndex('dev-a') });
  payload.generated_at = nowIso(365);
  const res = runValidator(payload, budgets, false);
  reject('generated_at + qualified_at + tested_at all at now+365d in valid order', res, ['is in the future beyond the 5-minute clock-skew allowance']);
}

// 31. qualified_at postdating generated_at by a day (both in the
//     past): rejected by the qualified-vs-generated skew rule.
{
  const past = Date.now() - 30 * DAY_MS;
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a', RELEASE_TIER, { tested_at: isoAt(past) })],
    qualifiedAt: isoAt(past + DAY_MS),
  });
  const payload = physicalPayload({ 'dev-a': deviceIndex('dev-a') });
  payload.generated_at = isoAt(past);
  const res = runValidator(payload, budgets, false);
  reject('qualified_at = generated_at + 1 day: reject beyond the clock-skew allowance', res, ['postdates payload.generated_at']);
}

// 32. tested_at two minutes in the future stays within the 5-minute
//     skew allowance: accepted (chronology valid: tested_at <=
//     qualified_at <= generated_at, all within skew).
{
  const t = Date.now();
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a', RELEASE_TIER, { tested_at: isoAt(t + 2 * MIN_MS) })],
    qualifiedAt: isoAt(t + 3 * MIN_MS),
  });
  const payload = physicalPayload({ 'dev-a': deviceIndex('dev-a') });
  payload.generated_at = isoAt(t + 4 * MIN_MS);
  pass('tested_at now+2min (within the 5-minute skew allowance): accepted', runValidator(payload, budgets, false));
}

// 33. tested_at six minutes in the future: rejected.
{
  const t = Date.now();
  const budgets = physicalBudgets({
    devices: [physicalDevice('dev-a', RELEASE_TIER, { tested_at: isoAt(t + 6 * MIN_MS) })],
    qualifiedAt: isoAt(t + 6 * MIN_MS + 1000),
  });
  const payload = physicalPayload({ 'dev-a': deviceIndex('dev-a') });
  payload.generated_at = isoAt(t + 6 * MIN_MS + 2000);
  const res = runValidator(payload, budgets, false);
  reject('tested_at now+6min: reject as beyond the clock-skew allowance', res, ['is in the future beyond the 5-minute clock-skew allowance']);
}

// 34. A space-separated local timestamp is not canonical RFC3339.
{
  const payload = legacySchema1Payload();
  payload.generated_at = '2026-09-05 02:00:00';
  const res = runValidator(payload, baseBudgets(), false);
  reject('generated_at "2026-09-05 02:00:00" (space separator, no offset): reject as non-canonical', res, ['not a canonical UTC RFC3339']);
}

// 35. A timestamp with a non-UTC offset is not canonical RFC3339.
{
  const payload = legacySchema1Payload();
  payload.generated_at = '2026-09-04T12:00:00.000+01:00';
  const res = runValidator(payload, baseBudgets(), false);
  reject('generated_at with +01:00 offset: reject as non-canonical (UTC designator required)', res, ['not a canonical UTC RFC3339']);
}

// ── Execution-version evidence cases (audit finding 1, round 6). ────
// The live grammar is the execution manifest's max_execution_version
// (read from protocol/execution-v1.json, currently 5). Every
// execution result row must record executionVersion equal to that
// maximum; a missing or lower version is evidence of an older-grammar
// run (the fixture's historical version-3 default) and rejects naming
// the cell. Non-execution rows (sha/argon/rsw) need no field.

// 36. All execution rows recorded at the current manifest maximum:
//     accepted (a clean schema-3 matrix whose execution rows carry
//     executionVersion = <manifest max> and whose sha/argon rows carry
//     none).
{
  const payload = schema3Payload();
  const execKeys = executionRowKeys(payload.results);
  const shaKeys = Object.keys(payload.results).filter(
    (k) => !k.startsWith('multi-widget') && !execKeys.includes(k)
  );
  if (shaKeys.length === 0) throw new Error('test fixture regression: schema-3 matrix has no non-execution rows');
  const res = runValidator(payload, baseBudgets(), false);
  pass(`all execution rows at the manifest max (${EXECUTION_MAX_VERSION}) + non-execution rows without executionVersion: accepted`, res);
}

// 37. Every execution row recorded at version 3 while the manifest
//     maximum is higher: the grammar-v3-era evidence is rejected.
{
  const payload = schema3Payload();
  for (const k of executionRowKeys(payload.results)) payload.results[k].executionVersion = 3;
  const res = runValidator(payload, baseBudgets(), false);
  reject(`manifest max ${EXECUTION_MAX_VERSION} + all execution rows at executionVersion 3: reject`, res, [`executionVersion 3 is not the live grammar version ${EXECUTION_MAX_VERSION}`]);
}

// 38. One execution cell below the manifest maximum: the rejection
//     names that cell.
{
  const payload = schema3Payload();
  const key = `${RELEASE_TIER}:execvm:cold:files`;
  payload.results[key].executionVersion = 4;
  const res = runValidator(payload, baseBudgets(), false);
  reject(`manifest max ${EXECUTION_MAX_VERSION} + one exec cell at 4: reject naming the cell`, res, [key, 'executionVersion 4 is not the live grammar version']);
}

// 39. Execution rows without an executionVersion field (current
//     schema): missing evidence rejects.
{
  const payload = schema3Payload();
  for (const k of executionRowKeys(payload.results)) delete payload.results[k].executionVersion;
  const res = runValidator(payload, baseBudgets(), false);
  reject('execution rows with executionVersion missing (current schema): reject', res, ['executionVersion is not recorded']);
}

// 40. Non-execution SHA/Argon rows without executionVersion: accepted
//     (the field is execution evidence only).
{
  const payload = schema3Payload();
  const execKeys = executionRowKeys(payload.results);
  for (const k of Object.keys(payload.results)) {
    if (!k.startsWith('multi-widget') && !execKeys.includes(k)) delete payload.results[k].executionVersion;
  }
  pass('non-execution SHA/Argon rows without executionVersion: accepted', runValidator(payload, baseBudgets(), false));
}

// ── Interactive-classification cases (audit finding 4, round 6). ────
// The interactive/non-interactive classification derives from the
// harness difficulty profiles (execchain interactive: false, the one
// difficulty never counted as an ordinary interactive release cell;
// every other profile defaults to interactive). The budgets file can
// no longer declare a classification: nonInteractiveDifficulties is an
// unknown/deprecated field, and changing only release-budgets.json can
// never change a difficulty's classification.

// 41. A budgets file that reintroduces nonInteractiveDifficulties
//     (even naming a real difficulty): rejected as unknown/deprecated.
{
  const budgets = baseBudgets();
  budgets.nonInteractiveDifficulties = ['execchain'];
  const res = runValidator(schema3Payload(), budgets, false);
  reject('budgets file reintroducing nonInteractiveDifficulties: reject as unknown/deprecated', res, ['nonInteractiveDifficulties is an unknown/deprecated field']);
}

// 42. execchain (non-interactive by harness profile) budget above the
//     5 s absolute ceiling: allowed — it is budgeted and measured like
//     every cell but never ceiling-checked.
{
  const payload = schema3Payload();
  const budgets = baseBudgets();
  for (const cache of CACHE_STATES) {
    budgets.budgets[RELEASE_TIER].execchain[cache].solveMsP95 = 6000;
    budgets.budgets[RELEASE_TIER].execchain[cache].pageToVerifiedMsP95 = 6000;
  }
  pass('execchain (interactive: false in the harness) budget 6000 ms above the absolute ceiling: allowed', runValidator(payload, budgets, false));
}

// 43. argon2id (interactive) budget above the 5 s absolute ceiling:
//     rejected.
{
  const payload = schema3Payload();
  const budgets = baseBudgets();
  for (const cache of CACHE_STATES) {
    budgets.budgets[RELEASE_TIER].argon2id[cache].solveMsP95 = 6000;
    budgets.budgets[RELEASE_TIER].argon2id[cache].pageToVerifiedMsP95 = 6000;
  }
  const res = runValidator(payload, budgets, false);
  reject('argon2id budget 6000 ms above the absolute ceiling: reject', res, ['argon2id', 'exceeds the absolute interactive ceiling'], ['exceeds the budget']);
}

// 44. sha20 (interactive) budget above the 5 s absolute ceiling:
//     rejected.
{
  const payload = schema3Payload();
  const budgets = baseBudgets();
  for (const cache of CACHE_STATES) {
    budgets.budgets[RELEASE_TIER].sha20[cache].solveMsP95 = 6000;
    budgets.budgets[RELEASE_TIER].sha20[cache].pageToVerifiedMsP95 = 6000;
  }
  const res = runValidator(payload, budgets, false);
  reject('sha20 budget 6000 ms above the absolute ceiling: reject', res, ['sha20', 'exceeds the absolute interactive ceiling'], ['exceeds the budget']);
}

// 45. The classification invariant: a budget file mutation trying to
//     flip sha20 to non-interactive (deprecated field + inflated
//     budget) rejects on BOTH reasons — the unknown/deprecated field
//     AND the still-binding interactive ceiling. Changing only the
//     release budgets can never change the interactive classification.
{
  const payload = schema3Payload();
  const budgets = baseBudgets();
  budgets.nonInteractiveDifficulties = ['sha20'];
  for (const cache of CACHE_STATES) {
    budgets.budgets[RELEASE_TIER].sha20[cache].solveMsP95 = 6000;
    budgets.budgets[RELEASE_TIER].sha20[cache].pageToVerifiedMsP95 = 6000;
  }
  const res = runValidator(payload, budgets, false);
  reject('budgets-only mutation trying to classify sha20 non-interactive (deprecated field + 6000 ms budget): reject on the deprecated field AND the still-binding ceiling', res, ['nonInteractiveDifficulties is an unknown/deprecated field', 'sha20', 'exceeds the absolute interactive ceiling']);
}

console.log(`\n${cases - failures}/${cases} mutation cases passed`);
process.exit(failures === 0 ? 0 : 1);
