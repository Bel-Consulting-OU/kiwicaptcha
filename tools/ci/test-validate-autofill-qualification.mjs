#!/usr/bin/env node
/**
 * Adversarial mutation corpus for
 * tools/ci/validate-autofill-qualification.mjs.
 *
 * The autofill qualification matrix is release-gating evidence, so the
 * validator is a certification parser: the negative states are the
 * important part. CI's ordinary invocation (the validator against the
 * committed matrix) only proves today's real file is refused; this
 * suite proves the validator REJECTS carefully constructed bad states
 * (and accepts the good ones), asserting on exit codes AND on the
 * specific reason substrings of the validator's own messages.
 *
 * Usage:
 *   node tools/ci/test-validate-autofill-qualification.mjs
 *
 * Every fixture is generated in os.tmpdir() (a fresh directory per run)
 * and the validator is executed as a subprocess exactly like the release
 * invocation:
 *   node tools/ci/validate-autofill-qualification.mjs <matrix.json>
 *        [--registry <surfaces.json>] [--window-days <n>]
 * The suite reads the committed surface registry
 * (tests/browser/qualification/surfaces.json) and derives every fixture
 * from it, so fixtures can never drift from the registry authority.
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
const VALIDATOR = join(SCRIPT_DIR, 'validate-autofill-qualification.mjs');
const REGISTRY = join(REPO_ROOT, 'tests', 'browser', 'qualification', 'surfaces.json');
const COMMITTED_MATRIX = join(REPO_ROOT, 'tests', 'browser', 'qualification', 'autofill-matrix.json');

const REGISTRY_DATA = JSON.parse(readFileSync(REGISTRY, 'utf8'));
const REQUIRED = REGISTRY_DATA.surfaces.filter((s) => s.required);
const ADVISORY = REGISTRY_DATA.surfaces.filter((s) => !s.required);

const DAY_MS = 86400000;
const HOUR_MS = 3600000;
const iso = (offsetMs) => new Date(Date.now() + offsetMs).toISOString();

const FIXTURE_DIR = mkdtempSync(join(tmpdir(), 'kiwicaptcha-autofill-'));
let fixtureSeq = 0;

/** A good pass row for a registry surface, with an exact version. */
function goodRow(surface, overrides = {}) {
  return {
    surface: surface.id,
    product: surface.product,
    version: '1.2.3',
    platform: surface.platform,
    status: 'pass',
    tested_at: iso(-HOUR_MS),
    ...overrides,
  };
}

/** The good matrix: every required surface passes with an exact version. */
function goodMatrix() {
  return {
    schema: 'kiwicaptcha.autofill-qualification/1',
    rows: REQUIRED.map((surface) => goodRow(surface)),
  };
}

function writeFixture(label, data) {
  const path = join(FIXTURE_DIR, `${String(fixtureSeq++).padStart(2, '0')}-${label}.json`);
  writeFileSync(path, JSON.stringify(data, null, 2));
  return path;
}

function runValidator(matrixPath, extraArgs = []) {
  const result = spawnSync('node', [VALIDATOR, matrixPath, ...extraArgs], { encoding: 'utf8' });
  if (result.error) throw result.error;
  return { code: result.status, output: `${result.stdout}${result.stderr}` };
}

let failures = 0;
let cases = 0;

/** Assert one mutation: expected exit code and expected reason substrings. */
function expect(label, matrix, { code = 1, contains = [] } = {}, extraArgs = []) {
  cases++;
  const path = writeFixture(label, matrix);
  const { code: actualCode, output } = runValidator(path, extraArgs);
  const problems = [];
  if (actualCode !== code) problems.push(`exit ${actualCode} != ${code}`);
  for (const needle of contains) {
    if (!output.includes(needle)) problems.push(`missing reason ${JSON.stringify(needle)}`);
  }
  if (problems.length) {
    failures++;
    process.stderr.write(`FAIL ${label}: ${problems.join('; ')}\n${output}\n`);
  } else {
    process.stdout.write(`ok ${label}\n`);
  }
}

// ── Positive cases. ─────────────────────────────────────────────────

expect('good matrix', goodMatrix(), { code: 0 });

{
  // A registry-advisory surface may record a pass without gating; the
  // run stays accepted with the advisory note.
  const matrix = goodMatrix();
  for (const surface of ADVISORY) matrix.rows.push(goodRow(surface));
  expect('advisory registry surface with a pass', matrix, { code: 0, contains: ['advisory'] });
}

{
  // Rows for ids the registry does not know are advisory, never gating.
  const matrix = goodMatrix();
  matrix.rows.push({
    surface: 'ad-hoc-manager',
    product: 'Ad hoc manager',
    version: '9.9.9',
    platform: 'desktop',
    status: 'pass',
    tested_at: iso(-HOUR_MS),
  });
  expect('extra advisory surface', matrix, { code: 0, contains: ['not in the surface registry'] });
}

// ── Schema and coverage. ────────────────────────────────────────────

expect('wrong matrix schema', { ...goodMatrix(), schema: 'kiwicaptcha.autofill-qualification/2' }, { contains: ['schema'] });

expect('matrix rows not an array', { schema: 'kiwicaptcha.autofill-qualification/1', rows: {} }, { contains: ['rows must be an array'] });

{
  const matrix = goodMatrix();
  matrix.rows.splice(3, 1);
  expect('missing required row', matrix, { contains: ['has no row in the matrix'] });
}

{
  const matrix = goodMatrix();
  matrix.rows.push({ ...goodRow(REQUIRED[0]), status: 'pass' });
  expect('duplicate row (first pass, second pass)', matrix, { contains: ['is duplicated'] });
}

{
  const matrix = goodMatrix();
  const row = matrix.rows[0];
  matrix.rows.push({ ...row, status: 'fail', tested_at: null, version: null });
  expect('duplicate row (first pass, second fail)', matrix, { contains: ['is duplicated'] });
}

{
  const matrix = goodMatrix();
  const row = matrix.rows[0];
  matrix.rows.push({ ...row, status: 'fail', tested_at: null, version: null });
  matrix.rows.reverse();
  expect('duplicate row (first fail, second pass)', matrix, { contains: ['is duplicated'] });
}

// ── Versions. ───────────────────────────────────────────────────────

expect('blank version', withRow(goodMatrix(), 0, { version: '   ' }), { contains: ['placeholder version'] });
expect('CURRENT version', withRow(goodMatrix(), 0, { version: 'CURRENT' }), { contains: ['placeholder version'] });
expect('TBD version', withRow(goodMatrix(), 0, { version: 'TBD' }), { contains: ['placeholder version'] });
expect('unknown version', withRow(goodMatrix(), 0, { version: 'unknown' }), { contains: ['placeholder version'] });
expect('null version on a pass row', withRow(goodMatrix(), 0, { version: null }), { contains: ['placeholder version'] });
expect('non-string version', withRow(goodMatrix(), 0, { version: 7 }), { contains: ['must be a string or null'] });

// ── Platforms. ──────────────────────────────────────────────────────

{
  const chrome = REQUIRED.find((s) => s.id === 'chrome-builtin-autofill');
  expect('wrong platform', withRow(goodMatrix(), 0, { platform: 'windows' }), {
    contains: [`not the registry platform ${JSON.stringify(chrome.platform)}`],
  });
}

{
  const matrix = goodMatrix();
  delete matrix.rows[1].platform;
  expect('absent platform', matrix, { contains: ['missing the required field platform'] });
}

expect('unknown platform class', withRow(goodMatrix(), 0, { platform: 'linux' }), { contains: ['is not one of'] });

// ── Dates. ──────────────────────────────────────────────────────────

expect('malformed date', withRow(goodMatrix(), 0, { tested_at: '08/30/2026' }), { contains: ['not a strict ISO-8601 date'] });
expect('malformed date (loose word)', withRow(goodMatrix(), 0, { tested_at: 'yesterday' }), { contains: ['not a strict ISO-8601 date'] });
expect('stale date', withRow(goodMatrix(), 0, { tested_at: iso(-100 * DAY_MS) }), { contains: ['older than the 90-day qualification window'] });
expect('future date', withRow(goodMatrix(), 0, { tested_at: iso(10 * DAY_MS) }), { contains: ['materially in the future'] });
expect('missing tested_at on a pass row', withRow(goodMatrix(), 0, { tested_at: null }), { contains: ['without a tested_at date'] });
expect('missing tested_at field', (() => { const m = goodMatrix(); delete m.rows[0].tested_at; return m; })(), { contains: ['missing the required field tested_at'] });

// ── Statuses. ───────────────────────────────────────────────────────

expect('blocked required row', withRow(goodMatrix(), 0, { status: 'blocked', tested_at: null }), { contains: ['status "blocked"'] });
expect('fail required row', withRow(goodMatrix(), 0, { status: 'fail', tested_at: null }), { contains: ['status "fail"'] });
expect('manual_pending required row', withRow(goodMatrix(), 0, { status: 'manual_pending', tested_at: null }), { contains: ['status "manual_pending"'] });
expect('unknown status', withRow(goodMatrix(), 0, { status: 'maybe' }), { contains: ['is not one of'] });

// ── Product identity. ───────────────────────────────────────────────

expect('mismatched product display name', withRow(goodMatrix(), 0, { product: 'Chromium-ish' }), { contains: ['is not the registry product'] });

// ── Registry integrity. ─────────────────────────────────────────────

{
  const duplicated = JSON.parse(JSON.stringify(REGISTRY_DATA));
  duplicated.surfaces.push({ ...duplicated.surfaces[0] });
  const registryPath = writeFixture('registry-duplicate-id', duplicated);
  expect('duplicate registry id', goodMatrix(), { contains: ['registry surface id', 'is duplicated'] }, ['--registry', registryPath]);
}

{
  const badPlatform = JSON.parse(JSON.stringify(REGISTRY_DATA));
  badPlatform.surfaces[0].platform = 'beos';
  const registryPath = writeFixture('registry-bad-platform', badPlatform);
  expect('registry bad platform class', goodMatrix(), { contains: ['is not one of'] }, ['--registry', registryPath]);
}

// ── Window tuning and the committed fail-closed matrix. ─────────────

expect('window-days override accepts an older pass', withRow(goodMatrix(), 0, { tested_at: iso(-100 * DAY_MS) }), { code: 0 }, ['--window-days', '200']);

{
  cases++;
  const { code, output } = runValidator(COMMITTED_MATRIX);
  if (code !== 1 || !output.includes('manual_pending')) {
    failures++;
    process.stderr.write(`FAIL committed matrix stays fail-closed: exit ${code}\n${output}\n`);
  } else {
    process.stdout.write('ok committed matrix stays fail-closed\n');
  }
}

if (failures) {
  process.stderr.write(`test-validate-autofill-qualification: ${failures} of ${cases} cases failed\n`);
  process.exit(1);
}
process.stdout.write(`test-validate-autofill-qualification: OK (${cases} cases)\n`);
process.exit(0);

/** Clone the good matrix with one row overridden. */
function withRow(matrix, index, overrides) {
  const clone = JSON.parse(JSON.stringify(matrix));
  Object.assign(clone.rows[index], overrides);
  return clone;
}
