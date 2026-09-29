#!/usr/bin/env node
/**
 * Adversarial mutation corpus for the accessibility qualification gate
 * (tools/ci/validate-accessibility-qualification.mjs). Each case mutates
 * a good matrix and must be refused with the named reason; the good
 * matrix itself must pass, so the accept path is proven too.
 *
 * Covered rejections: missing 200% zoom, NVDA on one browser only,
 * missing VoiceOver + Safari, missing speech/switch row, placeholder
 * version, stale date, future date, wrong release asset digest, a pass
 * with missing observation fields, pending status, duplicate rows,
 * malformed schema and a required row demoted to advisory.
 *
 * Usage: node tools/ci/test-validate-accessibility-qualification.mjs
 * Exit status: 0 when every case behaved as expected, 1 otherwise.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalClientAssets } from '../client-perf/client-assets.mjs';
import { canonicalJson, sha256Hex } from '../client-perf/canonical-json.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const VALIDATOR = join(SCRIPT_DIR, 'validate-accessibility-qualification.mjs');
const TMP = mkdtempSync(join(tmpdir(), 'kiwicaptcha-a11y-qual-'));

const REQUIRED_IDS = [
  'nvda-chrome-windows',
  'nvda-firefox-windows',
  'voiceover-safari-macos',
  'speech-or-switch-desktop',
];
const ASSET_IDENTITY = sha256Hex(canonicalJson(canonicalClientAssets()));
const nowIso = new Date(Date.now() - 60 * 60 * 1000).toISOString();

let cases = 0;
let failures = 0;

function goodEvidence(product) {
  return {
    browser: product.includes('Firefox') ? 'Firefox' : product.includes('Safari') ? 'Safari' : 'Chrome',
    browser_version: '141.0.7390.55',
    assistive_technology: product.split(' ')[0],
    assistive_technology_version: '2025.3',
    zoom_percent: 200,
    keyboard: 'pass',
    live_region: 'pass',
    focus: 'pass',
    content_loss: 'pass',
    asset_identity: ASSET_IDENTITY,
  };
}

function goodMatrix() {
  return {
    schema: 'kiwicaptcha.accessibility-qualification/1',
    qualification_window_days: 90,
    rows: REQUIRED_IDS.map((id) => ({
      id,
      product: id,
      platform: id.includes('windows') ? 'windows' : id.includes('macos') ? 'macos' : 'desktop',
      required: true,
      status: 'pass',
      tested_at: nowIso,
      evidence: goodEvidence(id),
    })),
  };
}

function withRow(matrix, index, overrides) {
  const clone = JSON.parse(JSON.stringify(matrix));
  Object.assign(clone.rows[index], overrides);
  return clone;
}

function runValidator(matrix) {
  const file = join(TMP, `matrix-${cases}-${Date.now()}.json`);
  writeFileSync(file, JSON.stringify(matrix, null, 2));
  const result = spawnSync(process.execPath, [VALIDATOR, file], { cwd: REPO_ROOT, encoding: 'utf8' });
  return { status: result.status, output: `${result.stdout || ''}${result.stderr || ''}` };
}

function expect(label, matrix, { status, includes = [] }) {
  cases += 1;
  const result = runValidator(matrix);
  if (result.status !== status) {
    failures += 1;
    process.stderr.write(`FAIL ${label}: expected exit ${status}, got ${result.status}\n${result.output.slice(0, 600)}\n`);
    return;
  }
  for (const needle of includes) {
    if (!result.output.includes(needle)) {
      failures += 1;
      process.stderr.write(`FAIL ${label}: output does not include ${JSON.stringify(needle)}\n${result.output.slice(0, 600)}\n`);
      return;
    }
  }
  process.stdout.write(`ok ${label}\n`);
}

// The accept path: a complete good matrix passes.
expect('good matrix passes', goodMatrix(), { status: 0, includes: ['PASS'] });

// Advisory rows do not block.
{
  const matrix = goodMatrix();
  matrix.rows.push({ id: 'jaws-windows', product: 'JAWS', platform: 'windows', required: false, status: 'manual_pending', tested_at: null, evidence: null });
  expect('advisory pending row does not block', matrix, { status: 0 });
}

// Missing 200% zoom.
expect(
  'missing 200% zoom is rejected',
  withRow(goodMatrix(), 0, { evidence: { ...goodEvidence('nvda-chrome-windows'), zoom_percent: 100 } }),
  { status: 1, includes: ['zoom_percent 100 is not 200', 'actual 200% browser/user zoom'] },
);

// NVDA on one browser only.
{
  const matrix = goodMatrix();
  matrix.rows = matrix.rows.filter((row) => row.id !== 'nvda-firefox-windows');
  expect('NVDA on one browser only is rejected', matrix, { status: 1, includes: ['required row nvda-firefox-windows is missing'] });
}

// Missing VoiceOver + Safari.
{
  const matrix = goodMatrix();
  matrix.rows = matrix.rows.filter((row) => row.id !== 'voiceover-safari-macos');
  expect('missing VoiceOver + Safari is rejected', matrix, { status: 1, includes: ['required row voiceover-safari-macos is missing'] });
}

// Missing speech/switch row.
{
  const matrix = goodMatrix();
  matrix.rows = matrix.rows.filter((row) => row.id !== 'speech-or-switch-desktop');
  expect('missing speech/switch row is rejected', matrix, { status: 1, includes: ['required row speech-or-switch-desktop is missing'] });
}

// Placeholder versions.
expect(
  'placeholder browser version is rejected',
  withRow(goodMatrix(), 0, { evidence: { ...goodEvidence('nvda-chrome-windows'), browser_version: 'CURRENT' } }),
  { status: 1, includes: ['browser_version "CURRENT" is a placeholder'] },
);
expect(
  'placeholder AT version is rejected',
  withRow(goodMatrix(), 0, { evidence: { ...goodEvidence('nvda-chrome-windows'), assistive_technology_version: 'TBD' } }),
  { status: 1, includes: ['assistive_technology_version "TBD" is a placeholder'] },
);

// Stale date.
expect(
  'stale tested_at is rejected',
  withRow(goodMatrix(), 0, { tested_at: new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString() }),
  { status: 1, includes: ['older than the 90-day qualification window'] },
);

// Future date.
expect(
  'future tested_at is rejected',
  withRow(goodMatrix(), 0, { tested_at: new Date(Date.now() + 60 * 60 * 1000).toISOString() }),
  { status: 1, includes: ['materially in the future'] },
);

// Wrong release asset digest.
expect(
  'wrong release asset digest is rejected',
  withRow(goodMatrix(), 0, { evidence: { ...goodEvidence('nvda-chrome-windows'), asset_identity: 'a'.repeat(64) } }),
  { status: 1, includes: ['is not the current release asset identity'] },
);

// Missing observation fields.
for (const field of ['keyboard', 'live_region', 'focus', 'content_loss']) {
  const evidence = goodEvidence('nvda-chrome-windows');
  delete evidence[field];
  expect(
    `missing ${field} observation is rejected`,
    withRow(goodMatrix(), 0, { evidence }),
    { status: 1, includes: [`evidence.${field} null is not "pass"`] },
  );
}

// Pending status on a required row.
expect(
  'pending status on a required row is rejected',
  withRow(goodMatrix(), 2, { status: 'manual_pending', tested_at: null, evidence: null }),
  { status: 1, includes: ['required row voiceover-safari-macos status "manual_pending" is not "pass"'] },
);

// Duplicate rows.
{
  const matrix = goodMatrix();
  matrix.rows.push(JSON.parse(JSON.stringify(matrix.rows[0])));
  expect('duplicate row ids are rejected', matrix, { status: 1, includes: ['repeats the row id'] });
}

// Required row demoted to advisory.
expect(
  'a required row demoted to advisory is rejected',
  withRow(goodMatrix(), 1, { required: false }),
  { status: 1, includes: ['must carry required: true'] },
);

// Malformed schema.
expect('malformed schema is rejected', { schema: 'nope', rows: [] }, { status: 1, includes: ['matrix schema must be'] });

// Missing evidence object.
expect(
  'pass without an evidence object is rejected',
  withRow(goodMatrix(), 0, { evidence: null }),
  { status: 1, includes: ['without an evidence object'] },
);

rmSync(TMP, { recursive: true, force: true });
if (failures) {
  process.stderr.write(`test-validate-accessibility-qualification: ${failures} of ${cases} cases failed\n`);
  process.exit(1);
}
process.stdout.write(`test-validate-accessibility-qualification: OK (${cases} cases)\n`);
process.exit(0);
