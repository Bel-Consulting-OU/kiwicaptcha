#!/usr/bin/env node
/**
 * Adversarial mutation corpus for the accessibility qualification gate
 * (tools/ci/validate-accessibility-qualification.mjs). Each case mutates
 * a good, signed matrix and must be refused with the named reason; the
 * good matrices — Chrome/NVDA, Firefox/NVDA, Safari/VoiceOver and real
 * speech or switch evidence — must pass, so the accept path is proven
 * too.
 *
 * Covered rejections: evidence substitution between rows (browser and
 * AT families), a wrong row platform, missing 200% zoom, placeholder
 * versions, stale and future dates, an enlarged matrix-declared window,
 * impossible timezone offsets (+99:99, +24:00, +01:60), a wrong release
 * asset digest, missing observation fields, pending status on a
 * required row, duplicate rows, missing required rows, a demoted
 * required row, malformed schema, a pass without evidence, a missing
 * signature, an unknown tester and evidence modified after signing.
 *
 * Usage: node tools/ci/test-validate-accessibility-qualification.mjs
 * Exit status: 0 when every case behaved as expected, 1 otherwise.
 */
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
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
const PLATFORMS = {
  'nvda-chrome-windows': 'windows',
  'nvda-firefox-windows': 'windows',
  'voiceover-safari-macos': 'macos',
  'speech-or-switch-desktop': 'desktop',
};
const ASSET_IDENTITY = sha256Hex(canonicalJson(canonicalClientAssets()));
const nowIso = new Date(Date.now() - 60 * 60 * 1000).toISOString();

const TESTER_ID = 'test-tester';
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const KEYS_FILE = join(TMP, 'tester-keys.json');
writeFileSync(
  KEYS_FILE,
  JSON.stringify({ schema: 'kiwicaptcha.tester-keys/1', testers: { [TESTER_ID]: publicKey.export({ type: 'spki', format: 'pem' }) } }, null, 2),
);

let cases = 0;
let failures = 0;

function signEvidence(evidence) {
  return cryptoSign(null, Buffer.from(canonicalJson(evidence), 'utf8'), privateKey).toString('base64');
}

function evidenceFor(id, overrides = {}) {
  const base = {
    browser: 'Google Chrome',
    browser_version: '141.0.7390.55',
    assistive_technology: 'NVDA',
    assistive_technology_version: '2025.3',
    zoom_percent: 200,
    keyboard: 'pass',
    live_region: 'pass',
    focus: 'pass',
    content_loss: 'pass',
    asset_identity: ASSET_IDENTITY,
    tester_id: TESTER_ID,
  };
  if (id === 'nvda-chrome-windows') Object.assign(base, { browser_family: 'chrome', assistive_technology_family: 'nvda' });
  if (id === 'nvda-firefox-windows') Object.assign(base, { browser: 'Firefox', browser_family: 'firefox', assistive_technology_family: 'nvda' });
  if (id === 'voiceover-safari-macos') Object.assign(base, { browser: 'Safari', browser_family: 'safari', assistive_technology: 'VoiceOver', assistive_technology_family: 'voiceover', assistive_technology_version: '26.0' });
  if (id === 'speech-or-switch-desktop') Object.assign(base, { browser_family: undefined, assistive_technology: 'Dragon Professional', assistive_technology_version: '16.0', interaction_mode: 'speech-recognition' });
  if (base.browser_family === undefined) delete base.browser_family;
  return { ...base, ...overrides };
}

function goodRow(id, overrides = {}) {
  const evidence = evidenceFor(id, overrides.evidence || {});
  return {
    id,
    product: id,
    platform: overrides.platform || PLATFORMS[id],
    required: true,
    status: 'pass',
    tested_at: overrides.tested_at || nowIso,
    evidence,
    signature: overrides.signature !== undefined ? overrides.signature : signEvidence(evidence),
  };
}

function goodMatrix() {
  return {
    schema: 'kiwicaptcha.accessibility-qualification/1',
    qualification_window_days: 90,
    rows: REQUIRED_IDS.map((id) => goodRow(id)),
  };
}

function withRow(matrix, index, mutator) {
  const clone = JSON.parse(JSON.stringify(matrix));
  mutator(clone.rows[index]);
  return clone;
}

function runValidator(matrix) {
  const file = join(TMP, `matrix-${cases}-${Date.now()}.json`);
  writeFileSync(file, JSON.stringify(matrix, null, 2));
  const result = spawnSync(process.execPath, [VALIDATOR, file, KEYS_FILE], { cwd: REPO_ROOT, encoding: 'utf8' });
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

// ── The accept path: correctly signed, structurally consistent rows. ──
expect('good matrix passes', goodMatrix(), { status: 0, includes: ['PASS'] });
expect('real switch-access evidence passes', withRow(goodMatrix(), 3, (row) => {
  row.evidence.interaction_mode = 'switch-access';
  row.evidence.assistive_technology = 'Switch Control';
  row.signature = signEvidence(row.evidence);
}), { status: 0 });
expect('Firefox + NVDA with the contract families passes', (() => {
  const matrix = goodMatrix();
  return matrix; // covered by the good matrix itself
})(), { status: 0 });

// Advisory pending rows do not block.
{
  const matrix = goodMatrix();
  matrix.rows.push({ id: 'jaws-windows', product: 'JAWS', platform: 'windows', required: false, status: 'manual_pending', tested_at: null, evidence: null, signature: null });
  expect('advisory pending row does not block', matrix, { status: 0 });
}

// ── Evidence substitution between rows. ──────────────────────────────
expect('nvda-chrome id with Safari/VoiceOver evidence is rejected', withRow(goodMatrix(), 0, (row) => {
  Object.assign(row.evidence, { browser: 'Safari', browser_family: 'safari', assistive_technology: 'VoiceOver', assistive_technology_family: 'voiceover', assistive_technology_version: '26.0' });
  row.signature = signEvidence(row.evidence);
}), { status: 1, includes: ['browser_family "safari" does not match the row contract family "chrome"', 'assistive_technology_family "voiceover" does not match'] });
expect('nvda-firefox id with Chrome/NVDA evidence is rejected', withRow(goodMatrix(), 1, (row) => {
  Object.assign(row.evidence, { browser: 'Google Chrome', browser_family: 'chrome' });
  row.signature = signEvidence(row.evidence);
}), { status: 1, includes: ['browser_family "chrome" does not match the row contract family "firefox"'] });
expect('voiceover-safari id with Chrome/NVDA evidence is rejected', withRow(goodMatrix(), 2, (row) => {
  Object.assign(row.evidence, { browser: 'Google Chrome', browser_family: 'chrome', assistive_technology: 'NVDA', assistive_technology_family: 'nvda', assistive_technology_version: '2025.3' });
  row.signature = signEvidence(row.evidence);
}), { status: 1, includes: ['browser_family "chrome" does not match the row contract family "safari"', 'assistive_technology_family "nvda" does not match'] });
expect('speech/switch id without an interaction mode is rejected', withRow(goodMatrix(), 3, (row) => {
  delete row.evidence.interaction_mode;
  Object.assign(row.evidence, { assistive_technology: 'NVDA', assistive_technology_version: '2025.3' });
  row.signature = signEvidence(row.evidence);
}), { status: 1, includes: ['interaction_mode null is not one of speech-recognition|switch-access'] });
expect('a Windows row with platform macos is rejected', withRow(goodMatrix(), 0, (row) => {
  row.platform = 'macos';
}), { status: 1, includes: ['platform "macos" is not the contract platform "windows"'] });

// ── Freshness, window authority and strict instants. ─────────────────
expect('missing 200% zoom is rejected', withRow(goodMatrix(), 0, (row) => {
  row.evidence.zoom_percent = 100;
  row.signature = signEvidence(row.evidence);
}), { status: 1, includes: ['zoom_percent 100 is not 200'] });
expect('placeholder browser version is rejected', withRow(goodMatrix(), 0, (row) => {
  row.evidence.browser_version = 'CURRENT';
  row.signature = signEvidence(row.evidence);
}), { status: 1, includes: ['browser_version "CURRENT" is a placeholder'] });
expect('stale tested_at is rejected', withRow(goodMatrix(), 0, (row) => {
  row.tested_at = new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString();
}), { status: 1, includes: ['older than the validator-owned 90-day qualification window'] });
expect('future tested_at is rejected', withRow(goodMatrix(), 0, (row) => {
  row.tested_at = new Date(Date.now() + 60 * 60 * 1000).toISOString();
}), { status: 1, includes: ['materially in the future'] });
expect('an enlarged matrix-declared window is rejected', (() => {
  const matrix = goodMatrix();
  matrix.qualification_window_days = 36500;
  matrix.rows.forEach((row) => {
    row.tested_at = new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString();
  });
  return matrix;
})(), { status: 1, includes: ['qualification_window_days 36500 must equal the validator-owned 90'] });
for (const [offset, label] of [['+99:99', 'impossible offset +99:99'], ['+24:00', 'impossible offset +24:00'], ['+01:60', 'impossible offset +01:60']]) {
  expect(`${label} is rejected`, withRow(goodMatrix(), 0, (row) => {
    row.tested_at = `2026-09-29T12:00:00${offset}`;
  }), { status: 1, includes: ['is not a strict ISO-8601 instant'] });
}

// ── Evidence quality. ────────────────────────────────────────────────
expect('wrong release asset digest is rejected', withRow(goodMatrix(), 0, (row) => {
  row.evidence.asset_identity = 'a'.repeat(64);
  row.signature = signEvidence(row.evidence);
}), { status: 1, includes: ['is not the current release asset identity'] });
for (const field of ['keyboard', 'live_region', 'focus', 'content_loss']) {
  expect(`missing ${field} observation is rejected`, withRow(goodMatrix(), 0, (row) => {
    delete row.evidence[field];
    row.signature = signEvidence(row.evidence);
  }), { status: 1, includes: [`evidence.${field} null is not "pass"`] });
}
expect('pending status on a required row is rejected', withRow(goodMatrix(), 2, (row) => {
  row.status = 'manual_pending';
  row.tested_at = null;
  row.evidence = null;
  row.signature = null;
}), { status: 1, includes: ['required row voiceover-safari-macos status "manual_pending" is not "pass"'] });

// ── Signing. ─────────────────────────────────────────────────────────
expect('a pass without a signature is rejected', withRow(goodMatrix(), 0, (row) => {
  row.signature = null;
}), { status: 1, includes: ['marked pass without a signature'] });
expect('an unknown tester is rejected', withRow(goodMatrix(), 0, (row) => {
  row.evidence.tester_id = 'someone-else';
  row.signature = signEvidence(row.evidence);
}), { status: 1, includes: ['is not in the tester public-key allowlist'] });
expect('evidence modified after signing is rejected', withRow(goodMatrix(), 0, (row) => {
  row.evidence.browser_version = '141.0.7390.99';
}), { status: 1, includes: ['signature does not verify against'] });

// ── Matrix structure. ────────────────────────────────────────────────
{
  const matrix = goodMatrix();
  matrix.rows.push(JSON.parse(JSON.stringify(matrix.rows[0])));
  expect('duplicate row ids are rejected', matrix, { status: 1, includes: ['repeats the row id'] });
}
{
  const matrix = goodMatrix();
  matrix.rows = matrix.rows.filter((row) => row.id !== 'nvda-firefox-windows');
  expect('NVDA on one browser only is rejected', matrix, { status: 1, includes: ['required row nvda-firefox-windows is missing'] });
}
{
  const matrix = goodMatrix();
  matrix.rows = matrix.rows.filter((row) => row.id !== 'speech-or-switch-desktop');
  expect('missing speech/switch row is rejected', matrix, { status: 1, includes: ['required row speech-or-switch-desktop is missing'] });
}
expect('a required row demoted to advisory is rejected', withRow(goodMatrix(), 1, (row) => {
  row.required = false;
}), { status: 1, includes: ['must carry required: true'] });
expect('malformed schema is rejected', { schema: 'nope', rows: [] }, { status: 1, includes: ['matrix schema must be'] });
expect('pass without an evidence object is rejected', withRow(goodMatrix(), 0, (row) => {
  row.evidence = null;
}), { status: 1, includes: ['without an evidence object'] });

rmSync(TMP, { recursive: true, force: true });
if (failures) {
  process.stderr.write(`test-validate-accessibility-qualification: ${failures} of ${cases} cases failed\n`);
  process.exit(1);
}
process.stdout.write(`test-validate-accessibility-qualification: OK (${cases} cases)\n`);
process.exit(0);
