#!/usr/bin/env node
/**
 * The manual accessibility qualification gate (release-blocking).
 *
 * packages/kiwicaptcha-wasm/ACCESSIBILITY.md promises that release
 * qualification includes a real-browser run at actual 200% zoom with
 * NVDA + Chrome (Windows), NVDA + Firefox (Windows), VoiceOver + Safari
 * (macOS) and one speech-recognition or switch-access pass, recorded as
 * signed evidence. This validator is that promise turned into a gate:
 * it reads tests/browser/qualification/accessibility-matrix.json and
 * refuses the release until every required row is a real pass.
 *
 * Checks (release-blocking; the mutation corpus in
 * tools/ci/test-validate-accessibility-qualification.mjs proves each
 * one rejects):
 *
 *   1. the matrix carries schema
 *      "kiwicaptcha.accessibility-qualification/1" and a rows array;
 *   2. the required row ids are exactly
 *      nvda-chrome-windows, nvda-firefox-windows,
 *      voiceover-safari-macos and speech-or-switch-desktop, each
 *      present exactly once (NVDA on one browser only is a rejection);
 *   3. every required row has status "pass" (manual_pending, fail and
 *      blocked all refuse the release with their status named);
 *   4. a pass row records a real tested_at: a strict ISO-8601 instant,
 *      not materially in the future, inside the qualification window
 *      (qualification_window_days, default 90);
 *   5. a pass row records an exact browser and assistive-technology
 *      version: CURRENT, TBD, unknown and similar placeholders are
 *      rejected;
 *   6. a pass row records zoom_percent === 200 (the actual 200% zoom
 *      run is part of the promised scope, not an inferred value);
 *   7. a pass row records keyboard, live_region, focus and
 *      content_loss observations, each exactly "pass";
 *   8. a pass row records asset_identity equal to the current
 *      canonical client asset digest (sha256 over the canonical JSON
 *      of the canonical client assets). The identity is bound to the
 *      release bytes themselves, so committing this record does not
 *      change the identity and a stale recording cannot certify
 *      different widget bytes.
 *
 * Scope is desktop only: no physical mobile device appears in this
 * gate. The automated mobile-width, RTL and text-scale reflow coverage
 * lives in the browser lanes.
 *
 * Usage:
 *   node tools/ci/validate-accessibility-qualification.mjs [matrix.json]
 * Exit status: 0 pass, 1 rejected.
 */
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalClientAssets } from '../client-perf/client-assets.mjs';
import { canonicalJson, sha256Hex } from '../client-perf/canonical-json.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const DEFAULT_MATRIX = join(REPO_ROOT, 'tests', 'browser', 'qualification', 'accessibility-matrix.json');

const SCHEMA = 'kiwicaptcha.accessibility-qualification/1';
const REQUIRED_ROWS = [
  'nvda-chrome-windows',
  'nvda-firefox-windows',
  'voiceover-safari-macos',
  'speech-or-switch-desktop',
];
const STATUSES = ['manual_pending', 'pass', 'fail', 'blocked'];
const PLACEHOLDER_PATTERN = /^(current|tbd|unknown|n\/a|na|none|blank|latest|-|\?*)$/i;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_WINDOW_DAYS = 90;

const reasons = [];
const notes = [];

function isPlaceholder(value) {
  return typeof value !== 'string' || PLACEHOLDER_PATTERN.test(value.trim());
}

/** Strict ISO-8601 with an explicit offset, and a real calendar date. */
function isStrictIsoDate(value) {
  if (typeof value !== 'string' || value.trim() === '') return false;
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/);
  if (!match) return false;
  const [, year, month, day, hour, minute, second] = match.map((v, i) => (i === 0 ? v : Number(v)));
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second || 0));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day &&
    date.getUTCHours() === hour &&
    date.getUTCMinutes() === minute
  );
}

function canonicalAssetIdentity() {
  return sha256Hex(canonicalJson(canonicalClientAssets()));
}

function validateEvidence(row, where) {
  const evidence = row.evidence;
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    reasons.push(`${where} is marked pass without an evidence object (browser/AT versions, zoom_percent 200, the observation fields and asset_identity are required)`);
    return;
  }
  if (isPlaceholder(evidence.browser)) {
    reasons.push(`${where} evidence.browser ${JSON.stringify(evidence.browser ?? null)} is a placeholder or missing; the exact browser is required`);
  }
  if (isPlaceholder(evidence.browser_version)) {
    reasons.push(`${where} evidence.browser_version ${JSON.stringify(evidence.browser_version ?? null)} is a placeholder or missing; the exact browser version is required`);
  }
  if (isPlaceholder(evidence.assistive_technology)) {
    reasons.push(`${where} evidence.assistive_technology ${JSON.stringify(evidence.assistive_technology ?? null)} is a placeholder or missing; the exact assistive technology is required`);
  }
  if (isPlaceholder(evidence.assistive_technology_version)) {
    reasons.push(`${where} evidence.assistive_technology_version ${JSON.stringify(evidence.assistive_technology_version ?? null)} is a placeholder or missing; the exact assistive-technology version is required`);
  }
  if (evidence.zoom_percent !== 200) {
    reasons.push(`${where} evidence.zoom_percent ${JSON.stringify(evidence.zoom_percent ?? null)} is not 200; the actual 200% browser/user zoom run is part of the promised qualification`);
  }
  for (const field of ['keyboard', 'live_region', 'focus', 'content_loss']) {
    if (evidence[field] !== 'pass') {
      reasons.push(`${where} evidence.${field} ${JSON.stringify(evidence[field] ?? null)} is not "pass"`);
    }
  }
  if (typeof evidence.asset_identity !== 'string' || !/^[0-9a-f]{64}$/.test(evidence.asset_identity)) {
    reasons.push(`${where} evidence.asset_identity ${JSON.stringify(evidence.asset_identity ?? null)} is not a 64-hex canonical client asset digest`);
  } else if (evidence.asset_identity !== canonicalAssetIdentity()) {
    reasons.push(`${where} evidence.asset_identity ${evidence.asset_identity} is not the current release asset identity ${canonicalAssetIdentity()}`);
  }
}

function main() {
  const matrixPath = process.argv[2] ? resolve(process.argv[2]) : DEFAULT_MATRIX;
  let doc;
  try {
    doc = JSON.parse(readFileSync(matrixPath, 'utf8'));
  } catch (e) {
    console.error(`validate-accessibility-qualification: cannot read ${matrixPath}: ${e.message}`);
    process.exit(1);
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) || doc.schema !== SCHEMA) {
    console.error(`validate-accessibility-qualification: REJECTED ${matrixPath}\n  - matrix schema must be ${SCHEMA}`);
    process.exit(1);
  }
  const rows = doc.rows;
  if (!Array.isArray(rows) || rows.length === 0) {
    console.error(`validate-accessibility-qualification: REJECTED ${matrixPath}\n  - rows must be a non-empty array`);
    process.exit(1);
  }
  const windowDays = Number.isFinite(doc.qualification_window_days) ? doc.qualification_window_days : DEFAULT_WINDOW_DAYS;
  const windowMs = windowDays * 24 * 60 * 60 * 1000;
  const now = Date.now();

  const byId = new Map();
  rows.forEach((row, index) => {
    const where = `rows[${index}]${row && typeof row.id === 'string' ? ` (${row.id})` : ''}`;
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      reasons.push(`${where} is not an object`);
      return;
    }
    if (typeof row.id !== 'string' || row.id.trim() === '') {
      reasons.push(`${where} has no non-empty id`);
      return;
    }
    if (byId.has(row.id)) {
      reasons.push(`${where} repeats the row id ${JSON.stringify(row.id)}`);
      return;
    }
    if (!STATUSES.includes(row.status)) {
      reasons.push(`${where} status ${JSON.stringify(row.status ?? null)} is not one of ${STATUSES.join('|')}`);
    }
    byId.set(row.id, row);
  });

  for (const requiredId of REQUIRED_ROWS) {
    const row = byId.get(requiredId);
    const where = `required row ${requiredId}`;
    if (!row) {
      reasons.push(`${where} is missing: the documentary release scope (NVDA + Chrome, NVDA + Firefox, VoiceOver + Safari, one speech/switch pass) must be represented and passed`);
      continue;
    }
    if (row.required !== true) {
      reasons.push(`${where} must carry required: true (the documentary release scope is not optional)`);
    }
    if (row.status !== 'pass') {
      reasons.push(`${where} status ${JSON.stringify(row.status ?? null)} is not "pass": release certification refuses until the manual qualification passes`);
      continue;
    }
    if (typeof row.tested_at !== 'string' || row.tested_at.trim() === '') {
      reasons.push(`${where} is marked pass without a tested_at date`);
    } else if (!isStrictIsoDate(row.tested_at)) {
      reasons.push(`${where} tested_at ${JSON.stringify(row.tested_at)} is not a strict ISO-8601 date or offset-carrying date-time`);
    } else if (Date.parse(row.tested_at) - now > FUTURE_SKEW_MS) {
      reasons.push(`${where} tested_at ${row.tested_at} is materially in the future (more than five minutes ahead of the validator clock)`);
    } else if (now - Date.parse(row.tested_at) > windowMs) {
      reasons.push(`${where} tested_at ${row.tested_at} is older than the ${windowDays}-day qualification window`);
    }
    validateEvidence(row, where);
  }

  for (const id of byId.keys()) {
    if (!REQUIRED_ROWS.includes(id) && byId.get(id).required === true) {
      reasons.push(`rows entry ${id} declares required: true but is not one of the documented required rows ${REQUIRED_ROWS.join(', ')}`);
    }
  }

  if (reasons.length) {
    console.error(`validate-accessibility-qualification: REJECTED ${matrixPath}`);
    for (const reason of reasons) console.error(`  - ${reason}`);
    process.exit(1);
  }
  const pending = rows.filter((row) => row.status !== 'pass').length;
  if (pending > 0) notes.push(`${pending} advisory row(s) not passed (not release-blocking)`);
  console.log(
    `validate-accessibility-qualification: PASS ${matrixPath} (schema ${SCHEMA}, ${REQUIRED_ROWS.length} required desktop rows passed, asset_identity ${canonicalAssetIdentity().slice(0, 16)}…)`,
  );
  for (const note of notes) console.log(`  note: ${note}`);
  process.exit(0);
}

main();
