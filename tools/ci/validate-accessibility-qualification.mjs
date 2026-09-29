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
 * refuses the release until every required row is a complete, signed,
 * semantically consistent pass.
 *
 * The row id is an evidence CONTRACT, not a label (findings 2 and 3):
 *
 *   1. the required surface set is structural — each id fixes its
 *      platform, browser family and assistive-technology family (or its
 *      allowed interaction modes), and the evidence must carry the
 *      canonical family fields that match:
 *        nvda-chrome-windows      windows / chrome / nvda
 *        nvda-firefox-windows     windows / firefox / nvda
 *        voiceover-safari-macos   macos / safari / voiceover
 *        speech-or-switch-desktop desktop / speech-recognition|switch-access
 *      The free-text product names stay documentary metadata; the
 *      canonical fields are what the validator trusts. Substituting
 *      another row's browser/AT evidence is refused;
 *   2. the row's declared platform must equal its contract platform;
 *   3. a pass row records a real tested_at — a strict ISO-8601 instant
 *      (calendar components, component ranges and offset ranges
 *      validated; a finite epoch required) inside the validator-owned
 *      90-day window. The window is NOT read from the matrix: an
 *      evidence file cannot choose the policy that validates it. A
 *      qualification_window_days field is accepted for readability only
 *      and must equal 90;
 *   4. a pass row records exact browser and assistive-technology
 *      versions: CURRENT, TBD, unknown and similar placeholders are
 *      rejected;
 *   5. a pass row records zoom_percent === 200 (the actual 200% zoom run
 *      is part of the promised scope, not an inferred value);
 *   6. a pass row records keyboard, live_region, focus and content_loss
 *      observations, each exactly "pass";
 *   7. a pass row records asset_identity equal to the current canonical
 *      client asset digest (sha256 over the canonical JSON of the
 *      canonical client assets), binding the record to the release
 *      bytes themselves rather than a commit string;
 *   8. a pass row is SIGNED: the evidence object carries tester_id, the
 *      tester must appear in the public-key allowlist
 *      (tests/browser/qualification/tester-keys.json by default) and the
 *      row carries an Ed25519 signature over the canonical JSON of the
 *      evidence object. A missing signature, an unknown tester and any
 *      post-signing modification of the evidence are refused.
 *
 * Scope is desktop only: no physical mobile device appears in this
 * gate. The automated mobile-width, RTL and text-scale reflow coverage
 * lives in the browser lanes.
 *
 * Usage:
 *   node tools/ci/validate-accessibility-qualification.mjs [matrix.json] [tester-keys.json]
 * Exit status: 0 pass, 1 rejected.
 */
import { readFileSync } from 'node:fs';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalClientAssets } from '../client-perf/client-assets.mjs';
import { canonicalJson, sha256Hex } from '../client-perf/canonical-json.mjs';
import { parseStrictIsoInstant } from './strict-iso-instant.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const DEFAULT_MATRIX = join(REPO_ROOT, 'tests', 'browser', 'qualification', 'accessibility-matrix.json');
const DEFAULT_TESTER_KEYS = join(REPO_ROOT, 'tests', 'browser', 'qualification', 'tester-keys.json');

const SCHEMA = 'kiwicaptcha.accessibility-qualification/1';
const REQUIRED_SURFACES = {
  'nvda-chrome-windows': { platform: 'windows', browserFamily: 'chrome', assistiveTechnologyFamily: 'nvda' },
  'nvda-firefox-windows': { platform: 'windows', browserFamily: 'firefox', assistiveTechnologyFamily: 'nvda' },
  'voiceover-safari-macos': { platform: 'macos', browserFamily: 'safari', assistiveTechnologyFamily: 'voiceover' },
  'speech-or-switch-desktop': { platform: 'desktop', interactionModes: ['speech-recognition', 'switch-access'] },
};
const REQUIRED_ROWS = Object.keys(REQUIRED_SURFACES);
const BROWSER_FAMILIES = new Set(['chrome', 'firefox', 'safari']);
const AT_FAMILIES = new Set(['nvda', 'voiceover']);
const STATUSES = ['manual_pending', 'pass', 'fail', 'blocked'];
const PLACEHOLDER_PATTERN = /^(current|tbd|unknown|n\/a|na|none|blank|latest|-|\?*)$/i;
const QUALIFICATION_WINDOW_DAYS = 90;
const FUTURE_SKEW_MS = 5 * 60 * 1000;

const reasons = [];
const notes = [];

function isPlaceholder(value) {
  return typeof value !== 'string' || PLACEHOLDER_PATTERN.test(value.trim());
}

function canonicalAssetIdentity() {
  return sha256Hex(canonicalJson(canonicalClientAssets()));
}

function loadTesterKeys(keysPath) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(keysPath, 'utf8'));
  } catch (e) {
    reasons.push(`tester key allowlist ${keysPath}: cannot read (${e.message})`);
    return new Map();
  }
  const testers = doc && typeof doc === 'object' && !Array.isArray(doc) ? doc.testers : null;
  if (!testers || typeof testers !== 'object' || Array.isArray(testers)) {
    reasons.push(`tester key allowlist ${keysPath}: must be an object with a "testers" map of tester_id -> SPKI PEM public key`);
    return new Map();
  }
  const keys = new Map();
  for (const [tester, pem] of Object.entries(testers)) {
    if (typeof pem !== 'string' || !pem.includes('BEGIN PUBLIC KEY')) {
      reasons.push(`tester key allowlist ${keysPath}: ${JSON.stringify(tester)} does not carry an SPKI PEM public key`);
      continue;
    }
    try {
      keys.set(tester, createPublicKey(pem));
    } catch (e) {
      reasons.push(`tester key allowlist ${keysPath}: ${JSON.stringify(tester)} public key is unusable (${e.message})`);
    }
  }
  return keys;
}

function verifyAttestation(row, where, testerKeys) {
  const evidence = row.evidence;
  if (isPlaceholder(evidence.tester_id)) {
    reasons.push(`${where} evidence.tester_id ${JSON.stringify(evidence.tester_id ?? null)} is missing; signed evidence names its tester`);
    return;
  }
  const publicKey = testerKeys.get(evidence.tester_id);
  if (!publicKey) {
    reasons.push(`${where} evidence.tester_id ${JSON.stringify(evidence.tester_id)} is not in the tester public-key allowlist`);
    return;
  }
  if (typeof row.signature !== 'string' || row.signature.trim() === '') {
    reasons.push(`${where} is marked pass without a signature (Ed25519 over the canonical JSON of the evidence object)`);
    return;
  }
  let signature;
  try {
    signature = Buffer.from(row.signature, 'base64');
  } catch (e) {
    reasons.push(`${where} signature is not valid base64 (${e.message})`);
    return;
  }
  const payload = Buffer.from(canonicalJson(evidence), 'utf8');
  let valid = false;
  try {
    valid = cryptoVerify(null, payload, publicKey, signature);
  } catch (e) {
    reasons.push(`${where} signature verification failed (${e.message})`);
    return;
  }
  if (!valid) {
    reasons.push(`${where} signature does not verify against ${JSON.stringify(evidence.tester_id)}: the evidence was modified after signing or signed by another key`);
  }
}

function validateEvidence(row, where, contract, testerKeys) {
  const evidence = row.evidence;
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    reasons.push(`${where} is marked pass without an evidence object (browser/AT families and versions, zoom_percent 200, the observation fields, tester_id and asset_identity are required)`);
    return;
  }
  if (row.platform !== contract.platform) {
    reasons.push(`${where} platform ${JSON.stringify(row.platform ?? null)} is not the contract platform ${JSON.stringify(contract.platform)}`);
  }
  if (isPlaceholder(evidence.browser)) {
    reasons.push(`${where} evidence.browser ${JSON.stringify(evidence.browser ?? null)} is a placeholder or missing; the exact browser is required`);
  }
  if (isPlaceholder(evidence.browser_version)) {
    reasons.push(`${where} evidence.browser_version ${JSON.stringify(evidence.browser_version ?? null)} is a placeholder or missing; the exact browser version is required`);
  }
  if (contract.browserFamily) {
    if (typeof evidence.browser_family !== 'string' || !BROWSER_FAMILIES.has(evidence.browser_family)) {
      reasons.push(`${where} evidence.browser_family ${JSON.stringify(evidence.browser_family ?? null)} is not one of ${[...BROWSER_FAMILIES].join('|')}`);
    } else if (evidence.browser_family !== contract.browserFamily) {
      reasons.push(`${where} evidence.browser_family ${JSON.stringify(evidence.browser_family)} does not match the row contract family ${JSON.stringify(contract.browserFamily)}: another row's browser evidence cannot certify this row`);
    }
  }
  if (isPlaceholder(evidence.assistive_technology)) {
    reasons.push(`${where} evidence.assistive_technology ${JSON.stringify(evidence.assistive_technology ?? null)} is a placeholder or missing; the exact assistive technology is required`);
  }
  if (isPlaceholder(evidence.assistive_technology_version)) {
    reasons.push(`${where} evidence.assistive_technology_version ${JSON.stringify(evidence.assistive_technology_version ?? null)} is a placeholder or missing; the exact assistive-technology version is required`);
  }
  if (contract.assistiveTechnologyFamily) {
    if (typeof evidence.assistive_technology_family !== 'string' || !AT_FAMILIES.has(evidence.assistive_technology_family)) {
      reasons.push(`${where} evidence.assistive_technology_family ${JSON.stringify(evidence.assistive_technology_family ?? null)} is not one of ${[...AT_FAMILIES].join('|')}`);
    } else if (evidence.assistive_technology_family !== contract.assistiveTechnologyFamily) {
      reasons.push(`${where} evidence.assistive_technology_family ${JSON.stringify(evidence.assistive_technology_family)} does not match the row contract family ${JSON.stringify(contract.assistiveTechnologyFamily)}: another row's AT evidence cannot certify this row`);
    }
  }
  if (contract.interactionModes) {
    if (!contract.interactionModes.includes(evidence.interaction_mode)) {
      reasons.push(`${where} evidence.interaction_mode ${JSON.stringify(evidence.interaction_mode ?? null)} is not one of ${contract.interactionModes.join('|')}: the speech/switch row requires real speech-recognition or switch-access evidence, not ordinary AT evidence`);
    }
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
  verifyAttestation(row, where, testerKeys);
}

function main() {
  const matrixPath = process.argv[2] ? resolve(process.argv[2]) : DEFAULT_MATRIX;
  const keysPath = process.argv[3] ? resolve(process.argv[3]) : DEFAULT_TESTER_KEYS;
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
  // The window is validator-owned policy: the matrix may repeat it for
  // readability, but it can never enlarge (or shrink) it.
  if (doc.qualification_window_days !== undefined && doc.qualification_window_days !== QUALIFICATION_WINDOW_DAYS) {
    reasons.push(`qualification_window_days ${JSON.stringify(doc.qualification_window_days)} must equal the validator-owned ${QUALIFICATION_WINDOW_DAYS}; an evidence file cannot choose the policy that validates it`);
  }
  const windowMs = QUALIFICATION_WINDOW_DAYS * 24 * 60 * 60 * 1000;
  const now = Date.now();
  const testerKeys = loadTesterKeys(keysPath);

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
    const contract = REQUIRED_SURFACES[requiredId];
    const row = byId.get(requiredId);
    const where = `required row ${requiredId}`;
    if (!row) {
      reasons.push(`${where} is missing: the documentary release scope must be represented and passed`);
      continue;
    }
    if (row.required !== true) {
      reasons.push(`${where} must carry required: true (the documentary release scope is not optional)`);
    }
    if (row.status !== 'pass') {
      reasons.push(`${where} status ${JSON.stringify(row.status ?? null)} is not "pass": release certification refuses until the manual qualification passes`);
      continue;
    }
    const epoch = parseStrictIsoInstant(row.tested_at);
    if (epoch === null) {
      reasons.push(`${where} tested_at ${JSON.stringify(row.tested_at ?? null)} is not a strict ISO-8601 instant (real calendar date, component ranges and offset ranges validated)`);
    } else if (epoch - now > FUTURE_SKEW_MS) {
      reasons.push(`${where} tested_at ${row.tested_at} is materially in the future (more than five minutes ahead of the validator clock)`);
    } else if (now - epoch > windowMs) {
      reasons.push(`${where} tested_at ${row.tested_at} is older than the validator-owned ${QUALIFICATION_WINDOW_DAYS}-day qualification window`);
    }
    validateEvidence(row, where, contract, testerKeys);
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
    `validate-accessibility-qualification: PASS ${matrixPath} (schema ${SCHEMA}, ${REQUIRED_ROWS.length} required desktop rows passed and signed, asset_identity ${canonicalAssetIdentity().slice(0, 16)}…)`,
  );
  for (const note of notes) console.log(`  note: ${note}`);
  process.exit(0);
}

main();
