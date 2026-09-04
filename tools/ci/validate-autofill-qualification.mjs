#!/usr/bin/env node
/**
 * Autofill-qualification matrix validator
 * (tests/browser/qualification/autofill-matrix.json).
 *
 * Usage:
 *   node tools/ci/validate-autofill-qualification.mjs <matrix.json>
 *
 * The matrix is the machine-readable record behind the manual
 * qualification protocol (docs/autofill-qualification-protocol.md):
 * one row per real autofill / password-manager / screen-reader
 * surface, with {product, version, platform, status, tested_at}.
 *
 * This validator is the release-touching-decoy gate. A release that
 * touches the decoy surface (the server-issued decoy field, its
 * rendering, the fill-evidence pipeline or the autofill-relevant
 * presentation facts) must pass it before the broad third-party
 * autofill and password-manager compatibility claim is made. The
 * validator rejects the matrix, with every reason printed, unless
 * all of these hold:
 *
 *   1. the matrix schema is kiwicaptcha.autofill-qualification/1;
 *   2. every required product below has a row in the matrix (a
 *      missing row is a rejection, not a silent gap);
 *   3. every required product row has status "pass";
 *   4. every passing row records a tested_at within the qualification
 *      window (90 days by default): an old qualification cannot gate
 *      a current release. Rows in any other status are reported as
 *      blocking notes but only "pass" rows carry the tested_at
 *      requirement.
 *
 * Rows not in the required list are advisory: they are printed but
 * never gate. The required set is the compact matrix the protocol
 * defines for the broad claim.
 *
 * Exit status: 0 when every gate holds (all required products pass
 * within the window), 1 otherwise. Runnable standalone; intended to
 * be wired into the release workflow next to the client-performance
 * baseline validator.
 */
import { readFileSync } from 'node:fs';

const MATRIX_SCHEMA = 'kiwicaptcha.autofill-qualification/1';
const QUALIFICATION_WINDOW_DAYS = 90;

// The compact matrix required for the broad third-party claim
// (docs/autofill-qualification-protocol.md, the qualification matrix):
// every listed surface, exactly one row each. Product names match the
// matrix rows. A required product missing from the file is a
// rejection.
const REQUIRED_PRODUCTS = [
  'Chrome built-in autofill',
  'Edge',
  'Firefox',
  'Safari',
  'iOS Safari',
  'Android Chrome',
  'iCloud Keychain',
  '1Password',
  'Bitwarden',
  'VoiceOver',
  'NVDA',
];

function main() {
  const argv = process.argv.slice(2);
  if (argv.length < 1 || argv[0] === '--help' || argv[0] === '-h') {
    process.stderr.write('usage: node tools/ci/validate-autofill-qualification.mjs <matrix.json>\n');
    process.exit(argv.length ? 0 : 1);
  }
  const matrixPath = argv[0];
  let matrix;
  try {
    matrix = JSON.parse(readFileSync(matrixPath, 'utf8'));
  } catch (e) {
    process.stderr.write(`autofill matrix cannot be read at ${matrixPath}: ${e.message}\n`);
    process.exit(1);
  }

  const reasons = [];
  const notes = [];

  if (matrix.schema !== MATRIX_SCHEMA) {
    reasons.push(`schema ${JSON.stringify(matrix.schema)} is not ${MATRIX_SCHEMA}`);
  }

  const rows = Array.isArray(matrix.rows) ? matrix.rows : [];
  const byProduct = new Map();
  for (const row of rows) {
    if (!row || typeof row.product !== 'string') continue;
    if (!byProduct.has(row.product)) byProduct.set(row.product, row);
  }

  const missing = REQUIRED_PRODUCTS.filter((p) => !byProduct.has(p));
  if (missing.length) {
    reasons.push(`required product row(s) missing from the matrix: ${missing.join(', ')}`);
  }

  const windowMs = QUALIFICATION_WINDOW_DAYS * 86400000;
  const now = Date.now();
  const blockedNotes = [];
  for (const product of REQUIRED_PRODUCTS) {
    const row = byProduct.get(product);
    if (!row) continue;
    const status = row.status;
    if (status !== 'pass') {
      blockedNotes.push(`${product}: status "${status}" (${row.version || 'CURRENT'}${row.tested_at ? `, tested ${row.tested_at}` : ', never tested'})`);
      continue;
    }
    if (typeof row.tested_at !== 'string' || row.tested_at === '') {
      reasons.push(`${product}: status "pass" without a tested_at date`);
      continue;
    }
    const testedMs = Date.parse(row.tested_at);
    if (Number.isNaN(testedMs)) {
      reasons.push(`${product}: tested_at ${JSON.stringify(row.tested_at)} is not a parseable date`);
      continue;
    }
    const ageMs = now - testedMs;
    if (ageMs > windowMs) {
      reasons.push(`${product}: qualified ${(ageMs / 86400000).toFixed(1)} days ago (tested_at ${row.tested_at}), older than the ${QUALIFICATION_WINDOW_DAYS}-day qualification window`);
    }
  }
  if (blockedNotes.length) {
    const prefix = reasons.length ? 'additional' : 'release';
    process.stderr.write(`validate-autofill-qualification: ${prefix} gate not met — the following required surfaces are not qualified within the window (release-touching-decoy requires every required row to be status "pass" with a fresh tested_at):\n`);
    for (const n of blockedNotes) process.stderr.write(`  - ${n}\n`);
    process.exit(1);
  }

  for (const row of rows) {
    if (!REQUIRED_PRODUCTS.includes(row.product) && row.status === 'pass') {
      notes.push(`${row.product} is qualified but not in the required set (advisory only)`);
    }
  }

  if (reasons.length) {
    process.stderr.write(`validate-autofill-qualification: REJECTED ${matrixPath}\n`);
    for (const r of reasons) process.stderr.write(`  - ${r}\n`);
    process.exit(1);
  }
  console.log(
    `validate-autofill-qualification: PASS ${matrixPath} (schema ${MATRIX_SCHEMA}; ${REQUIRED_PRODUCTS.length} required surfaces qualified within ${QUALIFICATION_WINDOW_DAYS} days)`,
  );
  for (const n of notes) console.log(`  note: ${n}`);
  process.exit(0);
}

main();
