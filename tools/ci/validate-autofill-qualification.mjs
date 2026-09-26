#!/usr/bin/env node
/**
 * Autofill-qualification matrix validator
 * (tests/browser/qualification/autofill-matrix.json).
 *
 * Usage:
 *   node tools/ci/validate-autofill-qualification.mjs <matrix.json>
 *        [--registry <surfaces.json>] [--window-days <n>]
 *
 * The matrix is the machine-readable record behind the manual
 * qualification protocol (docs/autofill-qualification-protocol.md):
 * one row per real autofill / password-manager / screen-reader surface.
 * The ONE canonical surface registry
 * (tests/browser/qualification/surfaces.json) is authoritative for
 * which stable surface ids exist, their expected platform class, and
 * whether a pass row must record an exact version; the protocol
 * document refers to those same ids.
 *
 * This validator is the release-touching-decoy gate. A release that
 * touches the decoy surface (the server-issued decoy field, its
 * rendering, the fill-evidence pipeline or the autofill-relevant
 * presentation facts) must pass it before the broad third-party
 * autofill and password-manager compatibility claim is made.
 *
 * Row shape (exact):
 *   surface   the stable registry id (kebab-case); an id the registry
 *             does not know is an advisory surface and never gates
 *   version   the tested surface version; a pass row must record an
 *             exact version (CURRENT/TBD/unknown/blank placeholders
 *             are rejected); a non-pass row may carry the placeholder
 *             or null
 *   platform  the tested platform; must equal the registry's expected
 *             platform class for a known surface (and be one of
 *             desktop|windows|macos|ios|android in every case)
 *   status    pass | fail | blocked | manual_pending
 *   tested_at null for a non-pass row, or a strict ISO-8601 date (or a
 *             date-time that carries a UTC designator or numeric
 *             offset) for a pass row
 *   product   optional display name; when present for a known id it
 *             must equal the registry's product
 *
 * The validator rejects the matrix, with every reason printed, unless
 * all of these hold:
 *
 *   1. the registry and the matrix schemas are the expected ones;
 *   2. the registry itself is well-formed (unique kebab-case ids, known
 *      platform classes, boolean exact_version/required, non-empty
 *      products);
 *   3. every row is structurally complete and well-typed: every field
 *      present, surface ids unique across rows, only one row per
 *      surface id, no two rows for one registry product;
 *   4. a known surface's row platform equals the registry's expected
 *      platform class;
 *   5. every REQUIRED surface (registry required=true) has exactly one
 *      row with status "pass";
 *   6. every pass row records an exact, non-placeholder version — the
 *      meaning of "pass" is universal, so an advisory row cannot claim
 *      a pass on placeholder evidence;
 *   7. every pass row records a real, non-future tested_at: a strict
 *      ISO-8601 date with calendar round-trip (Feb 30, hour 24 and
 *      second 60 are rejected, never normalized), and any time-of-day
 *      carries a UTC designator or numeric offset, never the runner's
 *      local timezone;
 *   8. every required pass row's tested_at is within the qualification
 *      window (90 days by default) and no more than five minutes ahead
 *      of the validator clock.
 *
 * Rows whose surface id is not in the registry, or whose registry
 * entry is advisory (required=false), are printed as notes but never
 * gate; their structural fields are still validated.
 *
 * Exit status: 0 when every gate holds (all required surfaces pass
 * with exact versions within the window), 1 otherwise. Runnable
 * standalone; wired into the release workflow next to the
 * client-performance baseline validator, and its adversarial mutation
 * suite (tools/ci/test-validate-autofill-qualification.mjs) guards the
 * validator itself in CI.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MATRIX_SCHEMA = 'kiwicaptcha.autofill-qualification/1';
const REGISTRY_SCHEMA = 'kiwicaptcha.autofill-surfaces/1';
const QUALIFICATION_WINDOW_DAYS = 90;
/**
 * A qualification date more than this far ahead of now is rejected as
 * materially in the future: the same narrow five-minute clock-skew
 * allowance the performance evidence uses, so a skewed or forged
 * record can never buy qualification time.
 */
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const PLATFORM_CLASSES = ['desktop', 'windows', 'macos', 'ios', 'android'];
const STATUSES = ['pass', 'fail', 'blocked', 'manual_pending'];
const SURFACE_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
/**
 * Version placeholders that never record a qualification, matched
 * case-insensitively against the trimmed value of a pass row. The
 * optional group makes the empty string a placeholder too.
 */
const VERSION_PLACEHOLDER_PATTERN = /^(current|tbd|tba|unknown|blank|n\/?a|none|null|pending|unversioned|-+)?$/i;
/**
 * A strict ISO-8601 calendar date, or a date-time that MUST carry a UTC
 * designator or numeric offset: an offset-less date-time would be parsed
 * in the validator runner's local timezone, never as qualification
 * evidence. The written calendar components are round-tripped below, so
 * an impossible date (2025-02-29, 2026-02-30, hour 24, minute 60,
 * second 60) is rejected instead of being normalized by Date.parse.
 */
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2}))?$/;

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REGISTRY = resolve(SCRIPT_DIR, '..', '..', 'tests', 'browser', 'qualification', 'surfaces.json');

function usage() {
  process.stderr.write(
    'usage: node tools/ci/validate-autofill-qualification.mjs <matrix.json> [--registry <surfaces.json>] [--window-days <n>]\n',
  );
}

function parseArgs(argv) {
  const args = { matrix: null, registry: DEFAULT_REGISTRY, windowDays: QUALIFICATION_WINDOW_DAYS };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return null;
    if (arg === '--registry') {
      args.registry = argv[++i];
      if (!args.registry) throw new Error('--registry needs a path');
      continue;
    }
    if (arg === '--window-days') {
      const raw = argv[++i];
      if (typeof raw !== 'string' || !/^[0-9]+$/.test(raw)) {
        throw new Error(`--window-days needs a positive integer, got ${JSON.stringify(raw)}`);
      }
      const parsed = Number.parseInt(raw, 10);
      if (!Number.isInteger(parsed) || parsed < 1) {
        throw new Error(`--window-days needs a positive integer, got ${JSON.stringify(raw)}`);
      }
      args.windowDays = parsed;
      continue;
    }
    if (arg.startsWith('--')) throw new Error(`unknown option ${arg}`);
    if (args.matrix !== null) throw new Error(`unexpected extra argument ${arg}`);
    args.matrix = arg;
  }
  return args;
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    process.stderr.write(`autofill ${label} cannot be read at ${path}: ${e.message}\n`);
    process.exit(1);
  }
}

/** Validate the registry itself; returns a Map id -> surface. */
function loadRegistry(path, reasons) {
  const registry = readJson(path, 'registry');
  if (registry.schema !== REGISTRY_SCHEMA) {
    reasons.push(`registry schema ${JSON.stringify(registry.schema)} is not ${REGISTRY_SCHEMA}`);
    return new Map();
  }
  if (!Array.isArray(registry.surfaces)) {
    reasons.push('registry surfaces must be an array');
    return new Map();
  }
  const byId = new Map();
  for (const [index, surface] of registry.surfaces.entries()) {
    const where = `registry surface #${index}`;
    if (!surface || typeof surface !== 'object' || Array.isArray(surface)) {
      reasons.push(`${where} must be an object`);
      continue;
    }
    if (typeof surface.id !== 'string' || !SURFACE_ID_PATTERN.test(surface.id)) {
      reasons.push(`${where} id ${JSON.stringify(surface.id)} must match ${SURFACE_ID_PATTERN}`);
      continue;
    }
    if (byId.has(surface.id)) {
      reasons.push(`registry surface id ${surface.id} is duplicated`);
      continue;
    }
    if (typeof surface.product !== 'string' || surface.product.trim() === '') {
      reasons.push(`registry surface ${surface.id} product must be a non-empty string`);
      continue;
    }
    if (!PLATFORM_CLASSES.includes(surface.platform)) {
      reasons.push(
        `registry surface ${surface.id} platform ${JSON.stringify(surface.platform)} is not one of ${PLATFORM_CLASSES.join('|')}`,
      );
      continue;
    }
    if (typeof surface.exact_version !== 'boolean') {
      reasons.push(`registry surface ${surface.id} exact_version must be a boolean`);
      continue;
    }
    if (typeof surface.required !== 'boolean') {
      reasons.push(`registry surface ${surface.id} required must be a boolean`);
      continue;
    }
    byId.set(surface.id, surface);
  }
  if (byId.size === 0 && reasons.length === 0) {
    reasons.push('registry declares no surfaces');
  }
  return byId;
}

/**
 * The written calendar components of a strict ISO value, or null when
 * the shape does not match. The round-trip in isIsoDate() compares these
 * against the UTC construction, so Date.parse normalization (Feb 30 to
 * Mar 2, hour 24 to the next day, second 60 to the next minute) can
 * never turn an impossible timestamp into evidence.
 */
function parseCalendarComponents(value) {
  const match = value.match(
    /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?)?/,
  );
  if (!match) return null;
  return {
    year: Number(match[1]),
    month: Number(match[2]),
    day: Number(match[3]),
    hour: match[4] === undefined ? null : Number(match[4]),
    minute: match[5] === undefined ? null : Number(match[5]),
    second: match[6] === undefined ? null : Number(match[6]),
    fraction: match[7] ?? '',
  };
}

function isIsoDate(value) {
  if (typeof value !== 'string' || !ISO_DATE_PATTERN.test(value)) return false;
  const c = parseCalendarComponents(value);
  if (c === null) return false;
  const hh = c.hour ?? 0;
  const mm = c.minute ?? 0;
  const ss = c.second ?? 0;
  const ms = c.fraction === '' ? 0 : Math.floor(Number(`0.${c.fraction}`) * 1000);
  const constructed = new Date(Date.UTC(c.year, c.month - 1, c.day, hh, mm, ss, ms));
  if (
    constructed.getUTCFullYear() !== c.year ||
    constructed.getUTCMonth() + 1 !== c.month ||
    constructed.getUTCDate() !== c.day ||
    constructed.getUTCHours() !== hh ||
    constructed.getUTCMinutes() !== mm ||
    constructed.getUTCSeconds() !== ss ||
    constructed.getUTCMilliseconds() !== ms
  ) {
    return false;
  }
  return !Number.isNaN(Date.parse(value));
}

function isVersionPlaceholder(value) {
  return typeof value !== 'string' || VERSION_PLACEHOLDER_PATTERN.test(value.trim());
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.length < 1) {
    usage();
    process.exit(1);
  }
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`validate-autofill-qualification: ${e.message}\n`);
    usage();
    process.exit(1);
  }
  if (args === null) {
    usage();
    process.exit(0);
  }
  if (args.matrix === null) {
    usage();
    process.exit(1);
  }

  const reasons = [];
  const notes = [];
  const notQualified = [];

  const registry = loadRegistry(args.registry, reasons);

  const matrix = readJson(args.matrix, 'matrix');
  if (matrix.schema !== MATRIX_SCHEMA) {
    reasons.push(`schema ${JSON.stringify(matrix.schema)} is not ${MATRIX_SCHEMA}`);
  }
  const rows = Array.isArray(matrix.rows) ? matrix.rows : [];
  if (!Array.isArray(matrix.rows)) {
    reasons.push('matrix rows must be an array');
  }

  const windowMs = args.windowDays * 86400000;
  const now = Date.now();

  // Structural validation and duplicate detection: a duplicate id or a
  // repeated registry product is a rejection whatever the two rows say,
  // never a silent first-row-wins collapse.
  const bySurface = new Map();
  const productOwner = new Map();
  for (const [index, row] of rows.entries()) {
    const where = `row #${index}${row && typeof row.surface === 'string' ? ` (${row.surface})` : ''}`;
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      reasons.push(`${where} must be an object`);
      continue;
    }
    for (const field of ['surface', 'version', 'platform', 'status', 'tested_at']) {
      if (!Object.prototype.hasOwnProperty.call(row, field)) {
        reasons.push(`${where} is missing the required field ${field}`);
      }
    }
    if (typeof row.surface !== 'string' || !SURFACE_ID_PATTERN.test(row.surface)) {
      reasons.push(`${where} surface ${JSON.stringify(row.surface)} must be a kebab-case id matching ${SURFACE_ID_PATTERN}`);
      continue;
    }
    if (bySurface.has(row.surface)) {
      reasons.push(`surface id ${row.surface} is duplicated (row #${index} repeats the earlier row)`);
      continue;
    }
    bySurface.set(row.surface, row);

    const surface = registry.get(row.surface);
    if (surface && Object.prototype.hasOwnProperty.call(row, 'product') && row.product !== surface.product) {
      reasons.push(`${row.surface} product ${JSON.stringify(row.product)} is not the registry product ${JSON.stringify(surface.product)}`);
    }
    if (surface) {
      if (productOwner.has(surface.product)) {
        reasons.push(`${row.surface} repeats the registry product ${JSON.stringify(surface.product)} already carried by ${productOwner.get(surface.product)}`);
      } else {
        productOwner.set(surface.product, row.surface);
      }
    }

    if (typeof row.platform !== 'string' || !PLATFORM_CLASSES.includes(row.platform)) {
      reasons.push(`${where} platform ${JSON.stringify(row.platform)} is not one of ${PLATFORM_CLASSES.join('|')}`);
    } else if (surface && row.platform !== surface.platform) {
      reasons.push(`${row.surface} platform ${JSON.stringify(row.platform)} is not the registry platform ${JSON.stringify(surface.platform)}`);
    }
    if (!STATUSES.includes(row.status)) {
      reasons.push(`${where} status ${JSON.stringify(row.status)} is not one of ${STATUSES.join('|')}`);
      continue;
    }
    if (row.version !== null && typeof row.version !== 'string') {
      reasons.push(`${where} version ${JSON.stringify(row.version)} must be a string or null`);
    }

    // The meaning of "pass" is universal: whether a row must exist and
    // pass depends on the registry's required flag, but ANY pass row —
    // required or advisory — must carry a real exact version and a real,
    // non-future timestamp. An advisory row cannot claim a pass on
    // placeholder evidence.
    if (row.status === 'pass') {
      if (isVersionPlaceholder(row.version)) {
        reasons.push(`${where} is marked pass with a placeholder version ${JSON.stringify(row.version ?? null)}; an exact tested version is required`);
      }
      if (typeof row.tested_at !== 'string' || row.tested_at.trim() === '') {
        reasons.push(`${where} is marked pass without a tested_at date`);
      } else if (!isIsoDate(row.tested_at)) {
        reasons.push(`${where} tested_at ${JSON.stringify(row.tested_at)} is not a strict ISO-8601 date or offset-carrying date-time`);
      } else if (Date.parse(row.tested_at) - now > FUTURE_SKEW_MS) {
        reasons.push(`${where} tested_at ${row.tested_at} is materially in the future (more than five minutes ahead of the validator clock)`);
      }
    }
  }

  // Required-surface gating.
  for (const [id, surface] of registry) {
    if (!surface.required) {
      if (bySurface.has(id)) {
        notes.push(`${id} (${surface.product}) is an advisory registry surface; its row never gates`);
      }
      continue;
    }
    const row = bySurface.get(id);
    if (!row) {
      reasons.push(`required surface ${id} (${surface.product}) has no row in the matrix`);
      continue;
    }
    if (row.status !== 'pass') {
      notQualified.push(
        `${id} (${surface.product}): status "${row.status}" (version ${JSON.stringify(row.version ?? null)}${
          row.tested_at ? `, tested ${row.tested_at}` : ', never tested'
        })`,
      );
      continue;
    }
    // The universal pass-row evidence checks (exact version, real
    // non-future timestamp) ran in the row loop; the required gate adds
    // the qualification window.
    if (typeof row.tested_at !== 'string' || row.tested_at.trim() === '' || !isIsoDate(row.tested_at)) {
      continue;
    }
    const testedMs = Date.parse(row.tested_at);
    const ageMs = now - testedMs;
    if (ageMs > windowMs) {
      reasons.push(
        `required surface ${id} qualified ${(ageMs / 86400000).toFixed(1)} days ago (tested_at ${row.tested_at}), older than the ${args.windowDays}-day qualification window`,
      );
    }
  }

  // Per-row freshness/version notes for advisory rows (never gating).
  for (const [id, row] of bySurface) {
    if (!registry.has(id)) {
      notes.push(`${id} is not in the surface registry (advisory row, never gates)`);
      continue;
    }
    const surface = registry.get(id);
    if (!surface.required && row.status === 'pass') {
      notes.push(`${id} (${surface.product}) is an advisory surface with a recorded pass; it never satisfies a required gate`);
    }
  }

  if (notQualified.length) {
    process.stderr.write(
      'validate-autofill-qualification: release gate not met — the following required surfaces are not qualified within the window (release-touching-decoy requires every required surface to be status "pass" with an exact version and a fresh tested_at):\n',
    );
    for (const n of notQualified) process.stderr.write(`  - ${n}\n`);
  }

  if (reasons.length || notQualified.length) {
    process.stderr.write(`validate-autofill-qualification: REJECTED ${args.matrix}\n`);
    for (const r of reasons) process.stderr.write(`  - ${r}\n`);
    process.exit(1);
  }
  const requiredCount = [...registry.values()].filter((s) => s.required).length;
  console.log(
    `validate-autofill-qualification: PASS ${args.matrix} (registry ${REGISTRY_SCHEMA}; ${requiredCount} required surfaces qualified with exact versions within ${args.windowDays} days)`,
  );
  for (const n of notes) console.log(`  note: ${n}`);
  process.exit(0);
}

main();
