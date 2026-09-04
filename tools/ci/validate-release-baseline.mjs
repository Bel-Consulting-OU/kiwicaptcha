#!/usr/bin/env node
/**
 * Release-baseline validator for the client-performance evidence
 * (tools/client-perf).
 *
 * Usage:
 *   node tools/ci/validate-release-baseline.mjs <baseline.json> [<release-budgets.json>]
 *   node tools/ci/validate-release-baseline.mjs --release <baseline.json> [<release-budgets.json>]
 *   RELEASE_PERFORMANCE=1 node tools/ci/validate-release-baseline.mjs <baseline.json>
 *
 * The baseline argument is a results payload (schema
 * kiwicaptcha.client-perf/3, the current harness schema, or the
 * committed tools/client-perf/results/baseline.json maintenance file).
 * The budgets argument defaults to tools/client-perf/release-budgets.json
 * next to the harness.
 *
 * Two modes:
 *
 *   CI mode (default) is the every-push gate wired into the
 *   "Performance budgets" workflow check. It enforces the full
 *   coverage and no-budget-bypass rules below and prints the current
 *   performance-qualification status line. It never fails solely on
 *   the qualification status: a lab-status gate is an honest "not yet
 *   certified", reported loudly, while the coverage and budget rules
 *   still bind. Once a committed file claims qualification.status
 *   "physical", EVERY physical-evidence proof below binds in CI mode
 *   too: a malformed committed claim cannot survive ordinary CI and
 *   wait for --release to catch it.
 *
 *   Release mode (--release or RELEASE_PERFORMANCE=1) is the release
 *   certification gate. It refuses to certify a release unless
 *   qualification.status is "physical" (with a qualified_at date and
 *   recorded devices) AND the physical-evidence proofs below hold
 *   (device registration, per-device coverage, provenance,
 *   per-device sample floors and failure budgets,
 *   worst-physical-p95 budget compliance, evidence freshness) AND,
 *   for a current-harness (schema 3) payload, the completed-run
 *   guards hold. A lab-status gate therefore always fails a release:
 *   physical-device data is the release boundary, and nothing else
 *   can substitute for it. In release mode the release-required cells
 *   additionally span the union of the budget file's tiers and its
 *   qualification.release_tiers, so a file cannot declare a release
 *   ladder that lacks p95 budget rows.
 *
 * The validator rejects the file, with every reason printed, unless
 * all of these hold:
 *
 *   1. the budget authority (release-budgets.json) declares the full
 *      released-mode set: its difficulty list equals the harness's
 *      DIFFICULTIES (read from client-perf.mjs at run time, never
 *      duplicated here) and every difficulty x qualified tier x
 *      cold|warm combination has an explicit positive p95 budget row.
 *      A released solver mode without a budget row fails the run:
 *      there is no uncovered-cell escape, notes never carry a
 *      release-required cell. The qualified tiers are the union of
 *      the budget file's tiers and its qualification.release_tiers
 *      whenever the file claims physical qualification (so ordinary
 *      CI proves the claim) or release mode is on; a declared release
 *      ladder without p95 budgets is a rejection in both cases.
 *   2. the budget authority carries a qualification block
 *      (status one of lab|physical, qualified_at null or ISO,
 *      harness_schema equal to the harness schema, devices array,
 *      release_tiers a non-empty ordered list of harness tier keys).
 *      A "physical" status without qualified_at, without devices, or
 *      without at least one kind:"physical" device (non-empty id and
 *      tier) is a rejection, never a silent claim.
 *   3. every release-required cell (every tier x difficulty x
 *      cold/warm combination the budgets file requires) has a
 *      matching measured baseline row (the aggregate three-part row
 *      and/or the per-asset-mode rows the baseline records for the
 *      cell): coverage gaps are hard failures, counted and named.
 *      When the file claims physical, per-device coverage replaces
 *      the generic coverage for release-tier cells: every registered
 *      physical device must carry its own evidence row for every
 *      released difficulty x cold/warm x required asset mode of its
 *      tier (rule 9 below).
 *   4. the measured p95 of every required cell (solveMs and
 *      pageToVerifiedMs, aggregated across the asset-mode rows the
 *      baseline records for the cell) stays under the matching budget
 *      row. When the file claims physical qualification, the budget
 *      of every release-tier cell is instead checked against the
 *      WORST physical p95 across ALL qualified devices of that tier
 *      (per-device p95 computed from each device's own evidence
 *      rows, worst device taken): the budget must cover the slowest
 *      qualified device, and a registered device without measurements
 *      is a coverage failure, never an invisible non-contributor.
 *   5. per-device quality: every registered physical device with
 *      evidence rows for a release-tier cell meets, on its OWN
 *      samples (never aggregated across devices), the budget file's
 *      minShaReps / minArgonReps floors and the per-mode
 *      failureRateBudgets rate (failure rate over its own samples,
 *      timedOut or errorCount; 1.0 when it has rows but zero
 *      samples). One healthy device can never mask a failing one:
 *      the floors and limits bind per device, per cell. In release
 *      mode the sha20 release-tier cells must additionally meet
 *      minSha20SamplesPhysical per device: the sha20 allowance must
 *      never be forced by a single exhaustion observation on a thin
 *      per-device sample.
 *   6. the record is no older than release-budgets.json recordAgeDays
 *      (default 90 days) and carries browser/OS/hardware identity.
 *      When the file claims physical, EVERY physical device's
 *      tested_at date is itself held to the same age bound, and the
 *      chronology must be consistent: tested_at <= qualified_at,
 *      tested_at <= payload.generated_at, and qualified_at >= the
 *      newest physical tested_at (a qualification date may never
 *      precede the evidence it certifies; a regenerated baseline can
 *      never launder old measurements).
 *   7. release mode only: qualification.status must be "physical";
 *      and a current-harness (schema 3) payload must additionally
 *      satisfy the completed-run guards: the completion marker,
 *      full default matrix coverage (every harness tier x difficulty
 *      x cold/warm x asset cell), default sample sizes, both cache
 *      and asset modes, and the real argon ladder (m=16384 KiB,
 *      target 8).
 *   8. the schema-3 full-matrix guard uses the per-mode result-row
 *      keys: deleting tier:difficulty:cache:files while the :inline
 *      row survives is detected, and vice versa (an aggregate
 *      three-part row never satisfies the per-mode matrix).
 *
 * Physical-evidence proofs (audit finding 3, round 4). When
 * qualification.status is "physical", the validator additionally
 * proves the claim, in CI mode and in release mode alike:
 *
 *   - devices: at least one entry with kind:"physical" and non-empty
 *     id and tier exists, ids are unique, every entry's kind is
 *     lab|physical, every entry carries a non-empty tier that is a
 *     harness tier, and a physical entry additionally carries
 *     non-empty hardware/os/browser/battery_state and a parseable
 *     tested_at date.
 *   - tier coverage: every tier named in qualification.release_tiers
 *     has at least one kind:"physical" device qualified on that tier
 *     ("release tier X has no physical qualification device"), and —
 *     because a committed physical claim must be fully provable in
 *     ordinary CI — every release tier must carry its own p95 budget
 *     rows in the same budget file ("physical release tier X has no
 *     budget tier").
 *   - freshness and chronology: every physical device's tested_at is
 *     within recordAgeDays of now; tested_at never postdates
 *     qualification.qualified_at or payload.generated_at; and
 *     qualified_at never precedes the newest physical tested_at.
 *   - evidence index: physical evidence lives in the baseline
 *     payload's top-level physical_results object,
 *     { "<device-id>": { "<result-key>": <row with reps> } }, one
 *     row per device and per cell (result keys are the per-mode
 *     resultRowKey, tier:difficulty:cache:assetMode, of the device's
 *     tier). A physical claim without physical_results is a silent
 *     gap and a hard reason. Every index key must name a registered
 *     kind:"physical" device; every row must carry source "physical"
 *     and a device_id equal to its index key; every row's cell tier
 *     must equal the device's qualified tier.
 *   - per-device coverage (the RELEASE invariant): every registered
 *     physical device x every released difficulty x cold/warm x every
 *     required asset mode has its own evidence row. A device missing
 *     a required cell is a hard reason naming the device and the
 *     cell: registered devices without measurements are never
 *     invisible.
 *   - per-device quality: each device's own samples meet the generic
 *     minShaReps/minArgonReps floor, the per-mode failure-rate budget
 *     of failureRateBudgets, and — release mode only — the
 *     minSha20SamplesPhysical sha20 floor, all computed per device
 *     per cell, never across devices.
 *   - derivation: every release-tier cell's p95 budget row covers the
 *     worst per-device physical p95 across the qualified devices of
 *     the tier (each device's own rows merged across the cell's
 *     asset modes, worst device taken), for solveMs and
 *     pageToVerifiedMs.
 *
 * Cell keys: the validator distinguishes the aggregate abstraction
 * (one logical tier:difficulty:cache cell whose reps are merged
 * across asset modes for the lab/budget rules) from the physical
 * result-row abstraction (one row per tier:difficulty:cache:assetMode
 * in the schema-3 matrix and in the per-device evidence). Two helpers
 * encode the split: aggregateCellKey(cell) =
 * tier:difficulty:cache, used by the merged budget logic, the
 * release-required coverage, and the per-device aggregation; and
 * resultRowKey(cell) = aggregateCellKey(cell) + ":" + assetMode when
 * the cell carries one, used by the schema-3 full-matrix guard and
 * every physical evidence-row lookup. matchingRows() starts from the
 * aggregate prefix and collects the aggregate row plus every
 * per-mode row, keeping the legacy schema-1 three-part behavior
 * intact.
 *
 * Exit status: 0 on a clean pass, 1 on any rejection. Every reason is
 * written to stderr with the offending keys and values; the pass
 * summary and the qualification status line go to stdout. Runnable
 * standalone (no harness install needed beyond node); the "Performance
 * budgets" workflow check runs it in CI mode against the committed
 * baseline, and the release workflow runs it with --release.
 */
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const HARNESS_FILE = join(REPO_ROOT, 'tools', 'client-perf', 'client-perf.mjs');
const DEFAULT_BUDGETS = join(REPO_ROOT, 'tools', 'client-perf', 'release-budgets.json');

const BUDGETS_SCHEMA = 'kiwicaptcha.release-budgets/2';
const RELEASE_STATUSES = ['lab', 'physical'];
const DEVICE_KINDS = ['lab', 'physical'];
const CACHE_STATES = ['cold', 'warm'];
const BUDGET_METRICS = [
  ['solveMsP95', 'solveMs'],
  ['pageToVerifiedMsP95', 'pageToVerifiedMs'],
];

/**
 * Read a constant out of the harness source: the validator never
 * duplicates the harness's authority. A layout change in the harness
 * that stops a pattern from matching fails loudly here, so the two
 * files cannot drift silently.
 */
function harnessConst(source, label, pattern) {
  const m = source.match(pattern);
  if (!m) {
    throw new Error(`validate-release-baseline: cannot read the harness ${label} from ${HARNESS_FILE} (pattern ${pattern}); update the validator`);
  }
  return m[1];
}

/** All difficulty names the harness defines, in source order. */
function harnessDifficulties(source) {
  const m = source.match(/const DIFFICULTIES = \{([\s\S]*?)\n\};/);
  if (!m) {
    throw new Error(`validate-release-baseline: cannot read the harness DIFFICULTIES block from ${HARNESS_FILE}; update the validator`);
  }
  const block = m[1];
  const names = [];
  for (const line of block.split('\n')) {
    const key = line.match(/^\s{2}([a-zA-Z0-9]+): \{$/);
    if (key) names.push(key[1]);
  }
  if (names.length === 0) {
    throw new Error(`validate-release-baseline: no difficulties parsed from ${HARNESS_FILE}; update the validator`);
  }
  return names;
}

/** {difficulty -> {isArgon, assetModes}} from the harness source. */
function harnessDifficultyProfiles(source) {
  const names = harnessDifficulties(source);
  const profiles = {};
  for (const name of names) {
    const start = source.indexOf('\n  ' + name + ': {');
    if (start === -1) {
      throw new Error(`validate-release-baseline: difficulty ${name} not found in ${HARNESS_FILE}; update the validator`);
    }
    const end = source.indexOf('\n  }', start);
    const block = source.slice(start, end);
    const isArgon = /isArgon: true/.test(block);
    const modesMatch = block.match(/assetModes: \[([^\]]*)\]/);
    if (!modesMatch) {
      throw new Error(`validate-release-baseline: difficulty ${name} has no parseable assetModes in ${HARNESS_FILE}; update the validator`);
    }
    const assetModes = [...modesMatch[1].matchAll(/'([a-z]+)'/g)].map((m) => m[1]);
    profiles[name] = { isArgon, assetModes };
  }
  return profiles;
}

function loadJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    process.stderr.write(`${label} cannot be read at ${path}: ${e.message}\n`);
    process.exit(1);
  }
}

/** Same percentile semantics as the harness's summarize(). */
function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

/** Aggregate the measured samples of one (tier, difficulty, cache). */
function aggregate(samples, field) {
  const values = samples
    .map((s) => (s && typeof s[field] === 'number' ? s[field] : null))
    .filter((v) => v !== null);
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return {
    count: sorted.length,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
  };
}

/**
 * Aggregate key of a cell: the merged tier:difficulty:cache logical
 * cell the budget rows and the per-device aggregations are keyed on
 * (asset modes are folded into the aggregate abstraction).
 */
function aggregateCellKey(cell) {
  return `${cell.tier}:${cell.difficulty}:${cell.cache}`;
}

/**
 * Result-row key of a cell: the aggregate key extended with the
 * asset mode when the cell carries one (tier:difficulty:cache:mode).
 * The schema-3 full-matrix coverage and every physical evidence-row
 * lookup use this key, so tier:difficulty:cache:inline and
 * tier:difficulty:cache:files are distinct rows and deleting one is
 * always detected.
 */
function resultRowKey(cell) {
  const base = aggregateCellKey(cell);
  return cell.assetMode !== undefined && cell.assetMode !== null ? `${base}:${cell.assetMode}` : base;
}

function main() {
  const argv = process.argv.slice(2);
  let releaseMode = process.env.RELEASE_PERFORMANCE === '1';
  const rest = [];
  for (const arg of argv) {
    if (arg === '--release') releaseMode = true;
    else rest.push(arg);
  }
  if (rest.length < 1 || rest[0] === '--help' || rest[0] === '-h') {
    process.stderr.write('usage: node tools/ci/validate-release-baseline.mjs [--release] <baseline.json> [<release-budgets.json>]\n');
    process.stderr.write('       RELEASE_PERFORMANCE=1 node tools/ci/validate-release-baseline.mjs <baseline.json> [<release-budgets.json>]\n');
    process.exit(rest.length ? 0 : 1);
  }
  const baselinePath = rest[0];
  const budgetsPath = rest[1] ?? DEFAULT_BUDGETS;

  let source;
  try {
    source = readFileSync(HARNESS_FILE, 'utf8');
  } catch (e) {
    process.stderr.write(`cannot read the harness at ${HARNESS_FILE}: ${e.message}\n`);
    process.exit(1);
  }
  let schema;
  let completionMarker;
  let tierNames;
  let difficultyProfiles;
  let shaRepsDefault;
  let argonRepsDefault;
  try {
    schema = harnessConst(source, 'schema string', /const SCHEMA = '([^']+)';/);
    completionMarker = harnessConst(source, 'completion marker', /const COMPLETION_MARKER = '([^']+)';/);
    const tiersMatch = source.match(/const TIERS = \{([\s\S]*?)\n\};/);
    if (!tiersMatch) {
      throw new Error('TIERS block');
    }
    tierNames = [];
    for (const line of tiersMatch[1].split('\n')) {
      const key = line.match(/^\s{2}'([a-z-]+)': \{$/);
      if (key) tierNames.push(key[1]);
    }
    if (tierNames.length === 0) throw new Error('TIERS keys');
    difficultyProfiles = harnessDifficultyProfiles(source);
    shaRepsDefault = parseInt(harnessConst(source, 'SHA rep default', /reps: (\d+), \/\/ SHA-256 solve repetitions/), 10);
    argonRepsDefault = parseInt(harnessConst(source, 'Argon rep default', /argonReps: (\d+), \/\/ Argon2id solve repetitions/), 10);
  } catch (e) {
    process.stderr.write(`validate-release-baseline: cannot parse the harness constants from ${HARNESS_FILE}: ${e.message}; update the validator\n`);
    process.exit(1);
  }

  const budgets = loadJson(budgetsPath, 'release budgets');
  const payload = loadJson(baselinePath, 'baseline');

  const reasons = [];
  const notes = [];
  const isCurrentHarnessPayload = payload.schema === schema;

  // ── The budget authority must be complete and honest. ──────────────
  if (budgets.schema !== BUDGETS_SCHEMA) {
    reasons.push(`budget file ${budgetsPath}: schema ${JSON.stringify(budgets.schema)} is not ${BUDGETS_SCHEMA}`);
  }

  // Qualification block.
  const qualification = budgets.qualification;
  if (!qualification || typeof qualification !== 'object') {
    reasons.push(`budget file ${budgetsPath}: missing top-level qualification object (status, qualified_at, harness_schema, devices, release_tiers)`);
  } else {
    if (!RELEASE_STATUSES.includes(qualification.status)) {
      reasons.push(`budget file ${budgetsPath}: qualification.status ${JSON.stringify(qualification.status)} is not one of ${RELEASE_STATUSES.join('|')}`);
    }
    if (qualification.harness_schema !== schema) {
      reasons.push(`budget file ${budgetsPath}: qualification.harness_schema ${JSON.stringify(qualification.harness_schema)} differs from the harness schema ${schema}`);
    }
    if (!Array.isArray(qualification.devices)) {
      reasons.push(`budget file ${budgetsPath}: qualification.devices must be an array (the rigs the qualification data was recorded on)`);
    }
    const qualifiedAt = qualification.qualified_at;
    if (qualifiedAt !== null && qualifiedAt !== undefined) {
      if (typeof qualifiedAt !== 'string' || Number.isNaN(Date.parse(qualifiedAt))) {
        reasons.push(`budget file ${budgetsPath}: qualification.qualified_at ${JSON.stringify(qualifiedAt)} is not null or a parseable ISO date`);
      }
    }
    if (qualification.status === 'physical') {
      if (!qualifiedAt) {
        reasons.push(`budget file ${budgetsPath}: qualification.status "physical" requires a qualified_at ISO date (a physical claim without a date is a silent gap)`);
      }
      if (!Array.isArray(qualification.devices) || qualification.devices.length === 0) {
        reasons.push(`budget file ${budgetsPath}: qualification.status "physical" requires recorded devices (a physical claim without device rows is a silent gap)`);
      }
    }

    // The release ladder: release_tiers is the explicit ordered list of
    // tiers the release gate certifies. Every entry must be a harness
    // tier key the repo documents (the README device-tier table); a
    // file cannot invent a tier name here.
    if (!Array.isArray(qualification.release_tiers)) {
      reasons.push(`budget file ${budgetsPath}: qualification.release_tiers must be an ordered list of the harness tier keys the release gate certifies (missing or not an array)`);
    } else {
      if (qualification.release_tiers.length === 0) {
        reasons.push(`budget file ${budgetsPath}: qualification.release_tiers must name at least one tier (an empty release ladder cannot be certified)`);
      }
      const seenTiers = new Set();
      for (const t of qualification.release_tiers) {
        if (typeof t !== 'string' || !t.length) {
          reasons.push(`budget file ${budgetsPath}: qualification.release_tiers entries must be non-empty tier key strings (got ${JSON.stringify(t)})`);
        } else if (!tierNames.includes(t)) {
          reasons.push(`budget file ${budgetsPath}: qualification.release_tiers names unknown tier ${JSON.stringify(t)} (not a harness tier; release tiers must be documented harness tier keys)`);
        }
        if (typeof t === 'string' && seenTiers.has(t)) {
          reasons.push(`budget file ${budgetsPath}: qualification.release_tiers repeats tier ${t} (the ladder is an ordered list without duplicates)`);
        }
        if (typeof t === 'string') seenTiers.add(t);
      }
    }
  }

  // Device registration: every device entry must identify the rig it
  // records (id, kind, tier), and a kind:"physical" entry must carry
  // the full physical identity (hardware/os/browser/battery_state and
  // a tested_at date) the release claim requires.
  const deviceEntries = [];
  const deviceById = new Map();
  if (qualification && Array.isArray(qualification.devices)) {
    const seenIds = new Set();
    qualification.devices.forEach((dev, i) => {
      if (!dev || typeof dev !== 'object' || Array.isArray(dev)) {
        reasons.push(`budget file ${budgetsPath}: qualification.devices[${i}] is not an object`);
        return;
      }
      if (typeof dev.id !== 'string' || dev.id.length === 0) {
        reasons.push(`budget file ${budgetsPath}: qualification.devices[${i}] needs a non-empty id string`);
      } else {
        if (seenIds.has(dev.id)) {
          reasons.push(`budget file ${budgetsPath}: duplicate qualification.devices id ${JSON.stringify(dev.id)} (device ids must be unique)`);
        }
        seenIds.add(dev.id);
      }
      if (!DEVICE_KINDS.includes(dev.kind)) {
        reasons.push(`budget file ${budgetsPath}: device ${JSON.stringify(dev.id || dev)} kind ${JSON.stringify(dev.kind)} is not one of ${DEVICE_KINDS.join('|')}`);
      }
      if (typeof dev.tier !== 'string' || dev.tier.length === 0) {
        reasons.push(`budget file ${budgetsPath}: device ${JSON.stringify(dev.id || dev)} needs a non-empty tier`);
      } else if (!tierNames.includes(dev.tier)) {
        reasons.push(`budget file ${budgetsPath}: device ${JSON.stringify(dev.id)} tier ${JSON.stringify(dev.tier)} is not a harness tier`);
      }
      if (dev.kind === 'physical') {
        for (const field of ['hardware', 'os', 'browser', 'battery_state']) {
          if (typeof dev[field] !== 'string' || dev[field].length === 0) {
            reasons.push(`budget file ${budgetsPath}: physical device ${JSON.stringify(dev.id)} needs a non-empty ${field}`);
          }
        }
        const testedAt = dev.tested_at;
        if (typeof testedAt !== 'string' || Number.isNaN(Date.parse(testedAt))) {
          reasons.push(`budget file ${budgetsPath}: physical device ${JSON.stringify(dev.id)} needs a parseable ISO tested_at date`);
        }
      }
      deviceEntries.push(dev);
      if (typeof dev.id === 'string' && dev.id.length > 0) deviceById.set(dev.id, dev);
    });
  }

  // The physical devices of the claim: kind:"physical" entries with a
  // non-empty id and tier (audit finding 3: the validator must never
  // count a lab rig or a device row without identity as physical
  // evidence).
  const physicalDevices = deviceEntries.filter(
    (d) => d.kind === 'physical' && typeof d.id === 'string' && d.id.length > 0 && typeof d.tier === 'string' && d.tier.length > 0
  );
  const physicalClaim = qualification && qualification.status === 'physical';
  if (physicalClaim) {
    if (physicalDevices.length === 0) {
      reasons.push(`budget file ${budgetsPath}: qualification.status "physical" requires at least one kind:"physical" device with a non-empty id and tier (${Array.isArray(qualification.devices) ? qualification.devices.length : 0} device(s) recorded, none physical)`);
    }
  }

  // Per-mode failure-rate limits (replaces the old global
  // maxCellFailureRate, which let every RSW/Argon/execution cell carry
  // ~5% failures): failureRateBudgets.default binds every mode that
  // has no explicit entry; only sha20 carries an explicit allowance
  // (0.02) for the measured driver-exhaustion tail of the 20-bit
  // pure-JS search. Unknown modes are rejections: a file cannot invent
  // a carve-out for a mode the harness does not solve.
  const failureRateBudgets = budgets.failureRateBudgets;
  if (!failureRateBudgets || typeof failureRateBudgets !== 'object' || Array.isArray(failureRateBudgets)) {
    reasons.push(`budget file ${budgetsPath}: failureRateBudgets must be an object { default: 0..1, "<mode>": 0..1 } (per-mode failure-rate limits; every mode except sha20 inherits default)`);
  } else {
    const frbKeys = Object.keys(failureRateBudgets);
    if (typeof failureRateBudgets.default !== 'number' || !(failureRateBudgets.default > 0 && failureRateBudgets.default <= 1)) {
      reasons.push(`budget file ${budgetsPath}: failureRateBudgets.default ${JSON.stringify(failureRateBudgets.default)} is not a rate in (0, 1]`);
    }
    for (const key of frbKeys) {
      if (key !== 'default' && !Object.prototype.hasOwnProperty.call(difficultyProfiles, key)) {
        reasons.push(`budget file ${budgetsPath}: failureRateBudgets names unknown mode ${JSON.stringify(key)} (only "default" or harness difficulties such as sha20 may carry a rate)`);
      }
      const v = failureRateBudgets[key];
      if (typeof v !== 'number' || !(v > 0 && v <= 1)) {
        reasons.push(`budget file ${budgetsPath}: failureRateBudgets[${JSON.stringify(key)}] ${JSON.stringify(v)} is not a rate in (0, 1]`);
      }
    }
  }
  const failureRateForMode = (difficulty) => {
    const frb = budgets.failureRateBudgets;
    if (!frb || typeof frb !== 'object') return null;
    return typeof frb[difficulty] === 'number' ? frb[difficulty] : (typeof frb.default === 'number' ? frb.default : null);
  };

  // The released-mode set: the budget difficulty list must equal the
  // harness's difficulty set. A mode the harness solves but the budget
  // file does not carry is a released mode without a p95 budget: hard
  // failure, never a note.
  const harnessDifficultyNames = Object.keys(difficultyProfiles);
  const budgetDifficulties = Array.isArray(budgets.difficulties) ? budgets.difficulties : [];
  const missingBudgetDifficulties = harnessDifficultyNames.filter((d) => !budgetDifficulties.includes(d));
  const extraBudgetDifficulties = budgetDifficulties.filter((d) => !harnessDifficultyNames.includes(d));
  if (missingBudgetDifficulties.length) {
    reasons.push(`budget file ${budgetsPath}: released mode(s) without a p95 budget row: ${missingBudgetDifficulties.join(', ')} (the budget difficulty list must cover every harness difficulty)`);
  }
  if (extraBudgetDifficulties.length) {
    reasons.push(`budget file ${budgetsPath}: unknown difficulty in the budget list: ${extraBudgetDifficulties.join(', ')} (not a harness difficulty)`);
  }

  // Qualified tier scope: every budget tier must be a harness tier, and
  // every difficulty x tier x cold|warm combination must carry an
  // explicit positive p95 budget row. In release mode the scope widens
  // to the union with qualification.release_tiers, so a file cannot
  // declare a release ladder that lacks p95 budgets.
  const budgetTiers = Array.isArray(budgets.tiers) ? budgets.tiers : [];
  if (budgetTiers.length === 0) {
    reasons.push(`budget file ${budgetsPath}: tiers list is empty (a release gate must name the tiers it qualifies)`);
  }
  const unknownBudgetTiers = budgetTiers.filter((t) => !tierNames.includes(t));
  if (unknownBudgetTiers.length) {
    reasons.push(`budget file ${budgetsPath}: unknown tier(s) ${unknownBudgetTiers.join(', ')} (not harness tiers)`);
  }
  const releaseTiers =
    qualification && Array.isArray(qualification.release_tiers)
      ? qualification.release_tiers.filter((t) => typeof t === 'string' && tierNames.includes(t))
      : [];
  // Certified tier scope. The scope widens to the union with
  // qualification.release_tiers whenever the file claims physical
  // qualification OR release mode is on: once status:"physical" is
  // committed, ordinary CI must prove every physical invariant (and
  // the release-tier budget rows must exist) immediately, never only
  // under --release.
  const releaseTierSet = new Set(releaseTiers);
  const certTiers = releaseMode || physicalClaim ? [...new Set([...budgetTiers, ...releaseTiers])] : [...budgetTiers];
  if (releaseMode || physicalClaim) {
    for (const t of releaseTiers) {
      if (!budgetTiers.includes(t)) {
        reasons.push(
          physicalClaim
            ? `physical release tier ${t} has no budget tier (a committed "physical" claim must carry the p95 budget rows of every release tier in the same file; ordinary CI then proves every physical invariant)`
            : `release tier ${t} is not covered by the budget file's tiers (release_tiers and the budget tiers must name the same ladder in release certification: ${t} has no p95 budget rows)`
        );
      }
    }
  }
  const missingBudgetRows = [];
  for (const tier of certTiers) {
    const tierBudget = (budgets.budgets || {})[tier];
    if (!tierBudget) {
      for (const difficulty of budgetDifficulties) {
        for (const cache of CACHE_STATES) {
          missingBudgetRows.push(`${tier}/${difficulty}/${cache}`);
        }
      }
      continue;
    }
    for (const difficulty of budgetDifficulties) {
      for (const cache of CACHE_STATES) {
        const b = (tierBudget[difficulty] || {})[cache];
        if (!b || !(b.solveMsP95 > 0) || !(b.pageToVerifiedMsP95 > 0)) {
          missingBudgetRows.push(`${tier}/${difficulty}/${cache}`);
        }
      }
    }
  }
  if (missingBudgetRows.length) {
    reasons.push(`${missingBudgetRows.length} release-required cell(s) have no p95 budget row (${missingBudgetRows.slice(0, 8).join(', ')}${missingBudgetRows.length > 8 ? ', ...' : ''}); every released mode x qualified tier x cold/warm needs an explicit solveMsP95 + pageToVerifiedMsP95 budget`);
  }
  const minShaReps = budgets.minShaReps;
  const minArgonReps = budgets.minArgonReps;
  if (!(Number.isInteger(minShaReps) && minShaReps > 0)) {
    reasons.push(`budget file ${budgetsPath}: minShaReps ${JSON.stringify(minShaReps)} is not a positive integer`);
  }
  if (!(Number.isInteger(minArgonReps) && minArgonReps > 0)) {
    reasons.push(`budget file ${budgetsPath}: minArgonReps ${JSON.stringify(minArgonReps)} is not a positive integer`);
  }
  // The physical sha20 sample floor (schema 1.x had no sample floor;
  // the sha20 allowance must never be forced by a single exhaustion
  // observation on a small sample). Enforced in release mode against
  // the physical sha20 evidence of a physical-qualified file.
  const minSha20SamplesPhysical = budgets.minSha20SamplesPhysical;
  if (!(Number.isInteger(minSha20SamplesPhysical) && minSha20SamplesPhysical > 0)) {
    reasons.push(`budget file ${budgetsPath}: minSha20SamplesPhysical ${JSON.stringify(minSha20SamplesPhysical)} is not a positive integer (the physical sha20 evidence floor)`);
  }

  // ── Baseline identity and age. ─────────────────────────────────────
  const env = payload.environment || {};
  const identityMissing = [];
  if (!env.os) identityMissing.push('environment.os');
  if (!env.machine) identityMissing.push('environment.machine');
  if (!env.cpus) identityMissing.push('environment.cpus');
  if (!payload.chromium) identityMissing.push('chromium');
  if (identityMissing.length) {
    reasons.push(`environment lacks browser/OS/hardware identity: missing ${identityMissing.join(', ')} (a release baseline must name the machine and browser it was measured on)`);
  }

  const recordAgeDays = typeof budgets.recordAgeDays === 'number' ? budgets.recordAgeDays : 90;
  if (typeof payload.generated_at !== 'string') {
    reasons.push('generated_at missing: the record age cannot be validated');
  } else {
    const ageMs = Date.now() - Date.parse(payload.generated_at);
    if (Number.isNaN(ageMs)) {
      reasons.push(`generated_at ${payload.generated_at} is not a parseable date`);
    } else {
      const ageDays = ageMs / 86400000;
      if (ageDays > recordAgeDays) {
        reasons.push(`record age ${ageDays.toFixed(1)} days exceeds the ${recordAgeDays}-day budget (generated ${payload.generated_at}); an old recording cannot qualify a current release`);
      }
    }
  }

  // ── Coverage and budget compliance: every release-required cell. ───
  // A required cell is every (tier, difficulty, cache) combination the
  // budgets file rows declare (plus, in release mode, every tier the
  // qualification declares in release_tiers), for every asset mode the
  // harness schema attaches to that difficulty. The baseline rows that
  // match a required cell are aggregated (per-repetition samples
  // concatenated across the cell's mode rows) and the aggregate p95s
  // are compared with the budget row.
  //
  // When the file claims physical qualification, the release-tier
  // cells are governed by the physical-evidence contract below
  // (provenance, per-device worst p95, per-mode failure budgets,
  // sample floors); the generic merged coverage/budget rules still
  // bind the cells of the remaining (lab-scope) tiers.
  const results = payload.results || {};
  const allRequiredCells = [];
  for (const tier of certTiers) {
    for (const difficulty of budgetDifficulties) {
      for (const cache of CACHE_STATES) {
        allRequiredCells.push({ tier, difficulty, cache, isArgon: !!difficultyProfiles[difficulty]?.isArgon });
      }
    }
  }
  const requiredCells = physicalClaim
    ? allRequiredCells.filter((c) => !releaseTierSet.has(c.tier))
    : allRequiredCells;

  const matchingRows = (cell) => {
    // Start from the aggregate prefix and collect the aggregate row
    // (legacy schema-1 three-part rows) plus every per-mode row the
    // baseline records for the cell.
    const prefix = aggregateCellKey(cell);
    const modes = [];
    if (results[prefix]) modes.push({ key: prefix, row: results[prefix] });
    for (const mode of difficultyProfiles[cell.difficulty]?.assetModes || []) {
      const key4 = `${prefix}:${mode}`;
      if (results[key4]) modes.push({ key: key4, row: results[key4] });
    }
    return modes;
  };

  const cellReps = (cell) => {
    const matches = matchingRows(cell);
    const reps = [];
    for (const { row } of matches) {
      if (Array.isArray(row.reps)) reps.push(...row.reps);
    }
    return reps;
  };

  const coverageField = (cell, field) => {
    const reps = cellReps(cell);
    if (reps.length > 0) {
      const agg = aggregate(reps, field);
      return agg ? agg.p95 : null;
    }
    // No per-rep samples: fall back to the stored summary of the
    // matched rows (a legacy row), taking the slowest recorded p95 so a
    // stored row can never under-report.
    const matches = matchingRows(cell);
    const p95s = [];
    for (const { row } of matches) {
      const s = row && row[field] && typeof row[field] === 'object' ? row[field] : null;
      if (s && typeof s.p95 === 'number') p95s.push(s.p95);
    }
    return p95s.length ? Math.max(...p95s) : null;
  };

  const missingCells = [];
  const lowSampleCells = [];
  for (const cell of requiredCells) {
    const matches = matchingRows(cell);
    if (matches.length === 0) {
      missingCells.push(aggregateCellKey(cell));
      continue;
    }
    const n = cellReps(cell).length;
    const min = cell.isArgon ? minArgonReps : minShaReps;
    if (n > 0 && n < min) {
      lowSampleCells.push(`${aggregateCellKey(cell)} has ${n} samples (need >= ${min})`);
    }
  }
  if (missingCells.length) {
    reasons.push(`${missingCells.length} release-required cell(s) have no measured baseline row (${missingCells.slice(0, 8).join(', ')}${missingCells.length > 8 ? ', ...' : ''}); every mode x tier x cold/warm combination the budgets file requires must be measured`);
  }
  if (lowSampleCells.length) {
    reasons.push(`${lowSampleCells.length} cell(s) below the budget-file sample floor (${lowSampleCells.slice(0, 5).join('; ')}${lowSampleCells.length > 5 ? '; ...' : ''})`);
  }

  const budgetViolations = [];
  const budgetRows = (cell) => {
    const b = ((budgets.budgets || {})[cell.tier] || {})[cell.difficulty] || {};
    return b[cell.cache] || null;
  };
  for (const cell of requiredCells) {
    const matches = matchingRows(cell);
    if (matches.length === 0) continue;
    const budget = budgetRows(cell);
    if (!budget) continue; // already reported by the budget-authority rule
    for (const [metric, field] of BUDGET_METRICS) {
      const measured = coverageField(cell, field);
      if (measured === null) {
        budgetViolations.push(`${aggregateCellKey(cell)} ${field}.p95 is not recorded`);
      } else if (measured > budget[metric]) {
        budgetViolations.push(`${aggregateCellKey(cell)} ${field}.p95 ${measured.toFixed(1)} ms exceeds the budget ${budget[metric]} ms`);
      }
    }
  }

  // ── Physical-evidence contract (audit finding 3, round 4). ─────────
  // When the file claims physical qualification, the claim must be
  // provable from a real device dimension: physical evidence lives in
  // the baseline payload's top-level physical_results object
  // { "<device-id>": { "<result-key>": <row with reps> } }, one row
  // per device and per cell (result keys are the per-mode result-row
  // keys of the device's tier). The release invariant is per-device:
  // every registered physical device x released difficulty x cold/warm
  // x required asset mode has its own evidence row; sample floors and
  // per-mode failure budgets bind per device, never across devices;
  // and each release-tier cell's p95 budget must cover the WORST
  // per-device physical p95 across all qualified devices of the tier.
  // Every physical-device tested_at is held to the record-age bound
  // and to the qualification chronology. These checks run in both
  // modes whenever the claim is physical — a committed "physical"
  // claim must prove itself on every push; the minSha20SamplesPhysical
  // floor is asserted only in release mode (certification), per the
  // sha20 carve-out contract.
  if (physicalClaim) {
    // Tier coverage: every declared release tier must have at least one
    // physical device qualified on it.
    for (const t of releaseTiers) {
      if (!physicalDevices.some((d) => d.tier === t)) {
        reasons.push(`release tier ${t} has no physical qualification device`);
      }
    }

    // Evidence-index presence: a physical claim without a
    // physical_results device index is a silent gap.
    const physicalResults = payload.physical_results;
    const physicalIndexOk =
      physicalResults && typeof physicalResults === 'object' && !Array.isArray(physicalResults);
    if (!physicalIndexOk || Object.keys(physicalResults).length === 0) {
      reasons.push(`baseline payload ${baselinePath} carries no physical_results object { "<device-id>": { "<result-key>": <row> } } with per-device evidence rows (a physical claim without per-device evidence rows is a silent gap)`);
    }
    const physicalIndex = physicalIndexOk ? physicalResults : {};

    // Structural scan of the device index: every index key must name a
    // registered kind:"physical" device; every row must be an object
    // carrying source "physical" and the device_id of its index key
    // (the row-level provenance pair merge-cells stamps); and every
    // row's cell tier must equal the device's qualified tier.
    for (const [deviceId, index] of Object.entries(physicalIndex)) {
      if (!index || typeof index !== 'object' || Array.isArray(index)) {
        reasons.push(`physical_results[${JSON.stringify(deviceId)}] is not an object of result-key -> row entries`);
        continue;
      }
      const dev = deviceById.get(deviceId);
      if (!dev || dev.kind !== 'physical') {
        reasons.push(`physical_results names device ${JSON.stringify(deviceId)} which is not a registered kind:"physical" device in qualification.devices`);
      }
      for (const [rowKey, row] of Object.entries(index)) {
        if (rowKey.startsWith('multi-widget')) continue;
        if (!row || typeof row !== 'object' || Array.isArray(row)) {
          reasons.push(`physical_results[${JSON.stringify(deviceId)}] row ${rowKey} is not an object`);
          continue;
        }
        if (row.source !== 'physical') {
          reasons.push(`physical_results[${JSON.stringify(deviceId)}] row ${rowKey} source ${JSON.stringify(row.source)} is not "physical" (every physical evidence row must carry source "physical")`);
        }
        if (row.device_id !== deviceId) {
          reasons.push(`physical_results[${JSON.stringify(deviceId)}] row ${rowKey} carries device_id ${JSON.stringify(row.device_id)} that does not match its index device (a row inside a device index must name that device)`);
        }
        if (dev && typeof dev.tier === 'string') {
          const rowTier = String(rowKey).split(':')[0];
          if (rowTier && rowTier !== dev.tier) {
            reasons.push(`physical_results[${JSON.stringify(deviceId)}] row ${rowKey} belongs to tier ${JSON.stringify(rowTier)} but device ${JSON.stringify(deviceId)} is qualified on tier ${JSON.stringify(dev.tier)} (a physical row's tier must equal its device's qualified tier)`);
          }
        }
      }
    }

    // Evidence freshness and chronology (finding 5): every physical
    // device's tested_at must be within recordAgeDays of now, must not
    // postdate qualification.qualified_at or payload.generated_at, and
    // qualified_at must not precede the newest physical tested_at (a
    // regenerated baseline can never launder old measurements).
    const qualifiedAt = qualification ? qualification.qualified_at : null;
    const qualifiedAtMs = typeof qualifiedAt === 'string' ? Date.parse(qualifiedAt) : NaN;
    const generatedAtMs = typeof payload.generated_at === 'string' ? Date.parse(payload.generated_at) : NaN;
    let newestTestedAtMs = null;
    let newestTestedAt = null;
    for (const dev of physicalDevices) {
      const testedAt = dev.tested_at;
      const testedAtMs = typeof testedAt === 'string' ? Date.parse(testedAt) : NaN;
      if (Number.isNaN(testedAtMs)) continue; // unparseable tested_at already reported at registration
      if (newestTestedAtMs === null || testedAtMs > newestTestedAtMs) {
        newestTestedAtMs = testedAtMs;
        newestTestedAt = testedAt;
      }
      const ageDays = (Date.now() - testedAtMs) / 86400000;
      if (ageDays > recordAgeDays) {
        reasons.push(`physical device ${dev.id} evidence is ${ageDays.toFixed(1)} days old; maximum is ${recordAgeDays} (tested ${testedAt})`);
      }
      if (!Number.isNaN(qualifiedAtMs) && testedAtMs > qualifiedAtMs) {
        reasons.push(`physical device ${dev.id} tested_at ${testedAt} is after qualification.qualified_at ${qualifiedAt} (evidence cannot postdate the qualification it certifies)`);
      }
      if (!Number.isNaN(generatedAtMs) && testedAtMs > generatedAtMs) {
        reasons.push(`physical device ${dev.id} tested_at ${testedAt} is after payload.generated_at ${payload.generated_at} (evidence cannot postdate the baseline record that carries it)`);
      }
    }
    if (!Number.isNaN(qualifiedAtMs) && newestTestedAtMs !== null && newestTestedAtMs > qualifiedAtMs) {
      reasons.push(`qualification.qualified_at ${qualifiedAt} precedes the newest physical device tested_at ${newestTestedAt} (a qualification date may never precede the evidence it certifies)`);
    }

    // Per-cell proofs over the release-tier cells: per-device coverage
    // (the RELEASE invariant), per-device quality (sample floors and
    // failure budgets, never aggregated across devices), then the
    // worst per-device p95 against the budget row.
    for (const tier of releaseTiers) {
      const tierDevices = physicalDevices.filter((d) => d.tier === tier);
      if (tierDevices.length === 0) continue; // tier coverage already reported
      for (const difficulty of budgetDifficulties) {
        for (const cache of CACHE_STATES) {
          const cell = { tier, difficulty, cache, isArgon: !!difficultyProfiles[difficulty]?.isArgon };
          const key = aggregateCellKey(cell);
          const budget = budgetRows(cell);
          const modes = difficultyProfiles[difficulty]?.assetModes || [];
          // Per-device evidence rows for this aggregate cell: the
          // per-mode rows the device index carries. A merged
          // (three-part) row folds the modes and can never satisfy the
          // per-mode invariant, so it is not counted as evidence.
          const deviceRows = new Map(); // deviceId -> [{key, row}]
          for (const dev of tierDevices) {
            const index = physicalIndex[dev.id];
            const hasIndex = index && typeof index === 'object' && !Array.isArray(index);
            const rows = [];
            for (const mode of modes) {
              const rk = resultRowKey({ tier, difficulty, cache, assetMode: mode });
              if (hasIndex && index[rk]) {
                rows.push({ key: rk, row: index[rk] });
              } else {
                reasons.push(`release tier ${tier}: physical device ${dev.id} has no evidence row for ${rk} (every registered physical device x released difficulty x cold/warm x required asset mode must have its own measured evidence row)`);
              }
            }
            if (rows.length > 0) deviceRows.set(dev.id, rows);
          }
          if (deviceRows.size === 0) continue; // coverage reasons already reported

          const deviceSamples = (deviceId) => {
            const rows = deviceRows.get(deviceId) || [];
            const reps = [];
            for (const { row } of rows) {
              if (Array.isArray(row.reps)) reps.push(...row.reps);
            }
            return reps;
          };
          const min = cell.isArgon ? minArgonReps : minShaReps;
          const rateBudget = failureRateForMode(difficulty);

          // Per-device quality: each device's OWN samples meet the
          // generic floor, the sha20 physical floor (release mode), and
          // the per-mode failure budget. The failure rate is 1.0 when
          // the device has rows but zero samples; reliability is never
          // aggregated across devices first, so one healthy device can
          // never mask a failing one.
          for (const [deviceId, rows] of deviceRows) {
            const samples = deviceSamples(deviceId);
            const failed = samples.filter(
              (s) => s && ((s.timedOut && s.timedOut !== false) || s.errorCount > 0)
            ).length;
            const failureRate = samples.length === 0 ? 1 : failed / samples.length;
            if (samples.length > 0 && samples.length < min) {
              reasons.push(`${key}/${deviceId} has ${samples.length} samples; need >= ${min} (per-device physical sample floor: one device's thin sample can never be masked by another device's depth)`);
            }
            if (releaseMode && difficulty === 'sha20' && samples.length < minSha20SamplesPhysical) {
              reasons.push(`${key}/${deviceId}: sha20 needs >= ${minSha20SamplesPhysical} physical samples (per-device physical sha20 floor: a single exhaustion observation on a thin per-device sample must never force the sha20 allowance)`);
            }
            if (rateBudget !== null && failureRate > rateBudget) {
              reasons.push(`${key}/${deviceId} failure rate ${(failureRate * 100).toFixed(1)}% (${failed}/${samples.length} failed samples) exceeds the ${(rateBudget * 100).toFixed(0)}% per-mode failure budget of mode ${difficulty} (per-device limit: one healthy device cannot mask a failing one)`);
            }
          }

          // Worst per-device physical p95 across the qualified devices
          // of the tier, compared against the budget row: per-device
          // p95 per cell (each device's own rows merged across the
          // cell's asset modes), max across devices, budget must cover
          // the slowest qualified device.
          if (!budget) continue; // budget-row gaps already reported
          for (const [metric, field] of BUDGET_METRICS) {
            const worst = { value: null, device: null };
            for (const [deviceId, rows] of deviceRows) {
              const reps = [];
              const summaryP95s = [];
              for (const { row } of rows) {
                if (Array.isArray(row.reps) && row.reps.length > 0) reps.push(...row.reps);
                const s = row && row[field] && typeof row[field] === 'object' ? row[field] : null;
                if (s && typeof s.p95 === 'number') summaryP95s.push(s.p95);
              }
              let p95 = null;
              if (reps.length > 0) {
                const agg = aggregate(reps, field);
                p95 = agg ? agg.p95 : null;
              }
              if (p95 === null && summaryP95s.length > 0) p95 = Math.max(...summaryP95s);
              if (p95 === null) continue;
              if (worst.value === null || p95 > worst.value) {
                worst.value = p95;
                worst.device = deviceId;
              }
            }
            if (worst.value === null) {
              budgetViolations.push(`${key} ${field} physical p95 is not recorded on any qualified physical device`);
            } else if (worst.value > budget[metric]) {
              budgetViolations.push(`${key} ${field} worst physical p95 ${worst.value.toFixed(1)} ms (device ${worst.device}) exceeds the budget ${budget[metric]} ms (the budget must cover the slowest qualified physical device)`);
            }
          }
        }
      }
    }
  }
  if (budgetViolations.length) {
    reasons.push(`${budgetViolations.length} p95 budget violation(s) (${budgetViolations.slice(0, 6).join('; ')}${budgetViolations.length > 6 ? '; ...' : ''})`);
  }

  // ── Completed-run guards: current-harness (schema 3) payloads only. ─
  // The committed maintenance baseline (schema 1, pre-matrix legacy
  // rows preserved byte-for-byte) is validated by the coverage and
  // budget rules above; a schema-3 payload must additionally be a clean
  // completed run, because a partial or interrupted run is never a
  // release baseline.
  if (payload.schema !== schema) {
    if (payload.schema !== undefined && payload.schema !== 'kiwicaptcha.client-perf/1') {
      notes.push(`baseline schema ${JSON.stringify(payload.schema)} is not the current harness schema ${schema}; validated on the budget-required coverage only`);
    }
  } else {
    const completion = payload.completion || {};
    if (completion.status !== 'completed' || completion.marker !== completionMarker) {
      reasons.push(`completion ${JSON.stringify(completion)} is not status "completed" with marker ${completionMarker} (the incomplete-run guard: a partial or interrupted run is never a release baseline)`);
    }
    const recordedTiers = payload.tiers ? Object.keys(payload.tiers) : [];
    const missingTiers = tierNames.filter((t) => !recordedTiers.includes(t));
    if (missingTiers.length) {
      reasons.push(`device tiers missing from the payload: ${missingTiers.join(', ')} (all ${tierNames.length} harness tiers are required)`);
    }
    const recordedKeys = new Set(Object.keys(results).filter((k) => !k.startsWith('multi-widget')));
    const expectedCells = [];
    for (const tier of tierNames) {
      for (const [difficulty, profile] of Object.entries(difficultyProfiles)) {
        for (const cache of CACHE_STATES) {
          for (const assetMode of profile.assetModes) {
            expectedCells.push({ tier, difficulty, cache, assetMode });
          }
        }
      }
    }
    // The full-matrix guard works on the per-mode result-row keys:
    // expectedCells carry assetMode and the lookup uses resultRowKey,
    // so tier:difficulty:cache:inline and :files are distinct rows and
    // deleting one while the other survives is always detected. An
    // aggregate three-part row never satisfies a per-mode cell.
    const missingCellsFull = expectedCells.filter((c) => !recordedKeys.has(resultRowKey(c)));
    if (missingCellsFull.length) {
      reasons.push(`${missingCellsFull.length} cells of the full default matrix missing (e.g. ${missingCellsFull.slice(0, 5).map(resultRowKey).join(', ')}); a schema-3 baseline must cover every tier x difficulty x cold/warm x asset cell (per-mode rows, keyed tier:difficulty:cache:assetMode)`);
    }
    const options = payload.options || {};
    if (!(options.reps >= shaRepsDefault)) {
      reasons.push(`SHA reps ${JSON.stringify(options.reps)} below the harness default ${shaRepsDefault}`);
    }
    if (!(options.argonReps >= argonRepsDefault)) {
      reasons.push(`Argon reps ${JSON.stringify(options.argonReps)} below the harness default ${argonRepsDefault}`);
    }
    if (options.argonMKib !== 16384) {
      reasons.push(`argon envelope ${JSON.stringify(options.argonMKib)} KiB is not the real ladder 16384`);
    }
    if (options.argonBits !== 8) {
      reasons.push(`argon target ${JSON.stringify(options.argonBits)} is not the real ladder 8`);
    }
    if (options.cache !== 'both') {
      reasons.push(`cache option ${JSON.stringify(options.cache)} is not 'both'`);
    }
    if (options.assets !== 'both') {
      reasons.push(`assets option ${JSON.stringify(options.assets)} is not 'both'`);
    }
  }

  // ── Qualification gate. CI mode prints the status; release mode
  // refuses to certify unless the qualification is physical. ─────────
  const qual = budgets.qualification || {};
  const status = qual.status;
  const physicalCount = physicalDevices.length;
  const statusLine =
    status === 'physical'
      ? `performance qualification status=physical (qualified_at ${qual.qualified_at || 'unset'}, ${Array.isArray(qual.devices) ? qual.devices.length : 0} device(s) recorded, ${physicalCount} physical device(s) on release tiers ${(Array.isArray(qual.release_tiers) ? qual.release_tiers : []).join('+') || '(none)'})`
      : `performance qualification status=${status} — physical-device data required before release certification`;
  if (releaseMode) {
    if (status !== 'physical') {
      reasons.push(`qualification status ${JSON.stringify(status)} is not "physical": release certification requires physical-device qualification data (qualified_at date and recorded devices), not lab-rig or emulation evidence`);
    }
  } else {
    console.log(statusLine);
  }

  if (reasons.length) {
    process.stderr.write(`validate-release-baseline: REJECTED ${baselinePath}\n`);
    for (const r of reasons) process.stderr.write(`  - ${r}\n`);
    for (const n of notes) process.stderr.write(`  note: ${n}\n`);
    process.exit(1);
  }
  if (releaseMode) console.log(statusLine);
  console.log(`validate-release-baseline: PASS ${baselinePath} (schema ${JSON.stringify(payload.schema) || 'none'}, generated ${payload.generated_at}, ${requiredCells.length} release-required cells, budgets ${budgetsPath}${physicalClaim ? ', physical claim: per-device evidence on release tiers ' + (releaseTiers.join('+') || '(none)') : ''}${releaseMode ? ', release mode' : ''})`);
  for (const n of notes) console.log(`  note: ${n}`);
  process.exit(0);
}

main();
