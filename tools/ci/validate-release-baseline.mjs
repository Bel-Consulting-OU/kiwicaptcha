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
 *   still bind.
 *
 *   Release mode (--release or RELEASE_PERFORMANCE=1) is the release
 *   certification gate. It refuses to certify a release unless
 *   qualification.status is "physical" (with a qualified_at date and
 *   recorded devices) AND, for a current-harness (schema 3) payload,
 *   the completed-run guards below hold. A lab-status gate therefore
 *   always fails a release: physical-device data is the release
 *   boundary, and nothing else can substitute for it.
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
 *      release-required cell.
 *   2. the budget authority carries a qualification block
 *      (status one of lab|physical, qualified_at null or ISO,
 *      harness_schema equal to the harness schema, devices array);
 *      a "physical" status without qualified_at or devices is a
 *      rejection, never a silent claim.
 *   3. every release-required cell (every mode x tier x cold/warm
 *      combination the budgets file requires) has a matching measured
 *      baseline row: coverage gaps are hard failures, counted and
 *      named.
 *   4. the measured p95 of every required cell (solveMs and
 *      pageToVerifiedMs, aggregated across the asset-mode rows the
 *      baseline records for the cell) stays under the matching budget
 *      row.
 *   5. the per-cell failure rate (timed-out + errored samples over the
 *      cell's sample count) stays under release-budgets.json
 *      maxCellFailureRate, and the sample count meets the budget file's
 *      minShaReps / minArgonReps floors (the floors are the lab
 *      evidence floors; the harness defaults exceed them).
 *   6. the record is no older than release-budgets.json recordAgeDays
 *      (default 90 days) and carries browser/OS/hardware identity.
 *   7. release mode only: qualification.status must be "physical";
 *      and a current-harness (schema 3) payload must additionally
 *      satisfy the completed-run guards: the completion marker,
 *      full default matrix coverage (every harness tier x difficulty
 *      x cold/warm x asset cell), default sample sizes, both cache
 *      and asset modes, and the real argon ladder (m=16384 KiB,
 *      target 8).
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

const BUDGETS_SCHEMA = 'kiwicaptcha.release-budgets/1';
const RELEASE_STATUSES = ['lab', 'physical'];

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
    reasons.push(`budget file ${budgetsPath}: missing top-level qualification object (status, qualified_at, harness_schema, devices)`);
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
  }

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
  // explicit positive p95 budget row.
  const budgetTiers = Array.isArray(budgets.tiers) ? budgets.tiers : [];
  if (budgetTiers.length === 0) {
    reasons.push(`budget file ${budgetsPath}: tiers list is empty (a release gate must name the tiers it qualifies)`);
  }
  const unknownBudgetTiers = budgetTiers.filter((t) => !tierNames.includes(t));
  if (unknownBudgetTiers.length) {
    reasons.push(`budget file ${budgetsPath}: unknown tier(s) ${unknownBudgetTiers.join(', ')} (not harness tiers)`);
  }
  const missingBudgetRows = [];
  for (const tier of budgetTiers) {
    const tierBudget = (budgets.budgets || {})[tier];
    if (!tierBudget) {
      for (const difficulty of budgetDifficulties) {
        for (const cache of ['cold', 'warm']) {
          missingBudgetRows.push(`${tier}/${difficulty}/${cache}`);
        }
      }
      continue;
    }
    for (const difficulty of budgetDifficulties) {
      for (const cache of ['cold', 'warm']) {
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
  // budgets file rows declare, for every asset mode the harness schema
  // attaches to that difficulty. The baseline rows that match a
  // required cell are aggregated (per-repetition samples concatenated
  // across the cell's mode rows) and the aggregate p95s are compared
  // with the budget row.
  const results = payload.results || {};
  const requiredCells = [];
  for (const tier of budgetTiers) {
    for (const difficulty of budgetDifficulties) {
      for (const cache of ['cold', 'warm']) {
        requiredCells.push({ tier, difficulty, cache, isArgon: !!difficultyProfiles[difficulty]?.isArgon });
      }
    }
  }

  const matchingRows = (cell) => {
    const prefix3 = `${cell.tier}:${cell.difficulty}:${cell.cache}`;
    const exact = results[prefix3];
    const modes = [];
    if (exact) modes.push({ key: prefix3, row: exact });
    for (const mode of difficultyProfiles[cell.difficulty]?.assetModes || []) {
      const key4 = `${prefix3}:${mode}`;
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
      missingCells.push(`${cell.tier}:${cell.difficulty}:${cell.cache}`);
      continue;
    }
    const n = cellReps(cell).length;
    const min = cell.isArgon ? minArgonReps : minShaReps;
    if (n > 0 && n < min) {
      lowSampleCells.push(`${cell.tier}:${cell.difficulty}:${cell.cache} has ${n} samples (need >= ${min})`);
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
    for (const [metric, field] of [['solveMsP95', 'solveMs'], ['pageToVerifiedMsP95', 'pageToVerifiedMs']]) {
      const measured = coverageField(cell, field);
      if (measured === null) {
        budgetViolations.push(`${cell.tier}:${cell.difficulty}:${cell.cache} ${field}.p95 is not recorded`);
      } else if (measured > budget[metric]) {
        budgetViolations.push(`${cell.tier}:${cell.difficulty}:${cell.cache} ${field}.p95 ${measured.toFixed(1)} ms exceeds the budget ${budget[metric]} ms`);
      }
    }
  }
  if (budgetViolations.length) {
    reasons.push(`${budgetViolations.length} p95 budget violation(s) (${budgetViolations.slice(0, 6).join('; ')}${budgetViolations.length > 6 ? '; ...' : ''})`);
  }

  // Failure rate over the aggregated samples of each required cell.
  const failureRateBudget = typeof budgets.maxCellFailureRate === 'number' ? budgets.maxCellFailureRate : 0.02;
  const cellFailureViolations = [];
  for (const cell of requiredCells) {
    const reps = cellReps(cell);
    if (reps.length === 0) continue;
    const failed = reps.filter((s) => s && ((s.timedOut && s.timedOut !== false) || s.errorCount > 0)).length;
    if (failed / reps.length > failureRateBudget) {
      cellFailureViolations.push(`${cell.tier}:${cell.difficulty}:${cell.cache} failure rate ${(failed / reps.length * 100).toFixed(1)}% (${failed}/${reps.length}) exceeds the ${(failureRateBudget * 100).toFixed(0)}% budget`);
    }
  }
  if (cellFailureViolations.length) {
    reasons.push(`${cellFailureViolations.length} cell(s) over the failure-rate budget (${cellFailureViolations.slice(0, 5).join('; ')}${cellFailureViolations.length > 5 ? '; ...' : ''})`);
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
        for (const cache of ['cold', 'warm']) {
          for (const assetMode of profile.assetModes) {
            expectedCells.push({ tier, difficulty, cache, assetMode });
          }
        }
      }
    }
    const missingCellsFull = expectedCells.filter((c) => !recordedKeys.has(cellKey(c)));
    if (missingCellsFull.length) {
      reasons.push(`${missingCellsFull.length} cells of the full default matrix missing (e.g. ${missingCellsFull.slice(0, 5).map(cellKey).join(', ')}); a schema-3 baseline must cover every tier x difficulty x cold/warm x asset cell`);
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
  const statusLine =
    status === 'physical'
      ? `performance qualification status=${status} (qualified_at ${qual.qualified_at || 'unset'}, ${Array.isArray(qual.devices) ? qual.devices.length : 0} device(s) recorded)`
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
  console.log(`validate-release-baseline: PASS ${baselinePath} (schema ${JSON.stringify(payload.schema) || 'none'}, generated ${payload.generated_at}, ${requiredCells.length} release-required cells, budgets ${budgetsPath}${releaseMode ? ', release mode' : ''})`);
  for (const n of notes) console.log(`  note: ${n}`);
  process.exit(0);
}

function cellKey(cell) {
  return `${cell.tier}:${cell.difficulty}:${cell.cache}:${cell.assetMode}`;
}

main();
