#!/usr/bin/env node
/**
 * Release-baseline validator for the client-performance evidence
 * (tools/client-perf).
 *
 * Usage:
 *   node tools/ci/validate-release-baseline.mjs <baseline.json> [<release-budgets.json>]
 *
 * The baseline argument is a results payload produced by
 * tools/client-perf/client-perf.mjs (schema kiwicaptcha.client-perf/3,
 * the current harness schema). The budgets argument defaults to
 * tools/client-perf/release-budgets.json next to the harness.
 *
 * The validator is the machine-enforced release qualification for the
 * client-performance evidence. A release that touches the widget, the
 * solver or the difficulty ladder must pass it against the promoted
 * baseline (tools/client-perf/results/baseline.json) before cutting.
 * It rejects the file, with every reason printed, unless all of
 * these hold:
 *
 *   1. schema equals the harness's current schema string (read from
 *      client-perf.mjs at run time, never duplicated here).
 *   2. the completion marker is present with status "completed" (the
 *      marker name is read from client-perf.mjs; a partial or
 *      interrupted run is never a release baseline).
 *   3. the environment carries browser/OS/hardware identity
 *      (chromium + environment.os/machine/cpus).
 *   4. every device tier the harness defines is present.
 *   5. the full default matrix is covered: every (tier, difficulty,
 *      cold|warm, asset mode) cell the harness defines — including
 *      the files and inline execution cells — exists in results.
 *   6. sample counts meet the harness defaults (>= 50 for SHA-profile
 *      cells, >= 20 for Argon-profile cells; the counts are read from
 *      client-perf.mjs, and the options-level reps are checked too).
 *   7. the record is no older than release-budgets.json
 *      recordAgeDays (default 90 days): an old recording cannot
 *      qualify a current release.
 *   8. every measured cell's p95 stays under the matching
 *      release-budgets.json budget row (solveMsP95 and
 *      pageToVerifiedMsP95, per tier/difficulty/cache; the execution
 *      cells carry no budget rows yet and are reported as
 *      budget-uncovered, never silently skipped).
 *   9. the per-cell failure rate (timed-out + errored samples over
 *      the cell's sample count) stays under release-budgets.json
 *      maxCellFailureRate (default 2%).
 *
 * The budget file is validated against the same harness-derived
 * constants first: schema, tier list, difficulty list, sample minima
 * and the complete sha16/sha18/sha20/argon2id x cold/warm budget grid
 * must all be present. A drifted budget authority fails loudly
 * instead of gate-keeping with stale numbers.
 *
 * Exit status: 0 on a clean pass, 1 on any rejection. Every reason is
 * written to stderr with the offending keys and values; the pass
 * summary goes to stdout. Runnable standalone (no harness install
 * needed beyond node); intended to be wired into the release
 * workflow as a gate against the promoted baseline.
 */
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const HARNESS_FILE = join(REPO_ROOT, 'tools', 'client-perf', 'client-perf.mjs');
const DEFAULT_BUDGETS = join(REPO_ROOT, 'tools', 'client-perf', 'release-budgets.json');

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
  let i = 0;
  while (i < source.length) {
    const entryStart = source.indexOf('\n  ' + names[0] + ': {', i);
    break;
  }
  void i;
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

function main() {
  const argv = process.argv.slice(2);
  if (argv.length < 1 || argv[0] === '--help' || argv[0] === '-h') {
    process.stderr.write('usage: node tools/ci/validate-release-baseline.mjs <baseline.json> [<release-budgets.json>]\n');
    process.exit(argv.length ? 0 : 1);
  }
  const baselinePath = argv[0];
  const budgetsPath = argv[1] ?? DEFAULT_BUDGETS;

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

  // The budget authority must agree with the harness first.
  if (budgets.schema !== 'kiwicaptcha.release-budgets/1') {
    reasons.push(`budget file ${budgetsPath}: schema ${JSON.stringify(budgets.schema)} is not kiwicaptcha.release-budgets/1`);
  }
  const budgetTiers = Array.isArray(budgets.tiers) ? budgets.tiers : [];
  const missingBudgetTiers = tierNames.filter((t) => !budgetTiers.includes(t));
  if (missingBudgetTiers.length) {
    reasons.push(`budget file ${budgetsPath}: missing tier rows for ${missingBudgetTiers.join(', ')}`);
  }
  if (budgets.minShaReps !== shaRepsDefault) {
    reasons.push(`budget file ${budgetsPath}: minShaReps ${budgets.minShaReps} differs from the harness default ${shaRepsDefault}`);
  }
  if (budgets.minArgonReps !== argonRepsDefault) {
    reasons.push(`budget file ${budgetsPath}: minArgonReps ${budgets.minArgonReps} differs from the harness default ${argonRepsDefault}`);
  }
  const budgetDifficulties = ['sha16', 'sha18', 'sha20', 'argon2id'];
  for (const tier of tierNames) {
    const tierBudget = (budgets.budgets || {})[tier];
    if (!tierBudget) continue;
    for (const difficulty of budgetDifficulties) {
      for (const cache of ['cold', 'warm']) {
        const b = (tierBudget[difficulty] || {})[cache];
        if (!b || !(b.solveMsP95 > 0) || !(b.pageToVerifiedMsP95 > 0)) {
          reasons.push(`budget file ${budgetsPath}: missing or non-positive ${tier}/${difficulty}/${cache} budget row (need solveMsP95 + pageToVerifiedMsP95)`);
        }
      }
    }
  }

  // 1. schema.
  if (payload.schema !== schema) {
    reasons.push(`schema ${JSON.stringify(payload.schema)} is not the current harness schema ${schema} (a legacy or foreign recording cannot qualify a release)`);
  }

  // 2. completion marker.
  const completion = payload.completion || {};
  if (completion.status !== 'completed' || completion.marker !== completionMarker) {
    reasons.push(`completion ${JSON.stringify(completion)} is not status "completed" with marker ${completionMarker} (the incomplete-run guard: a partial or interrupted run is never a release baseline)`);
  }

  // 3. environment identity.
  const env = payload.environment || {};
  const identityMissing = [];
  if (!env.os) identityMissing.push('environment.os');
  if (!env.machine) identityMissing.push('environment.machine');
  if (!env.cpus) identityMissing.push('environment.cpus');
  if (!payload.chromium) identityMissing.push('chromium');
  if (identityMissing.length) {
    reasons.push(`environment lacks browser/OS/hardware identity: missing ${identityMissing.join(', ')} (a release baseline must name the machine and browser it was measured on)`);
  }

  // 4. tiers.
  const recordedTiers = payload.tiers ? Object.keys(payload.tiers) : [];
  const missingTiers = tierNames.filter((t) => !recordedTiers.includes(t));
  if (missingTiers.length) {
    reasons.push(`device tiers missing from the payload: ${missingTiers.join(', ')} (all ${tierNames.length} harness tiers are required)`);
  }

  // 5. full matrix coverage, 6. per-cell sample counts, 9. failure rate.
  const results = payload.results || {};
  const recordedKeys = new Set(Object.keys(results).filter((k) => !k.startsWith('multi-widget')));
  const expectedCells = [];
  for (const tier of tierNames) {
    for (const [difficulty, profile] of Object.entries(difficultyProfiles)) {
      for (const cache of ['cold', 'warm']) {
        for (const assetMode of profile.assetModes) {
          expectedCells.push({ tier, difficulty, cache, assetMode, isArgon: profile.isArgon });
        }
      }
    }
  }
  const missingCells = expectedCells.filter((c) => !recordedKeys.has(cellKey(c)));
  if (missingCells.length) {
    reasons.push(`${missingCells.length} cells of the full default matrix missing (e.g. ${missingCells.slice(0, 5).map(cellKey).join(', ')}); a release baseline must cover every tier x difficulty x cold/warm x asset cell`);
  }

  const options = payload.options || {};
  if (!(options.reps >= shaRepsDefault)) {
    reasons.push(`SHA reps ${JSON.stringify(options.reps)} below the harness default ${shaRepsDefault}`);
  }
  if (!(options.argonReps >= argonRepsDefault)) {
    reasons.push(`Argon reps ${JSON.stringify(options.argonReps)} below the harness default ${argonRepsDefault}`);
  }

  const failureRateBudget = typeof budgets.maxCellFailureRate === 'number' ? budgets.maxCellFailureRate : 0.02;
  const cellFailureViolations = [];
  const sampleViolations = [];
  for (const cell of expectedCells) {
    const agg = results[cellKey(cell)];
    if (!agg || !Array.isArray(agg.reps)) continue;
    const n = agg.reps.length;
    const min = cell.isArgon ? argonRepsDefault : shaRepsDefault;
    if (n < min) {
      sampleViolations.push(`${cellKey(cell)} has ${n} samples (need >= ${min})`);
    }
    const failed = (agg.timedOutCount || 0) + (agg.errorCount || 0);
    if (n > 0 && failed / n > failureRateBudget) {
      cellFailureViolations.push(`${cellKey(cell)} failure rate ${(failed / n * 100).toFixed(1)}% (${failed}/${n}) exceeds the ${(failureRateBudget * 100).toFixed(0)}% budget`);
    }
  }
  if (sampleViolations.length) {
    reasons.push(`${sampleViolations.length} cell(s) below the harness sample-count default (${sampleViolations.slice(0, 5).join('; ')}${sampleViolations.length > 5 ? '; ...' : ''})`);
  }
  if (cellFailureViolations.length) {
    reasons.push(`${cellFailureViolations.length} cell(s) over the failure-rate budget (${cellFailureViolations.slice(0, 5).join('; ')}${cellFailureViolations.length > 5 ? '; ...' : ''})`);
  }

  // 7. record age.
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

  // 8. p95 under the budgets.
  const budgetViolations = [];
  const uncovered = [];
  for (const cell of expectedCells) {
    const agg = results[cellKey(cell)];
    if (!agg) continue;
    if (['execvm', 'execsha18', 'execargon', 'execchain', 'execvminline', 'execsha18inline'].includes(cell.difficulty)) {
      uncovered.push(cellKey(cell));
      continue;
    }
    const row = ((budgets.budgets || {})[cell.tier] || {})[cell.difficulty] || {};
    const budget = row[cell.cache];
    if (!budget) {
      reasons.push(`no budget row for ${cellKey(cell)} (the budgets file must cover every sha/argon cell)`);
      continue;
    }
    for (const [metric, field] of [['solveMsP95', 'solveMs'], ['pageToVerifiedMsP95', 'pageToVerifiedMs']]) {
      const measured = agg[field] && typeof agg[field].p95 === 'number' ? agg[field].p95 : null;
      if (measured === null) {
        budgetViolations.push(`${cellKey(cell)} ${field}.p95 is not recorded`);
      } else if (measured > budget[metric]) {
        budgetViolations.push(`${cellKey(cell)} ${field}.p95 ${measured.toFixed(1)} ms exceeds the budget ${budget[metric]} ms`);
      }
    }
  }
  if (budgetViolations.length) {
    reasons.push(`${budgetViolations.length} p95 budget violation(s) (${budgetViolations.slice(0, 6).join('; ')}${budgetViolations.length > 6 ? '; ...' : ''})`);
  }
  if (uncovered.length) {
    notes.push(`${uncovered.length} execution cell(s) have no latency budget row yet (${uncovered.length} execution cells are required and sample-checked, but their p95 budgets arrive with the first physical-device qualification; see the release-budgets.json note)`);
  }

  if (reasons.length) {
    process.stderr.write(`validate-release-baseline: REJECTED ${baselinePath}\n`);
    for (const r of reasons) process.stderr.write(`  - ${r}\n`);
    for (const n of notes) process.stderr.write(`  note: ${n}\n`);
    process.exit(1);
  }
  console.log(`validate-release-baseline: PASS ${baselinePath} (schema ${schema}, generated ${payload.generated_at}, ${expectedCells.length} cells, ${tierNames.length} tiers, budgets ${budgetsPath})`);
  for (const n of notes) console.log(`  note: ${n}`);
  process.exit(0);
}

function cellKey(cell) {
  return `${cell.tier}:${cell.difficulty}:${cell.cache}:${cell.assetMode}`;
}

main();
