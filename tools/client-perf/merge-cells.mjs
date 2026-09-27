#!/usr/bin/env node
/**
 * Audit-6 maintenance helper: build the mode-merged mainstream-desktop
 * rows and the budget numbers for the client-performance release gate.
 *
 * The committed tools/client-perf/results/baseline.json is the legacy
 * schema-1 store (one row per tier:difficulty:cache, asset modes
 * folded). This script merges the per-asset-mode rows of a schema-3
 * run (the 2026-09-03 desktop recording plus the focused 2026-09-04
 * rsw/inline-execution run) into that legacy row shape, recomputing
 * every summary statistic over the concatenated repetitions exactly
 * like the harness summarize() does, and emits:
 *   - the merged rows (stdout, JSON),
 *   - the budget numbers: ceil(1.2 * merged p95) per metric,
 * so the release-budgets.json rows and the baseline rows stay derived
 * from the same measurements.
 *
 * Usage:
 *   node tools/client-perf/merge-cells.mjs \
 *     --run results/run-2026-09-03.json [--run results/results-2026-09-04.json]
 *     --tier mainstream-desktop [--difficulties sha16,...]
 *
 * Physical-evidence plumbing (release-budgets schema 2): when the
 * merged rows will back a qualification.devices entry, stamp them with
 *   --source physical --device-id <id from qualification.devices>
 * Every emitted merged row then carries row.source and row.device_id,
 * the provenance the release validator proves on release-tier cells.
 * Both flags must be given together; without them the rows are
 * emitted exactly as before (unattributed lab evidence).
 *
 * Device-index plumbing (round 4): the release validator proves a
 * physical claim from the baseline payload's per-device evidence
 * index, payload.physical_results = { "<device-id>": {
 * "<tier>:<difficulty>:<cache>:<asset-mode>": <row> } }, and the
 * release invariant demands per-mode evidence rows PER DEVICE (a
 * merged row folds the asset modes and can never prove per-mode
 * coverage). Emit that index with:
 *   --physical-index --source physical --device-id <id> [--tier ...]
 * which routes every per-mode row of the run(s) into the device
 * index WITHOUT folding asset modes together:
 *   node tools/client-perf/merge-cells.mjs --physical-index \
 *     --source physical --device-id pixel-9-mainstream-01 \
 *     --tier mainstream-desktop \
 *     --run results/physical-pixel9-run.json
 * prints { "physical_results": { "pixel-9-mainstream-01": { ... } } },
 * the fragment to merge into the baseline payload next to results.
 * Multiple --run files for the same device are merged per
 * (difficulty, cache, asset mode): repetitions concatenate and every
 * summary statistic is recomputed over the concatenation, exactly
 * like the legacy merge. The budget numbers are still derived in the
 * default merged mode (one device's merged rows at a time; the
 * release file's budget rows must cover the slowest qualified device,
 * which the validator checks against this index).
 *
 * Run-combination guard (audit finding 2, asset bind): before any
 * repetition is concatenated, every --run file must have been
 * measured against the SAME measurement context:
 *
 *   - the canonical client asset set: each run's recorded
 *     clientAssets block must name exactly the current canonical
 *     release asset set (packages/kiwicaptcha-wasm/release-assets.txt)
 *     with per-asset bytes and full sha256 equal to the current tree
 *     (the canonicalClientAssets/assertAssetSetCurrent checks of the
 *     shared client-assets module — a run recorded against other
 *     bytes is refused),
 *   - the harness schema,
 *   - the Argon parameters (options.argonBits / options.argonMKib),
 *   - the execution maximum (options.executionMaxVersion, the
 *     execution-version ceiling the run's interpreter/profile was
 *     measured against; absent on pre-versioned payloads),
 *   - the difficulty definitions (payload.difficulties),
 *   - the asset mode (options.assets).
 *
 * Any difference throws 'cannot merge performance runs measured
 * against different client assets' with the naming detail: merging
 * repetitions recorded against different bytes, ladders or grammar
 * versions would fabricate a percentile over incomparable
 * measurements.
 *
 * Measurement-context binding (physical qualification): every
 * --physical-index run is additionally bound to the release measurement
 * context the shared measurement-context module defines ({ schema,
 * sha256 } over the canonical clientAssets set, the harness schema and
 * source hash, the execution manifest maximum, the solver configuration
 * actually used — reps/argonReps/cache/assets/argonBits/argonMKib plus
 * the always-applied fixed-work options — and the harness difficulty
 * definitions). The context is BUILT FROM THE RUN'S RECORDED VALUES
 * (run.clientAssets, run.schema, run.options, the run-recorded
 * execution maximum and difficulty definitions), never from the current
 * tree; a run whose recorded values are not the current release
 * context, or whose recorded difficulty definitions disagree with the
 * current harness constants, is refused with the naming detail. The
 * emitted device evidence object then carries the one context shared by
 * its runs:
 *   { "physical_results": { "<device-id>": {
 *       "measurement_context": { "schema": ..., "sha256": ... },
 *       "<tier>:<difficulty>:<cache>:<asset-mode>": <row> } } }
 * so the release validator can prove the device's evidence was
 * measured against the current bytes/configuration and can never be
 * silently re-bound to client bytes the device never measured.
 */
import { readFileSync } from 'node:fs';
import { assertAssetSetCurrent, canonicalClientAssets } from './client-assets.mjs';
import {
  buildMeasurementContext,
  canonicalJson,
  currentReleaseMeasurementFields,
  readHarnessMeasurementFacts,
  recordedDifficultyMismatches,
  runMeasurementFields,
} from './measurement-context.mjs';

function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

function summarize(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    count: sorted.length,
    min: sorted.length ? sorted[0] : null,
    max: sorted.length ? sorted[sorted.length - 1] : null,
    mean: sorted.length ? sorted.reduce((a, b) => a + b, 0) / sorted.length : null,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
  };
}

const args = process.argv.slice(2);
const runs = [];
const difficulties = [];
let tier = null;
let source = null;
let deviceId = null;
let physicalIndex = false;
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === '--run') runs.push(args[++i]);
  else if (args[i] === '--tier') tier = args[++i];
  else if (args[i] === '--difficulties') difficulties.push(...args[++i].split(','));
  else if (args[i] === '--source') source = args[++i];
  else if (args[i] === '--device-id') deviceId = args[++i];
  else if (args[i] === '--physical-index') physicalIndex = true;
  else if (args[i] === '--help') {
    console.log('usage: node merge-cells.mjs --run FILE [--run FILE] --tier TIER [--difficulties a,b,c] [--source lab|physical --device-id ID] [--physical-index]');
    process.exit(0);
  } else {
    console.error(`unknown option: ${args[i]}`);
    process.exit(2);
  }
}
if (!runs.length || !tier) {
  console.error('merge-cells: --run and --tier are required');
  process.exit(2);
}
if ((source === null) !== (deviceId === null)) {
  console.error('merge-cells: --source and --device-id must be given together (the provenance pair of a merged row)');
  process.exit(2);
}
if (physicalIndex && (source === null || source !== 'physical')) {
  console.error('merge-cells: --physical-index routes per-device physical evidence and requires --source physical --device-id <id>');
  process.exit(2);
}
if (source !== null && source !== 'lab' && source !== 'physical') {
  console.error(`merge-cells: --source ${source} is not one of lab|physical`);
  process.exit(2);
}

const SUMMARY_METRICS = [
  'solveMs', 'pureSolveMs', 'pageToVerifiedMs', 'bootstrapToConnectingMs',
  'jsParseCompileMs', 'inlineScriptEvalMs', 'wasmCompileMs', 'wasmInstantiateMs',
  'workerStartupMs', 'longTaskTotalMs', 'longTaskMaxMs', 'peakHeapMb',
  'domContentLoadedMs', 'loadMs', 'transferredBytes', 'cacheHitCount',
  'resourceCount', 'runtimeLazyFetchStartMs', 'runtimeLazyFetchDurationMs',
  'driverFetchStartMs', 'driverFetchDurationMs', 'executionFetchStartMs',
  'executionFetchDurationMs', 'shaHashesPerSec', 'shaFixedWorkMs',
  'argonDerivationsPerSec', 'argonFixedWorkMs',
];

// ── Run-combination guard (audit finding 2, asset bind) ─────────────
// Every --run payload is loaded once and checked before any repetition
// is concatenated: canonical client asset equality (each run measured
// against the current release asset bytes), identical harness schema,
// Argon parameters, execution maximum, difficulty definitions and
// asset mode. Any difference throws the audit's refusal naming the
// run and the field.
const runPayloads = runs.map((runPath) => {
  let payload;
  try {
    payload = JSON.parse(readFileSync(runPath, 'utf8'));
  } catch (e) {
    console.error(`merge-cells: cannot read run file ${runPath}: ${e.message}`);
    process.exit(1);
  }
  return { runPath, payload };
});

const currentAssets = canonicalClientAssets();
for (const { runPath, payload } of runPayloads) {
  const reasons = [];
  assertAssetSetCurrent(payload.clientAssets, currentAssets, reasons);
  if (reasons.length) {
    const detail = reasons.map((r) => `  - ${r}`).join('\n');
    throw new Error(
      `cannot merge performance runs measured against different client assets: ${runPath} was not measured against the current canonical client asset set\n${detail}`
    );
  }
}

const firstPayload = runPayloads[0].payload;
const contextFields = [
  ['harness schema', (p) => p.schema],
  ['Argon bits', (p) => (p.options || {}).argonBits],
  ['Argon memory KiB', (p) => (p.options || {}).argonMKib],
  ['execution maximum version', (p) => (p.options || {}).executionMaxVersion],
  ['difficulty definitions', (p) => JSON.stringify(p.difficulties || null)],
  ['asset mode', (p) => (p.options || {}).assets],
];
const mergeContextValues = new Map(
  contextFields.map(([label, pick]) => [label, pick(firstPayload)]),
);
for (const { runPath, payload } of runPayloads.slice(1)) {
  for (const [label, pick] of contextFields) {
    const a = mergeContextValues.get(label);
    const b = pick(payload);
    if (JSON.stringify(a) !== JSON.stringify(b)) {
      throw new Error(
        `cannot merge performance runs measured against different client assets: ${runPath} ${label} ${JSON.stringify(b)} differs from ${JSON.stringify(a)} of ${runPayloads[0].runPath}`
      );
    }
  }
}

// ── Measurement-context binding (physical evidence) ─────────────────
// Every run that feeds a physical device index must carry the CURRENT
// release measurement context. The context is built FROM THE RUN'S
// RECORDED VALUES — clientAssets, schema, options, the recorded
// execution maximum and the run's recorded difficulty definitions —
// never from the current tree; the shared builder then compares that
// run-derived sha256 with the current release context, and a mismatch
// is refused naming the run and the differing component. A run can
// therefore never be stamped with a fresh identity it was not measured
// against, and the emitted device evidence object carries the one
// context its rows were recorded under. The recorded difficulty
// definitions must also still equal the current harness constants: a
// run recorded under different definitions would otherwise be
// re-labelled by the merge.
let deviceMeasurementContext = null;
if (physicalIndex) {
  let facts;
  let currentFields;
  let currentContext;
  try {
    facts = readHarnessMeasurementFacts();
    currentFields = currentReleaseMeasurementFields(facts);
    currentContext = buildMeasurementContext(currentFields);
  } catch (e) {
    console.error(`merge-cells: cannot build the current release measurement context: ${e.message}`);
    process.exit(1);
  }
  for (const { runPath, payload } of runPayloads) {
    let fields;
    try {
      fields = runMeasurementFields(payload, facts);
    } catch (e) {
      throw new Error(
        `cannot merge performance runs measured against different client assets: ${runPath} cannot be bound to a release measurement context (${e.message})`
      );
    }
    const difficultyMismatches = recordedDifficultyMismatches(payload, facts);
    if (difficultyMismatches.length) {
      const detail = difficultyMismatches.map((r) => `  - ${r}`).join('\n');
      throw new Error(
        `cannot merge performance runs measured against different client assets: ${runPath} recorded difficulty definitions do not match the current harness constants\n${detail}`
      );
    }
    const context = buildMeasurementContext(fields);
    if (context.sha256 !== currentContext.sha256) {
      const differing = ['harness', 'execution', 'solver', 'difficulties', 'clientAssets'].filter(
        (component) => canonicalJson(fields[component]) !== canonicalJson(currentFields[component])
      );
      throw new Error(
        `cannot merge performance runs measured against different client assets: ${runPath} measurement context ${context.sha256} is not the current release measurement context ${currentContext.sha256}${differing.length ? ` (differing component(s): ${differing.join(', ')})` : ''}`
      );
    }
    if (deviceMeasurementContext && context.sha256 !== deviceMeasurementContext.sha256) {
      throw new Error(
        `cannot merge performance runs measured against different client assets: ${runPath} measurement context ${context.sha256} differs from ${deviceMeasurementContext.sha256} of an earlier run`
      );
    }
    deviceMeasurementContext = context;
  }
}

const perRunRows = [];
for (const { payload } of runPayloads) {
  const results = payload.results || {};
  for (const [key, agg] of Object.entries(results)) {
    if (key.startsWith('multi-widget')) continue;
    const parts = key.split(':');
    if (parts.length !== 4) continue;
    const [rowTier, difficulty, cache] = parts;
    if (rowTier !== tier) continue;
    if (difficulties.length && !difficulties.includes(difficulty)) continue;
    // The physical index keeps the asset mode as its own dimension
    // (the release invariant is per-device x per-mode); the legacy
    // merged shape folds the modes.
    const mode = parts[3];
    perRunRows.push({ difficulty, cache, mode, agg, run: payload.generated_at, schema: payload.schema });
  }
}

const merged = new Map();
const indexed = new Map();
for (const { difficulty, cache, mode, agg } of perRunRows) {
  const mapKey = `${difficulty}:${cache}`;
  if (!merged.has(mapKey)) merged.set(mapKey, []);
  merged.get(mapKey).push(agg);
  if (physicalIndex) {
    const indexKey = `${difficulty}:${cache}:${mode}`;
    if (!indexed.has(indexKey)) indexed.set(indexKey, []);
    indexed.get(indexKey).push(agg);
  }
}

const buildRow = (difficulty, cache, aggs, mode) => {
  const reps = aggs.flatMap((a) => a.reps || []);
  const row = {
    tier,
    difficulty,
    cache,
    reps,
  };
  // The release validator requires every execution row to carry the
  // program version byte its repetitions decoded from the armed
  // challenge responses. The run records it per repetition; the row
  // carries it only when every versioned repetition agrees (a
  // disagreement is omitted so the validator rejects instead of
  // fabricating a version).
  if (difficulty.startsWith('exec')) {
    const versions = new Set(
      reps
        .map((s) => s.executionVersion)
        .filter((v) => v !== null && v !== undefined),
    );
    if (versions.size === 1) row.executionVersion = [...versions][0];
  }
  if (mode !== null) row.assets = mode;
  if (source !== null) {
    row.source = source;
    row.device_id = deviceId;
  }
  for (const metric of SUMMARY_METRICS) {
    row[metric] = summarize(reps.map((s) => s[metric]).filter((v) => v !== null && v !== undefined));
  }
  row.longTaskCount = summarize(reps.map((s) => s.longTaskCount).filter((v) => v !== null));
  row.timedOutCount = reps.filter((s) => s.timedOut).length;
  row.errorCount = reps.filter((s) => s.errorCount > 0).length;
  return row;
};

const out = [];
for (const [mapKey, aggs] of [...merged.entries()].sort()) {
  const [difficulty, cache] = mapKey.split(':');
  out.push(buildRow(difficulty, cache, aggs, null));
}

if (physicalIndex) {
  // Per-device per-mode evidence index: rows keyed
  // tier:difficulty:cache:assetMode, never folded across modes. The
  // device evidence object opens with measurement_context: the release
  // measurement context ALL of its runs were recorded against (proved
  // equal to the current release context above), so the release
  // validator can bind this device's rows to the exact client bytes,
  // harness, manifest and solver configuration they measured.
  const index = { measurement_context: deviceMeasurementContext };
  for (const [indexKey, aggs] of [...indexed.entries()].sort()) {
    const [difficulty, cache, mode] = indexKey.split(':');
    index[`${tier}:${difficulty}:${cache}:${mode}`] = buildRow(difficulty, cache, aggs, mode);
  }
  console.log(JSON.stringify({ physical_results: { [deviceId]: index } }, null, 2));
  process.exit(0);
}

const budget = {};
for (const row of out) {
  const key = `${row.difficulty}:${row.cache}`;
  budget[key] = {
    n: row.reps.length,
    solveMsP95: row.solveMs && row.solveMs.p95 !== null ? Math.ceil(row.solveMs.p95 * 1.2) : null,
    pageToVerifiedMsP95: row.pageToVerifiedMs && row.pageToVerifiedMs.p95 !== null ? Math.ceil(row.pageToVerifiedMs.p95 * 1.2) : null,
    measuredSolveMsP95: row.solveMs && row.solveMs.p95 !== null ? Math.round(row.solveMs.p95 * 10) / 10 : null,
    measuredPageToVerifiedMsP95: row.pageToVerifiedMs && row.pageToVerifiedMs.p95 !== null ? Math.round(row.pageToVerifiedMs.p95 * 10) / 10 : null,
    errors: row.errorCount,
    timedOut: row.timedOutCount,
  };
}

console.log(JSON.stringify({ mergedRows: out, budget }, null, 2));
