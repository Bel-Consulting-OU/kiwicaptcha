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
 * sha256 } over the run's recorded harness identity — payload.harness
 * plus the recorded harness source sha256 — the recorded execution
 * manifest schema and maximum, the recorded solver configuration
 * (payload.options plus the always-applied fixed-work facts recorded in
 * payload.methodology.fixedWork), the run's recorded difficulty
 * definitions and the run's recorded clientAssets). The context is
 * BUILT FROM THE RUN'S RECORDED VALUES ONLY, never from the current
 * tree: a run that lacks a required recorded fact (no harness source
 * sha256, no options, no fixed-work envelope, no execution maximum, no
 * difficulty table, no clientAssets) is refused with the exact reason,
 * and a run whose recorded facts differ from the current release facts
 * is refused naming every differing field. The current tree is
 * consulted only for the comparison side and to verify the run's
 * recorded tier table entry by entry; when several --run files feed one
 * device, their recorded field sets must agree with each other as well,
 * or the later run is refused naming the disagreement. For an accepted
 * run the recorded field set equals the current release field set, so
 * the context the device is stamped with is the run's own context. The
 * emitted device evidence object then carries the one context shared by
 * its runs:
 *   { "physical_results": { "<device-id>": {
 *       "measurement_context": { "schema": ..., "sha256": ... },
 *       "source_runs": [ { "completion": "completed", "marker": ...,
 *         "measurement_sources_sha256": ..., "generated_at": ...,
 *         "run_digest": ... } ],
 *       "<tier>:<difficulty>:<cache>:<asset-mode>": <row> } } }
 * so the release validator can prove the device's evidence was
 * measured against the current bytes/configuration and can never be
 * silently re-bound to client bytes the device never measured, and so
 * the completion state of every contributing run survives row
 * extraction.
 *
 * Every consumed run must carry the clean completion marker (status
 * "completed" plus the harness marker); physical evidence additionally
 * requires fixture.mode "owned-snapshot" (the harness owned its server)
 * and harnessOrigin.mode "frozen-detached-worktree" (the committed
 * bytes were re-executed from a frozen worktree).
 */
import { readFileSync } from 'node:fs';
import { assertAssetSetCurrent, canonicalClientAssets } from './client-assets.mjs';
import { sha256Hex } from './canonical-json.mjs';
import {
  COMPLETION_MARKER,
  buildMeasurementContext,
  currentReleaseMeasurementFields,
  measurementFieldDifferences,
  readHarnessMeasurementFacts,
  recordedTierMismatches,
  runMeasurementFields,
} from './measurement-context.mjs';

/**
 * A run may only feed evidence when it cleanly completed every cell it
 * was configured to run (audit finding 2). The harness omits the
 * completion marker from a crashed, interrupted or contaminated run on
 * purpose; merge-cells has no completion check of its own on the
 * physical path, and once rows are extracted from an incomplete run
 * that state is gone. Focused recordings remain fine: a clean run over
 * a deliberately selected subset carries the marker. What can never
 * qualify is an incomplete execution, alone or combined with others
 * until coverage is satisfied.
 */
function completionReasons(payload, runPath) {
  const reasons = [];
  const completion = payload.completion || {};
  if (completion.status !== 'completed') {
    reasons.push(
      `${runPath} completion.status ${JSON.stringify(completion.status ?? null)} is not "completed": an interrupted, failed or contaminated execution can never feed evidence`,
    );
  }
  if (completion.marker !== COMPLETION_MARKER) {
    reasons.push(
      `${runPath} completion.marker ${JSON.stringify(completion.marker ?? null)} is not ${JSON.stringify(COMPLETION_MARKER)}`,
    );
  }
  return reasons;
}

/**
 * The certifiable-origin gates (audit findings 1 and 3): physical
 * evidence must come from a run that owned its fixture (an external
 * server can reinterpret /challenge and /verify while serving
 * byte-identical page and assets) and that executed the committed
 * bytes from a frozen detached worktree (an in-process run loaded
 * mutable source). Both are top-level, immutable payload fields.
 */
function certifiableOriginReasons(payload, runPath) {
  const reasons = [];
  const fixtureMode = payload.fixture && payload.fixture.mode;
  if (fixtureMode !== 'owned-snapshot') {
    reasons.push(
      `${runPath} fixture.mode ${JSON.stringify(fixtureMode ?? null)} is not "owned-snapshot": a run that attached to a server it does not own can be served a cheaper challenge under the recorded difficulty queries`,
    );
  }
  const originMode = payload.harnessOrigin && payload.harnessOrigin.mode;
  if (originMode !== 'frozen-detached-worktree') {
    reasons.push(
      `${runPath} harnessOrigin.mode ${JSON.stringify(originMode ?? null)} is not "frozen-detached-worktree": only a run re-executed from a frozen worktree of the committed bytes can feed physical evidence (use tools/client-perf/run-frozen.mjs)`,
    );
  }
  return reasons;
}

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
  let raw;
  try {
    raw = readFileSync(runPath, 'utf8');
    payload = JSON.parse(raw);
  } catch (e) {
    console.error(`merge-cells: cannot read run file ${runPath}: ${e.message}`);
    process.exit(1);
  }
  // The completion gate applies to every run any merge consumes
  // (audit finding 2): a partial, failed or contaminated execution is
  // not evidence in either the lab or the physical path.
  const completionProblems = completionReasons(payload, runPath);
  if (completionProblems.length) {
    throw new Error(
      `cannot merge performance runs measured against different client assets: an incomplete run cannot feed evidence\n${completionProblems.map((r) => `  - ${r}`).join('\n')}`,
    );
  }
  return { runPath, payload, raw };
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

// The legacy run-combination guard for the LAB merged mode (no device
// stamp): every run fed into one merged result must carry the same
// schema, Argon parameters, execution ceiling, difficulty table and
// asset mode. The --physical-index path below does not use this guard:
// it compares the runs' full recorded field sets (a superset of these
// fields) against each other and against the current release facts, so
// its refusal reasons are exact.
if (!physicalIndex) {
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
}

// ── Measurement-context binding (physical evidence) ─────────────────
// Every run that feeds a physical device index is bound from ITS OWN
// RECORDED FACTS: runMeasurementFields(payload) reads only the run file
// (harness path + recorded harness source sha256, schema, recorded
// execution manifest schema and maximum, recorded options and
// fixed-work envelope, recorded difficulty table, recorded client
// assets). The current tree is consulted only for the comparison side
// and for the per-entry tier check. A run that lacks a required
// recorded fact is refused with the exact reason; a run whose recorded
// facts differ from the current release facts is refused naming every
// differing field; and when several runs feed one device their recorded
// field sets must agree with each other or the later run is refused
// naming the disagreement. For an accepted run the recorded fields
// equal the current release fields, so the device is stamped with the
// run's own context — a run recorded under different bytes, harness,
// manifest, solver configuration or difficulty definitions can never be
// stamped with the current identity.
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
  let deviceFields = null;
  let firstRunPath = null;
  for (const { runPath, payload } of runPayloads) {
    // 0. The certifiable-origin gates (audit findings 1 and 3): physical
    // evidence requires the harness to have owned its fixture and to
    // have executed the committed bytes from a frozen detached
    // worktree. A run recorded against an external fixture or executed
    // in-process can never be stamped into the device index.
    const originProblems = certifiableOriginReasons(payload, runPath);
    if (originProblems.length) {
      throw new Error(
        `cannot use the run as physical evidence: its fixture/harness origin is not certifiable\n${originProblems.map((r) => `  - ${r}`).join('\n')}`,
      );
    }
    // 1. The run's own recorded facts. A missing or malformed recorded
    // fact refuses the run: the current tree is never substituted for
    // something the run did not record.
    const { fields, reasons: recordedReasons } = runMeasurementFields(payload);
    if (!fields) {
      throw new Error(
        `cannot merge performance runs measured against different client assets: ${runPath} cannot be bound to a release measurement context from its own recorded facts\n${recordedReasons.map((r) => `  - ${r}`).join('\n')}`
      );
    }
    // 2. Multiple runs feeding one device must record one context.
    if (deviceFields !== null) {
      const runDifferences = measurementFieldDifferences(fields, deviceFields);
      if (runDifferences.length) {
        throw new Error(
          `cannot merge performance runs measured against different client assets: ${runPath} recorded measurement facts disagree with those of ${firstRunPath} (every run feeding one device must share one measurement context)\n${runDifferences.map((r) => `  - ${r}`).join('\n')}`
        );
      }
    }
    // 3. Every recorded fact must equal the current release fact.
    const differences = measurementFieldDifferences(fields, currentFields);
    if (differences.length) {
      throw new Error(
        `cannot merge performance runs measured against different client assets: ${runPath} recorded measurement facts differ from the current release facts\n${differences.map((r) => `  - ${r}`).join('\n')}`
      );
    }
    // 4. The recorded tier table is verified entry by entry (a run
    // records only the tiers it executed), and every result row the
    // merge could emit must be defined by the run's recorded tables.
    const rowReasons = new Set();
    for (const key of Object.keys(payload.results || {})) {
      if (key.startsWith('multi-widget')) continue;
      const parts = key.split(':');
      if (parts.length !== 4) continue;
      const [rowTier, rowDifficulty] = parts;
      if (!Object.prototype.hasOwnProperty.call(payload.difficulties || {}, rowDifficulty)) {
        rowReasons.add(`run records rows for difficulty ${rowDifficulty} that its recorded difficulty table does not define`);
      }
      if (!Object.prototype.hasOwnProperty.call(payload.tiers || {}, rowTier)) {
        rowReasons.add(`run records rows for tier ${rowTier} that its recorded tier table does not define`);
      }
    }
    const tableReasons = [...recordedTierMismatches(payload.tiers, facts.tiers), ...rowReasons];
    if (tableReasons.length) {
      throw new Error(
        `cannot merge performance runs measured against different client assets: ${runPath} recorded tier definitions or rows do not match the current harness definitions\n${tableReasons.map((r) => `  - ${r}`).join('\n')}`
      );
    }
    if (deviceFields === null) {
      firstRunPath = runPath;
      deviceFields = fields;
    }
    deviceMeasurementContext = buildMeasurementContext(fields);
  }
  // For an accepted run every recorded fact equals the current release
  // fact, so the run-derived context must equal the current release
  // context. A divergence here is an internal error, never a stamp.
  if (deviceMeasurementContext.sha256 !== currentContext.sha256) {
    console.error(
      `merge-cells: internal error: run-derived measurement context ${deviceMeasurementContext.sha256} is not the current release measurement context ${currentContext.sha256}`
    );
    process.exit(1);
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
  // harness, manifest and solver configuration they measured. It then
  // records one source_runs entry per contributing run (audit finding
  // 2): the clean completion state survives row extraction, so a run
  // that was interrupted, failed or contaminated can never be smuggled
  // in after the fact by editing the derived rows.
  const sourceRuns = runPayloads.map(({ payload, raw }) => ({
    completion: (payload.completion || {}).status ?? null,
    marker: (payload.completion || {}).marker ?? null,
    measurement_sources_sha256: (payload.measurementSources || {}).sha256 ?? null,
    generated_at: payload.generated_at ?? null,
    run_digest: sha256Hex(raw),
  }));
  const index = { measurement_context: deviceMeasurementContext, source_runs: sourceRuns };
  for (const [indexKey, aggs] of [...indexed.entries()].sort()) {
    const [difficulty, cache, mode] = indexKey.split(':');
    index[`${tier}:${difficulty}:${cache}:${mode}`] = buildRow(difficulty, cache, aggs, mode);
  }
  console.log(JSON.stringify({ physical_results: { [deviceId]: index } }, null, 2));
} else {
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
}
