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
 */
import { readFileSync } from 'node:fs';

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
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === '--run') runs.push(args[++i]);
  else if (args[i] === '--tier') tier = args[++i];
  else if (args[i] === '--difficulties') difficulties.push(...args[++i].split(','));
  else if (args[i] === '--help') {
    console.log('usage: node merge-cells.mjs --run FILE [--run FILE] --tier TIER [--difficulties a,b,c]');
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

const perRunRows = [];
for (const runPath of runs) {
  const payload = JSON.parse(readFileSync(runPath, 'utf8'));
  const results = payload.results || {};
  for (const [key, agg] of Object.entries(results)) {
    if (key.startsWith('multi-widget')) continue;
    const parts = key.split(':');
    if (parts.length !== 4) continue;
    const [rowTier, difficulty, cache] = parts;
    if (rowTier !== tier) continue;
    if (difficulties.length && !difficulties.includes(difficulty)) continue;
    perRunRows.push({ difficulty, cache, agg, run: payload.generated_at, schema: payload.schema });
  }
}

const merged = new Map();
for (const { difficulty, cache, agg } of perRunRows) {
  const mapKey = `${difficulty}:${cache}`;
  if (!merged.has(mapKey)) merged.set(mapKey, []);
  merged.get(mapKey).push(agg);
}

const out = [];
for (const [mapKey, aggs] of [...merged.entries()].sort()) {
  const [difficulty, cache] = mapKey.split(':');
  const reps = aggs.flatMap((a) => a.reps || []);
  const base = { ...aggs[0] };
  delete base.assets;
  const row = {
    tier,
    difficulty,
    cache,
    reps,
  };
  for (const metric of SUMMARY_METRICS) {
    row[metric] = summarize(reps.map((s) => s[metric]).filter((v) => v !== null && v !== undefined));
  }
  row.longTaskCount = summarize(reps.map((s) => s.longTaskCount).filter((v) => v !== null));
  row.timedOutCount = reps.filter((s) => s.timedOut).length;
  row.errorCount = reps.filter((s) => s.errorCount > 0).length;
  out.push(row);
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
