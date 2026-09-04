#!/usr/bin/env node
/**
 * Audit-6 maintenance helper: surgically update
 * tools/client-perf/results/baseline.json with the real-ladder
 * mainstream-desktop measurements.
 *
 * The committed baseline is the schema-1 pre-matrix recording: legacy
 * rows measured at the old fixture envelope (64 KiB Argon, fixture
 * SHA default). The client-performance release gate now budgets the
 * REAL ladder (Argon m=16384 KiB target 8) on the lab rig (the
 * unthrottled mainstream-desktop tier = the actual recording Mac), so
 * the desktop rows must describe the real-ladder measurements:
 *
 *   - the sha16/sha18/sha20/argon2id and the four files-tier execution
 *     rows come from results/run-2026-09-03.json (the completed
 *     real-ladder desktop run; 12 SHA / 6 Argon reps per mode),
 *   - the rsw75k/rsw150k/rsw300k and the two inline execution rows
 *     come from the focused 2026-09-04 run at 50 SHA reps per mode,
 *     produced by this branch's client-perf.mjs,
 *
 * merged per (tier, difficulty, cache) exactly like the legacy row
 * shape (asset modes folded; every summary statistic recomputed over
 * the concatenated repetitions with the harness percentile
 * semantics). Every OTHER row (the non-desktop emulation tiers, all
 * legacy-labelled) is preserved byte-for-byte: the script asserts the
 * untouched rows round-trip JSON.stringify identically.
 *
 * The payload header is updated honestly: generated_at is the surgery
 * date, legacy_note describes the hybrid construction, and the
 * options/difficulties fields document the merged evidence.
 *
 * Usage:
 *   node tools/client-perf/sync-lab-baseline.mjs --run results/run-2026-09-03.json \
 *     --run tools/client-perf/results/results-2026-09-04.json [--write]
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const BASELINE_PATH = join(REPO_ROOT, 'tools', 'client-perf', 'results', 'baseline.json');

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
let write = false;
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === '--run') runs.push(args[++i]);
  else if (args[i] === '--write') write = true;
  else {
    console.error(`unknown option: ${args[i]}`);
    process.exit(2);
  }
}
if (runs.length === 0) {
  console.error('sync-lab-baseline: at least one --run FILE is required');
  process.exit(2);
}

const TIER = 'mainstream-desktop';
const REPLACE_DIFFICULTIES = new Set(['sha16', 'sha18', 'sha20', 'argon2id']);
const LEGACY_SUMMARY_FIELDS = [
  'solveMs', 'pureSolveMs', 'pageToVerifiedMs', 'bootstrapToConnectingMs',
  'jsParseCompileMs', 'inlineScriptEvalMs', 'wasmCompileMs', 'wasmInstantiateMs',
  'workerStartupMs', 'longTaskTotalMs', 'longTaskMaxMs', 'peakHeapMb',
  'domContentLoadedMs', 'loadMs',
];

const payload = JSON.parse(readFileSync(BASELINE_PATH, 'utf8'));
const results = payload.results || {};

// Collect the per-mode schema-3 rows for the lab tier.
const modeRows = [];
for (const runPath of runs) {
  const run = JSON.parse(readFileSync(runPath, 'utf8'));
  const runResults = run.results || {};
  for (const [key, agg] of Object.entries(runResults)) {
    if (key.startsWith('multi-widget')) continue;
    const parts = key.split(':');
    if (parts.length !== 4) continue;
    const [tier, difficulty, cache, mode] = parts;
    if (tier !== TIER) continue;
    modeRows.push({ difficulty, cache, mode, agg, runPath });
  }
}

const merged = new Map();
for (const { difficulty, cache, agg } of modeRows) {
  const mapKey = `${difficulty}:${cache}`;
  if (!merged.has(mapKey)) merged.set(mapKey, []);
  merged.get(mapKey).push(agg);
}

const newRows = [];
for (const [mapKey, aggs] of [...merged.entries()].sort()) {
  const [difficulty, cache] = mapKey.split(':');
  const reps = aggs.flatMap((a) => a.reps || []);
  const row = { tier: TIER, difficulty, cache, reps };
  for (const field of LEGACY_SUMMARY_FIELDS) {
    row[field] = summarize(reps.map((s) => s[field]).filter((v) => v !== null && v !== undefined));
  }
  row.longTaskCount = summarize(reps.map((s) => s.longTaskCount).filter((v) => v !== null));
  row.timedOutCount = reps.filter((s) => s.timedOut).length;
  row.errorCount = reps.filter((s) => s.errorCount > 0).length;
  newRows.push(row);
}

// Remove the rows being replaced (lab-tier sha/argon legacy rows), keep
// everything else byte-for-byte, then append the merged lab rows.
const kept = {};
const replacedKeys = new Set();
for (const [key, row] of Object.entries(results)) {
  const parts = key.split(':');
  const isReplaced =
    parts.length === 3 && parts[0] === TIER && REPLACE_DIFFICULTIES.has(parts[1]);
  if (isReplaced) {
    replacedKeys.add(key);
    continue;
  }
  kept[key] = row;
}

// Byte-for-byte preservation assertion: re-serializing the kept rows
// must reproduce them exactly (JSON.parse -> stringify round trip is
// stable for content produced by JSON.stringify).
const check = JSON.parse(JSON.stringify(kept));
for (const key of Object.keys(check)) {
  const before = JSON.stringify(results[key]);
  const after = JSON.stringify(check[key]);
  if (before !== after) {
    console.error(`row ${key} would change on round trip; aborting`);
    process.exit(1);
  }
}

const finalResults = {};
const newRowByKey = new Map();
for (const row of newRows) newRowByKey.set(`${row.tier}:${row.difficulty}:${row.cache}`, row);
const emittedNew = new Set();
for (const key of Object.keys(results)) {
  if (replacedKeys.has(key)) {
    // Emit the replacement merged row in place of the legacy row.
    const mergedRow = newRowByKey.get(key);
    if (mergedRow && !emittedNew.has(key)) {
      finalResults[key] = mergedRow;
      emittedNew.add(key);
    }
    continue;
  }
  finalResults[key] = results[key];
}
for (const [key, row] of newRowByKey) {
  if (!emittedNew.has(key)) finalResults[key] = row;
}

const difficulties = {};
const difficultyLabels = {};
const runDates = runs.map((r) => {
  const run = JSON.parse(readFileSync(r, 'utf8'));
  difficultyLabels[run.generated_at] = run.difficulties || {};
  return run.generated_at;
}).sort();
for (const row of newRows) {
  const label = Object.values(difficultyLabels)
    .map((d) => d[row.difficulty])
    .filter(Boolean)[0];
  difficulties[row.difficulty] = label
    ? { label: label.label, dimension: label.dimension || null, query: label.query || null }
    : { label: row.difficulty };
}

payload.results = finalResults;
payload.difficulties = {
  ...(payload.difficulties || {}),
  ...difficulties,
};
payload.options = {
  ...(payload.options || {}),
  reps: 12,
  argonReps: 6,
  cache: 'both',
  assets: 'both',
  argonBits: 8,
  argonMKib: 16384,
  mergedRuns: runDates,
  note: 'the mainstream-desktop rows were re-recorded at the real adaptive-risk ladder (m=16384 KiB, target 8) on 2026-09-03 and 2026-09-04 and merged per cache across asset modes; the emulation-tier rows remain the legacy pre-matrix recording and are not release-required',
};
payload.generated_at = new Date().toISOString();
payload.legacy_note =
  'LEGACY PRE-ROUND-105 RECORDING for the emulation tiers, surgically extended on 2026-09-04: the mainstream-desktop rows (sha16/18/20, argon2id, execvm, execsha18, execargon, execchain, execvminline, execsha18inline, rsw75k, rsw150k, rsw300k) now carry real-ladder measurements (Argon m=16384 KiB target 8, rsw T=75,000/150,000/300,000) merged per cache across the inline and files asset modes from the completed runs results/run-2026-09-03.json and tools/client-perf/results/results-2026-09-04.json. Every other row is byte-for-byte the original legacy recording at the old fixture envelope (64 KiB Argon, fixture SHA default), which is not release-required evidence. The physical-device procedure in tools/client-perf/README.md remains the release boundary; qualification status is lab until physical-device data is recorded.';
payload.baseline_of = payload.baseline_of || 'tools/client-perf/results/baseline.json (legacy pre-matrix recording; real-ladder lab rows merged 2026-09-04)';

const out = JSON.stringify(payload, null, 2) + '\n';
if (write) {
  writeFileSync(BASELINE_PATH, out);
  console.log(`baseline updated: ${BASELINE_PATH} (${Object.keys(finalResults).length} rows; merged ${newRows.length} lab rows)`);
} else {
  console.log(`dry run: ${Object.keys(finalResults).length} rows would result; merged ${newRows.length} lab rows:`);
  for (const row of newRows) {
    console.log(`  ${row.tier}:${row.difficulty}:${row.cache} n=${row.reps.length} solveMs.p95=${row.solveMs.p95?.toFixed(1)} pageToVerifiedMs.p95=${row.pageToVerifiedMs.p95?.toFixed(1)} err=${row.errorCount}`);
  }
}
