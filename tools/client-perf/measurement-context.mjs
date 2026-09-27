#!/usr/bin/env node
/**
 * The SINGLE release-measurement-context implementation of the
 * client-performance authority (tools/client-perf) and its release
 * gate (tools/ci/validate-release-baseline.mjs).
 *
 * A physical qualification may only certify the exact measurement
 * context a device's rows were recorded against. This module defines
 * that context once, so the tool that stamps it (merge-cells.mjs
 * --physical-index) and the gate that proves it (the release-baseline
 * validator) can never drift:
 *
 *   measurement_context = {
 *     schema: 'kiwicaptcha.measurement-context/1',
 *     sha256: SHA-256 over the canonical JSON (sorted keys, no
 *             whitespace) of the full release measurement field set:
 *       - the full canonical clientAssets set (per-asset bytes and full
 *         sha256, read from the release asset manifest; the
 *         widget-driver.js / widget-risk.js / kiwi-worker.js worker and
 *         runtime identities are part of it),
 *       - the harness schema string and the harness source sha256
 *         (tools/client-perf/client-perf.mjs, the recorder itself),
 *       - the execution manifest identity
 *         (protocol/execution-v1.json) and its max_execution_version,
 *       - the solver configuration actually used (reps / argonReps /
 *         cache / assets / argonBits / argonMKib) plus the
 *         always-applied fixed-work measurement options (shaFixedWork /
 *         argonFixedWork / shaTargetBits / argonT / argonP),
 *       - the difficulty definitions read from the harness source
 *         constants (name, label, dimension, isArgon, interactive,
 *         assetModes — never a copy kept in this module).
 *
 * Two call sites, one contract:
 *
 *   - merge-cells.mjs --physical-index builds the context FROM THE
 *     RUN'S RECORDED values (run.clientAssets, run.schema, run.options,
 *     the recorded execution maximum, the run-recorded difficulty
 *     definitions) and refuses a run whose context is not the current
 *     release context. The stored device context is therefore provably
 *     the run's own identity, never a fresh stamp over old rows.
 *   - validate-release-baseline.mjs builds the CURRENT release context
 *     from the current tree (canonicalClientAssets(), the current
 *     harness source, the current manifest) and demands every physical
 *     device's stored context sha256 equals it.
 *
 * A change to any measured input — client bytes, harness source,
 * execution grammar ceiling, solver configuration, difficulty
 * definitions — changes the context sha256, so the gate refuses to
 * inherit old evidence under a new identity.
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalClientAssets } from './client-assets.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');

export const HARNESS_FILE = join(REPO_ROOT, 'tools', 'client-perf', 'client-perf.mjs');
export const EXECUTION_MANIFEST_FILE = join(REPO_ROOT, 'protocol', 'execution-v1.json');
export const HARNESS_REL_PATH = 'tools/client-perf/client-perf.mjs';
export const EXECUTION_MANIFEST_REL_PATH = 'protocol/execution-v1.json';
export const EXECUTION_MANIFEST_SCHEMA = 'kiwicaptcha.execution-v1/1';
export const MEASUREMENT_CONTEXT_SCHEMA = 'kiwicaptcha.measurement-context/1';
export const MEASUREMENT_CONTEXT_SHA256_RE = /^[0-9a-f]{64}$/;

/**
 * Canonical JSON of an arbitrary measurement field: object keys sorted
 * recursively, arrays kept in order, no whitespace. The hash domain is
 * therefore stable across JSON member ordering and machines. An
 * `undefined` member is not representable and throws: a measurement
 * context with a missing field must never hash as if the field were
 * absent.
 */
export function canonicalJson(value) {
  if (value === undefined) {
    throw new Error('measurement-context: undefined is not a representable canonical JSON value (a measurement field is missing); bind the field or refuse the context');
  }
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/** SHA-256, lowercase hex. */
export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

/** SHA-256 over the canonical JSON of a measurement field set. */
export function measurementContextSha256(fields) {
  return sha256Hex(canonicalJson(fields));
}

/**
 * The stored context object: the measurement-context schema tag plus
 * the sha256 of the canonical field set. This exact shape is what
 * merge-cells writes into each physical device evidence object and
 * what the release validator demands.
 */
export function buildMeasurementContext(fields) {
  return { schema: MEASUREMENT_CONTEXT_SCHEMA, sha256: measurementContextSha256(fields) };
}

function harnessConst(source, label, pattern) {
  const m = source.match(pattern);
  if (!m) {
    throw new Error(
      `measurement-context: cannot read the harness ${label} from ${HARNESS_FILE} (pattern ${pattern}); update the measurement-context module`
    );
  }
  return m[1];
}

/**
 * The difficulty definitions from the HARNESS SOURCE CONSTANTS, in
 * source order: [{ name, label, dimension, isArgon, interactive,
 * assetModes }]. The definitions are parsed here once; neither
 * merge-cells nor the validator keeps its own copy.
 */
export function harnessDifficultyDefinitions(source) {
  const m = source.match(/const DIFFICULTIES = \{([\s\S]*?)\n\};/);
  if (!m) {
    throw new Error(`measurement-context: cannot read the harness DIFFICULTIES block from ${HARNESS_FILE}; update the measurement-context module`);
  }
  const names = [];
  for (const line of m[1].split('\n')) {
    const key = line.match(/^\s{2}([a-zA-Z0-9]+): \{$/);
    if (key) names.push(key[1]);
  }
  if (names.length === 0) {
    throw new Error(`measurement-context: no difficulties parsed from ${HARNESS_FILE}; update the measurement-context module`);
  }
  return names.map((name) => {
    const start = source.indexOf('\n  ' + name + ': {');
    if (start === -1) {
      throw new Error(`measurement-context: difficulty ${name} not found in ${HARNESS_FILE}; update the measurement-context module`);
    }
    const end = source.indexOf('\n  }', start);
    const block = source.slice(start, end);
    const label = block.match(/label: '([^']*)'/);
    if (!label) {
      throw new Error(`measurement-context: difficulty ${name} has no parseable label in ${HARNESS_FILE}; update the measurement-context module`);
    }
    const dimension = block.match(/dimension: '([a-z]+)'/);
    if (!dimension) {
      throw new Error(`measurement-context: difficulty ${name} has no parseable dimension in ${HARNESS_FILE}; update the measurement-context module`);
    }
    const modesMatch = block.match(/assetModes: \[([^\]]*)\]/);
    if (!modesMatch) {
      throw new Error(`measurement-context: difficulty ${name} has no parseable assetModes in ${HARNESS_FILE}; update the measurement-context module`);
    }
    return {
      name,
      label: label[1],
      dimension: dimension[1],
      isArgon: /isArgon: true/.test(block),
      interactive: !/interactive: false/.test(block),
      assetModes: [...modesMatch[1].matchAll(/'([a-z]+)'/g)].map((mm) => mm[1]),
    };
  });
}

/**
 * The harness facts of the CURRENT tree: schema string, source sha256,
 * execution manifest maximum, difficulty definitions and the release
 * solver defaults. Every field is read from the repository authority
 * (harness source, manifest) at call time, never duplicated.
 */
export function readHarnessMeasurementFacts(source = readFileSync(HARNESS_FILE, 'utf8')) {
  const schema = harnessConst(source, 'schema string', /const SCHEMA = '([^']+)';/);
  const manifest = JSON.parse(readFileSync(EXECUTION_MANIFEST_FILE, 'utf8'));
  if (
    manifest.$schema !== EXECUTION_MANIFEST_SCHEMA ||
    !Number.isInteger(manifest.max_execution_version) ||
    manifest.max_execution_version < 1
  ) {
    throw new Error(
      `measurement-context: ${EXECUTION_MANIFEST_FILE} is not the ${EXECUTION_MANIFEST_SCHEMA} authority (schema ${JSON.stringify(manifest.$schema)}, max_execution_version ${JSON.stringify(manifest.max_execution_version)})`
    );
  }
  return {
    schema,
    sourceSha256: sha256Hex(source),
    maxExecutionVersion: manifest.max_execution_version,
    difficulties: harnessDifficultyDefinitions(source),
    solverDefaults: {
      reps: parseInt(harnessConst(source, 'SHA rep default', /reps: (\d+), \/\/ SHA-256 solve repetitions/), 10),
      argonReps: parseInt(harnessConst(source, 'Argon rep default', /argonReps: (\d+), \/\/ Argon2id solve repetitions/), 10),
      cache: harnessConst(source, 'cache default', /cache: '([a-z]+)', \/\/ cold/),
      assets: harnessConst(source, 'assets default', /assets: '([a-z]+)', \/\/ inline/),
      argonBits: parseInt(harnessConst(source, 'argon bits default', /argonBits: (\d+), \/\/ the real adaptive-risk ladder/), 10),
      argonMKib: parseInt(harnessConst(source, 'argon memory default', /argonMKib: (\d+), \/\/ the real ladder envelope/), 10),
      shaFixedWork: parseInt(harnessConst(source, 'fixed SHA work default', /const FIXED_WORK_SHA_DEFAULT = (\d+);/), 10),
      argonFixedWork: parseInt(harnessConst(source, 'fixed Argon work default', /const FIXED_WORK_ARGON_DEFAULT = (\d+);/), 10),
      shaTargetBits: parseInt(harnessConst(source, 'fixed SHA target bits', /const FIXED_WORK_SHA_TARGET_BITS = (\d+);/), 10),
      argonT: parseInt(harnessConst(source, 'fixed Argon t', /const FIXED_WORK_ARGON_T = (\d+);/), 10),
      argonP: parseInt(harnessConst(source, 'fixed Argon p', /const FIXED_WORK_ARGON_P = (\d+);/), 10),
    },
  };
}

/**
 * Assemble the canonical measurement field set in ONE place, so the
 * current-release fields and the run-recorded fields always share the
 * exact same shape (a shape difference would otherwise silently make
 * every run context differ from the current one).
 */
function measurementFields({ harnessSchema, harnessSourceSha256, executionMaxVersion, solver, difficulties, clientAssets }) {
  return {
    context: MEASUREMENT_CONTEXT_SCHEMA,
    harness: {
      path: HARNESS_REL_PATH,
      schema: harnessSchema,
      sourceSha256: harnessSourceSha256,
    },
    execution: {
      manifest: EXECUTION_MANIFEST_REL_PATH,
      maxExecutionVersion: executionMaxVersion,
    },
    solver,
    difficulties,
    clientAssets,
  };
}

/**
 * The CURRENT release measurement fields: the canonical client asset
 * set, the current harness facts and the harness's release solver
 * defaults. The solver configuration is the canonical release
 * configuration (reps 50 / argonReps 20 / cache both / assets both /
 * argon ladder target 4 at 16384 KiB plus the always-applied fixed-work
 * options); a physical run recorded at any other configuration is a
 * different measurement context and can never be certified against
 * this one.
 */
export function currentReleaseMeasurementFields(facts = readHarnessMeasurementFacts()) {
  return measurementFields({
    harnessSchema: facts.schema,
    harnessSourceSha256: facts.sourceSha256,
    executionMaxVersion: facts.maxExecutionVersion,
    solver: { ...facts.solverDefaults },
    difficulties: facts.difficulties,
    clientAssets: canonicalClientAssets(),
  });
}

/** The current release measurement context { schema, sha256 }. */
export function currentReleaseMeasurementContext(facts = readHarnessMeasurementFacts()) {
  return buildMeasurementContext(currentReleaseMeasurementFields(facts));
}

/**
 * The execution grammar maximum a RUN records: schema-3 payloads carry
 * methodology.execution.maxVersion; older payloads carry
 * options.executionMaxVersion; the maintenance header shape carries
 * execution.maxVersion. Null when none is recorded — a run that never
 * recorded the grammar ceiling cannot be bound to a context.
 */
export function recordedExecutionMax(payload) {
  const candidates = [
    payload && payload.methodology && payload.methodology.execution ? payload.methodology.execution.maxVersion : null,
    payload && payload.options ? payload.options.executionMaxVersion : null,
    payload && payload.execution ? payload.execution.maxVersion : null,
  ];
  for (const value of candidates) {
    if (Number.isInteger(value) && value >= 1) return value;
  }
  return null;
}

/**
 * The always-applied fixed-work measurement options a RUN records
 * (methodology.fixedWork): the SHA target bits and the Argon t/p
 * envelope. Missing members fall back to the current harness constants
 * at the call site; they are part of every run's measurement method.
 */
export function recordedFixedWork(payload) {
  const fw = payload && payload.methodology ? payload.methodology.fixedWork : null;
  if (!fw || typeof fw !== 'object' || Array.isArray(fw)) return null;
  const out = {};
  if (Number.isInteger(fw.shaTargetBits)) out.shaTargetBits = fw.shaTargetBits;
  const env = fw.argonEnvelope;
  if (env && typeof env === 'object') {
    if (Number.isInteger(env.t)) out.argonT = env.t;
    if (Number.isInteger(env.p)) out.argonP = env.p;
  }
  return out;
}

/**
 * The measurement fields of a RECORDED run, built from the run's own
 * values: run.clientAssets (never the current tree's), run.schema,
 * run.options (reps/argonReps/cache/assets/argonBits/argonMKib and the
 * always-applied fixed-work options), the recorded execution maximum
 * and the fixed-work envelope the run recorded. The harness source
 * hash and the difficulty definitions are the harness-level authority
 * shared with the current-release fields; merge-cells additionally
 * refuses a run whose recorded difficulty definitions disagree with
 * them. A run whose recorded values differ from the current release
 * fields produces a different sha256 and can never be stamped with the
 * current identity.
 */
export function runMeasurementFields(runPayload, facts = readHarnessMeasurementFacts()) {
  if (!runPayload || typeof runPayload !== 'object' || Array.isArray(runPayload)) {
    throw new Error('run payload is not an object');
  }
  if (typeof runPayload.schema !== 'string' || runPayload.schema.length === 0) {
    throw new Error('run payload records no harness schema string');
  }
  if (!runPayload.clientAssets || typeof runPayload.clientAssets !== 'object' || Array.isArray(runPayload.clientAssets)) {
    throw new Error('run payload records no clientAssets block');
  }
  const options = runPayload.options || {};
  const intOption = (name) => {
    const value = options[name];
    if (!Number.isInteger(value)) {
      throw new Error(`run payload option ${name} ${JSON.stringify(value)} is not an integer`);
    }
    return value;
  };
  const stringOption = (name) => {
    const value = options[name];
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`run payload option ${name} ${JSON.stringify(value)} is not a non-empty string`);
    }
    return value;
  };
  const executionMaxVersion = recordedExecutionMax(runPayload);
  if (executionMaxVersion === null) {
    throw new Error('run payload records no execution grammar maximum (methodology.execution.maxVersion / options.executionMaxVersion)');
  }
  const fixedWork = recordedFixedWork(runPayload) || {};
  return measurementFields({
    harnessSchema: runPayload.schema,
    harnessSourceSha256: facts.sourceSha256,
    executionMaxVersion,
    solver: {
      reps: intOption('reps'),
      argonReps: intOption('argonReps'),
      cache: stringOption('cache'),
      assets: stringOption('assets'),
      argonBits: intOption('argonBits'),
      argonMKib: intOption('argonMKib'),
      shaFixedWork: intOption('shaFixedWork'),
      argonFixedWork: intOption('argonFixedWork'),
      shaTargetBits: fixedWork.shaTargetBits ?? facts.solverDefaults.shaTargetBits,
      argonT: fixedWork.argonT ?? facts.solverDefaults.argonT,
      argonP: fixedWork.argonP ?? facts.solverDefaults.argonP,
    },
    difficulties: facts.difficulties,
    clientAssets: runPayload.clientAssets,
  });
}

/**
 * The run's RECORDED difficulty definitions (payload.difficulties)
 * versus the current harness source constants. Returns one human
 * reason per mismatch (empty when they agree). merge-cells refuses a
 * physical-index run with mismatches: the rows were measured under
 * different difficulty definitions than the current harness defines,
 * so stamping them with the current context would re-bind the device
 * to definitions it never ran.
 */
export function recordedDifficultyMismatches(runPayload, facts = readHarnessMeasurementFacts()) {
  const recorded = runPayload && runPayload.difficulties;
  if (!recorded || typeof recorded !== 'object' || Array.isArray(recorded)) {
    return ['run payload records no difficulties block (the harness record of the definitions it measured)'];
  }
  const currentByName = new Map(facts.difficulties.map((d) => [d.name, d]));
  const mismatches = [];
  for (const [name, def] of Object.entries(recorded)) {
    const current = currentByName.get(name);
    if (!current) {
      mismatches.push(`recorded difficulty ${name} is not a current harness difficulty`);
      continue;
    }
    if (!def || typeof def !== 'object' || Array.isArray(def)) {
      mismatches.push(`recorded difficulty ${name} is not an object`);
      continue;
    }
    if (def.label !== current.label) {
      mismatches.push(`recorded difficulty ${name} label ${JSON.stringify(def.label)} differs from the current harness label ${JSON.stringify(current.label)}`);
    }
    if (def.dimension !== current.dimension) {
      mismatches.push(`recorded difficulty ${name} dimension ${JSON.stringify(def.dimension)} differs from the current harness dimension ${JSON.stringify(current.dimension)}`);
    }
    const recordedModes = Array.isArray(def.assetModes) ? def.assetModes : [];
    if (canonicalJson(recordedModes) !== canonicalJson(current.assetModes)) {
      mismatches.push(`recorded difficulty ${name} assetModes ${JSON.stringify(recordedModes)} differ from the current harness assetModes ${JSON.stringify(current.assetModes)}`);
    }
  }
  return mismatches;
}
