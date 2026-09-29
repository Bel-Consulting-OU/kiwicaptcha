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
 * validator) can never drift.
 *
 * ── Provenance contract (re-audit: run-derived provenance) ─────────
 *
 * The context is a sha256 over a canonical field set. The RUN-STORED
 * context (what merge-cells stamps on a device) is built from the
 * facts the RUN FILE itself records — never from the current tree:
 *
 *   - harness.path / harness.schema — recorded payload.harness (the
 *     recorder path the run wrote) and payload.schema. The run must
 *     also record the recorder's source identity: payload.harnessSha256
 *     (64-hex), or payload.harness.sha256 when payload.harness is an
 *     object. The current harness does not write that field yet; a run
 *     that lacks it is REFUSED at merge time (a run whose recorder
 *     identity was never recorded cannot be bound to a context), and
 *     the module states the required field in the refusal reason.
 *   - execution.manifestSchema / execution.manifestSha256 /
 *     execution.maxExecutionVersion — recorded
 *     payload.methodology.execution (manifestSchema, the full grammar
 *     bytes hash and maxVersion; older payloads may record
 *     options.executionMaxVersion or payload.execution.maxVersion for
 *     the ceiling). The schema tag and the maximum version alone are
 *     NOT enough: an opcode remap or trace-name change keeps both and
 *     must still refuse inherited evidence.
 *   - sources — the recorded payload.measurementSources block: the
 *     frozen measurement-source manifest (audit finding 1) and its
 *     canonical digest. The manifest binds the exact bytes of the
 *     harness, the asset-fingerprint policy, the fixture workload
 *     router, the execution manifest, the release asset set, every
 *     canonical client asset and the PHP core source tree the run
 *     executed against. The recorded manifest is cross-checked against
 *     the recorded harness source sha256, the recorded execution
 *     manifest sha256 and the recorded clientAssets entries, so a run
 *     cannot claim one population in the manifest and another in its
 *     other facts.
 *   - solver.* — recorded payload.options (reps, argonReps, cache,
 *     assets, argonBits, argonMKib, shaFixedWork, argonFixedWork) plus
 *     the always-applied fixed-work options recorded in
 *     payload.methodology.fixedWork (shaTargetBits, argonEnvelope.t,
 *     argonEnvelope.p). There is NO fallback to the current harness
 *     constants: a missing fixed-work fact refuses the run.
 *   - difficulties — the run's recorded payload.difficulties table
 *     (label, dimension, query, assetModes per difficulty). The
 *     isArgon/interactive classification is deliberately NOT part of
 *     the measurement context: runs do not record it, and it is a
 *     release-gate validation policy (read from the current harness
 *     profiles by the validator), not a measurement fact.
 *   - clientAssets — the recorded payload.clientAssets block (bytes +
 *     full sha256 per canonical asset).
 *
 * Facts a run does not record are NOT substituted from the current
 * tree. Where a fact is genuinely not recorded (the recorder source
 * hash), the run is refused. The tier table is verified separately
 * (recordedTierMismatches): a run records only the tiers it executed,
 * so every recorded tier entry must equal the current harness tier
 * definition, and every result-row tier/difficulty the merge emits must
 * be defined by the run's recorded tables. Tiers are not part of the
 * context hash because a per-tier physical run legitimately records a
 * one-tier table and substituting the other current tiers would be the
 * exact false binding this contract removes.
 *
 * The CURRENT release context (what the validator demands) is built
 * from the current repository authorities: the current harness source
 * (schema, source sha256, solver defaults, difficulty definitions), the
 * execution manifest and the canonical client asset set. merge-cells
 * compares the run-recorded fields against it field by field and
 * refuses any difference, naming the run and the differing field. A run
 * whose recorded facts differ from the current release facts therefore
 * can never be stamped with the current release context: its own
 * recorded fields hash to a different sha256, and the merge refuses it
 * before any repetition is indexed.
 *
 * Two call sites, one contract:
 *
 *   - merge-cells.mjs --physical-index builds the fields from
 *     runMeasurementFields(payload) — recorded facts only — compares
 *     them against currentReleaseMeasurementFields() and refuses on any
 *     difference, then stamps the device with the context (which, for
 *     an accepted run, is identical to the run-derived context).
 *   - validate-release-baseline.mjs builds the CURRENT release context
 *     from the current tree and demands every physical device's stored
 *     context sha256 equals it.
 *
 * A change to any measured input — client bytes, harness source,
 * execution manifest, solver configuration, difficulty definitions —
 * changes the current context sha256, so the gate refuses to inherit
 * old evidence under a new identity.
 */
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalClientAssets } from './client-assets.mjs';
import { canonicalJson, sha256Hex } from './canonical-json.mjs';
import { snapshotMeasurementSources } from './measurement-sources.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');

export { canonicalJson, sha256Hex };

export const HARNESS_FILE = join(REPO_ROOT, 'tools', 'client-perf', 'client-perf.mjs');
export const EXECUTION_MANIFEST_FILE = join(REPO_ROOT, 'protocol', 'execution-v1.json');
export const HARNESS_REL_PATH = 'tools/client-perf/client-perf.mjs';
export const EXECUTION_MANIFEST_REL_PATH = 'protocol/execution-v1.json';
export const EXECUTION_MANIFEST_SCHEMA = 'kiwicaptcha.execution-v1/1';
export const MEASUREMENT_CONTEXT_SCHEMA = 'kiwicaptcha.measurement-context/1';

/**
 * The completion marker a run must carry before ANY consumer treats it
 * as evidence. The harness deliberately omits it when a run aborts, is
 * interrupted or is contaminated; merge-cells and the loader modes
 * require it, and the physical evidence records it per source run so
 * the original run's completion state survives row extraction.
 */
export const COMPLETION_MARKER = 'kiwicaptcha.client-perf.completed.v1';
export const MEASUREMENT_CONTEXT_SHA256_RE = /^[0-9a-f]{64}$/;
export const HARNESS_SOURCE_SHA256_RE = /^[0-9a-f]{64}$/;

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
 * Substitute the harness query template members the source uses
 * (`${o.argonBits}` / `${o.argonMKib}`) with the given solver options.
 * Any other member (or a leftover `${` expression) is a source shape
 * this module does not understand and fails loudly: the query is a
 * recorded run fact and the current side must derive the same value.
 */
function expandQueryTemplate(template, opts) {
  const expanded = template.replace(/\$\{o\.([a-zA-Z0-9]+)\}/g, (_, key) => {
    if (key === 'argonBits') return String(opts.argonBits);
    if (key === 'argonMKib') return String(opts.argonMKib);
    throw new Error(`measurement-context: unsupported query template member \${o.${key}} in ${HARNESS_FILE}; update the measurement-context module`);
  });
  if (expanded.includes('${')) {
    throw new Error(`measurement-context: unexpanded query template member in ${HARNESS_FILE} (${JSON.stringify(template)}); update the measurement-context module`);
  }
  return expanded;
}

/**
 * The current harness's query string for one difficulty, derived from
 * the source expression exactly as the harness's own query function
 * derives it: literal strings, the two solver-option template members
 * (o.argonBits / o.argonMKib) and the shared executionQuery prefix
 * (?execution=1&exec_cap=<manifest maximum>). The query is what the run
 * records in payload.difficulties[<name>].query, so it must be part of
 * the compared field set or a run measured at a different fixture arm
 * could hash as the current context. A source shape this module cannot
 * derive fails loudly, never silently.
 */
function harnessDifficultyQuery(block, name, opts) {
  const execPrefix = `?execution=1&exec_cap=${opts.maxExecutionVersion}`;
  let m = block.match(/query: \(\) => executionQuery\('([^']*)'\)/);
  if (m) return `${execPrefix}${m[1]}`;
  m = block.match(/query: \(o\) => executionQuery\(`([^`]*)`\)/);
  if (m) return `${execPrefix}${expandQueryTemplate(m[1], opts)}`;
  m = block.match(/query: \(\) => '([^']*)'/);
  if (m) return m[1];
  m = block.match(/query: \(o\) => `([^`]*)`/);
  if (m) return expandQueryTemplate(m[1], opts);
  throw new Error(`measurement-context: cannot read the difficulty ${name} query from ${HARNESS_FILE}; update the measurement-context module`);
}

/**
 * The difficulty definitions from the HARNESS SOURCE CONSTANTS, in an
 * object keyed by name: { <name>: { label, dimension, query,
 * assetModes } }. query is derived with the current solver options (the
 * two template members the source uses) and the manifest maximum for
 * the armed execution queries. The isArgon/interactive classification
 * is intentionally absent: runs do not record it and it is not part of
 * the measurement identity (the validator reads it from its own harness
 * profile parse for release-gate classification).
 */
export function harnessDifficultyDefinitions(source, opts) {
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
  const difficulties = {};
  for (const name of names) {
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
    difficulties[name] = {
      label: label[1],
      dimension: dimension[1],
      query: harnessDifficultyQuery(block, name, opts),
      assetModes: [...modesMatch[1].matchAll(/'([a-z]+)'/g)].map((mm) => mm[1]),
    };
  }
  return difficulties;
}

/**
 * The tier definitions from the HARNESS SOURCE CONSTANTS, in an object
 * keyed by name: { <name>: { label, device, cpuThrottle } }. device is
 * null for tiers without a Playwright descriptor (low-desktop,
 * mainstream-desktop). Used to verify a run's recorded payload.tiers
 * entry by entry (recordedTierMismatches); it is not a hash field,
 * because a run records only the tiers it executed.
 */
export function harnessTierDefinitions(source) {
  const m = source.match(/const TIERS = \{([\s\S]*?)\n\};/);
  if (!m) {
    throw new Error(`measurement-context: cannot read the harness TIERS block from ${HARNESS_FILE}; update the measurement-context module`);
  }
  const names = [];
  for (const line of m[1].split('\n')) {
    const key = line.match(/^\s{2}'([a-z-]+)': \{$/);
    if (key) names.push(key[1]);
  }
  if (names.length === 0) {
    throw new Error(`measurement-context: no tiers parsed from ${HARNESS_FILE}; update the measurement-context module`);
  }
  const tiers = {};
  for (const name of names) {
    const start = source.indexOf("\n  '" + name + "': {");
    if (start === -1) {
      throw new Error(`measurement-context: tier ${name} not found in ${HARNESS_FILE}; update the measurement-context module`);
    }
    const end = source.indexOf('\n  }', start);
    const block = source.slice(start, end);
    const label = block.match(/label: '([^']*)'/);
    if (!label) {
      throw new Error(`measurement-context: tier ${name} has no parseable label in ${HARNESS_FILE}; update the measurement-context module`);
    }
    const throttle = block.match(/cpuThrottle: (\d+)/);
    if (!throttle) {
      throw new Error(`measurement-context: tier ${name} has no parseable cpuThrottle in ${HARNESS_FILE}; update the measurement-context module`);
    }
    const device = block.match(/device: '([^']*)'/);
    tiers[name] = {
      label: label[1],
      device: device ? device[1] : null,
      cpuThrottle: parseInt(throttle[1], 10),
    };
  }
  return tiers;
}

/**
 * The harness facts of the CURRENT tree: schema string, source sha256,
 * execution manifest schema and maximum, difficulty definitions with
 * the derived query strings, tier definitions and the release solver
 * defaults. Every field is read from the repository authority (harness
 * source, manifest) at call time, never duplicated. This is the
 * CURRENT side only; a run's context is built by runMeasurementFields
 * from what the run recorded, and the two are compared field by field.
 */
export function readHarnessMeasurementFacts(source = readFileSync(HARNESS_FILE, 'utf8')) {
  const schema = harnessConst(source, 'schema string', /const SCHEMA = '([^']+)';/);
  // The FULL execution manifest bytes are part of the identity (audit
  // finding 2): the schema tag and the maximum version alone cannot
  // distinguish an opcode remap, a trace-name change or an opcode-count
  // change from the grammar the evidence ran. The sha256 of the exact
  // manifest bytes is bound, and the harness records it per run.
  const manifestBytes = readFileSync(EXECUTION_MANIFEST_FILE);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  if (
    manifest.$schema !== EXECUTION_MANIFEST_SCHEMA ||
    !Number.isInteger(manifest.max_execution_version) ||
    manifest.max_execution_version < 1
  ) {
    throw new Error(
      `measurement-context: ${EXECUTION_MANIFEST_FILE} is not the ${EXECUTION_MANIFEST_SCHEMA} authority (schema ${JSON.stringify(manifest.$schema)}, max_execution_version ${JSON.stringify(manifest.max_execution_version)})`
    );
  }
  const solverDefaults = {
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
  };
  return {
    schema,
    sourceSha256: sha256Hex(source),
    manifestSchema: manifest.$schema,
    manifestSha256: sha256Hex(manifestBytes),
    maxExecutionVersion: manifest.max_execution_version,
    solverDefaults,
    difficulties: harnessDifficultyDefinitions(source, {
      argonBits: solverDefaults.argonBits,
      argonMKib: solverDefaults.argonMKib,
      maxExecutionVersion: manifest.max_execution_version,
    }),
    tiers: harnessTierDefinitions(source),
  };
}

/**
 * Assemble the canonical measurement field set in ONE place, so the
 * current-release fields and the run-recorded fields always share the
 * exact same shape (a shape difference would otherwise silently make
 * every run context differ from the current one). The tier table is
 * deliberately absent: a run records only the tiers it executed, and
 * tiers are verified per recorded entry instead (recordedTierMismatches).
 */
function measurementFields({ harnessPath, harnessSchema, harnessSourceSha256, manifestSchema, manifestSha256, executionMaxVersion, solver, difficulties, clientAssets, sources }) {
  return {
    context: MEASUREMENT_CONTEXT_SCHEMA,
    harness: {
      path: harnessPath,
      schema: harnessSchema,
      sourceSha256: harnessSourceSha256,
    },
    execution: {
      manifest: EXECUTION_MANIFEST_REL_PATH,
      manifestSchema,
      manifestSha256,
      maxExecutionVersion: executionMaxVersion,
    },
    solver,
    difficulties,
    clientAssets,
    // The canonical measurement-source manifest (audit finding 2): the
    // exact bytes of every benchmark-defining repository input the run
    // was frozen against (harness, asset policy, fixture workload
    // router, execution manifest, release asset set, every canonical
    // asset, the PHP core source tree). The manifest digest is what the
    // release gate binds, so a change to any one of those files — an
    // opcode remap, a trace-name change, a router bits reinterpretation,
    // an Argon fixture envelope change — refuses inherited evidence
    // even when the schema tags and the maximum version are unchanged.
    sources: {
      manifest: sources.manifest,
      sha256: sources.manifestSha256,
    },
  };
}

/**
 * The CURRENT measurement-source snapshot: hashes (no copy) of every
 * benchmark-defining authority of the working tree. Used to build the
 * current release fields; the harness freezes its own copy at startup
 * and records it.
 */
export function currentMeasurementSourceSnapshot() {
  return snapshotMeasurementSources({ snapshotRoot: null });
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
    harnessPath: HARNESS_REL_PATH,
    harnessSchema: facts.schema,
    harnessSourceSha256: facts.sourceSha256,
    manifestSchema: facts.manifestSchema,
    manifestSha256: facts.manifestSha256,
    executionMaxVersion: facts.maxExecutionVersion,
    solver: { ...facts.solverDefaults },
    difficulties: facts.difficulties,
    clientAssets: canonicalClientAssets(),
    sources: currentMeasurementSourceSnapshot(),
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
 * The recorder identity a RUN records. Accepted recorded shapes:
 *
 *   - payload.harness: "<path>" plus payload.harnessSha256: "<64 hex>"
 *     (the top-level field is the canonical recorded form), or
 *   - payload.harness: { path: "<path>", sha256: "<64 hex>" }.
 *
 * The source sha256 is REQUIRED: a run that does not record which
 * recorder source produced it can never be bound to a measurement
 * context (the current tree's harness hash is not a fact of the run and
 * substituting it would be exactly the false provenance this contract
 * removes). When both recorded forms are present they must agree.
 */
function recordedHarnessIdentity(payload, reasons) {
  const topLevelSha = payload.harnessSha256;
  let path = null;
  let objectSha = null;
  if (typeof payload.harness === 'string' && payload.harness.length > 0) {
    path = payload.harness;
  } else if (payload.harness && typeof payload.harness === 'object' && !Array.isArray(payload.harness)) {
    if (typeof payload.harness.path === 'string' && payload.harness.path.length > 0) {
      path = payload.harness.path;
    } else {
      reasons.push(`run payload harness object records no path string (harness.path ${JSON.stringify(payload.harness.path)})`);
    }
    if (payload.harness.sha256 !== undefined) {
      if (typeof payload.harness.sha256 === 'string' && HARNESS_SOURCE_SHA256_RE.test(payload.harness.sha256)) {
        objectSha = payload.harness.sha256;
      } else {
        reasons.push(`run payload harness.sha256 ${JSON.stringify(payload.harness.sha256)} is not a 64-hex lowercase sha256`);
      }
    }
  } else {
    reasons.push(`run payload records no harness path string (harness ${JSON.stringify(payload.harness)})`);
  }
  let sha256 = null;
  if (topLevelSha !== undefined) {
    if (typeof topLevelSha === 'string' && HARNESS_SOURCE_SHA256_RE.test(topLevelSha)) {
      sha256 = topLevelSha;
    } else {
      reasons.push(`run payload harnessSha256 ${JSON.stringify(topLevelSha)} is not a 64-hex lowercase sha256`);
    }
  }
  if (sha256 !== null && objectSha !== null && sha256 !== objectSha) {
    reasons.push(`run payload records two disagreeing harness source sha256 values (harnessSha256 ${sha256}, harness.sha256 ${objectSha})`);
  }
  if (sha256 === null && objectSha !== null) sha256 = objectSha;
  if (sha256 === null) {
    reasons.push('run payload records no harness source sha256 (harnessSha256, or harness.sha256 when harness is an object): the recorder source identity was not recorded, so the run cannot be bound to a release measurement context');
  }
  return { path, sha256 };
}

/**
 * The measurement fields of a RECORDED run, built from the run's own
 * values only — payload.schema, payload.harness + payload.harnessSha256,
 * payload.methodology.execution, payload.options, the recorded
 * fixed-work envelope (payload.methodology.fixedWork), the recorded
 * difficulty table (payload.difficulties) and the recorded clientAssets
 * block. The current tree is never consulted: a fact the run did not
 * record is a refusal reason, never a silent substitution.
 *
 * Returns { fields, reasons }. fields is null when the run lacks any
 * required recorded fact; reasons carries one exact string per missing,
 * malformed or internally inconsistent recorded fact. merge-cells
 * refuses such a run before any repetition is indexed.
 */
export function runMeasurementFields(runPayload) {
  const reasons = [];
  if (!runPayload || typeof runPayload !== 'object' || Array.isArray(runPayload)) {
    return { fields: null, reasons: ['run payload is not an object'] };
  }
  const harnessIdentity = recordedHarnessIdentity(runPayload, reasons);

  let harnessSchema = null;
  if (typeof runPayload.schema === 'string' && runPayload.schema.length > 0) {
    harnessSchema = runPayload.schema;
  } else {
    reasons.push(`run payload records no harness schema string (schema ${JSON.stringify(runPayload.schema)})`);
  }

  const options = runPayload.options && typeof runPayload.options === 'object' && !Array.isArray(runPayload.options)
    ? runPayload.options
    : {};
  const intOption = (name) => {
    const value = options[name];
    if (!Number.isInteger(value)) {
      reasons.push(`run payload option ${name} ${JSON.stringify(value)} is not an integer`);
      return null;
    }
    return value;
  };
  const stringOption = (name) => {
    const value = options[name];
    if (typeof value !== 'string' || value.length === 0) {
      reasons.push(`run payload option ${name} ${JSON.stringify(value)} is not a non-empty string`);
      return null;
    }
    return value;
  };

  const executionMaxVersion = recordedExecutionMax(runPayload);
  if (executionMaxVersion === null) {
    reasons.push('run payload records no execution grammar maximum (methodology.execution.maxVersion / options.executionMaxVersion)');
  }
  const methodology = runPayload.methodology && typeof runPayload.methodology === 'object' && !Array.isArray(runPayload.methodology)
    ? runPayload.methodology
    : {};
  const executionRecord = methodology.execution && typeof methodology.execution === 'object' && !Array.isArray(methodology.execution)
    ? methodology.execution
    : {};
  let manifestSchema = null;
  if (typeof executionRecord.manifestSchema === 'string' && executionRecord.manifestSchema.length > 0) {
    manifestSchema = executionRecord.manifestSchema;
  } else {
    reasons.push(`run payload records no execution manifest schema (methodology.execution.manifestSchema ${JSON.stringify(executionRecord.manifestSchema)})`);
  }
  // The FULL execution-manifest hash (audit finding 2): schema tag and
  // maximum version alone cannot distinguish an opcode remap or a
  // trace-name change. A run that never recorded the manifest bytes it
  // measured cannot be bound to a context.
  let manifestSha256 = null;
  if (typeof executionRecord.manifestSha256 === 'string' && HARNESS_SOURCE_SHA256_RE.test(executionRecord.manifestSha256)) {
    manifestSha256 = executionRecord.manifestSha256;
  } else {
    reasons.push(`run payload records no execution manifest sha256 (methodology.execution.manifestSha256 ${JSON.stringify(executionRecord.manifestSha256)}): the exact grammar bytes the run measured were not recorded`);
  }

  const fixedWork = methodology.fixedWork && typeof methodology.fixedWork === 'object' && !Array.isArray(methodology.fixedWork)
    ? methodology.fixedWork
    : null;
  if (!fixedWork) {
    reasons.push('run payload records no methodology.fixedWork block (the always-applied fixed-work measurement options)');
  }
  const intFixedWork = (label, value) => {
    if (!Number.isInteger(value)) {
      reasons.push(`run payload fixedWork ${label} ${JSON.stringify(value)} is not an integer`);
      return null;
    }
    return value;
  };
  const argonEnvelope = fixedWork && fixedWork.argonEnvelope && typeof fixedWork.argonEnvelope === 'object' && !Array.isArray(fixedWork.argonEnvelope)
    ? fixedWork.argonEnvelope
    : null;
  if (fixedWork && !argonEnvelope) {
    reasons.push(`run payload fixedWork records no argonEnvelope object (${JSON.stringify(fixedWork.argonEnvelope)})`);
  }
  const shaTargetBits = fixedWork ? intFixedWork('shaTargetBits', fixedWork.shaTargetBits) : null;
  const argonT = argonEnvelope ? intFixedWork('argonEnvelope.t', argonEnvelope.t) : null;
  const argonP = argonEnvelope ? intFixedWork('argonEnvelope.p', argonEnvelope.p) : null;

  const solver = {
    reps: intOption('reps'),
    argonReps: intOption('argonReps'),
    cache: stringOption('cache'),
    assets: stringOption('assets'),
    argonBits: intOption('argonBits'),
    argonMKib: intOption('argonMKib'),
    shaFixedWork: intOption('shaFixedWork'),
    argonFixedWork: intOption('argonFixedWork'),
    shaTargetBits,
    argonT,
    argonP,
  };

  // Within-run consistency of the duplicated fixed-work facts: the
  // options N values and the recorded envelope must agree with each
  // other, or the run itself recorded two different measurement
  // configurations.
  if (fixedWork && Number.isInteger(fixedWork.shaHashes) && solver.shaFixedWork !== null && fixedWork.shaHashes !== solver.shaFixedWork) {
    reasons.push(`run payload fixedWork shaHashes ${fixedWork.shaHashes} disagrees with option shaFixedWork ${solver.shaFixedWork}`);
  }
  if (fixedWork && Number.isInteger(fixedWork.argonDerivations) && solver.argonFixedWork !== null && fixedWork.argonDerivations !== solver.argonFixedWork) {
    reasons.push(`run payload fixedWork argonDerivations ${fixedWork.argonDerivations} disagrees with option argonFixedWork ${solver.argonFixedWork}`);
  }
  if (argonEnvelope && Number.isInteger(argonEnvelope.mKib) && solver.argonMKib !== null && argonEnvelope.mKib !== solver.argonMKib) {
    reasons.push(`run payload fixedWork argonEnvelope.mKib ${argonEnvelope.mKib} disagrees with option argonMKib ${solver.argonMKib}`);
  }

  // The recorded difficulty table: every entry must carry the four
  // facts the context binds (label, dimension, query, assetModes).
  let difficulties = null;
  if (!runPayload.difficulties || typeof runPayload.difficulties !== 'object' || Array.isArray(runPayload.difficulties)) {
    reasons.push('run payload records no difficulties block (the harness record of the definitions it measured)');
  } else {
    difficulties = {};
    for (const [name, def] of Object.entries(runPayload.difficulties)) {
      if (!def || typeof def !== 'object' || Array.isArray(def)) {
        reasons.push(`run payload difficulty ${name} is not an object`);
        continue;
      }
      const missing = [];
      if (typeof def.label !== 'string' || def.label.length === 0) missing.push('label');
      if (typeof def.dimension !== 'string' || def.dimension.length === 0) missing.push('dimension');
      if (typeof def.query !== 'string' || def.query.length === 0) missing.push('query');
      if (!Array.isArray(def.assetModes) || def.assetModes.length === 0 || !def.assetModes.every((mm) => typeof mm === 'string' && mm.length > 0)) {
        missing.push('assetModes');
      }
      if (missing.length) {
        reasons.push(`run payload difficulty ${name} records no valid ${missing.join('/')}`);
        continue;
      }
      difficulties[name] = {
        label: def.label,
        dimension: def.dimension,
        query: def.query,
        assetModes: [...def.assetModes],
      };
    }
    if (Object.keys(difficulties).length === 0) {
      reasons.push('run payload records an empty difficulties block (no measured difficulty definitions)');
    }
  }

  if (!runPayload.clientAssets || typeof runPayload.clientAssets !== 'object' || Array.isArray(runPayload.clientAssets)) {
    reasons.push('run payload records no clientAssets block (the client bytes it measured)');
  }

  // The recorded measurement-source manifest (audit finding 1/2): the
  // frozen snapshot of every benchmark-defining authority the run was
  // executed against. Without it a run cannot be bound to a source
  // identity, and the exact manifest is validated for shape and
  // cross-checked against the other recorded facts.
  let sources = null;
  const recordedSources = runPayload.measurementSources;
  if (!recordedSources || typeof recordedSources !== 'object' || Array.isArray(recordedSources)) {
    reasons.push('run payload records no measurementSources block (the frozen measurement-source manifest the run executed against)');
  } else {
    if (typeof recordedSources.sha256 !== 'string' || !HARNESS_SOURCE_SHA256_RE.test(recordedSources.sha256)) {
      reasons.push(`run payload measurementSources.sha256 ${JSON.stringify(recordedSources.sha256)} is not a 64-hex lowercase sha256`);
    }
    const manifest = recordedSources.manifest;
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest) || Object.keys(manifest).length === 0) {
      reasons.push('run payload measurementSources.manifest is not a non-empty object');
    } else {
      const validated = {};
      for (const [rel, entry] of Object.entries(manifest)) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
          reasons.push(`run payload measurementSources.manifest[${JSON.stringify(rel)}] is not an object`);
          continue;
        }
        if (!['file', 'tree', 'asset'].includes(entry.kind)) {
          reasons.push(`run payload measurementSources.manifest[${JSON.stringify(rel)}].kind ${JSON.stringify(entry.kind)} is not one of file|tree|asset`);
          continue;
        }
        if (typeof entry.sha256 !== 'string' || !HARNESS_SOURCE_SHA256_RE.test(entry.sha256)) {
          reasons.push(`run payload measurementSources.manifest[${JSON.stringify(rel)}].sha256 ${JSON.stringify(entry.sha256)} is not a 64-hex lowercase sha256`);
          continue;
        }
        validated[rel] = entry;
      }
      if (reasons.length === 0) {
        sources = { manifest: validated, manifestSha256: recordedSources.sha256 };
        // The recorded digest must hash the recorded manifest: a
        // fabricated digest that does not describe its own manifest is
        // malformed evidence, whatever it happens to compare against.
        const recomputed = sha256Hex(canonicalJson(validated));
        if (recomputed !== recordedSources.sha256) {
          reasons.push(`run payload measurementSources.sha256 ${recordedSources.sha256} does not hash its own manifest (recomputed ${recomputed})`);
        }
        // Cross-consistency: the manifest must describe the same bytes
        // as the run's other recorded identities, or the run recorded
        // two different measurement populations.
        const harnessEntry = validated[harnessIdentity.path];
        if (!harnessEntry) {
          reasons.push(`run payload measurementSources.manifest does not carry the harness entry ${JSON.stringify(harnessIdentity.path)}`);
        } else if (harnessEntry.sha256 !== harnessIdentity.sha256) {
          reasons.push(`run payload measurementSources.manifest[${JSON.stringify(harnessIdentity.path)}].sha256 ${harnessEntry.sha256} disagrees with the recorded harness source sha256 ${harnessIdentity.sha256}`);
        }
        const manifestEntry = validated[EXECUTION_MANIFEST_REL_PATH];
        if (!manifestEntry) {
          reasons.push(`run payload measurementSources.manifest does not carry the execution manifest entry ${JSON.stringify(EXECUTION_MANIFEST_REL_PATH)}`);
        } else if (manifestSha256 !== null && manifestEntry.sha256 !== manifestSha256) {
          reasons.push(`run payload measurementSources.manifest[${JSON.stringify(EXECUTION_MANIFEST_REL_PATH)}].sha256 ${manifestEntry.sha256} disagrees with the recorded methodology.execution.manifestSha256 ${manifestSha256}`);
        }
        if (Object.keys(validated).length !== Object.keys(manifest).length) {
          sources = null;
        } else if (runPayload.clientAssets && typeof runPayload.clientAssets === 'object' && !Array.isArray(runPayload.clientAssets)) {
          for (const [name, asset] of Object.entries(runPayload.clientAssets)) {
            const rel = `packages/kiwicaptcha-wasm/assets/${name}`;
            const entry = validated[rel];
            if (!entry) {
              reasons.push(`run payload measurementSources.manifest does not carry the recorded client asset ${name}`);
              continue;
            }
            if (entry.sha256 !== asset.sha256 || entry.bytes !== asset.bytes) {
              reasons.push(`run payload measurementSources.manifest[${JSON.stringify(rel)}] disagrees with the recorded clientAssets entry for ${name} (manifest ${entry.bytes} bytes / ${entry.sha256}, clientAssets ${asset.bytes} bytes / ${asset.sha256})`);
            }
          }
        }
      }
    }
  }

  if (reasons.length > 0) return { fields: null, reasons };
  return {
    fields: measurementFields({
      harnessPath: harnessIdentity.path,
      harnessSchema,
      harnessSourceSha256: harnessIdentity.sha256,
      manifestSchema,
      manifestSha256,
      executionMaxVersion,
      solver,
      difficulties,
      clientAssets: runPayload.clientAssets,
      sources,
    }),
    reasons: [],
  };
}

/**
 * Field-by-field difference report between a recorded field set and the
 * current release field set. Returns one human reason per differing leaf
 * (naming the path, e.g. solver.reps, difficulties.sha16.label,
 * clientAssets["widget-driver.js"].sha256), capped so a wholly foreign
 * run cannot flood the refusal. An empty array means every recorded fact
 * equals the current release fact.
 */
export function measurementFieldDifferences(recorded, current, limit = 40) {
  const out = [];
  const shown = (value) => (value === undefined ? '(not recorded)' : JSON.stringify(value));
  const same = (a, b) => (a === undefined || b === undefined ? a === b : canonicalJson(a) === canonicalJson(b));
  const segment = (key) => (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? `${key}` : `[${JSON.stringify(key)}]`);
  const walk = (a, b, path) => {
    if (out.length >= limit || same(a, b)) return;
    const aPlain = a && typeof a === 'object' && !Array.isArray(a);
    const bPlain = b && typeof b === 'object' && !Array.isArray(b);
    if (aPlain && bPlain) {
      const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
      for (const key of keys) walk(a[key], b[key], path ? `${path}.${segment(key)}` : segment(key));
      return;
    }
    out.push(`${path || 'measurement fields'} recorded ${shown(a)} differs from current ${shown(b)}`);
  };
  walk(recorded, current, '');
  if (out.length >= limit) out.push(`... and further differences beyond the first ${limit} (the run was recorded against a different measurement context)`);
  return out;
}

/**
 * The run's RECORDED tier table (payload.tiers) versus the current
 * harness tier definitions. A run records only the tiers it executed,
 * so this is a subset check (every recorded entry must equal the
 * current definition); a missing or extra *recorded* tier is not itself
 * a mismatch. Returns one human reason per mismatch (empty when they
 * agree); merge-cells refuses a physical-index run with mismatches and
 * additionally refuses result rows whose tier/difficulty the run's
 * recorded tables do not define.
 */
export function recordedTierMismatches(recorded, currentTiers) {
  if (!recorded || typeof recorded !== 'object' || Array.isArray(recorded)) {
    return ['run payload records no tier table (payload.tiers): the tier definitions the run measured were not recorded'];
  }
  if (Object.keys(recorded).length === 0) {
    return ['run payload records an empty tier table (payload.tiers)'];
  }
  const reasons = [];
  for (const [name, def] of Object.entries(recorded)) {
    const current = currentTiers[name];
    if (!current) {
      reasons.push(`recorded tier ${name} is not a current harness tier`);
      continue;
    }
    if (!def || typeof def !== 'object' || Array.isArray(def)) {
      reasons.push(`recorded tier ${name} is not an object`);
      continue;
    }
    if (def.label !== current.label) {
      reasons.push(`recorded tier ${name} label ${JSON.stringify(def.label)} differs from the current harness label ${JSON.stringify(current.label)}`);
    }
    const recordedDevice = def.device === undefined ? null : def.device;
    if (recordedDevice !== current.device) {
      reasons.push(`recorded tier ${name} device ${JSON.stringify(recordedDevice)} differs from the current harness device ${JSON.stringify(current.device)}`);
    }
    if (def.cpuThrottle !== current.cpuThrottle) {
      reasons.push(`recorded tier ${name} cpuThrottle ${JSON.stringify(def.cpuThrottle)} differs from the current harness cpuThrottle ${JSON.stringify(current.cpuThrottle)}`);
    }
  }
  return reasons;
}
