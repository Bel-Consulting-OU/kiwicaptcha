#!/usr/bin/env node
/**
 * The SINGLE measurement-source-snapshot implementation of the
 * client-performance authority (tools/client-perf).
 *
 * ── Why (audit finding 1: the physical-run TOCTOU) ──────────────────
 *
 * The recorder's provenance must describe the immutable byte set the
 * repetitions ACTUALLY ran against, not "whatever the tree serves when
 * the payload is finalized". A multi-hour physical run on a local
 * machine can race an edit: the harness is loaded into memory at
 * version A, the tree moves to version B mid-run, and a payload-time
 * hash would stamp B on rows measured against A (or a mixed A/B asset
 * population). A start/end equality check cannot prove every
 * repetition used one byte set: a file can change and be restored
 * between checks.
 *
 * The fix: freeze the experiment at benchmark startup. This module
 * reads every repository-controlled input that determines what gets
 * measured ONCE, hashes those exact bytes into a canonical
 * measurement-source manifest, and (when a snapshot directory is
 * given) writes them into an immutable temporary benchmark directory
 * that the fixture server serves EXCLUSIVELY. The recorded manifest is
 * therefore the bytes the browser received, whatever happens to the
 * working tree afterwards.
 *
 * On top of the snapshot the harness verifies the WORKING TREE against
 * the frozen manifest before every cell and aborts as contaminated
 * when it moved: the evidence must describe the tree the operator
 * intends to commit, so a mid-run edit (even one later restored) is a
 * refusal, never a silently valid result.
 *
 * ── The canonical source set (audit finding 2) ──────────────────────
 *
 * The manifest hashes actual bytes for every benchmark-defining
 * authority:
 *
 *   - the harness source (tools/client-perf/client-perf.mjs),
 *   - the frozen launcher that re-executes the harness from a detached
 *     worktree of the committed bytes (tools/client-perf/run-frozen.mjs),
 *   - the asset-fingerprint policy (tools/client-perf/client-assets.mjs),
 *   - this freeze implementation and the canonical-JSON primitives it
 *     hashes with (tools/client-perf/measurement-sources.mjs,
 *     tools/client-perf/canonical-json.mjs),
 *   - the fixture workload authority (tests/browser/router.php),
 *   - the full execution grammar (protocol/execution-v1.json; its
 *     sha256 is additionally surfaced as execution.manifestSha256),
 *   - the canonical release asset set definition
 *     (packages/kiwicaptcha-wasm/release-assets.txt),
 *   - every canonical client asset (packages/kiwicaptcha-wasm/assets/*),
 *   - the fixture's executable PHP source trees, loaded through the
 *     router's deterministic PSR-4 loader (never through Composer):
 *     packages/kiwicaptcha-php/src, packages/kiwicaptcha-risk-php/src
 *     and packages/kiwicaptcha/integrations/symfony/src, plus the core
 *     composer.json. The Composer vendor tree is not executable
 *     benchmark input and is not part of the snapshot: a modified
 *     vendor/autoload.php can neither load fixture classes nor change
 *     the measurement identity;
 *   - the Node dependency the benchmark executes: the intended version
 *     from tests/browser/package.json and package-lock.json, and the
 *     exact installed @playwright/test, playwright and playwright-core
 *     trees (hashed but not copied by the harness snapshot, because the
 *     frozen launcher already copied them into the immutable worktree).
 *     Playwright drives browser launch, contexts, device descriptors,
 *     CPU throttling/CDP and navigation instrumentation, so its bytes
 *     are part of the measurement identity.
 *
 * The set is deliberately narrow. The manual qualification page
 * (tests/browser/autofill-qualification.php) is EXCLUDED by design:
 * editing it can never invalidate a performance recording, because it
 * never serves a benchmark request. Hashing narrow benchmark
 * authorities is cleaner than hashing the whole repository.
 *
 * The manifest digest (sha256 over the canonical JSON of the manifest)
 * is embedded in the measurement context, so evidence recorded against
 * one source manifest can never be certified for another.
 */
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, sha256Hex } from './canonical-json.mjs';
import { canonicalClientAssetNames } from './client-assets.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');

/** Plain files whose exact bytes determine the measurement. */
export const SOURCE_FILE_PATHS = [
  'tools/client-perf/client-perf.mjs',
  'tools/client-perf/run-frozen.mjs',
  'tools/client-perf/client-assets.mjs',
  'tools/client-perf/measurement-sources.mjs',
  'tools/client-perf/canonical-json.mjs',
  'tests/browser/router.php',
  // The intended Node dependency version (the lockfile) and the package
  // manifest: a tracked Playwright bump must change the measurement
  // identity even before the installed tree is considered.
  'tests/browser/package.json',
  'tests/browser/package-lock.json',
  'protocol/execution-v1.json',
  'packages/kiwicaptcha-wasm/release-assets.txt',
  'packages/kiwicaptcha-php/composer.json',
];

/**
 * Directories hashed as a canonical tree digest (every file bound).
 * These are the fixture's executable PHP inputs: the router loads them
 * through its deterministic PSR-4 loader, never through Composer, so
 * every class the benchmark executes is hashed.
 */
export const SOURCE_TREE_PATHS = [
  'packages/kiwicaptcha-php/src',
  'packages/kiwicaptcha-risk-php/src',
  'packages/kiwicaptcha/integrations/symfony/src',
];

/**
 * Trees hashed into the manifest but NOT copied by the harness snapshot
 * (the frozen launcher already made them immutable inside the frozen
 * worktree, and they are never served). These are the exact Playwright
 * bytes the benchmark executes: Playwright controls browser launch,
 * contexts, device descriptors, CPU throttling/CDP and navigation
 * instrumentation, so a modified installation must never run under an
 * unchanged measurement identity.
 */
export const HASH_ONLY_TREE_PATHS = [
  'tests/browser/node_modules/@playwright/test',
  'tests/browser/node_modules/playwright',
  'tests/browser/node_modules/playwright-core',
];

/**
 * Serving-only directories copied into the immutable snapshot but NOT
 * hashed. Empty by design: the fixture no longer executes anything
 * outside the hashed source trees, so there is no unhashed executable
 * input to carry into the snapshot.
 */
export const SERVED_COPY_DIRS = [];

export const ASSET_DIR_REL = 'packages/kiwicaptcha-wasm/assets';

function listFilesRecursive(root) {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) out.push(relative(root, full).split(sep).join('/'));
    }
  };
  walk(root);
  return out;
}

function copyTree(sourceRoot, targetRoot) {
  mkdirSync(targetRoot, { recursive: true });
  for (const rel of listFilesRecursive(sourceRoot)) {
    const dest = join(targetRoot, rel);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, readFileSync(join(sourceRoot, rel)));
  }
}

/**
 * Freeze the measurement sources. Without `snapshotRoot` this is a pure
 * read-and-hash (the current-tree side of the context comparison);
 * with `snapshotRoot` every hashed file and every serving-only
 * directory is also copied there, and the fixture server is pointed at
 * the copy (serve exclusively from the immutable snapshot).
 *
 * Returns:
 *   manifest       { "<repo-relative path>": { kind, bytes, files?, sha256 } }
 *   manifestSha256 sha256 over the canonical JSON of the manifest
 *   assetBodies    { "<asset name>": Buffer } for served-byte probes
 *   snapshotRoot   the immutable copy root, or null
 */
export function snapshotMeasurementSources({
  repoRoot = REPO_ROOT,
  snapshotRoot = null,
  filePaths = SOURCE_FILE_PATHS,
  treePaths = SOURCE_TREE_PATHS,
  hashOnlyTrees = HASH_ONLY_TREE_PATHS,
  servedCopyDirs = SERVED_COPY_DIRS,
  includeAssets = true,
} = {}) {
  const manifest = {};
  const assetBodies = {};
  const copyFile = (rel, bytes) => {
    if (!snapshotRoot) return;
    const dest = join(snapshotRoot, rel);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, bytes);
  };

  for (const rel of filePaths) {
    const bytes = readFileSync(join(repoRoot, rel));
    manifest[rel] = { kind: 'file', bytes: bytes.length, sha256: sha256Hex(bytes) };
    copyFile(rel, bytes);
  }

  for (const rel of treePaths) {
    const treeRoot = join(repoRoot, rel);
    if (!statSync(treeRoot).isDirectory()) {
      throw new Error(`measurement-sources: ${rel} is not a directory under ${repoRoot}`);
    }
    const entries = {};
    let total = 0;
    for (const fileRel of listFilesRecursive(treeRoot)) {
      const bytes = readFileSync(join(treeRoot, fileRel));
      entries[fileRel] = sha256Hex(bytes);
      total += bytes.length;
      copyFile(`${rel}/${fileRel}`, bytes);
    }
    manifest[rel] = {
      kind: 'tree',
      files: Object.keys(entries).length,
      bytes: total,
      sha256: sha256Hex(canonicalJson(entries)),
    };
  }

  for (const rel of hashOnlyTrees) {
    const treeRoot = join(repoRoot, rel);
    if (!statSync(treeRoot).isDirectory()) {
      throw new Error(`measurement-sources: ${rel} is not a directory under ${repoRoot}`);
    }
    const entries = {};
    let total = 0;
    for (const fileRel of listFilesRecursive(treeRoot)) {
      const bytes = readFileSync(join(treeRoot, fileRel));
      entries[fileRel] = sha256Hex(bytes);
      total += bytes.length;
    }
    manifest[rel] = {
      kind: 'tree',
      files: Object.keys(entries).length,
      bytes: total,
      sha256: sha256Hex(canonicalJson(entries)),
    };
  }

  if (includeAssets) {
    for (const name of canonicalClientAssetNames()) {
      const bytes = readFileSync(join(repoRoot, ASSET_DIR_REL, name));
      const rel = `${ASSET_DIR_REL}/${name}`;
      manifest[rel] = { kind: 'asset', bytes: bytes.length, sha256: sha256Hex(bytes) };
      assetBodies[name] = bytes;
      copyFile(rel, bytes);
    }
  }

  if (snapshotRoot) {
    for (const rel of servedCopyDirs) {
      copyTree(join(repoRoot, rel), join(snapshotRoot, rel));
    }
  }

  return {
    manifest,
    manifestSha256: sha256Hex(canonicalJson(manifest)),
    assetBodies,
    snapshotRoot,
  };
}

/**
 * Re-read the working tree and compare every manifest entry against the
 * frozen snapshot. Returns one human reason per missing file or
 * differing bytes (empty when the tree still matches). Called before
 * every cell by the harness: a tree that moved mid-run is contaminated
 * evidence and the run aborts.
 */
export function verifyMeasurementSources(snapshot, { repoRoot = REPO_ROOT } = {}) {
  const reasons = [];
  if (!snapshot || typeof snapshot !== 'object' || !snapshot.manifest) {
    return ['measurement-sources: no frozen snapshot to verify'];
  }
  let current;
  try {
    current = snapshotMeasurementSources({ repoRoot, snapshotRoot: null });
  } catch (e) {
    return [`measurement-sources: cannot re-read the working tree (${e.message})`];
  }
  const frozenNames = Object.keys(snapshot.manifest);
  const currentNames = Object.keys(current.manifest);
  for (const rel of frozenNames) {
    const frozen = snapshot.manifest[rel];
    const live = current.manifest[rel];
    if (!live) {
      reasons.push(`${rel} disappeared from the working tree (frozen ${frozen.sha256})`);
      continue;
    }
    if (live.sha256 !== frozen.sha256 || live.bytes !== frozen.bytes) {
      reasons.push(`${rel} changed during the run (frozen ${frozen.bytes} bytes / ${frozen.sha256}, working tree ${live.bytes} bytes / ${live.sha256})`);
    }
  }
  for (const rel of currentNames) {
    if (!Object.prototype.hasOwnProperty.call(snapshot.manifest, rel)) {
      reasons.push(`${rel} appeared in the working tree during the run (not part of the frozen measurement source set)`);
    }
  }
  if (current.manifestSha256 !== snapshot.manifestSha256 && reasons.length === 0) {
    reasons.push(`measurement source manifest digest changed during the run (frozen ${snapshot.manifestSha256}, working tree ${current.manifestSha256})`);
  }
  return reasons;
}

/**
 * The served URL(s) of each canonical asset on the benchmark page. The
 * fixture serves the wasm glue and the worker at fixed paths and every
 * other asset through the content-addressed files-tier route; the URL
 * hash is the full sha256 of the frozen bytes.
 */
export function servedAssetUrls(assetName, sha256) {
  switch (assetName) {
    case 'kiwicaptcha-wasm.js':
      return ['/kiwicaptcha-wasm.js', `/kiwi-captcha/assets/runtime.${sha256}.js`];
    case 'kiwi-worker.js':
      return ['/kiwi-worker.js', `/kiwi-captcha/assets/worker.${sha256}.js`];
    case 'widget-driver.js':
      return [`/kiwi-captcha/assets/driver.${sha256}.js`];
    case 'widget-risk.js':
      return [`/kiwi-captcha/assets/risk.${sha256}.js`];
    case 'widget-telemetry.js':
      return [`/kiwi-captcha/assets/telemetry.${sha256}.js`];
    case 'widget-locales.js':
      return [`/kiwi-captcha/assets/locales.${sha256}.js`];
    case 'widget.css':
      return [`/kiwi-captcha/assets/widget.${sha256}.css`];
    case 'execution-interpreter.js':
      return [`/kiwi-captcha/assets/execution.${sha256}.js`];
    default:
      // widget-compat.js rides the incumbent loader, never the benchmark page.
      return [];
  }
}

/**
 * Fetch every served asset URL and compare the served bytes against the
 * frozen manifest: the audit's "verify the actual served bytes against
 * those frozen hashes". A mismatch (or a non-200) is a hard reason.
 * The cache-buster query never reaches the router's path match.
 */
export async function probeServedMeasurementBytes(baseUrl, snapshot) {
  const issues = [];
  for (const [rel, entry] of Object.entries(snapshot.manifest)) {
    if (entry.kind !== 'asset') continue;
    const name = basename(rel);
    for (const url of servedAssetUrls(name, entry.sha256)) {
      const probe = `${baseUrl}${url}${url.includes('?') ? '&' : '?'}measurement-probe=${Math.random().toString(36).slice(2)}`;
      let response;
      try {
        response = await fetch(probe, { redirect: 'error' });
      } catch (e) {
        issues.push(`served asset ${url} could not be fetched (${e.message})`);
        continue;
      }
      if (response.status !== 200) {
        issues.push(`served asset ${url} answered HTTP ${response.status} instead of 200`);
        continue;
      }
      const body = Buffer.from(await response.arrayBuffer());
      const sha = sha256Hex(body);
      if (sha !== entry.sha256) {
        issues.push(`served asset ${url} differs from the frozen measurement source (served ${body.length} bytes / ${sha}, frozen ${entry.bytes} bytes / ${entry.sha256})`);
      }
    }
  }
  return issues;
}

/**
 * Fetch the benchmark page a cell is about to load and verify the
 * actual served bytes: every inline <script>/<style> block must hash to
 * a frozen canonical asset (the inline tier embeds the glue, driver,
 * risk module and stylesheet verbatim), and every content-addressed
 * asset reference must carry the frozen asset's full sha256. A page
 * this probe cannot attribute to the frozen source set aborts the run.
 */
export async function probeServedPage(baseUrl, pagePathAndQuery, snapshot) {
  const issues = [];
  const shaByName = new Map();
  const shaSet = new Set();
  for (const [rel, entry] of Object.entries(snapshot.manifest)) {
    if (entry.kind === 'asset') {
      shaByName.set(basename(rel), entry.sha256);
      shaSet.add(entry.sha256);
    }
  }
  const url = `${baseUrl}${pagePathAndQuery}${pagePathAndQuery.includes('?') ? '&' : '?'}measurement-probe=${Math.random().toString(36).slice(2)}`;
  let response;
  try {
    response = await fetch(url, { redirect: 'error' });
  } catch (e) {
    return [`benchmark page ${pagePathAndQuery} could not be fetched for the served-bytes probe (${e.message})`];
  }
  if (response.status !== 200) {
    return [`benchmark page ${pagePathAndQuery} answered HTTP ${response.status} instead of 200`];
  }
  const html = await response.text();
  // Every inline script/style block must be exactly one frozen asset
  // (the inline tier embeds the stylesheet, the wasm glue, the driver
  // and the risk module verbatim; the files tier embeds the
  // stylesheet only).
  const blocks = [
    ...html.matchAll(/<script>([\s\S]*?)<\/script>/g),
    ...html.matchAll(/<style>([\s\S]*?)<\/style>/g),
  ];
  for (const match of blocks) {
    const body = Buffer.from(match[1], 'utf8');
    const sha = sha256Hex(body);
    if (!shaSet.has(sha)) {
      issues.push(
        `benchmark page ${pagePathAndQuery} carries an inline block (${body.length} bytes / ${sha}) that is not any frozen canonical asset: the page is not served from the frozen measurement snapshot`
      );
      break;
    }
  }
  // Every content-addressed reference must carry the frozen asset hash.
  const routeToAsset = {
    widget: 'widget.css',
    runtime: 'kiwicaptcha-wasm.js',
    driver: 'widget-driver.js',
    worker: 'kiwi-worker.js',
    execution: 'execution-interpreter.js',
    risk: 'widget-risk.js',
    telemetry: 'widget-telemetry.js',
    locales: 'widget-locales.js',
  };
  for (const match of html.matchAll(/\/kiwi-captcha\/assets\/([a-z]+)\.([0-9a-f]{64})\.(?:js|css)/g)) {
    const [, routeName, sha] = match;
    const assetName = routeToAsset[routeName];
    if (!assetName) {
      issues.push(`benchmark page ${pagePathAndQuery} references an unknown asset route ${routeName}`);
      continue;
    }
    const frozen = shaByName.get(assetName);
    if (!frozen) {
      issues.push(`benchmark page ${pagePathAndQuery} references ${assetName}, which is not in the frozen asset set`);
      continue;
    }
    if (frozen !== sha) {
      issues.push(`benchmark page ${pagePathAndQuery} references ${assetName} at hash ${sha}, but the frozen asset hash is ${frozen}`);
    }
  }
  return issues;
}

/** Remove an immutable snapshot directory (idempotent). */
export function removeMeasurementSnapshot(snapshot) {
  if (snapshot && snapshot.snapshotRoot) {
    rmSync(snapshot.snapshotRoot, { recursive: true, force: true });
  }
}
