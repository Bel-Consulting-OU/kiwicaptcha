#!/usr/bin/env node
/**
 * The SINGLE client-asset fingerprint implementation of the
 * client-performance authority (tools/client-perf).
 *
 * Every consumer that records, merges, promotes or validates client
 * performance evidence fingerprints the served client assets through
 * this module — client-perf.mjs (recording runs), sync-lab-baseline.mjs
 * and merge-cells.mjs (building merged evidence), and
 * tools/ci/validate-release-baseline.mjs (the release gate). The
 * fingerprint policy is fixed here and nowhere else:
 *
 *   - the canonical client asset set is the repo's release asset
 *     manifest (packages/kiwicaptcha-wasm/release-assets.txt, the set
 *     tools/ci/release-asset-contract.sh guards across the release
 *     workflow, the SRI list and the strict-rebuild block),
 *   - every asset is read from the repo path the harness serves
 *     (packages/kiwicaptcha-wasm/assets/<name>),
 *   - every asset is hashed with FULL SHA-256 (64 lowercase hex, never
 *     a truncated prefix: a 16-hex prefix binds only 64 bits and cannot
 *     distinguish the recorded bytes from a different file of the same
 *     length), alongside its exact byte count.
 *
 * The recorded shape is the payload block
 *
 *   "clientAssets": { "<name>": { "bytes": N, "sha256": "<64 hex>" } }
 *
 * recorded by every completed run. assertAssetSetCurrent() is the
 * audit's comparison: the recorded block must name exactly the current
 * canonical set, and every named asset must match the current tree's
 * bytes AND sha256 — anything less means the performance rows were not
 * measured against the bytes they are claimed to certify.
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const ASSETS_DIR = join(REPO_ROOT, 'packages', 'kiwicaptcha-wasm', 'assets');
const MANIFEST = join(REPO_ROOT, 'packages', 'kiwicaptcha-wasm', 'release-assets.txt');

// Asset names may only be plain release file names (the same pattern
// the release-asset-contract carrier scans use); anything else would
// be a path traversal out of the assets directory.
const ASSET_NAME_RE = /^[A-Za-z0-9._-]+$/;

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/**
 * The canonical client asset names, in the manifest's order: the
 * release asset set (packages/kiwicaptcha-wasm/release-assets.txt).
 * Blank lines and '#' comment lines are ignored. A manifest that names
 * no assets is a broken authority and fails loudly.
 */
export function canonicalClientAssetNames() {
  const lines = readFileSync(MANIFEST, 'utf8').split('\n');
  const names = [];
  for (const raw of lines) {
    const name = raw.trim();
    if (name === '' || name.startsWith('#')) continue;
    if (!ASSET_NAME_RE.test(name)) {
      throw new Error(
        `client-assets: manifest ${MANIFEST} names ${JSON.stringify(name)}, which is not a plain release asset file name; update the manifest`
      );
    }
    names.push(name);
  }
  if (names.length === 0) {
    throw new Error(`client-assets: the canonical asset manifest ${MANIFEST} names no assets`);
  }
  return names;
}

/**
 * Fingerprint the canonical client asset set of the CURRENT working
 * tree: { "<name>": { "bytes": N, "sha256": "<64 lowercase hex>" } },
 * read from the repo path the harness serves. A canonical asset whose
 * file is missing or unreadable is a hard error: evidence can never be
 * recorded, merged or certified against an incomplete asset tree.
 */
export function canonicalClientAssets() {
  const names = canonicalClientAssetNames();
  const out = {};
  const missing = [];
  for (const name of names) {
    const file = join(ASSETS_DIR, name);
    let bytes;
    try {
      bytes = readFileSync(file);
    } catch (e) {
      missing.push(name);
      continue;
    }
    out[name] = {
      bytes: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    };
  }
  if (missing.length) {
    throw new Error(
      `client-assets: canonical client asset(s) missing from ${ASSETS_DIR}: ${missing.join(', ')} (the working tree does not match the release asset manifest)`
    );
  }
  return out;
}

/**
 * Audit comparison: the RECORDED clientAssets block versus the CURRENT
 * canonical fingerprints. Appends a hard reason for every difference
 * and returns the number of reasons appended:
 *
 *   - a missing or non-object recorded block (the record carries no
 *     identity: its performance rows are not bound to any bytes),
 *   - a name-set difference: 'client asset set differs from current
 *     release asset set' (a recorded extra asset, or a current asset
 *     the record lacks — a run recorded against a different asset
 *     universe),
 *   - a per-asset difference: 'client asset <name> does not match
 *     current bytes' (byte-count difference, or a sha256 difference —
 *     the record's bytes are not the current tree's bytes).
 *
 * The reason strings carry the exact audit phrases, plus the recorded
 * vs current values so a refusal names what drifted.
 *
 * @param {object|null|undefined} recorded the payload's clientAssets
 *   block ({ name -> { bytes, sha256 } }), or absent
 * @param {object} current the canonicalClientAssets() of the tree the
 *   evidence is being bound to
 * @param {string[]} reasons the validator/promoter/merge reason array
 *   to append to
 * @returns {number} the number of reasons appended
 */
export function assertAssetSetCurrent(recorded, current, reasons) {
  let added = 0;
  const add = (reason) => {
    reasons.push(reason);
    added += 1;
  };
  if (!recorded || typeof recorded !== 'object' || Array.isArray(recorded)) {
    add('clientAssets missing from the record: the performance rows are not bound to the client bytes they certify (client asset set differs from current release asset set)');
    return added;
  }
  const recordedNames = Object.keys(recorded);
  const currentNames = Object.keys(current);
  const currentNameSet = new Set(currentNames);
  for (const name of recordedNames) {
    if (!currentNameSet.has(name)) {
      add(`client asset set differs from current release asset set: recorded clientAssets carries ${JSON.stringify(name)}, which is not in the current release asset set (extra asset)`);
    }
  }
  for (const name of currentNames) {
    if (!Object.prototype.hasOwnProperty.call(recorded, name)) {
      add(`client asset set differs from current release asset set: recorded clientAssets lacks ${name} of the current release asset set (missing asset)`);
    }
  }
  for (const name of currentNames) {
    if (!Object.prototype.hasOwnProperty.call(recorded, name)) continue;
    const rec = recorded[name];
    const cur = current[name];
    const validEntry =
      rec &&
      typeof rec === 'object' &&
      !Array.isArray(rec) &&
      typeof rec.bytes === 'number' &&
      Number.isInteger(rec.bytes) &&
      rec.bytes > 0 &&
      typeof rec.sha256 === 'string' &&
      SHA256_HEX_RE.test(rec.sha256);
    if (!validEntry) {
      add(`client asset ${name} has an invalid fingerprint record (expected { bytes: N, sha256: "<64 hex>" }; got ${JSON.stringify(rec)})`);
      continue;
    }
    if (rec.bytes !== cur.bytes) {
      add(`client asset ${name} does not match current bytes (recorded ${rec.bytes} bytes / sha256 ${rec.sha256}, current ${cur.bytes} bytes / sha256 ${cur.sha256})`);
      continue;
    }
    if (rec.sha256 !== cur.sha256) {
      add(`client asset ${name} does not match current bytes (bytes equal at ${cur.bytes}, but the recorded sha256 ${rec.sha256} differs from the current ${cur.sha256})`);
    }
  }
  return added;
}
