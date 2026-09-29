#!/usr/bin/env node
/**
 * The frozen launcher for certifying client-performance runs
 * (tools/client-perf/run-frozen.mjs).
 *
 * A run that will back release evidence must not execute mutable
 * source. In-process runs freeze the measurement sources before the
 * first browser, but Node has already loaded the harness modules by
 * then: an edit made between module load and the snapshot read would be
 * executed as version A while the payload records version B. This
 * launcher closes that window by construction:
 *
 *   1. it refuses a dirty tracked tree (the run must describe committed
 *      bytes);
 *   2. it records HEAD and creates a detached git worktree of that
 *      exact commit;
 *   3. it COPIES the installed Playwright node_modules into the
 *      worktree (never a symlink): the benchmark executes the frozen
 *      copy and the manifest hashes the exact copied trees, so a
 *      modified original installation cannot run under an unchanged
 *      identity and a later mutation cannot affect a running run; the
 *      fixture executes only the committed PHP source trees and needs
 *      no Composer vendor;
 *   4. it re-executes tools/client-perf/client-perf.mjs FROM THE
 *      WORKTREE with the frozen origin recorded in the environment.
 *
 * The benchmark process therefore loads only the committed bytes, and
 * the payload's harnessOrigin field proves it. In-process runs remain
 * useful for development, but --promote-baseline, the physical
 * evidence merge and the release validator accept only runs whose
 * origin is "frozen-detached-worktree" (and whose fixture mode is
 * "owned-snapshot").
 *
 * Usage:
 *   node tools/client-perf/run-frozen.mjs [client-perf options]
 *   node tools/client-perf/run-frozen.mjs --tiers mainstream-desktop
 *
 * Exit status: the harness's exit status; 2 for launcher refusals.
 */
import { spawn, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256Hex } from './canonical-json.mjs';
import { hashTreeDigest } from './measurement-sources.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const LAUNCHER_SHA256 = sha256Hex(readFileSync(fileURLToPath(import.meta.url)));

function refuse(message) {
  console.error(`run-frozen: ${message}`);
  process.exit(2);
}

const args = process.argv.slice(2);
if (args.some((a) => a === '--promote-baseline')) {
  refuse('--promote-baseline is a loader mode, not a benchmark run; execute it directly with node tools/client-perf/client-perf.mjs --promote-baseline FILE (the loader checks the recorded origin itself)');
}

// 0. Reject ambient Node controls. A certifying run must not preload
//    untracked JavaScript through the environment or through the node
//    invocation: NODE_OPTIONS (--require/--import/--loader) and any
//    execArgv flags would execute code outside the frozen tree.
if ((process.env.NODE_OPTIONS ?? '').trim() !== '') {
  refuse(`NODE_OPTIONS is set (${JSON.stringify(process.env.NODE_OPTIONS)}); a certifying run refuses injected Node controls — unset it and start the launcher plain`);
}
if (process.execArgv.length > 0) {
  refuse(`unexpected Node execArgv ${JSON.stringify(process.execArgv)}; start the launcher as plain \`node tools/client-perf/run-frozen.mjs\``);
}

function git(gitArgs, { allowFailure = false } = {}) {
  const result = spawnSync('git', ['-C', REPO_ROOT, ...gitArgs], { encoding: 'utf8' });
  if (result.status !== 0 && !allowFailure) {
    refuse(`git ${gitArgs.join(' ')} failed: ${(result.stderr || result.stdout || '').trim()}`);
  }
  return result;
}

// 1. The run must describe committed bytes: no staged or unstaged
//    changes to tracked files. Untracked and ignored files (vendor,
//    node_modules, results files) do not affect the measurement sources.
const status = git(['status', '--porcelain', '--untracked-files=no']);
if (status.stdout.trim() !== '') {
  refuse(
    `the tracked working tree is not clean; commit or stash before a certifying run (the launcher executes the committed bytes, never a dirty tree)\n${status.stdout.trim()}`,
  );
}
const commit = git(['rev-parse', 'HEAD']).stdout.trim();
if (!/^[0-9a-f]{40}$/.test(commit)) {
  refuse(`cannot resolve HEAD to a commit (got ${JSON.stringify(commit)})`);
}

// 2. The detached worktree of that exact commit.
const tempRoot = mkdtempSync(join(tmpdir(), 'kiwicaptcha-client-perf-frozen-'));
const tree = join(tempRoot, 'tree');
const add = git(['worktree', 'add', '--detach', tree, commit], { allowFailure: true });
if (add.status !== 0) {
  rmSync(tempRoot, { recursive: true, force: true });
  refuse(`cannot create the frozen worktree at ${tree}: ${(add.stderr || add.stdout || '').trim()}`);
}

function cleanup() {
  spawnSync('git', ['-C', REPO_ROOT, 'worktree', 'remove', '--force', tree], { encoding: 'utf8' });
  spawnSync('git', ['-C', REPO_ROOT, 'worktree', 'prune'], { encoding: 'utf8' });
  rmSync(tempRoot, { recursive: true, force: true });
}
process.on('exit', cleanup);

// 3. The untracked runtime dependency the harness needs: Playwright's
//    node_modules. It is COPIED into the worktree, never symlinked: the
//    benchmark executes the frozen copy, and the measurement-source
//    manifest hashes the exact copied @playwright/test, playwright and
//    playwright-core trees. A modified original installation can
//    therefore never run under an unchanged identity, and a mutation
//    after the copy can never affect the running experiment. The
//    fixture executes only the committed PHP source trees through its
//    deterministic loader, so no Composer vendor tree is linked or
//    copied.
for (const rel of ['tests/browser/node_modules']) {
  const target = join(REPO_ROOT, rel);
  if (!existsSync(target)) {
    cleanup();
    refuse(`missing runtime dependency ${rel} in ${REPO_ROOT}; run npm ci in tests/browser before a certifying run`);
  }
  const dest = join(tree, rel);
  if (existsSync(dest)) {
    cleanup();
    refuse(`the frozen worktree already contains ${rel}; refusing to overwrite it`);
  }
  try {
    cpSync(target, dest, { recursive: true });
  } catch (e) {
    cleanup();
    refuse(`cannot copy ${rel} into the frozen worktree: ${e.message}`);
  }
}

// 3b. The Playwright browser bundle: resolve the exact executable with
//     the installed Playwright (ignoring any ambient
//     PLAYWRIGHT_BROWSERS_PATH, which could redirect to another
//     installation), copy the bundle into the frozen run directory and
//     force the child to that immutable copy. The harness re-hashes the
//     copied bundle into the run's runtime identity, so two Chromium
//     installations that merely report the same version can never share
//     an evidence identity, and mutating the original cache after the
//     copy cannot affect the running experiment.
// The ambient PLAYWRIGHT_BROWSERS_PATH must be neutralized BEFORE
// playwright-core is loaded: the package captures the browsers path at
// import time, so deleting it afterwards would not affect resolution.
const ambientBrowsersPath = process.env.PLAYWRIGHT_BROWSERS_PATH;
delete process.env.PLAYWRIGHT_BROWSERS_PATH;
const browserRequire = createRequire(join(tree, 'tests', 'browser', 'package.json'));
let chromiumApi;
try {
  ({ chromium: chromiumApi } = browserRequire('playwright-core'));
} catch (e) {
  cleanup();
  refuse(`cannot load playwright-core from the frozen worktree: ${e.message}`);
}
let browserExecutable;
try {
  browserExecutable = chromiumApi.executablePath();
} catch (e) {
  cleanup();
  refuse(`cannot resolve the Playwright Chromium executable: ${e.message}`);
}
if (ambientBrowsersPath !== undefined && ambientBrowsersPath !== '') {
  console.log(`run-frozen: ignoring the ambient PLAYWRIGHT_BROWSERS_PATH ${JSON.stringify(ambientBrowsersPath)}; the certifying run resolves and copies the default installation`);
}
if (!browserExecutable || !existsSync(browserExecutable)) {
  cleanup();
  refuse(`the Playwright Chromium executable is missing at ${browserExecutable ?? '(unresolved)'}; run npx playwright install chromium before a certifying run`);
}
let bundleRoot = dirname(browserExecutable);
while (bundleRoot !== dirname(bundleRoot) && !/^chromium(-headless-shell)?-\d+$/.test(basename(bundleRoot))) {
  bundleRoot = dirname(bundleRoot);
}
if (!/^chromium(-headless-shell)?-\d+$/.test(basename(bundleRoot))) {
  cleanup();
  refuse(`cannot find the Chromium bundle root above ${browserExecutable}`);
}
const browsersDir = join(tempRoot, 'browsers');
mkdirSync(browsersDir, { recursive: true });
const frozenBundle = join(browsersDir, basename(bundleRoot));
try {
  cpSync(bundleRoot, frozenBundle, { recursive: true });
} catch (e) {
  cleanup();
  refuse(`cannot copy the Chromium bundle into the frozen run directory: ${e.message}`);
}
const browserTreeSha = hashTreeDigest(frozenBundle);

console.log(
  `run-frozen: executing ${commit.slice(0, 12)} from the frozen worktree ${tree} (launcher sha256 ${LAUNCHER_SHA256.slice(0, 12)}, owned snapshot fixture, dirty-tree refusal armed, Node controls refused, Chromium bundle ${basename(bundleRoot)} copied and frozen with tree sha256 ${browserTreeSha.slice(0, 12)})`,
);

// 4. Re-execute the harness from the frozen worktree with an
//    ALLOWLISTED environment: ambient NODE_OPTIONS, PHPRC,
//    PHP_INI_SCAN_DIR and PLAYWRIGHT_BROWSERS_PATH can never reach the
//    benchmark process; the harness freezes the PHP configuration and
//    browser path itself. The child's cwd stays the caller's directory,
//    so relative --out paths land in the invoking repository.
const childEnv = {
  PATH: process.env.PATH ?? '/usr/bin:/bin:/usr/sbin:/sbin',
  HOME: process.env.HOME ?? tmpdir(),
  TMPDIR: process.env.TMPDIR ?? tmpdir(),
  LANG: process.env.LANG ?? 'en_US.UTF-8',
  KIWI_PERF_FROZEN: '1',
  KIWI_PERF_FROZEN_COMMIT: commit,
  KIWI_PERF_FROZEN_LAUNCHER_SHA256: LAUNCHER_SHA256,
  KIWI_PERF_FROZEN_TREE: tree,
  PLAYWRIGHT_BROWSERS_PATH: browsersDir,
};
const child = spawn(process.execPath, [join(tree, 'tools', 'client-perf', 'client-perf.mjs'), ...args], {
  stdio: 'inherit',
  env: childEnv,
});
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => {
    try {
      child.kill(signal);
    } catch (e) {
      /* the child already exited */
    }
  });
}
child.on('exit', (code, signal) => {
  cleanup();
  if (signal) {
    console.error(`run-frozen: the harness was terminated by ${signal}`);
    process.exit(1);
  }
  process.exit(code ?? 1);
});
