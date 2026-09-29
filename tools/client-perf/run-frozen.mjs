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
 *   3. it links the untracked runtime dependency (Playwright's
 *      node_modules) into the worktree; the fixture executes only the
 *      committed PHP source trees and needs no Composer vendor;
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
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256Hex } from './canonical-json.mjs';

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
//    node_modules (module resolution). The fixture executes only the
//    committed PHP source trees through its deterministic loader, so no
//    Composer vendor tree is linked or copied.
for (const rel of ['tests/browser/node_modules']) {
  const target = join(REPO_ROOT, rel);
  if (!existsSync(target)) {
    cleanup();
    refuse(`missing runtime dependency ${rel} in ${REPO_ROOT}; install it before a certifying run`);
  }
  const link = join(tree, rel);
  if (existsSync(link)) {
    cleanup();
    refuse(`the frozen worktree already contains ${rel}; refusing to shadow it`);
  }
  symlinkSync(target, link, 'dir');
}

console.log(
  `run-frozen: executing ${commit.slice(0, 12)} from the frozen worktree ${tree} (launcher sha256 ${LAUNCHER_SHA256.slice(0, 12)}, owned snapshot fixture, dirty-tree refusal armed)`,
);

// 4. Re-execute the harness from the frozen worktree. The child's cwd
//    stays the caller's directory, so relative --out paths land in the
//    invoking repository.
const child = spawn(process.execPath, [join(tree, 'tools', 'client-perf', 'client-perf.mjs'), ...args], {
  stdio: 'inherit',
  env: {
    ...process.env,
    KIWI_PERF_FROZEN: '1',
    KIWI_PERF_FROZEN_COMMIT: commit,
    KIWI_PERF_FROZEN_LAUNCHER_SHA256: LAUNCHER_SHA256,
    KIWI_PERF_FROZEN_TREE: tree,
  },
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
