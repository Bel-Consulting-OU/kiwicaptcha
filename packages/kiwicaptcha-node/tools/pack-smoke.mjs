#!/usr/bin/env node
/**
 * Pack smoke test: prove that what `npm pack` ships is installable and
 * usable from a clean consumer project — not just runnable from this
 * working tree.
 *
 * Three isolated temp directories, one job each:
 *   1. pack     — `npm pack --pack-destination` produces the publish tarball
 *   2. extract  — the tarball is unpacked so its layout can be inspected
 *   3. consumer — a minimal project installs the tarball with
 *                 `npm install --no-save`, imports the published entry and
 *                 runs the published `kiwicaptcha-doctor` bin
 *
 * The consumer install must succeed with no registry fetches for the
 * package itself (its runtime deps are Node builtins; better-sqlite3 and
 * ioredis are optional peers) and the entry must expose `verify`.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const pkgDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
const pkgName = pkgJson.name;

function fail(message) {
  console.error(`pack-smoke: FAIL: ${message}`);
  process.exit(1);
}

function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, {
    cwd: opts.cwd ?? pkgDir,
    encoding: 'utf8',
    timeout: opts.timeoutMs ?? 120_000,
    shell: opts.shell ?? false,
    env: opts.env ?? process.env,
  });
  if (res.error) fail(`${cmd} ${args.join(' ')} could not start: ${res.error.message}`);
  if (res.status !== 0) {
    fail(
      `${cmd} ${args.join(' ')} exited ${res.status} in ${opts.cwd ?? pkgDir}\n` +
        `--- stdout ---\n${res.stdout ?? ''}\n--- stderr ---\n${res.stderr ?? ''}`,
    );
  }
  return res;
}

// The smoke consumes the built package; build it explicitly so the
// script is self-contained (a stale or missing dist/ would pack an
// empty tarball and fail somewhere unintelligible instead).
run(process.execPath, [path.join(pkgDir, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json']);

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'kiwi-pack-smoke-'));
try {
  // 1. Pack into the first temp dir.
  const packDir = path.join(tmpRoot, 'pack');
  fs.mkdirSync(packDir);
  const packed = run('npm', ['pack', '--pack-destination', packDir, '--loglevel', 'error']);
  const tarballName = packed.stdout.trim().split('\n').filter(Boolean).pop();
  if (!tarballName || !tarballName.endsWith('.tgz')) {
    fail(`npm pack did not report a tarball name; got: ${JSON.stringify(packed.stdout)}`);
  }
  const tarball = path.join(packDir, tarballName);
  if (!fs.existsSync(tarball)) fail(`npm pack reported ${tarballName} but it does not exist`);
  console.log(`pack-smoke: packed ${tarballName} (${fs.statSync(tarball).size} bytes)`);

  // 2. Extract into the second temp dir and check the shipped layout.
  const extractDir = path.join(tmpRoot, 'extract');
  fs.mkdirSync(extractDir);
  run('tar', ['-xzf', tarball, '-C', extractDir], { timeoutMs: 60_000 });
  const unpacked = path.join(extractDir, 'package');
  const shippedEntry = path.join(unpacked, 'dist', 'src', 'index.js');
  const shippedCli = path.join(unpacked, 'dist', 'src', 'cli.js');
  for (const f of [shippedEntry, shippedCli, path.join(unpacked, 'package.json')]) {
    if (!fs.existsSync(f)) fail(`tarball is missing ${path.relative(unpacked, f)}`);
  }
  const shippedPkg = JSON.parse(fs.readFileSync(path.join(unpacked, 'package.json'), 'utf8'));
  if (shippedPkg.name !== pkgName || shippedPkg.version !== pkgJson.version) {
    fail(`tarball package.json identity mismatch: ${shippedPkg.name}@${shippedPkg.version}`);
  }
  console.log('pack-smoke: tarball layout OK (dist entry, cli bin, package.json)');

  // 3. Install the tarball into a third, clean consumer project.
  const consumerDir = path.join(tmpRoot, 'consumer');
  fs.mkdirSync(consumerDir);
  fs.writeFileSync(
    path.join(consumerDir, 'package.json'),
    JSON.stringify({ name: 'pack-smoke-consumer', private: true, version: '0.0.0' }, null, 2) + '\n',
  );
  run('npm', ['install', '--no-save', '--no-audit', '--no-fund', '--loglevel', 'error', tarball], {
    cwd: consumerDir,
    timeoutMs: 300_000,
  });
  const installedEntry = path.join(consumerDir, 'node_modules', ...pkgName.split('/'), 'dist', 'src', 'index.js');
  if (!fs.existsSync(installedEntry)) fail(`installed tree is missing ${path.relative(consumerDir, installedEntry)}`);
  console.log(`pack-smoke: ${pkgName} installed into a clean consumer project`);

  // 4a. The published entry resolves and exposes the verify API.
  const importCheck =
    `import(${JSON.stringify(pkgName)})` +
    `.then(m => { if (typeof m.verify !== 'function') throw new Error('verify missing'); ` +
    `if (typeof m.runDoctor !== 'function') throw new Error('runDoctor missing'); ` +
    `console.log('entry OK'); })` +
    `.catch(e => { console.error(e); process.exit(1); })`;
  const entryRes = run(process.execPath, ['-e', importCheck], {
    cwd: consumerDir,
    timeoutMs: 60_000,
  });
  if (!entryRes.stdout.includes('entry OK')) fail(`entry import did not confirm: ${entryRes.stdout}`);
  console.log(`pack-smoke: import('${pkgName}') resolves with verify/runDoctor`);

  // 4b. The published bin works through node_modules/.bin.
  const binName = Object.keys(pkgJson.bin ?? {})[0];
  if (!binName) fail('package.json declares no bin');
  const binRel = ['node_modules', '.bin', binName + (process.platform === 'win32' ? '.cmd' : '')].join('/');
  const binPath = path.join(consumerDir, binRel);
  if (!fs.existsSync(binPath)) fail(`installed bin link missing: ${binRel}`);
  const help = run(process.execPath, [binPath, '--help'], { cwd: consumerDir, timeoutMs: 60_000 });
  if (!/usage|kiwicaptcha-doctor/i.test(help.stdout + help.stderr)) {
    fail(`bin --help printed no recognizable usage: ${help.stdout} ${help.stderr}`);
  }
  console.log(`pack-smoke: bin ${binName} --help works through node_modules/.bin`);

  console.log('pack-smoke: PASS');
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true, maxRetries: 3 });
}
