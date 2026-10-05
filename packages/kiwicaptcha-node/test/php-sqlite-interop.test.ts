import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import DatabaseDefault from 'better-sqlite3';
import { goldenVectors, PACKAGE_ROOT } from './corpus.js';
import { SqliteStore, type SqliteLike } from '../src/stores/sqlite.js';
import { verify } from '../src/verify.js';

/**
 * The live cross-adapter SQLite check: the PHP core writes a pending
 * golden record into one database file through its SqliteStorage, and
 * this SDK reads, consumes and verifies it from the same file with the
 * MAC-carrying commit. Skipped when the PHP vendor tree or the
 * pdo_sqlite extension is unavailable.
 */

const Database = DatabaseDefault as unknown as new (path: string) => unknown;
const HERE = dirname(fileURLToPath(import.meta.url));
const PHP_ROOT = resolve(PACKAGE_ROOT, '..', 'kiwicaptcha-php');
const PHP_AUTOLOAD = join(PHP_ROOT, 'vendor', 'autoload.php');
const FIXTURE = join(PACKAGE_ROOT, 'test', 'fixtures', 'golden-php-vectors.json');

function phpHasSqlite(): boolean {
  if (!existsSync(PHP_AUTOLOAD)) {
    return false;
  }
  try {
    const modules = execFileSync('php', ['-m'], { encoding: 'utf8' });
    return modules.includes('pdo_sqlite');
  } catch {
    return false;
  }
}

const phpAvailable = phpHasSqlite();

function writerScript(dbDir: string): string {
  return `<?php
declare(strict_types=1);
require ${JSON.stringify(PHP_AUTOLOAD)};
use KiwiCaptcha\\ChallengeRecord;
use KiwiCaptcha\\Storage\\SqliteStorage;
$payload = json_decode(file_get_contents(${JSON.stringify(FIXTURE)}), true);
$record = ChallengeRecord::fromArray($payload['records'][0]['record']);
// The golden record travels back to its issuance era on the PHP
// storage clock too, mirroring the Node side.
$issuedAt = $record->issuedAt;
$storage = new SqliteStorage(${JSON.stringify(join(dbDir, 'shared.db'))}, 5000, 60, fn (): int => $issuedAt + 10);
$storage->store($record);
if ($storage->find($record->nonce) === null) { fwrite(STDERR, "php could not read back\n"); exit(1); }
echo "stored\n";
`;
}

test('php: a PHP-written sqlite record verifies in this SDK with the MAC commit', { skip: !phpAvailable }, async () => {
  const golden = goldenVectors();
  const row = golden.records[0] as import('./corpus.js').GoldenRecord;
  assert.equal(row.name, 'sha_plain');
  const record = row.record as Record<string, unknown>;
  const issuedAt = record['issued_at'] as number;
  const issuedAtNs = record['issued_at_ns'] as number;
  const nonce = record['nonce'] as string;
  const dir = mkdtempSync(join(tmpdir(), 'kiwi-php-sqlite-'));
  try {
    const scriptPath = join(dir, 'writer.php');
    writeFileSync(scriptPath, writerScript(dir));
    const out = execFileSync('php', [scriptPath], { encoding: 'utf8' });
    assert.equal(out.trim(), 'stored');
    const db = new Database(join(dir, 'shared.db')) as unknown as SqliteLike;
    const store = new SqliteStore(db, { now: () => issuedAt + 10 });
    assert.ok((await store.find(nonce)) !== null, 'the PHP-written record must read back in Node');
    const result = await verify(row.token_b64, {
      storage: store,
      secretKey: golden.hkdf.secret,
      expectedScope: 'login',
      now: () => issuedAt + 10,
      nowNs: issuedAtNs + 2_000_000,
    });
    assert.equal(result.ok, true);
    // The verify already committed the MAC-carrying result exactly once.
    assert.equal(await store.commitResult(nonce, true, null, 'a'.repeat(64)), false);
    const retained = await store.runtimeState(nonce);
    assert.equal(retained.kind, 'consumed');
    assert.ok(retained.consumed?.consumedResult?.mac !== null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
