import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import Database from 'better-sqlite3';
import { goldenVectors } from './corpus.js';
import { runDoctor } from '../src/doctor.js';
import { MemoryStore } from '../src/stores/memory.js';
import { SqliteStore, type SqliteLike } from '../src/stores/sqlite.js';
import { RedisStore } from '../src/stores/redis.js';
import { RSW_T_MAX } from '../src/rsw.js';

/**
 * The doctor: secret strength, identifier shapes, store reachability
 * and exactly-once, and the optional rsw trapdoor pair.
 */

const SECRET = goldenVectors().hkdf.secret;

test('a sound deployment passes every check', async () => {
  const report = await runDoctor({ secret: SECRET, store: new MemoryStore() });
  assert.equal(report.ok, true);
  assert.deepEqual(
    report.checks.map((check) => check.name),
    ['secret', 'region', 'issuer', 'store'],
  );
  assert.equal(report.checks.every((check) => check.ok), true);
});

test('a short secret fails the doctor', async () => {
  const report = await runDoctor({ secret: 'short', store: new MemoryStore() });
  assert.equal(report.ok, false);
  assert.equal(report.checks.find((check) => check.name === 'secret')?.ok, false);
});

test('identifier shape violations are reported', async () => {
  const report = await runDoctor({
    secret: SECRET,
    store: new MemoryStore(),
    region: 'has space',
    issuer: 'ok-issuer',
  });
  assert.equal(report.ok, false);
  assert.equal(report.checks.find((check) => check.name === 'region')?.ok, false);
  assert.equal(report.checks.find((check) => check.name === 'issuer')?.ok, true);
});

test('a store that breaks single-use fails the doctor', async () => {
  // A store whose consume always reports a fresh win is not single-use.
  const lying = new MemoryStore();
  const patched = new Proxy(lying, {
    get(target, prop, receiver) {
      if (prop === 'consume') {
        return async () => ({
          record: (await target.find('missing')) as never,
          consumedNow: true,
          consumedBefore: false,
          consumedResult: null,
          operationIdentity: null,
        });
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  const report = await runDoctor({ secret: SECRET, store: patched as unknown as MemoryStore });
  assert.equal(report.ok, false);
  assert.equal(report.checks.find((check) => check.name === 'store')?.ok, false);
});

test('the sqlite store passes the doctor probe on a temp file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kiwi-doctor-'));
  try {
    const db = new Database(join(dir, 'kiwi.db'));
    const report = await runDoctor({
      secret: SECRET,
      store: new SqliteStore(db as unknown as SqliteLike),
    });
    assert.equal(report.ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an unreachable redis store fails the doctor with a typed detail', async () => {
  // Port 1 is never a Redis listener; the probe must fail closed.
  const client = {
    get: async () => {
      throw new Error('connection refused');
    },
    set: async () => {
      throw new Error('connection refused');
    },
    del: async () => undefined,
    pttl: async () => {
      throw new Error('connection refused');
    },
    eval: async () => {
      throw new Error('connection refused');
    },
    evalsha: async () => {
      throw new Error('connection refused');
    },
    script: async () => {
      throw new Error('connection refused');
    },
  };
  const report = await runDoctor({
    secret: SECRET,
    store: new RedisStore(client as unknown as import('../src/stores/redis.js').RedisLike),
  });
  assert.equal(report.ok, false);
  assert.match(report.checks.find((check) => check.name === 'store')?.detail ?? '', /probe failed/);
});

test('the rsw trapdoor check validates or rejects the configured pair', async () => {
  const { readProtocol } = await import('./corpus.js');
  const fx = readProtocol('rsw-identity-v1/fixtures.json') as { modulus_n_b64: string; lambda_b64: string };
  const good = await runDoctor({
    secret: SECRET,
    store: new MemoryStore(),
    rsw: { modulusN: fx.modulus_n_b64, lambda: fx.lambda_b64 },
  });
  assert.equal(good.ok, true);
  assert.equal(good.checks.find((check) => check.name === 'rsw')?.ok, true);
  const bad = await runDoctor({
    secret: SECRET,
    store: new MemoryStore(),
    rsw: { modulusN: Buffer.alloc(256, 0xff).toString('base64'), lambda: Buffer.of(0x02).toString('base64') },
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.checks.find((check) => check.name === 'rsw')?.ok, false);
  assert.ok(RSW_T_MAX > 0);
});
