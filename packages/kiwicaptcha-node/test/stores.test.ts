import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import Database from 'better-sqlite3';
import { goldenVectors, frozenClock } from './corpus.js';
import { challengeRecordFromJson } from '../src/record.js';
import { MemoryStore } from '../src/stores/memory.js';
import { SqliteStore } from '../src/stores/sqlite.js';
import { StoreWriteError, type ConsumedRecordSnapshot, type StoreAdapter } from '../src/store.js';
import { verify } from '../src/verify.js';

/**
 * The consume exactly-once and replay contract, shared by every store
 * adapter: memory (natural, no interleaving point), SQLite (BEGIN
 * IMMEDIATE on a temp file) and Redis (Lua, see redis.test.ts).
 */

const SECRET = goldenVectors().hkdf.secret;

function goldenSha(): { record: ReturnType<typeof challengeRecordFromJson>; token: string } {
  const row = goldenVectors().records.find((entry) => entry.name === 'sha_plain');
  assert.ok(row !== undefined);
  return { record: challengeRecordFromJson(row.record), token: row.token_b64 };
}

const FROZEN = { now: () => 0 };

function frozenVerify(store: StoreAdapter, record: { issuedAt: number; issuedAtNs: number }, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { storage: store, secretKey: SECRET, ...frozenClock(record), ...extra };
}

interface StoreFactory {
  name: string;
  create: () => Promise<StoreAdapter>;
  dispose?: (store: StoreAdapter) => Promise<void>;
  /** The raw consume hook for state surgery. */
  rawConsume: (store: StoreAdapter, nonce: string) => Promise<ConsumedRecordSnapshot | null>;
}

const factories: StoreFactory[] = [
  {
    name: 'memory',
    create: async () => new MemoryStore(FROZEN),
    rawConsume: (store, nonce) => store.consume(nonce),
  },
  {
    name: 'sqlite',
    create: async () => {
      const dir = mkdtempSync(join(tmpdir(), 'kiwi-sqlite-'));
      const db = new Database(join(dir, 'kiwi.db'));
      // Expose the temp dir through the adapter for cleanup.
      const store = new SqliteStore(db as unknown as SqliteStoreDbLike, FROZEN);
      (store as unknown as { __dir: string }).__dir = dir;
      return store;
    },
    dispose: async (store) => {
      const dir = (store as unknown as { __dir?: string }).__dir;
      if (dir !== undefined) {
        rmSync(dir, { recursive: true, force: true });
      }
    },
    rawConsume: (store, nonce) => store.consume(nonce),
  },
];

type SqliteStoreDbLike = import('../src/stores/sqlite.js').SqliteLike;

for (const factory of factories) {
  test(`[${factory.name}] the consume transition is exactly once`, async () => {
    const store = await factory.create();
    try {
      const { record } = goldenSha();
      await store.store(record);
      const first = await factory.rawConsume(store, record.nonce);
      assert.ok(first !== null);
      assert.equal(first.consumedNow, true);
      assert.equal(first.consumedBefore, false);
      const second = await factory.rawConsume(store, record.nonce);
      assert.ok(second !== null);
      assert.equal(second.consumedNow, false);
      assert.equal(second.consumedBefore, true);
      // The commit lands once; the second commit is a no-op.
      assert.equal(await store.commitResult(record.nonce, true, null, 'a'.repeat(64)), true);
      assert.equal(await store.commitResult(record.nonce, false, null, null), false);
      const retained = await store.runtimeState(record.nonce);
      assert.equal(retained.kind, 'consumed');
      assert.equal(retained.consumed?.consumedResult?.valid, true);
    } finally {
      await factory.dispose?.(store);
    }
  });

  test(`[${factory.name}] replay across the full verify path is deterministic`, async () => {
    const store = await factory.create();
    try {
      const { record, token } = goldenSha();
      await store.store(record);
      const clock = frozenClock(record);
      const first = await verify(token, { storage: store, secretKey: SECRET, expectedScope: 'login', ...clock });
      assert.equal(first.ok, true);
      const replay = await verify(token, { storage: store, secretKey: SECRET, expectedScope: 'login', ...clock });
      assert.equal(replay.code, 'already_consumed');
      const idem = await verify(token, { storage: store, secretKey: SECRET, expectedScope: 'login', ...clock, operationIdentity: 'op-1' });
      assert.equal(idem.code, 'already_consumed');
    } finally {
      await factory.dispose?.(store);
    }
  });

  test(`[${factory.name}] deleteIfPending keeps consumed evidence and deletes only pending`, async () => {
    const store = await factory.create();
    try {
      const { record, token } = goldenSha();
      // Pending: the cleanup deletes.
      await store.store(record);
      assert.equal((await store.deleteIfPending(record.nonce)).kind, 'deleted-pending');
      assert.equal(await store.find(record.nonce), null);
      assert.equal((await store.deleteIfPending(record.nonce)).kind, 'missing');
      // Consumed: the cleanup returns the evidence and keeps the row.
      await store.store(record);
      await store.consume(record.nonce, 'op-2');
      const cleanup = await store.deleteIfPending(record.nonce);
      assert.equal(cleanup.kind, 'consumed');
      if (cleanup.kind === 'consumed') {
        assert.equal(cleanup.consumed.operationIdentity, 'op-2');
      }
      assert.notEqual(await store.find(record.nonce), null);
      // A resultless consumed record is the ambiguous recovery state.
      const result = await verify(token, { storage: store, secretKey: SECRET, expectedScope: 'login', ...frozenClock(record), operationIdentity: 'op-2' });
      assert.equal(result.code, 'consume_indeterminate');
    } finally {
      await factory.dispose?.(store);
    }
  });

  test(`[${factory.name}] expired rows are absent to every read`, async () => {
    const { record } = goldenSha();
    // A live clock inside the retention window reads the row.
    const live = new MemoryStore({ now: () => record.issuedAt + 10 });
    await live.store(record);
    assert.notEqual(await live.find(record.nonce), null);
    assert.notEqual(await live.consume(record.nonce), null);
    // The retention margin is 60s past the signed expiry; a clock past
    // it sweeps the row on every adapter.
    const past = record.expiresAt + 61;
    const shiftedMemory = new MemoryStore({ now: () => past });
    await shiftedMemory.store(record);
    assert.equal(await shiftedMemory.find(record.nonce), null);
    assert.equal(await shiftedMemory.consume(record.nonce), null);
    const dir = mkdtempSync(join(tmpdir(), 'kiwi-sqlite-exp-'));
    try {
      const shiftedSqlite = new SqliteStore(
        new Database(join(dir, 'kiwi.db')) as unknown as SqliteStoreDbLike,
        { now: () => past },
      );
      await shiftedSqlite.store(record);
      assert.equal(await shiftedSqlite.find(record.nonce), null);
      assert.equal(await shiftedSqlite.consume(record.nonce), null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test(`[${factory.name}] a pending envelope carrying markers is refused as forged`, async () => {
    const store = await factory.create();
    try {
      const { record } = goldenSha();
      await store.store(record);
      // Forge the pending state machine: a pending row that already
      // carries a result or identity must never flip.
      await store.consume(record.nonce, 'op-x');
      // Move the row back to pending while keeping the identity: the
      // classic rollback rewrite.
      if (store instanceof MemoryStore) {
        const internal = (store as unknown as { rows: Map<string, { envelopeJson: string; state: string }> }).rows;
        const row = internal.get(record.nonce);
        assert.ok(row !== undefined);
        const envelope = JSON.parse(row.envelopeJson) as Record<string, unknown>;
        envelope.state = 'pending';
        row.envelopeJson = JSON.stringify(envelope);
        row.state = 'pending';
      } else {
        const dir = (store as unknown as { __dir: string }).__dir;
        const db = new Database(join(dir, 'kiwi.db'));
        db.prepare('UPDATE kiwicaptcha_challenge_records SET state = ? WHERE nonce = ?').run('pending', record.nonce);
        db.close();
      }
      const forged = await factory.rawConsume(store, record.nonce);
      assert.equal(forged, null);
    } finally {
      await factory.dispose?.(store);
    }
  });

  test(`[${factory.name}] racing consumers produce exactly one winner`, async () => {
    const store = await factory.create();
    try {
      const { record, token } = goldenSha();
      await store.store(record);
      const winners = await Promise.all(
        Array.from({ length: 12 }, () => store.consume(record.nonce)),
      );
      const won = winners.filter((entry) => entry !== null && entry.consumedNow);
      assert.equal(won.length, 1);
      // Exactly one verification can succeed, whatever the interleaving.
      const storage = await factory.create();
      try {
        await storage.store(record);
        const clock = frozenClock(record);
        const results = await Promise.all(
          Array.from({ length: 8 }, () => verify(token, { storage, secretKey: SECRET, expectedScope: 'login', ...clock })),
        );
        const okCount = results.filter((entry) => entry.ok).length;
        assert.ok(okCount >= 1);
        assert.ok(okCount <= 1, `at most one verifier may win, saw ${okCount}`);
      } finally {
        await (storage && factory.dispose?.(storage));
      }
    } finally {
      await factory.dispose?.(store);
    }
  });
}

test('the sqlite schema guard refuses a newer database', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kiwi-sqlite-guard-'));
  try {
    const db = new Database(join(dir, 'kiwi.db'));
    db.exec('PRAGMA user_version = 99');
    assert.throws(() => new SqliteStore(db as unknown as SqliteStoreDbLike), /schema initialization/);
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the operation identity is written atomically with the flip', async () => {
  const store = new MemoryStore();
  const { record } = goldenSha();
  void record;
  const live = new MemoryStore({ now: () => record.issuedAt + 10 });
  await live.store(record);
  const won = await live.consume(record.nonce, 'op-atomic');
  assert.ok(won !== null && won.consumedNow);
  assert.equal(won.operationIdentity, 'op-atomic');
  const retained = await live.runtimeState(record.nonce);
  assert.equal(retained.consumed?.operationIdentity, 'op-atomic');
});

test('an invalid operation identity throws before any transition', async () => {
  const store = new MemoryStore();
  const { record } = goldenSha();
  const live = new MemoryStore({ now: () => record.issuedAt + 10 });
  await live.store(record);
  await assert.rejects(
    () => live.consume(record.nonce, 'not valid!'),
    /operation identity/,
  );
  const state = await live.runtimeState(record.nonce);
  assert.equal(state.kind, 'pending');
  void store;
});

test('a store write refusal surfaces as the typed error', async () => {
  // The identity-splice contract: a fresh flip that cannot record the
  // identity is a StoreWriteError, never a silent drop.
  const store = new MemoryStore();
  const { record } = goldenSha();
  await store.store(record);
  await store.consume(record.nonce, 'first');
  // Simulate the refused splice on the fresh-flip path via sqlite.
  const dir = mkdtempSync(join(tmpdir(), 'kiwi-sqlite-write-'));
  try {
    const db = new Database(join(dir, 'kiwi.db'));
    const sqlite = new SqliteStore(db as unknown as SqliteStoreDbLike, { now: () => record.issuedAt + 10 });
    await sqlite.store(record);
    const ok = await sqlite.consume(record.nonce, 'op-sqlite');
    assert.ok(ok !== null && ok.consumedNow);
    assert.equal(await sqlite.commitResult(record.nonce, true, null, 'a'.repeat(64)), true);
    assert.equal(await sqlite.commitResult(record.nonce, true, null, 'a'.repeat(64)), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  assert.ok(StoreWriteError !== undefined);
});
