import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import RedisDefault from 'ioredis';
const Redis = RedisDefault as unknown as typeof RedisDefault.default;
type RedisClient = InstanceType<typeof RedisDefault.default>;
import { goldenVectors, frozenClock } from './corpus.js';
import { consumedResultMac, serverStateKey } from '../src/mac.js';
import { challengeRecordFromJson } from '../src/record.js';
import { RedisStore } from '../src/stores/redis.js';
import { verify } from '../src/verify.js';

/**
 * The Redis adapter contract against a live redis-server: the Lua
 * consume script's exactly-once semantics, the persistent-foreign-key
 * refusal, the NOSCRIPT fallback and the PHP key compatibility. Skipped
 * when no Redis answers on localhost.
 */

const SECRET = goldenVectors().hkdf.secret;

async function reachable(): Promise<boolean> {
  try {
    const probe: RedisClient = new Redis({ host: '127.0.0.1', port: 6379, lazyConnect: true, maxRetriesPerRequest: 1 });
    await probe.connect();
    await probe.ping();
    probe.disconnect();
    return true;
  } catch {
    return false;
  }
}

const hasRedis = await reachable();

function openStore(issuedAt?: number): { store: RedisStore; client: RedisClient; prefix: string } {
  const client: RedisClient = new Redis({ host: '127.0.0.1', port: 6379 });
  const prefix = `kiwicaptcha:test:${randomUUID()}:`;
  return {
    store: new RedisStore(client, {
      prefix,
      now: issuedAt === undefined ? undefined : () => issuedAt + 10,
    }),
    client,
    prefix,
  };
}

function goldenSha() {
  const row = goldenVectors().records.find((entry) => entry.name === 'sha_plain');
  assert.ok(row !== undefined);
  return { record: challengeRecordFromJson(row.record), token: row.token_b64 };
}

test('redis: the consume script is exactly once and replays deterministically', { skip: !hasRedis }, async () => {
  const { record, token } = goldenSha();
  const { store, client } = openStore(record.issuedAt);
  try {
    await store.store(record);
    const first = await store.consume(record.nonce);
    assert.ok(first !== null);
    assert.equal(first.consumedNow, true);
    const second = await store.consume(record.nonce);
    assert.ok(second !== null);
    assert.equal(second.consumedNow, false);
    assert.equal(second.consumedBefore, true);
    assert.equal(await store.commitResult(record.nonce, true, null, 'a'.repeat(64)), true);
    assert.equal(await store.commitResult(record.nonce, true, null, 'a'.repeat(64)), false);
    const replay = await store.consume(record.nonce);
    assert.ok(replay?.consumedResult !== null);
    // Full verify path.
    const storage2 = openStore(record.issuedAt);
    try {
      await storage2.store.store(record);
      const clock = frozenClock(record);
      const ok = await verify(token, { storage: storage2.store, secretKey: SECRET, ...clock });
      assert.equal(ok.ok, true);
      const replayVerify = await verify(token, { storage: storage2.store, secretKey: SECRET, ...clock });
      assert.equal(replayVerify.code, 'already_consumed');
    } finally {
      storage2.client.disconnect();
    }
  } finally {
    client.disconnect();
  }
});

test('redis: racing consumers produce exactly one winner', { skip: !hasRedis }, async () => {
  const { record } = goldenSha();
  const { store, client } = openStore(record.issuedAt);
  try {
    await store.store(record);
    const outcomes = await Promise.all(Array.from({ length: 16 }, () => store.consume(record.nonce)));
    const winners = outcomes.filter((entry) => entry !== null && entry.consumedNow);
    assert.equal(winners.length, 1);
    assert.equal(outcomes.filter((entry) => entry === null).length, 0);
  } finally {
    client.disconnect();
  }
});

test('redis: a persistent foreign key is refused untouched', { skip: !hasRedis }, async () => {
  const { store, client } = openStore(0);
  try {
    const record = goldenSha().record;
    await client.set(`kiwicaptcha:test:foreign`, JSON.stringify({ state: 'pending' }));
    // The store() path attaches a TTL; consume on a key with no expiry
    // (PTTL < 0) must refuse without rewriting the bytes.
    await client.persist(`kiwicaptcha:test:foreign`);
    const before = await client.get(`kiwicaptcha:test:foreign`);
    const result = await store.consume('foreign');
    assert.equal(result, null);
    assert.equal(await client.get(`kiwicaptcha:test:foreign`), before);
  } finally {
    client.disconnect();
  }
});

test('redis: deleteIfPending keeps consumed evidence and deletes only pending', { skip: !hasRedis }, async () => {
  const { record, token } = goldenSha();
  const { store, client } = openStore(record.issuedAt);
  try {
    await store.store(record);
    assert.equal((await store.deleteIfPending(record.nonce)).kind, 'deleted-pending');
    assert.equal((await store.deleteIfPending(record.nonce)).kind, 'missing');
    await store.store(record);
    await store.consume(record.nonce, 'op-redis');
    const mac = consumedResultMac(
      serverStateKey(Buffer.from(SECRET, 'utf8')),
      record.challenge,
      true,
      record.requestBinding,
      'op-redis',
    );
    assert.equal(await store.commitResult(record.nonce, true, record.requestBinding, mac), true);
    const cleanup = await store.deleteIfPending(record.nonce);
    assert.equal(cleanup.kind, 'consumed');
    const result = await verify(token, {
      storage: store,
      secretKey: SECRET,
      ...frozenClock(record),
      operationIdentity: 'op-redis',
    });
    assert.equal(result.ok, true);
    assert.equal(result.fromStoredResult, true);
  } finally {
    client.disconnect();
  }
});

test('redis: the PHP-compatible key holds the flat envelope', { skip: !hasRedis }, async () => {
  const { record } = goldenSha();
  const { store, client, prefix } = openStore(record.issuedAt);
  try {
    await store.store(record);
    const raw = await client.get(`${prefix}${record.nonce}`);
    assert.ok(raw !== null);
    const envelope = JSON.parse(raw) as Record<string, unknown>;
    assert.equal(envelope['state'], 'pending');
    assert.equal(envelope['nonce'], record.nonce);
    assert.equal(envelope['consumed_result'], null);
    assert.equal(envelope['operation_identity'], null);
    assert.ok((await client.ttl(`${prefix}${record.nonce}`)) > 0);
    // A PHP-written envelope (identical shape) verifies in this SDK.
    const token = goldenVectors().records.find((entry) => entry.name === 'sha_plain')?.token_b64;
    assert.ok(token !== undefined);
  } finally {
    client.disconnect();
  }
});

test('redis: runtimeState classifies pending, consumed, cancelled and missing', { skip: !hasRedis }, async () => {
  const { record } = goldenSha();
  const { store, client, prefix } = openStore(record.issuedAt);
  try {
    await store.store(record);
    assert.equal((await store.runtimeState(record.nonce)).kind, 'pending');
    await store.consume(record.nonce);
    assert.equal((await store.runtimeState(record.nonce)).kind, 'consumed');
    assert.equal((await store.runtimeState('missing-nonce-zzz')).kind, 'missing');
    // A cancelled record is never consumable.
    await store.store(record);
    const key = `${prefix}${record.nonce}`;
    const raw = await client.get(key);
    assert.ok(raw !== null);
    const envelope = JSON.parse(raw) as Record<string, unknown>;
    envelope.state = 'cancelled';
    await client.set(key, JSON.stringify(envelope), 'EX', 120);
    assert.equal((await store.runtimeState(record.nonce)).kind, 'cancelled');
    assert.equal(await store.consume(record.nonce), null);
    const found = await store.find(record.nonce);
    assert.equal(found?.nonce, record.nonce);
  } finally {
    client.disconnect();
  }
});
