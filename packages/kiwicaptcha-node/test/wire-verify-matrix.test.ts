import assert from 'node:assert/strict';
import { test } from 'node:test';

import { goldenVectors, type GoldenRecord } from './corpus.js';
import { challengeRecordFromJson } from '../src/record.js';
import { MemoryStore } from '../src/stores/memory.js';
import { verify, type VerifyOptions } from '../src/verify.js';

const SECRET = goldenVectors().hkdf.secret;
const ROW = goldenVectors().records.find((entry) => entry.name === 'sha_plain') as GoldenRecord;
const RECORD = challengeRecordFromJson(ROW.record);

function load(): { storage: MemoryStore; token: string } {
  const storage = new MemoryStore({ now: () => RECORD.issuedAt + 10 });
  return { storage, token: ROW.token_b64 };
}

function options(storage: MemoryStore, overrides: Partial<VerifyOptions> = {}): VerifyOptions {
  return {
    storage,
    secretKey: SECRET,
    expectedScope: 'login',
    clientIp: null,
    now: () => RECORD.issuedAt + 10,
    nowNs: (RECORD.issuedAt + 10) * 1_000_000,
    region: 'eu',
    expectedPolicyVersion: 1,
    ...overrides,
  };
}

async function attempt(overrides: Partial<VerifyOptions>): Promise<{ ok: boolean; code: string }> {
  const { storage, token } = load();
  await storage.store(RECORD);
  const result = await verify(token, options(storage, overrides));
  return { ok: result.ok, code: result.code };
}

test('scope pairing: the exact scope passes, another scope is refused, an empty scope is required_scope', async () => {
  const cases: Array<[string, boolean, string]> = [
    ['login', true, ''],
    ['comment', false, 'wrong_scope'],
    ['', false, 'required_scope'],
  ];
  for (const [scope, ok, code] of cases) {
    const result = await attempt({ expectedScope: scope });
    assert.equal(result.ok, ok, `scope ${JSON.stringify(scope)}`);
    if (!ok) {
      assert.equal(result.code, code, `scope ${JSON.stringify(scope)}`);
    }
  }
});

test('tenant pairing: an untenanted record verifies only under the global keys', async () => {
  assert.equal((await attempt({ tenantId: null })).ok, true);
  const tenant = await attempt({ tenantId: 'tenant-a' });
  assert.equal(tenant.ok, false);
  assert.equal(tenant.code, 'bad_signature');
});

test('expiry and skew: the signed deadline is exact and the future skew is bounded', async () => {
  const ttl = RECORD.expiresAt - RECORD.issuedAt;
  const cases: Array<[number, boolean]> = [
    [-61, false],
    [-60, true],
    [ttl - 1, true],
    [ttl, false],
  ];
  for (const [offset, want] of cases) {
    const result = await attempt({
      now: () => RECORD.issuedAt + offset,
      nowNs: (RECORD.issuedAt + 10) * 1_000_000,
    });
    assert.equal(result.ok, want, `offset ${offset}`);
  }
});

test('a replay of the same token yields at most one grant', async () => {
  const { storage, token } = load();
  await storage.store(RECORD);
  const first = await verify(token, options(storage, { operationIdentity: 'op-first' }));
  assert.equal(first.ok, true, first.code);
  const second = await verify(token, options(storage, { operationIdentity: 'op-second' }));
  assert.equal(second.ok, false);
});
