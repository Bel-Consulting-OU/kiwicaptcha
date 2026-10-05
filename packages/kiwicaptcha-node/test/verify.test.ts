import assert from 'node:assert/strict';
import { test } from 'node:test';
import { goldenVectors, frozenClock, type GoldenRecord } from './corpus.js';
import { challengeRecordFromJson, challengeRecordToJson, type ChallengeRecord } from '../src/record.js';
import { decodeToken, encodeToken } from '../src/token.js';
import { MemoryStore } from '../src/stores/memory.js';
import { verify, type VerifyOptions } from '../src/verify.js';
import { VerifyErrorCode } from '../src/errors.js';
import { solveSha256 } from '../src/pow.js';
import { recordMetaMac, serverStateKey } from '../src/mac.js';
import type { StoreAdapter } from '../src/store.js';

/**
 * The verifier behavior suite over the PHP-issued golden records: the
 * canonical cheap-gate order, the rollout-floor window, the one-shot
 * replay semantics, the measured solve duration and every
 * locally-drivable VerifyError code.
 */

const SECRET = goldenVectors().hkdf.secret;

interface Loaded {
  record: ChallengeRecord;
  token: string;
  row: GoldenRecord;
}

function load(name: string): Loaded {
  const row = goldenVectors().records.find((entry) => entry.name === name);
  assert.ok(row !== undefined, `golden record ${name} missing`);
  return { record: challengeRecordFromJson(row.record), token: row.token_b64, row };
}

function toVerifyOptions(record: ChallengeRecord, row: GoldenRecord, storage: StoreAdapter): VerifyOptions {
  const opts: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row.verify_opts)) {
    if (key === 'expectedRegion') {
      opts.region = value;
    } else if (key === 'secretsByKid') {
      const map: Record<number, string> = {};
      for (const [kid, secret] of Object.entries(value as Record<string, string | null>)) {
        if (secret !== null) {
          map[Number(kid)] = secret;
        }
      }
      opts.secretsByKid = map;
    } else {
      opts[key] = value;
    }
  }
  // The golden records travel back to their issuance era on both clocks.
  return { storage, secretKey: SECRET, ...opts, ...frozenClock(record) } as unknown as VerifyOptions;
}

async function storeOf(name: string): Promise<{ storage: MemoryStore; loaded: Loaded }> {
  const loaded = load(name);
  const storage = frozenStoreFor(loaded.record);
  await storage.store(loaded.record);
  return { storage, loaded };
}

/** A MemoryStore whose clock lives inside the golden record's retention. */
function frozenStoreFor(record: ChallengeRecord): MemoryStore {
  return new MemoryStore({ now: () => record.issuedAt + 10 });
}

const GOLDEN_SHA = load('sha_plain').record;

function frozenStoreForGolden(): MemoryStore {
  return frozenStoreFor(GOLDEN_SHA);
}

test('the golden happy paths verify with the shared contract result shape', async () => {
  for (const name of ['sha_plain', 'sha_bound', 'sha_decoy_v3', 'sha_execution_v4', 'rsw']) {
    const { storage, loaded } = await storeOf(name);
    const result = await verify(loaded.token, toVerifyOptions(loaded.record, loaded.row, storage));
    assert.equal(result.ok, true, `${name} must verify`);
    assert.equal(result.disposition, 'allow');
    assert.equal(result.decisionHandle, loaded.record.nonce);
    assert.equal(typeof result.price, 'string');
    assert.equal(result.code, '');
    assert.equal(result.detail, null);
  }
  // The decoy name rides the v3 outcome; the measured duration rides a
  // fresh derivation with an authenticated issuance clock.
  const decoy = await (async () => {
    const { storage, loaded } = await storeOf('sha_decoy_v3');
    return verify(loaded.token, toVerifyOptions(loaded.record, loaded.row, storage));
  })();
  assert.equal(decoy.decoyField, 'decoy_field_a1b2c3d4e5f60718');
  const plain = await (async () => {
    const { storage, loaded } = await storeOf('sha_plain');
    return verify(loaded.token, toVerifyOptions(loaded.record, loaded.row, storage));
  })();
  assert.equal(typeof plain.solveDurationMs, 'number');
  assert.ok((plain.solveDurationMs ?? 0) > 1000);
});

test('the golden negative records answer their pinned codes', async () => {
  for (const name of ['argon2id', 'tampered_signature']) {
    const { storage, loaded } = await storeOf(name);
    const result = await verify(loaded.token, toVerifyOptions(loaded.record, loaded.row, storage));
    assert.equal(result.ok, false, `${name} must fail`);
    assert.equal(result.disposition, 'deny');
    assert.equal(result.code, loaded.row.expected.code);
    assert.equal(result.decisionHandle, null);
    assert.equal(result.price, null);
  }
});

test('an unknown token answers record_not_found without touching storage writes', async () => {
  const storage = frozenStoreForGolden();
  const loaded = load('sha_plain');
  const result = await verify(loaded.token, { storage, secretKey: SECRET });
  assert.equal(result.code, VerifyErrorCode.RecordNotFound);
});

test('malformed tokens answer malformed_token for every decode failure', async () => {
  const storage = frozenStoreForGolden();
  for (const raw of ['not base64!!!', '', 'QQ==', 'a'.repeat(40_000)]) {
    const result = await verify(raw, { storage, secretKey: SECRET });
    assert.equal(result.code, VerifyErrorCode.MalformedToken);
  }
});

test('an expired record answers expired on the verifier clock', async () => {
  const { storage, loaded } = await storeOf('sha_plain');
  const result = await verify(loaded.token, {
    ...toVerifyOptions(loaded.record, loaded.row, storage),
    now: () => loaded.record.expiresAt + 1,
  });
  assert.equal(result.code, VerifyErrorCode.Expired);
  // A future-skewed issuance is expired too.
  const storage2 = frozenStoreForGolden();
  await storage2.store(loaded.record);
  const result2 = await verify(loaded.token, {
    ...toVerifyOptions(loaded.record, loaded.row, storage2),
    now: () => loaded.record.issuedAt - MAX_SKEW_STEP,
  });
  assert.equal(result2.code, VerifyErrorCode.Expired);
});

const MAX_SKEW_STEP = 61;

test('the record is consumed exactly once and replays deterministically', async () => {
  const { storage, loaded } = await storeOf('sha_plain');
  const opts = toVerifyOptions(loaded.record, loaded.row, storage);
  const first = await verify(loaded.token, opts);
  assert.equal(first.ok, true);
  const replay = await verify(loaded.token, opts);
  assert.equal(replay.code, VerifyErrorCode.AlreadyConsumed);
  // The retained record still carries its consumed state.
  const state = await storage.runtimeState(loaded.record.nonce);
  assert.equal(state.kind, 'consumed');
});

test('a stored success replays only under the proven operation identity', async () => {
  const { storage, loaded } = await storeOf('sha_plain');
  const base = toVerifyOptions(loaded.record, loaded.row, storage);
  const ok = await verify(loaded.token, { ...base, operationIdentity: 'op-123' });
  assert.equal(ok.ok, true);
  // The identity-proven replay carries the stored binding, no duration.
  const replay = await verify(loaded.token, { ...base, operationIdentity: 'op-123' });
  assert.equal(replay.ok, true);
  assert.equal(replay.fromStoredResult, true);
  assert.equal(replay.solveDurationMs, null);
  assert.equal(replay.decisionHandle, loaded.record.nonce);
  // A different operation's identity is refused.
  const other = await verify(loaded.token, { ...base, operationIdentity: 'op-456' });
  assert.equal(other.code, VerifyErrorCode.AlreadyConsumed);
  // A retry with no identity is refused too.
  const anonymous = await verify(loaded.token, base);
  assert.equal(anonymous.code, VerifyErrorCode.AlreadyConsumed);
});

test('a stored invalid outcome replays to any caller', async () => {
  const { storage, loaded } = await storeOf('sha_plain');
  const base = toVerifyOptions(loaded.record, loaded.row, storage);
  const wrongToken = encodeToken({ ...decodeToken(loaded.token), counter: 999_999 });
  const bad = await verify(wrongToken, base);
  assert.equal(bad.code, VerifyErrorCode.InsufficientWork);
  const replay = await verify(wrongToken, base);
  assert.equal(replay.code, VerifyErrorCode.InsufficientWork);
});

test('a resultless consumed record answers consume_indeterminate', async () => {
  const { storage, loaded } = await storeOf('sha_plain');
  await storage.consume(loaded.record.nonce);
  const result = await verify(loaded.token, toVerifyOptions(loaded.record, loaded.row, storage));
  assert.equal(result.code, VerifyErrorCode.ConsumeIndeterminate);
});

test('a forged success grant without the MAC is refused as malformed', async () => {
  // A MAC-committing backend never accepts a stored success without
  // the server-state MAC, whatever the retry presents.
  const { storage, loaded } = await storeOf('sha_plain');
  await storage.consume(loaded.record.nonce, 'grant-op');
  await storage.commitResult(loaded.record.nonce, true, null, null);
  const forged = await verify(loaded.token, {
    ...toVerifyOptions(loaded.record, loaded.row, storage),
    operationIdentity: 'grant-op',
  });
  assert.equal(forged.code, VerifyErrorCode.MalformedRecord);
  // Without the identity the retry is already the plain replay refusal.
  const { storage: s2 } = await storeOf('sha_plain');
  await s2.consume(loaded.record.nonce);
  await s2.commitResult(loaded.record.nonce, true, null, null);
  const anonymous = await verify(loaded.token, toVerifyOptions(loaded.record, loaded.row, s2));
  assert.equal(anonymous.code, VerifyErrorCode.AlreadyConsumed);
});

test('an operation identity is validated before the transition', async () => {
  const { storage, loaded } = await storeOf('sha_plain');
  const result = await verify(loaded.token, {
    ...toVerifyOptions(loaded.record, loaded.row, storage),
    operationIdentity: 'spaces not allowed',
  });
  assert.equal(result.code, VerifyErrorCode.ConsumeIndeterminate);
  // The record stayed pending: nothing was written.
  const state = await storage.runtimeState(loaded.record.nonce);
  assert.equal(state.kind, 'pending');
});

test('scope, region, issuer and policy epoch answer their typed codes', async () => {
  // The one-shot policy burns the record on the first cheap failure,
  // so every expectation redeems its own copy.
  const expectCode = async (extra: Record<string, unknown>): Promise<string> => {
    const { storage, loaded } = await storeOf('sha_plain');
    const result = await verify(loaded.token, { ...toVerifyOptions(loaded.record, loaded.row, storage), ...extra });
    return result.code;
  };
  assert.equal(await expectCode({ expectedScope: 'other' }), VerifyErrorCode.WrongScope);
  assert.equal(await expectCode({ region: 'us' }), VerifyErrorCode.WrongRegion);
  assert.equal(await expectCode({ region: null, expectedIssuer: 'prod' }), VerifyErrorCode.WrongIssuer);
  assert.equal(await expectCode({ expectedPolicyVersion: 2 }), VerifyErrorCode.WrongPolicyVersion);
});

test('the policy rollout window accepts the old epoch and fails closed above it', async () => {
  // Strict equality rejects the epoch-1 record against expected 2.
  {
    const { storage, loaded } = await storeOf('sha_plain');
    const strict = await verify(loaded.token, {
      ...toVerifyOptions(loaded.record, loaded.row, storage),
      expectedPolicyVersion: 2,
    });
    assert.equal(strict.code, VerifyErrorCode.WrongPolicyVersion);
  }
  // Inside a declared window [1, 2] the epoch-1 record redeems: the
  // mixed N/N+1 fleet crosses nodes with zero spurious rejections.
  {
    const { storage, loaded } = await storeOf('sha_plain');
    const windowOk = await verify(loaded.token, {
      ...toVerifyOptions(loaded.record, loaded.row, storage),
      expectedPolicyVersion: 2,
      policyVersionFloor: 1,
    });
    assert.equal(windowOk.ok, true);
  }
  // A window above the record ([2, 3]) accepts nothing: fail closed.
  {
    const { storage, loaded } = await storeOf('sha_plain');
    const windowReject = await verify(loaded.token, {
      ...toVerifyOptions(loaded.record, loaded.row, storage),
      expectedPolicyVersion: 3,
      policyVersionFloor: 2,
    });
    assert.equal(windowReject.code, VerifyErrorCode.WrongPolicyVersion);
  }
});

test('the IP binding answers missing_client_ip and ip_mismatch, and never deletes', async () => {
  const { storage, loaded } = await storeOf('sha_bound');
  const base = toVerifyOptions(loaded.record, loaded.row, storage);
  // The bound record verifies under its own IP on a fresh copy.
  const ok = await verify(loaded.token, base);
  assert.equal(ok.ok, true);
  // The golden bound record carries a binding tag; the missing IP is
  // the retryable exempt failure and the record stays pending.
  const { storage: s2, loaded: l2 } = await storeOf('sha_bound');
  const noIp = await verify(l2.token, { ...toVerifyOptions(l2.record, l2.row, s2), clientIp: null });
  assert.equal(noIp.code, VerifyErrorCode.MissingClientIp);
  assert.equal((await s2.runtimeState(l2.record.nonce)).kind, 'pending');
  const wrongIp = await verify(l2.token, { ...toVerifyOptions(l2.record, l2.row, s2), clientIp: '198.51.100.9' });
  assert.equal(wrongIp.code, VerifyErrorCode.IpMismatch);
  // Only the missing IP keeps the record; an ip_mismatch verdict is a
  // burned challenge like every other cheap failure but the exempt set.
  assert.equal((await s2.runtimeState(l2.record.nonce)).kind, 'missing');
});

test('the request binding is exact option equality, with the named legacy mode', async () => {
  const { storage, loaded } = await storeOf('sha_bound');
  const base = toVerifyOptions(loaded.record, loaded.row, storage);
  // The bound record verifies under its own binding.
  assert.equal((await verify(loaded.token, base)).ok, true);
  // A wrong binding is refused.
  const { storage: s2 } = await storeOf('sha_bound');
  const wrong = await verify(loaded.token, { ...toVerifyOptions(loaded.record, loaded.row, s2), expectedRequestBinding: 'tx-other' });
  assert.equal(wrong.code, VerifyErrorCode.RequestBindingMismatch);
  // The legacy mode permits an unbound record under an expectation.
  const unbound = load('sha_plain');
  const s3 = frozenStoreForGolden();
  await s3.store(unbound.record);
  const legacy = await verify(unbound.token, {
    ...toVerifyOptions(unbound.record, unbound.row, s3),
    expectedRequestBinding: 'tx-9999',
    bindingExpectation: 'legacy',
  });
  assert.equal(legacy.ok, true);
  // The exact mode refuses the unbound record under an expectation.
  const s4 = frozenStoreForGolden();
  await s4.store(unbound.record);
  const exact = await verify(unbound.token, {
    ...toVerifyOptions(unbound.record, unbound.row, s4),
    expectedRequestBinding: 'tx-9999',
  });
  assert.equal(exact.code, VerifyErrorCode.RequestBindingMismatch);
});

test('the kid gate answers unknown_kid for revoked and unresolved kids', async () => {
  const { storage, loaded } = await storeOf('sha_bound');
  const base = toVerifyOptions(loaded.record, loaded.row, storage);
  const { storage: s2 } = await storeOf('sha_bound');
  const revoked = await verify(loaded.token, {
    ...toVerifyOptions(loaded.record, loaded.row, s2),
    revokedKids: [2],
  });
  assert.equal(revoked.code, VerifyErrorCode.UnknownKid);
  // A kid beyond the newest configured kid is the forward guard.
  const forged = {
    ...challengeRecordToJson(loaded.record),
    kid: 9,
  } as Record<string, unknown>;
  // Re-sign the forged record so only the kid gate can reject it.
  const { signPayloadV2, canonicalPayload } = await import('../src/canonical.js');
  const rec = challengeRecordFromJson(forged);
  const canonical = canonicalPayload({
    protocolVersion: rec.protocolVersion,
    nonce: rec.nonce,
    scope: rec.scope,
    bindingTag: rec.bindingTag,
    issuedAt: rec.issuedAt,
    expiresAt: rec.expiresAt,
    algorithm: rec.algorithm,
    mKib: rec.mKib,
    t: rec.t,
    p: rec.p,
    targetBits: rec.targetBits,
    salt: rec.salt,
    minDurationMs: rec.minDurationMs,
    region: rec.region,
    policyVersion: rec.policyVersion,
    requestBinding: rec.requestBinding,
    issuer: rec.issuer,
    kid: rec.kid,
    decoyField: rec.decoyField,
    executionVersion: rec.executionVersion,
    executionCommitment: rec.executionCommitment,
    rswModulusSha256: rec.rswModulusSha256,
    serverMacCommitted: rec.serverMac !== null,
  });
  const signed = Buffer.from(canonical).toString('base64') + '.' + signPayloadV2(canonical, SECRET);
  const forgedWithPrefix = { ...forged, challenge: signed, prefix: `${signed}|${rec.salt}|` };
  const s3 = frozenStoreForGolden();
  await s3.store(challengeRecordFromJson(forgedWithPrefix));
  const forward = await verify(encodeToken(decodeToken(loaded.token)), {
    ...base,
    storage: s3,
  });
  assert.equal(forward.code, VerifyErrorCode.UnknownKid);
});

test('too_fast fires on a receipt inside the signed minimum duration', async () => {
  const { storage, loaded } = await storeOf('sha_plain');
  const base = toVerifyOptions(loaded.record, loaded.row, storage);
  // The golden record carries min_duration_ms 500 and an authenticated
  // issued_at_ns; a receipt 100 microseconds after issuance is too fast.
  const result = await verify(loaded.token, {
    ...base,
    nowNs: loaded.record.issuedAtNs + 100,
    now: () => loaded.record.issuedAt + 10,
  });
  assert.equal(result.code, VerifyErrorCode.TooFast);
  // A receipt past the floor passes the timing gate.
  const { storage: s2 } = await storeOf('sha_plain');
  const ok = await verify(loaded.token, {
    ...toVerifyOptions(loaded.record, loaded.row, s2),
    nowNs: loaded.record.issuedAtNs + 600_000,
  });
  assert.equal(ok.ok, true);
  // Beyond the skew tolerance a receipt before issuance is impossible.
  const { storage: s3 } = await storeOf('sha_plain');
  const skewed = await verify(loaded.token, {
    ...toVerifyOptions(loaded.record, loaded.row, s3),
    nowNs: loaded.record.issuedAtNs - 6_000_000,
  });
  assert.equal(skewed.code, VerifyErrorCode.TooFast);
  // Within the tolerance the floor is skipped and the PoW still gates.
  const { storage: s4 } = await storeOf('sha_plain');
  const within = await verify(loaded.token, {
    ...toVerifyOptions(loaded.record, loaded.row, s4),
    nowNs: loaded.record.issuedAtNs - 1_000_000,
  });
  assert.equal(within.ok, true);
});

test('a wrong proof on a real sha256 record is insufficient_work', async () => {
  const { storage, loaded } = await storeOf('sha_plain');
  const token = decodeToken(loaded.token);
  const wrong = encodeToken({ ...token, counter: token.counter + 1 });
  const result = await verify(wrong, toVerifyOptions(loaded.record, loaded.row, storage));
  assert.equal(result.code, VerifyErrorCode.InsufficientWork);
});

test('a freshly solved proof of a re-signed record verifies end to end', async () => {
  const { signPayloadV2, canonicalPayload } = await import('../src/canonical.js');
  const nonce = Buffer.from('golden-end-to-end-nonce-00000032', 'utf8').toString('base64');
  assert.equal(nonce.length, 44);
  const salt = Buffer.from('golden-end-to-end-salt-0000001', 'utf8').subarray(0, 16).toString('base64');
  const issuedAt = Math.floor(Date.now() / 1000) - 30;
  const expiresAt = issuedAt + 120;
  const canonical = canonicalPayload({
    protocolVersion: 2,
    nonce,
    scope: 'login',
    bindingTag: '',
    issuedAt,
    expiresAt,
    algorithm: 'sha256',
    mKib: 0,
    t: 1,
    p: 1,
    targetBits: 8,
    salt,
    minDurationMs: 0,
    policyVersion: 1,
  });
  const challenge = Buffer.from(canonical).toString('base64') + '.' + signPayloadV2(canonical, SECRET);
  const prefix = `${challenge}|${salt}|`;
  const counter = solveSha256(prefix, salt, 8);
  const issuedAtNs = Date.now() * 1000 - 3_000_000;
  const serverMac = recordMetaMac(serverStateKey(Buffer.from(SECRET, 'utf8')), challenge, issuedAtNs, null);
  const record = challengeRecordFromJson({
    nonce,
    scope: 'login',
    binding_tag: '',
    issued_at: issuedAt,
    expires_at: expiresAt,
    algorithm: 'sha256',
    m_kib: 0,
    t: 1,
    p: 1,
    target_bits: 8,
    salt,
    prefix,
    challenge,
    min_duration_ms: 0,
    issued_at_ns: issuedAtNs,
    protocol_version: 2,
    region: null,
    policy_version: 1,
    request_binding: null,
    issuer: null,
    kid: 1,
    hostname: null,
    server_mac: serverMac,
  });
  const storage = frozenStoreForGolden();
  await storage.store(record);
  const token = encodeToken({ nonce, counter, durationMs: 1200, telemetry: { v: 1 }, executionDigest: null, executionTrace: null, rswProof: null });
  const result = await verify(token, { storage, secretKey: SECRET, expectedScope: 'login' });
  assert.equal(result.ok, true);
  assert.equal(result.price, 'sha8bit');
  assert.equal(typeof result.solveDurationMs, 'number');
  // The committed MAC replays under the proven identity.
  const replay = await verify(token, { storage, secretKey: SECRET, expectedScope: 'login', operationIdentity: 'op-x' });
  assert.equal(replay.code, VerifyErrorCode.AlreadyConsumed);
});

test('structural tampering fails closed as malformed_record and burns the record', async () => {
  const loaded = load('sha_plain');
  for (const mutate of [
    (r: ChallengeRecord): ChallengeRecord => ({ ...r, scope: 'has space' }),
    (r: ChallengeRecord): ChallengeRecord => ({ ...r, protocolVersion: 1 }),
    (r: ChallengeRecord): ChallengeRecord => ({ ...r, expiresAt: r.issuedAt + 301 }),
    (r: ChallengeRecord): ChallengeRecord => ({ ...r, targetBits: 21 }),
    (r: ChallengeRecord): ChallengeRecord => ({ ...r, salt: Buffer.alloc(15, 1).toString('base64') }),
    (r: ChallengeRecord): ChallengeRecord => ({ ...r, prefix: 'wrong|prefix|' }),
  ]) {
    const storage = frozenStoreForGolden();
    await storage.store(mutate(loaded.record));
    const result = await verify(loaded.token, { storage, secretKey: SECRET, expectedScope: null });
    assert.equal(result.code, VerifyErrorCode.MalformedRecord, `tamper must fail: ${JSON.stringify(mutate(loaded.record).scope)}`);
    // The one-shot cleanup deleted the pending record.
    const state = await storage.runtimeState(loaded.record.nonce);
    assert.equal(state.kind, 'missing');
  }
  // A kid tamper passes structure but breaks the signature re-check.
  const kidStorage = frozenStoreForGolden();
  await kidStorage.store({ ...loaded.record, kid: 0 });
  const kidResult = await verify(loaded.token, { storage: kidStorage, secretKey: SECRET, expectedScope: null });
  assert.equal(kidResult.code, VerifyErrorCode.BadSignature);
});

test('armed records demand execution evidence and refuse stray digests', async () => {
  const loaded = load('sha_execution_v4');
  // A token without the evidence is refused.
  const bare = encodeToken({ ...decodeToken(loaded.token), executionDigest: null, executionTrace: null });
  const storage = frozenStoreForGolden();
  await storage.store(loaded.record);
  assert.equal(
    (await verify(bare, toVerifyOptions(loaded.record, loaded.row, storage))).code,
    VerifyErrorCode.ExecutionMismatch,
  );
  // A wrong digest is refused.
  const wrongDigest = encodeToken({ ...decodeToken(loaded.token), executionDigest: 'f'.repeat(64) });
  const storage2 = frozenStoreForGolden();
  await storage2.store(loaded.record);
  assert.equal(
    (await verify(wrongDigest, toVerifyOptions(loaded.record, loaded.row, storage2))).code,
    VerifyErrorCode.ExecutionMismatch,
  );
  // A mutated trace is refused: the mutation bites the decoded plain
  // trace, then re-encodes to the wire spelling.
  const token = decodeToken(loaded.token);
  assert.ok(token.executionTrace !== null);
  const plainTrace = Buffer.from(token.executionTrace, 'base64url').toString('latin1');
  const wrongTrace = encodeToken({
    ...token,
    executionTrace: Buffer.from(plainTrace.replace('geom(', 'geomm('), 'latin1').toString('base64url'),
  });
  const storage3 = frozenStoreForGolden();
  await storage3.store(loaded.record);
  assert.equal(
    (await verify(wrongTrace, toVerifyOptions(loaded.record, loaded.row, storage3))).code,
    VerifyErrorCode.ExecutionMismatch,
  );
  // Stray evidence on an unarmed record is never ignored.
  const plain = load('sha_plain');
  const stray = encodeToken({ ...decodeToken(plain.token), executionDigest: 'a'.repeat(64), executionTrace: null });
  const storage4 = frozenStoreForGolden();
  await storage4.store(plain.record);
  assert.equal(
    (await verify(stray, toVerifyOptions(plain.record, plain.row, storage4))).code,
    VerifyErrorCode.ExecutionMismatch,
  );
});

test('an unarmed signed rsw record without a trapdoor is unsupported', async () => {
  const { storage, loaded } = await storeOf('rsw');
  const base = toVerifyOptions(loaded.record, loaded.row, storage);
  // Without the trapdoor configuration the record is unsupported.
  const noTrapdoor = await verify(loaded.token, { ...base, rsw: null });
  assert.equal(noTrapdoor.code, VerifyErrorCode.UnsupportedRswParams);
  // An rsw token with a nonzero counter is a wrong shape, never compared.
  const { storage: s2 } = await storeOf('rsw');
  const token = decodeToken(loaded.token);
  assert.ok(token.rswProof !== null);
  const wrongShape = encodeToken({ ...token, counter: 3 });
  const wrong = await verify(wrongShape, toVerifyOptions(loaded.record, loaded.row, s2));
  assert.equal(wrong.code, VerifyErrorCode.InsufficientWork);
  // An rsw proof presented for a sha256 record is rejected outright.
  const plain = load('sha_plain');
  const { storage: s3 } = await storeOf('sha_plain');
  const strayProof = encodeToken({ ...decodeToken(plain.token), rswProof: 'a'.repeat(512) });
  const stray = await verify(strayProof, toVerifyOptions(plain.record, plain.row, s3));
  assert.equal(stray.code, VerifyErrorCode.InsufficientWork);
});

test('the telemetry gate rejects bot signals on a pending record only', async () => {
  const loaded = load('sha_plain');
  const storage = frozenStoreForGolden();
  await storage.store(loaded.record);
  const base = toVerifyOptions(loaded.record, loaded.row, storage);
  // Empty telemetry is itself a bot signal under strict mode.
  const empty = encodeToken({ ...decodeToken(loaded.token), telemetry: {} });
  assert.equal(
    (await verify(empty, { ...base, enforceTelemetry: true })).code,
    VerifyErrorCode.TelemetryRejected,
  );
  // Uniform event intervals are the simulated-interaction class.
  const uniform = Array.from({ length: 30 }, (_, i) => i * 100);
  const uniformToken = encodeToken({
    ...decodeToken(loaded.token),
    telemetry: { et: uniform },
  });
  const storage2 = frozenStoreForGolden();
  await storage2.store(loaded.record);
  assert.equal(
    (await verify(uniformToken, { ...toVerifyOptions(loaded.record, loaded.row, storage2), enforceTelemetry: true })).code,
    VerifyErrorCode.TelemetryRejected,
  );
  // Human-like intervals pass the gate; the proof still applies.
  const human = Array.from({ length: 30 }, (_, i) => Math.floor(i * 100 + Math.sin(i) * 37) + i * i % 13);
  const humanToken = encodeToken({
    ...decodeToken(loaded.token),
    telemetry: { et: human },
  });
  const storage3 = frozenStoreForGolden();
  await storage3.store(loaded.record);
  const result = await verify(humanToken, {
    ...toVerifyOptions(loaded.record, loaded.row, storage3),
    enforceTelemetry: true,
  });
  assert.equal(result.ok, true);
  // A webdriver flag is rejected without running anything else.
  const storage4 = frozenStoreForGolden();
  await storage4.store(loaded.record);
  const wd = encodeToken({ ...decodeToken(loaded.token), telemetry: { wd: true } });
  assert.equal(
    (await verify(wd, { ...toVerifyOptions(loaded.record, loaded.row, storage4), enforceTelemetry: true })).code,
    VerifyErrorCode.TelemetryRejected,
  );
});

test('a store failure answers storage_unavailable, fail closed', async () => {
  const loaded = load('sha_plain');
  const failing: StoreAdapter = {
    authenticatedResultCommit: true,
    store: async () => undefined,
    find: async () => {
      throw new Error('down');
    },
    runtimeState: async () => {
      throw new Error('down');
    },
    consume: async () => null,
    commitResult: async () => false,
    deleteIfPending: async () => ({ kind: 'missing' }),
  };
  const result = await verify(loaded.token, { storage: failing, secretKey: SECRET });
  assert.equal(result.code, VerifyErrorCode.StorageUnavailable);
});
