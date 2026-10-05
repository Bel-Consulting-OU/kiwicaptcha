import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { test } from 'node:test';
import { readProtocol, goldenVectors } from './corpus.js';
import {
  canonicalPayload,
  signPayloadV2,
  bindingTag,
  canonicalIpFamily,
  executionCommitment,
  signedCanonicalCommitsRecordMeta,
  hashIp,
} from '../src/canonical.js';
import { derivedKeys, INFO_IP_BIND, INFO_RESULT_TOKEN, MIN_SECRET_BYTES } from '../src/keys.js';
import {
  recordMetaInput,
  recordMetaMac,
  consumedResultInput,
  consumedResultMac,
  serverStateKey,
} from '../src/mac.js';
import {
  MAX_TTL_SECS,
  MAX_CLOCK_SKEW,
  MAX_ARGON_MEMORY_KIB,
  MAX_ARGON_TIME,
  MAX_DIFFICULTY,
  MIN_DIFFICULTY,
  MAX_PARALLELISM,
  MIN_ARGON_MEMORY_KIB,
  MIN_ARGON_TIME,
  MIN_PARALLELISM,
} from '../src/verify.js';
import { SOLVER_MAX_HASHES, MAX_DURATION_MS } from '../src/token.js';
import { RSW_T_MAX, RSW_T_MIN, RSW_MODULUS_BYTES, RSW_PROOF_HEX_LENGTH } from '../src/rsw.js';
import { EXECUTION_MAX_PROGRAM_BASE64, EXECUTION_MAX_VERSION } from '../src/execution.js';
import { timingSafeEqualsHex } from '../src/mac.js';

/**
 * Cross-language byte conformance: the shared limits register, the
 * HKDF purpose keys, the canonical assembly with tagged segments, the
 * server-state MAC inputs and the deployment binding tags, all pinned
 * to the PHP core's values.
 */

test('the shared limits register matches the Node constants', () => {
  const limits = readProtocol('limits.json') as Record<string, number>;
  assert.equal(limits['ttl_max_secs'], MAX_TTL_SECS);
  assert.equal(limits['solver_max_hashes'], SOLVER_MAX_HASHES);
  assert.equal(limits['token_max_duration_ms'], MAX_DURATION_MS);
  assert.equal(limits['min_master_bytes'], MIN_SECRET_BYTES);
  assert.equal(limits['rsw_t_min'], RSW_T_MIN);
  assert.equal(limits['rsw_t_max'], RSW_T_MAX);
  assert.equal(limits['execution_max_program_base64'], EXECUTION_MAX_PROGRAM_BASE64);
  assert.equal(limits['execution_max_version'], EXECUTION_MAX_VERSION);
  assert.equal(limits['argon2_max_m_kib'], MAX_ARGON_MEMORY_KIB);
  assert.equal(limits['argon2_max_t_verification'], MAX_ARGON_TIME);
  // Verifier-side bounds the register derives from the cores.
  assert.equal(MIN_DIFFICULTY, 1);
  assert.equal(MAX_DIFFICULTY, 20);
  assert.equal(MIN_ARGON_MEMORY_KIB, 8);
  assert.equal(MIN_ARGON_TIME, 3);
  assert.equal(MIN_PARALLELISM, 1);
  assert.equal(MAX_PARALLELISM, 4);
  assert.equal(RSW_MODULUS_BYTES, 256);
  assert.equal(RSW_PROOF_HEX_LENGTH, 512);
  assert.equal(MAX_CLOCK_SKEW, 60);
});

test('HKDF purpose keys match the PHP derivation byte for byte', () => {
  const golden = goldenVectors();
  const keys = derivedKeys(golden.hkdf.secret);
  assert.equal(keys.challengeKey.toString('hex'), golden.hkdf.challenge_hex);
  assert.equal(keys.ipBindKey.toString('hex'), golden.hkdf.ip_bind_hex);
  assert.equal(keys.resultKey.toString('hex'), golden.hkdf.result_hex);
  assert.equal(keys.serverStateKey.toString('hex'), golden.hkdf.server_state_hex);
  assert.equal(keys.challengeKey.length, 32);
  assert.equal(keys.ipBindKey.length, 32);
  assert.equal(keys.resultKey.length, 32);
  assert.equal(keys.serverStateKey.length, 32);
});

test('tenant-scoped derivation differs from the global keys', () => {
  const golden = goldenVectors();
  const global = derivedKeys(golden.hkdf.secret);
  const tenant = derivedKeys(golden.hkdf.secret, 'tenant-a');
  assert.notEqual(global.challengeKey.toString('hex'), tenant.challengeKey.toString('hex'));
  assert.notEqual(global.ipBindKey.toString('hex'), tenant.ipBindKey.toString('hex'));
  const tenantB = derivedKeys(golden.hkdf.secret, 'tenant-b');
  assert.notEqual(tenant.challengeKey.toString('hex'), tenantB.challengeKey.toString('hex'));
});

test('short secrets are refused at the derivation boundary', () => {
  assert.throws(() => derivedKeys('too-short'), /at least 32 bytes/);
});

test('canonical assembly is byte-identical across the tagged capability shapes', () => {
  const golden = goldenVectors();
  const nonce = 'bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==';
  const salt = 'c2FsdC1yZXZpc2lvbi0z';
  const baseArgs = {
    protocolVersion: 2,
    nonce,
    scope: 'login',
    bindingTag: 'tag456',
    issuedAt: 111,
    expiresAt: 222,
    algorithm: 'sha256' as const,
    mKib: 0,
    t: 1,
    p: 1,
    targetBits: 8,
    salt,
    minDurationMs: 5,
    region: 'eu',
    policyVersion: 2,
    requestBinding: 'bind-1',
    issuer: 'prod',
    kid: 3,
  };
  assert.equal(canonicalPayload(baseArgs), golden.canonical.base);
  assert.equal(signPayloadV2(golden.canonical.base, golden.hkdf.secret), golden.canonical.signature_hex);
  assert.equal(
    canonicalPayload({ ...baseArgs, protocolVersion: 3, region: null, policyVersion: 1, requestBinding: null, issuer: null, kid: 1, decoyField: 'billing_address_line_a3f9c21d8e5b7401' }),
    golden.canonical.v3_decoy,
  );
  const commitment = 'a'.repeat(64);
  assert.equal(
    canonicalPayload({ ...baseArgs, protocolVersion: 4, region: null, policyVersion: 1, requestBinding: null, issuer: null, kid: 1, executionVersion: 1, executionCommitment: commitment }),
    golden.canonical.v4_execution,
  );
  assert.equal(
    canonicalPayload({ ...baseArgs, protocolVersion: 5, region: null, policyVersion: 1, requestBinding: null, issuer: null, kid: 1, rswModulusSha256: 'b'.repeat(64) }),
    golden.canonical.v5_identity,
  );
  // Revision-3 injectivity: distinct capability shapes never collide.
  assert.notEqual(golden.canonical.v3_decoy, golden.canonical.v5_identity.replace('|r=', '|d='));
  assert.throws(
    () => canonicalPayload({ ...baseArgs, executionVersion: 1 }),
    /passed together/,
  );
});

test('the m=1 marker rides the canonical and the challenge parser sees it', () => {
  const args = {
    protocolVersion: 2,
    nonce: 'bm9uY2UtcmV2aXNpb24tMy10ZXN0LXZlY3Rvcg==',
    scope: 'login',
    bindingTag: '',
    issuedAt: 1,
    expiresAt: 2,
    algorithm: 'sha256' as const,
    mKib: 0,
    t: 1,
    p: 1,
    targetBits: 8,
    salt: 'c2FsdC1yZXZpc2lvbi0z',
    minDurationMs: 0,
    serverMacCommitted: true,
  };
  const challenge = Buffer.from(canonicalPayload(args)).toString('base64') + '.aa';
  assert.equal(signedCanonicalCommitsRecordMeta(challenge), true);
  const plain = Buffer.from(canonicalPayload({ ...args, serverMacCommitted: false })).toString('base64') + '.aa';
  assert.equal(signedCanonicalCommitsRecordMeta(plain), false);
  assert.equal(signedCanonicalCommitsRecordMeta('not-base64!.aa'), false);
});

test('server-state MAC inputs and digests match the PHP core', () => {
  const golden = goldenVectors();
  const key = serverStateKey(Buffer.from(golden.hkdf.secret, 'utf8'));
  assert.equal(key.toString('hex'), golden.hkdf.server_state_hex);
  const fixed = 'bm9uY2Uuc2ln';
  assert.equal(recordMetaInput(fixed, 1700000000123456, 'example.test'), golden.server_state_mac.record_meta_input);
  assert.equal(recordMetaMac(key, fixed, 1700000000123456, 'example.test'), golden.server_state_mac.record_meta_hex);
  assert.equal(
    consumedResultInput(fixed, true, 'bind-9', 'op-7'),
    golden.server_state_mac.consumed_result_input,
  );
  assert.equal(
    consumedResultMac(key, fixed, true, 'bind-9', 'op-7'),
    golden.server_state_mac.consumed_result_hex,
  );
});

test('binding tags and legacy IP hashes match the PHP core', () => {
  const secret = goldenVectors().hkdf.secret;
  const nonce = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=';
  const tag4 = bindingTag(nonce, '203.0.113.7', secret);
  const keyed = derivedKeys(secret).ipBindKey.toString('hex');
  const expected = timingSafeEqualsHex(
    tag4,
    // Recomputed over the exact domain message with the derived key.
    hmacHex(Buffer.from(`kiwicaptcha/ip-bind/v2\0${nonce}\0`, 'latin1'), Buffer.concat([Buffer.of(4), Buffer.of(203, 0, 113, 7)]), Buffer.from(keyed, 'hex')),
  );
  assert.equal(expected, true);
  // IPv6 spellings of one address produce one family.
  const v6a = canonicalIpFamily('2001:db8::1');
  const v6b = canonicalIpFamily('2001:0db8:0:0:0:0:0:1');
  assert.deepEqual(v6a, v6b);
  assert.equal(v6a?.[0], 6);
  assert.equal(v6a?.length, 17);
  // IPv4-mapped and IPv4-compatible spellings normalize to 4 bytes.
  const mapped = canonicalIpFamily('::ffff:203.0.113.7');
  assert.deepEqual(mapped, canonicalIpFamily('203.0.113.7'));
  const compatible = canonicalIpFamily('::203.0.113.7');
  assert.deepEqual(compatible, mapped);
  assert.notDeepEqual(canonicalIpFamily('::1'), mapped);
  assert.notDeepEqual(canonicalIpFamily('::'), mapped);
  // Foreign spellings are refused.
  assert.equal(canonicalIpFamily('203.0.113.007'), null);
  assert.equal(canonicalIpFamily('fe80::1%eth0'), null);
  assert.equal(canonicalIpFamily('nope'), null);
  assert.equal(canonicalIpFamily('1:2:3:4:5:6:7:8:9'), null);
  assert.equal(canonicalIpFamily('1:2:3:4:5:6:7::8'), null);
  // The legacy v1 hash: SHA-256 of salt followed by the raw IP string.
  assert.equal(hashIp('203.0.113.7', 'salt'), createHash('sha256').update('salt203.0.113.7', 'latin1').digest('hex'));
});

function hmacHex(message: Buffer, family: Buffer, key: Buffer): string {
  return createHmac('sha256', key).update(Buffer.concat([message, family])).digest('hex');
}

test('execution commitments are the SHA-256 of the program wire string', () => {
  const program = goldenVectors().records.find((row) => row.name === 'sha_execution_v4');
  const stored = program?.record['execution_program'];
  assert.equal(typeof stored, 'string');
  assert.equal(executionCommitment(stored as string), program?.record['execution_commitment']);
});
