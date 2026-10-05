import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readProtocol, goldenVectors, executionCorpus, frozenClock, type GoldenRecord } from './corpus.js';
import { challengeRecordFromJson } from '../src/record.js';
import { decodeToken, encodeToken, SOLVER_MAX_HASHES } from '../src/token.js';
import { MemoryStore } from '../src/stores/memory.js';
import { verify, type VerifyOptions } from '../src/verify.js';
import { outcomeMapping } from '../src/outcomes.js';
import { VerifyErrorCode, ALL_VERIFY_ERROR_CODES } from '../src/errors.js';

/**
 * The cross-SDK conformance runner: the shared protocol corpus
 * (solution-token-v1, limits.json, rsw-identity-v1, risk-v1 outcomes
 * vectors, the execution differential corpus) plus the PHP-issued
 * golden records, asserted end to end so behavior cannot drift from
 * the other cores.
 */

test('conformance: the shared registers agree with the implementation constants', () => {
  const limits = readProtocol('limits.json') as Record<string, number>;
  assert.equal(limits['solver_max_hashes'], SOLVER_MAX_HASHES);
  const tokenFixture = readProtocol('solution-token-v1/fixtures.json') as { solver_max_hashes: number };
  assert.equal(tokenFixture.solver_max_hashes, SOLVER_MAX_HASHES);
});

test('conformance: every verify error code is in the shared vocabulary', () => {
  // The snake_case wire vocabulary of the PHP enum, asserted wholesale.
  assert.deepEqual([...ALL_VERIFY_ERROR_CODES].sort(), [
    'admission_unavailable',
    'already_consumed',
    'bad_signature',
    'capacity_exceeded',
    'consume_indeterminate',
    'execution_mismatch',
    'expired',
    'insufficient_work',
    'ip_mismatch',
    'malformed_record',
    'malformed_token',
    'missing_client_ip',
    'record_not_found',
    'request_binding_mismatch',
    'storage_unavailable',
    'telemetry_rejected',
    'too_fast',
    'too_many_attempts',
    'unknown_kid',
    'unsupported_argon2_params',
    'unsupported_rsw_params',
    'wrong_issuer',
    'wrong_policy_version',
    'wrong_region',
    'wrong_scope',
  ]);
  for (const code of ALL_VERIFY_ERROR_CODES) {
    assert.match(code, /^[a-z0-9_]+$/);
  }
});

test('conformance: the execution corpus matches the differential expectations', () => {
  const corpus = executionCorpus();
  const valid = corpus.cases.filter((row) => row.expected === 'valid');
  const mismatch = corpus.cases.filter((row) => row.expected === 'execution_mismatch');
  const malformed = corpus.cases.filter((row) => row.expected === 'malformed');
  assert.ok(valid.length >= 5 && mismatch.length >= 5 && malformed.length >= 3);
});

test('conformance: every golden record verifies to its PHP-pinned verdict', async () => {
  const golden = goldenVectors();
  for (const row of golden.records as GoldenRecord[]) {
    const record = challengeRecordFromJson(row.record);
    // The record JSON survives a strict parse and a canonical rewrite.
    const token = decodeToken(row.token_b64);
    assert.equal(encodeToken(token), row.token_b64);
    const storage = new MemoryStore({ now: () => record.issuedAt + 10 });
    await storage.store(record);
    const opts: Record<string, unknown> = { storage, secretKey: golden.hkdf.secret, ...frozenClock(record) };
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
    const result = await verify(row.token_b64, opts as unknown as VerifyOptions);
    assert.equal(result.ok, row.expected.ok, `${row.name}: ok mismatch`);
    if (row.expected.code !== undefined) {
      assert.equal(result.code, row.expected.code, `${row.name}: code mismatch`);
    }
    if (row.expected.decoyField !== undefined) {
      assert.equal(result.decoyField, row.expected.decoyField);
    }
  }
});

test('conformance: the outcome channels match the risk-v1 event kinds', () => {
  const vectors = readProtocol('risk-v1/outcomes-vectors.json') as {
    vectors: { outcome: string; accepted: boolean; channel_value?: number }[];
  };
  for (const vector of vectors.vectors) {
    if (!vector.accepted) {
      continue;
    }
    assert.equal(outcomeMapping(vector.outcome as never).channel, vector.channel_value);
  }
});

test('conformance: a consumed golden record replays the identical denial code', async () => {
  const golden = goldenVectors();
  const row = golden.records.find((entry) => entry.name === 'sha_plain') as GoldenRecord;
  const record = challengeRecordFromJson(row.record);
  const storage = new MemoryStore({ now: () => record.issuedAt + 10 });
  await storage.store(record);
  const wrongToken = encodeToken({ ...decodeToken(row.token_b64), counter: 12345 });
  const clock = frozenClock(record);
  const first = await verify(wrongToken, { storage, secretKey: golden.hkdf.secret, ...clock });
  assert.equal(first.code, VerifyErrorCode.InsufficientWork);
  const second = await verify(wrongToken, { storage, secretKey: golden.hkdf.secret, ...clock });
  assert.equal(second.code, VerifyErrorCode.InsufficientWork);
});
