import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readProtocol } from './corpus.js';
import { decodeToken, encodeToken, DecodeError, SOLVER_MAX_HASHES, MAX_DURATION_MS } from '../src/token.js';
import { encodeStdBase64 } from '../src/base64.js';

/**
 * The shared solution-token boundary fixture: the solver hash ceiling
 * and the exact counter spellings both decoders must accept or reject,
 * read from the SAME protocol corpus the PHP and Rust suites decode.
 */

interface TokenFixture {
  solver_max_hashes: number;
  nonce_b64: string;
  duration_ms: number;
  telemetry_json: string;
  accepted: Record<string, string>;
  rejected: Record<string, string>;
  cross_language: { counter: number; encoded: string };
}

test('every accepted token spelling decodes and re-encodes byte-identically', () => {
  const fixture = readProtocol('solution-token-v1/fixtures.json') as unknown as TokenFixture;
  assert.equal(fixture.solver_max_hashes, SOLVER_MAX_HASHES);
  for (const [counter, encoded] of Object.entries(fixture.accepted)) {
    const token = decodeToken(encoded);
    assert.equal(token.counter, Number(counter));
    assert.equal(token.nonce, fixture.nonce_b64);
    assert.equal(token.durationMs, fixture.duration_ms);
    assert.deepEqual(token.telemetry, JSON.parse(fixture.telemetry_json));
    assert.equal(encodeToken(token), encoded, `round trip failed for counter ${counter}`);
  }
});

test('counters at or above the solver ceiling are rejected with the typed code', () => {
  const fixture = readProtocol('solution-token-v1/fixtures.json') as unknown as TokenFixture;
  for (const [counter, encoded] of Object.entries(fixture.rejected)) {
    assert.equal(Number(counter) >= SOLVER_MAX_HASHES, true);
    assert.throws(() => decodeToken(encoded), (error: unknown) => {
      assert.ok(error instanceof DecodeError);
      assert.equal(error.code, 'counter_exceeds_solver_maximum');
      return true;
    });
  }
});

test('the cross-language row decodes to its stated counter', () => {
  const fixture = readProtocol('solution-token-v1/fixtures.json') as unknown as TokenFixture;
  const token = decodeToken(fixture.cross_language.encoded);
  assert.equal(token.counter, fixture.cross_language.counter);
  assert.equal(encodeToken(token), fixture.cross_language.encoded);
});

const NONCE = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=';

function envelope(plain: string): string {
  return encodeStdBase64(Buffer.from(plain, 'utf8'));
}

function expectMalformed(plain: string, code: DecodeError['code'] = 'malformed'): void {
  assert.throws(
    () => decodeToken(envelope(plain)),
    (error: unknown) => error instanceof DecodeError && error.code === code,
  );
}

test('the token language accepts exactly one spelling per value', () => {
  const plain = (counter: string, duration: string, telemetry: string): string =>
    `${NONCE}.${counter}.${duration}.${telemetry}`;
  // Leading zeros are foreign spellings.
  expectMalformed(plain('007', '10', '{}'), 'invalid_counter');
  expectMalformed(plain('10', '007', '{}'), 'invalid_duration');
  // Empty and non-numeric segments.
  expectMalformed(plain('', '10', '{}'), 'invalid_counter');
  expectMalformed(plain('10', '', '{}'), 'invalid_duration');
  expectMalformed(plain('abc', '10', '{}'), 'invalid_counter');
  // Negative values cannot appear over the wire.
  expectMalformed(plain('-1', '10', '{}'), 'invalid_counter');
  // The duration ceiling: one hour accepted, one millisecond more is not.
  const atCeiling = decodeToken(envelope(plain('10', String(MAX_DURATION_MS), '{}')));
  assert.equal(atCeiling.durationMs, MAX_DURATION_MS);
  expectMalformed(plain('10', String(MAX_DURATION_MS + 1), '{}'), 'invalid_duration');
  // The telemetry segment must be a JSON object, never an array or scalar.
  expectMalformed(plain('10', '10', '[]'));
  expectMalformed(plain('10', '10', '"x"'));
  expectMalformed(plain('10', '10', 'null'));
  expectMalformed(plain('10', '10', '123'));
  // A token needs at least four segments.
  expectMalformed(`${NONCE}.1.2`);
  // The nonce shape: 43 alphabet chars plus one padding '='.
  expectMalformed(plain('10', '10', '{}').replace(NONCE, NONCE.slice(0, 43) + 'A='));
  // Non-canonical base64 envelopes are refused outright.
  assert.throws(
    () => decodeToken(envelope(plain('10', '10', '{}')).replace(/=+$/, '')),
    (error: unknown) => error instanceof DecodeError && error.code === 'invalid_base64',
  );
  assert.throws(
    () => decodeToken('%%%'),
    (error: unknown) => error instanceof DecodeError && error.code === 'invalid_base64',
  );
  // Oversized tokens are abuse probes, not solutions.
  assert.throws(
    () => decodeToken('QQ=='.repeat(20_000)),
    (error: unknown) => error instanceof DecodeError && error.code === 'malformed',
  );
  // The counter ceiling accepts 19999999 and refuses 20000000.
  assert.equal(decodeToken(envelope(plain('19999999', '10', '{}'))).counter, 19_999_999);
  expectMalformed(plain('20000000', '10', '{}'), 'counter_exceeds_solver_maximum');
});

test('an rsw proof rides as the final 512-hex segment', () => {
  const rswTail = 'a'.repeat(512);
  const token = decodeToken(envelope(`${NONCE}.0.10.{}.${rswTail}`));
  assert.equal(token.rswProof, rswTail);
  assert.equal(token.counter, 0);
  assert.equal(encodeToken(token), envelope(`${NONCE}.0.10.{}.${rswTail}`));
  // A 511-hex tail is not an rsw proof and fails the JSON parse.
  expectMalformed(`${NONCE}.0.10.{}.${'a'.repeat(511)}`);
});

test('execution evidence rides the digest:trace segment and survives the round trip', () => {
  const digest = 'a'.repeat(64);
  const trace = Buffer.from('dcreate(QUErOQ==);dappend(1);slen(11)', 'utf8').toString('base64url');
  const encoded = encodeToken({
    nonce: NONCE,
    counter: 12,
    durationMs: 100,
    telemetry: {},
    executionDigest: digest,
    executionTrace: trace,
    rswProof: null,
  });
  const token = decodeToken(encoded);
  assert.equal(token.executionDigest, digest);
  assert.equal(token.executionTrace, trace);
  assert.equal(token.counter, 12);
  assert.equal(encodeToken(token), encoded);
  // A digest that is not 64 lowercase hex stays out of the language.
  expectMalformed(`${NONCE}.12.100.{}.short:abc`);
  // The rsw and execution suffixes compose: proof last, evidence before.
  const composed = decodeToken(
    envelope(`${NONCE}.0.100.{}.${digest}:${trace}.${'b'.repeat(512)}`),
  );
  assert.equal(composed.rswProof, 'b'.repeat(512));
  assert.equal(composed.executionDigest, digest);
  assert.equal(composed.executionTrace, trace);
});
