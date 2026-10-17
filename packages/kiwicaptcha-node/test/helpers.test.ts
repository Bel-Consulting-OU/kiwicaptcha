import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  ALL_VERIFY_ERROR_CODES,
  VerifyErrorCode,
  describeVerifyError,
  isReplayExempt,
} from '../src/errors.js';
import { buffersEqual, signPayloadV1 } from '../src/canonical.js';
import {
  isValidDecoyFieldName,
  isValidIdentifier,
  protocolExtensionGrammarOk,
} from '../src/record.js';
import { deriveSha256Hash, leadingZeroBits, meetsTarget } from '../src/pow.js';
import { decodeEnvelope, validatedOperationIdentity } from '../src/store.js';
import { headerTokenValues, stringValues } from '../src/middleware/token-source.js';
import { ladderRung, measurableSolveDurationMs, policyVersionAccepted } from '../src/verify.js';
import type { ChallengeRecord } from '../src/record.js';

/**
 * Direct pins for the exported helper surface. Every one of these is
 * public API and is also consumed by the verify/middleware paths; the
 * pins make the contract explicit instead of relying on an indirect
 * caller to notice a change.
 */

test('every error code has a distinct operator description', () => {
  const descriptions = new Set<string>();
  for (const code of ALL_VERIFY_ERROR_CODES) {
    const description = describeVerifyError(code);
    assert.equal(typeof description, 'string');
    assert.ok(description.length > 0, `${code} has no description`);
    descriptions.add(description);
  }
  assert.equal(descriptions.size, ALL_VERIFY_ERROR_CODES.length);
});

test('only the receipt-circumstance failures are replay-exempt', () => {
  const exempt = new Set<string>([
    VerifyErrorCode.Expired,
    VerifyErrorCode.IpMismatch,
    VerifyErrorCode.MissingClientIp,
    VerifyErrorCode.TelemetryRejected,
  ]);
  for (const code of ALL_VERIFY_ERROR_CODES) {
    assert.equal(isReplayExempt(code), exempt.has(code), `replay exemption drifted for ${code}`);
  }
});

test('buffersEqual is a length-safe constant-time comparison', () => {
  assert.equal(buffersEqual(Buffer.from('same'), Buffer.from('same')), true);
  assert.equal(buffersEqual(Buffer.from('same'), Buffer.from('diff')), false);
  assert.equal(buffersEqual(Buffer.from('short'), Buffer.from('longer')), false);
});

test('signPayloadV1 is deterministic and secret-bound', () => {
  const payload = 'v1|nonce|login|123';
  assert.equal(signPayloadV1(payload, 'a'.repeat(32)), signPayloadV1(payload, 'a'.repeat(32)));
  assert.notEqual(signPayloadV1(payload, 'a'.repeat(32)), signPayloadV1(payload, 'b'.repeat(32)));
});

test('identifier and decoy grammars reject separators, whitespace and overlong values', () => {
  assert.equal(isValidIdentifier('login', 128), true);
  assert.equal(isValidIdentifier('tenant.a:b-c_d', 64), true);
  assert.equal(isValidIdentifier('', 128), false);
  assert.equal(isValidIdentifier('a'.repeat(129), 128), false);
  assert.equal(isValidIdentifier('has space', 128), false);
  assert.equal(isValidIdentifier('pipe|separator', 128), false);

  assert.equal(isValidDecoyFieldName('kiwi_website-1'), true);
  assert.equal(isValidDecoyFieldName(''), false);
  assert.equal(isValidDecoyFieldName('has.dot'), false);
  assert.equal(isValidDecoyFieldName('a'.repeat(65)), false);
});

test('the protocol extension matrix matches the signed grammar', () => {
  // v1/v2 carry no extension; v3 requires the decoy; v4 requires the
  // execution triplet; v5 requires the rsw identity.
  assert.equal(protocolExtensionGrammarOk(1, false, false, false), true);
  assert.equal(protocolExtensionGrammarOk(1, true, false, false), false);
  assert.equal(protocolExtensionGrammarOk(2, false, false, false), true);
  assert.equal(protocolExtensionGrammarOk(2, false, true, false), false);
  assert.equal(protocolExtensionGrammarOk(3, true, false, false), true);
  assert.equal(protocolExtensionGrammarOk(3, false, false, false), false);
  assert.equal(protocolExtensionGrammarOk(4, false, true, false), true);
  assert.equal(protocolExtensionGrammarOk(4, false, false, false), false);
  assert.equal(protocolExtensionGrammarOk(5, false, true, true), true);
  assert.equal(protocolExtensionGrammarOk(5, false, true, false), false);
});

test('the SHA-256 proof derivation matches the core byte order', () => {
  const salt = Buffer.from([1, 2, 3, 4]);
  const expected = createHash('sha256')
    .update(Buffer.concat([Buffer.from('prefix7', 'latin1'), salt]))
    .digest();
  assert.deepEqual(deriveSha256Hash('prefix', 7, salt), expected);

  // 0x00 0x0f: eight zero bits plus four leading zero bits = 12.
  const hash = Buffer.from([0x00, 0x0f, ...new Array(30).fill(0xff)]);
  assert.equal(leadingZeroBits(hash), 12);
  assert.equal(meetsTarget(hash, 12), true);
  assert.equal(meetsTarget(hash, 13), false);
  assert.equal(leadingZeroBits(Buffer.alloc(32, 0xff)), 0);
});

test('operation identities are validated before they reach storage', () => {
  assert.equal(validatedOperationIdentity(null), null);
  assert.equal(validatedOperationIdentity(undefined), null);
  assert.equal(validatedOperationIdentity('op-1_A'), 'op-1_A');
  assert.throws(() => validatedOperationIdentity(''), RangeError);
  assert.throws(() => validatedOperationIdentity('has space'), RangeError);
  assert.throws(() => validatedOperationIdentity('a'.repeat(129)), RangeError);
});

test('a structurally broken storage envelope degrades to null, never a partial record', () => {
  assert.equal(decodeEnvelope('not json'), null);
  assert.equal(decodeEnvelope('null'), null);
  assert.equal(decodeEnvelope('[]'), null);
  assert.equal(decodeEnvelope('"string"'), null);
  assert.equal(decodeEnvelope('{}'), null);
  assert.equal(decodeEnvelope('{"state":42}'), null);
});

test('token source collection keeps every non-empty value and splits merged headers', () => {
  assert.deepEqual(stringValues('one'), ['one']);
  assert.deepEqual(stringValues(''), []);
  assert.deepEqual(stringValues(['a', '', 7, 'b']), ['a', 'b']);
  assert.deepEqual(stringValues(undefined), []);

  assert.deepEqual(
    headerTokenValues(['x-kiwi-token', 'a,b', 'X-Kiwi-Token', 'c'], undefined),
    ['a', 'b', 'c'],
  );
  assert.deepEqual(headerTokenValues(undefined, 'a, b'), ['a', 'b']);
  assert.deepEqual(headerTokenValues(undefined, undefined), []);
});

test('the ladder rung names the signed parameters', () => {
  const record = (fields: Partial<ChallengeRecord>) => fields as ChallengeRecord;
  assert.equal(ladderRung(record({ algorithm: 'sha256', targetBits: 16 })), 'sha16');
  assert.equal(ladderRung(record({ algorithm: 'sha256', targetBits: 18 })), 'sha18');
  assert.equal(ladderRung(record({ algorithm: 'sha256', targetBits: 20 })), 'sha20');
  assert.equal(ladderRung(record({ algorithm: 'sha256', targetBits: 17 })), 'sha17bit');
  assert.equal(ladderRung(record({ algorithm: 'argon2id', mKib: 16384 })), 'argon16');
  assert.equal(ladderRung(record({ algorithm: 'argon2id', mKib: 32768 })), 'argon32');
  assert.equal(ladderRung(record({ algorithm: 'argon2id', mKib: 65536 })), 'argon64');
  assert.equal(ladderRung(record({ algorithm: 'rsw' })), 'rsw');
});

test('the policy window is exact, floored or open as configured', () => {
  const config = (expectedPolicyVersion: number | null, policyVersionFloor: number | null) =>
    ({ expectedPolicyVersion, policyVersionFloor }) as never;
  assert.equal(policyVersionAccepted(config(null, null), 99), true);
  assert.equal(policyVersionAccepted(config(7, null), 7), true);
  assert.equal(policyVersionAccepted(config(7, null), 6), false);
  assert.equal(policyVersionAccepted(config(7, 5), 5), true);
  assert.equal(policyVersionAccepted(config(7, 5), 7), true);
  assert.equal(policyVersionAccepted(config(7, 5), 4), false);
  assert.equal(policyVersionAccepted(config(7, 5), 8), false);
});

test('the server-measured solve duration is present only for a receipted fresh record', () => {
  const record = (fields: Partial<ChallengeRecord>) => fields as ChallengeRecord;
  assert.equal(
    measurableSolveDurationMs(record({ serverMac: 'mac', issuedAtNs: 1_000_000 }), 3_000_000),
    2000,
  );
  assert.equal(measurableSolveDurationMs(record({ serverMac: null, issuedAtNs: 1_000_000 }), 3_000_000), null);
  assert.equal(measurableSolveDurationMs(record({ serverMac: 'mac', issuedAtNs: 0 }), 3_000_000), null);
  assert.equal(measurableSolveDurationMs(record({ serverMac: 'mac', issuedAtNs: 3_000_000 }), 1_000_000), null);
  assert.equal(measurableSolveDurationMs(record({ serverMac: 'mac', issuedAtNs: 1_000_000 }), null), null);
});
