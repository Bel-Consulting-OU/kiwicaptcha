import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { readProtocol, goldenVectors } from './corpus.js';
import { Rsw, modulusFingerprintHex, rswIdentityMatches, deriveBase, rswProofHex } from '../src/rsw.js';

/**
 * The rsw identity fixture: the one canonical modulus identity every
 * component must agree on, plus the trapdoor math on native BigInt.
 */

interface RswIdentityFixture {
  modulus_n_b64: string;
  lambda_b64: string;
  rsw_modulus_n_sha256: string;
  legacy_base64_text_sha256: string;
  secondary: { modulus_n_b64: string; lambda_b64: string };
}

function fixture(): RswIdentityFixture {
  return readProtocol('rsw-identity-v1/fixtures.json') as unknown as RswIdentityFixture;
}

test('the canonical and legacy identities match the shared fixture', () => {
  const fx = fixture();
  assert.equal(modulusFingerprintHex(fx.modulus_n_b64), fx.rsw_modulus_n_sha256);
  assert.equal(
    createHash('sha256').update(fx.modulus_n_b64, 'latin1').digest('hex'),
    fx.legacy_base64_text_sha256,
  );
  assert.equal(rswIdentityMatches(fx.rsw_modulus_n_sha256, fx.modulus_n_b64, false), true);
  assert.equal(rswIdentityMatches(fx.legacy_base64_text_sha256, fx.modulus_n_b64, false), false);
  assert.equal(rswIdentityMatches(fx.legacy_base64_text_sha256, fx.modulus_n_b64, true), true);
  // A foreign identity never matches.
  assert.equal(rswIdentityMatches('f'.repeat(64), fx.modulus_n_b64, true), false);
});

test('the primary trapdoor validates and the secondary pair refuses cross-proofs', () => {
  const fx = fixture();
  const primary = new Rsw(fx.modulus_n_b64, fx.lambda_b64);
  assert.equal(primary.n.toString(2).length, 2048);
  const secondary = new Rsw(fx.secondary.modulus_n_b64, fx.secondary.lambda_b64);
  assert.notEqual(primary.n, secondary.n);
  // The trapdoor consistency spot-check rejects a mismatched lambda.
  assert.throws(() => new Rsw(fx.modulus_n_b64, fx.secondary.lambda_b64), /matching trapdoor/);
});

test('modulus and lambda shapes are validated before any math runs', () => {
  const fx = fixture();
  assert.throws(() => new Rsw('', fx.lambda_b64), /non-empty/);
  // A modulus of the wrong size.
  const small = Buffer.alloc(128, 0xff);
  assert.throws(() => new Rsw(small.toString('base64'), fx.lambda_b64), /exactly 256 bytes/);
  // A modulus without the top bit set.
  const low = Buffer.alloc(256);
  low[0] = 0x7f;
  low[255] = 0x01;
  assert.throws(() => new Rsw(low.toString('base64'), fx.lambda_b64), /top bit set/);
  // An even modulus.
  const even = Buffer.alloc(256, 0xff);
  even[255] = 0xfe;
  assert.throws(() => new Rsw(even.toString('base64'), fx.lambda_b64), /odd/);
  // An odd lambda.
  assert.throws(() => new Rsw(fx.modulus_n_b64, Buffer.of(0x05).toString('base64')), /even/);
  // A small-prime modulus.
  assert.throws(() => new Rsw(Buffer.of(0xff, 0x03).toString('base64'), Buffer.of(0x02).toString('base64')), /small prime|exactly 256/);
});

test('the golden rsw proof verifies through the BigInt trapdoor', () => {
  const golden = goldenVectors();
  const row = golden.records.find((entry) => entry.name === 'rsw');
  assert.ok(row !== undefined);
  const trapdoor = new Rsw(fixture().modulus_n_b64, fixture().lambda_b64);
  // The PHP-issued expected proof is the valid client proof.
  const prefix = row.record['prefix'] as string;
  const nonce = row.record['nonce'] as string;
  const t = row.record['t'] as number;
  const expected = trapdoor.expectedProofHex(prefix, nonce, t);
  assert.match(expected, /^[0-9a-f]{512}$/);
  // The base derivation is the SHA-256 residue of prefix plus nonce.
  const base = deriveBase(prefix, nonce, trapdoor.n);
  assert.equal(base < trapdoor.n, true);
  assert.equal(rswProofHex(base).length, 512);
});
