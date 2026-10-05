import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The protocol corpus loader: the test suite reads the SAME protocol
 * fixture files every other core reads, plus the PHP-issued golden
 * vectors and the ported execution differential corpus under
 * test/fixtures.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
/** The package root (dist/test resolves two levels up). */
export const PACKAGE_ROOT = resolve(HERE, '..', '..');
/** The repository root holding the shared protocol/ corpus. */
export const REPO_ROOT = resolve(PACKAGE_ROOT, '..', '..');

export function readProtocol(relpath: string): unknown {
  return JSON.parse(readFileSync(resolve(REPO_ROOT, 'protocol', relpath), 'utf8')) as unknown;
}

export function readFixture(relpath: string): unknown {
  return JSON.parse(readFileSync(resolve(PACKAGE_ROOT, 'test', 'fixtures', relpath), 'utf8')) as unknown;
}

export interface GoldenVectors {
  hkdf: {
    secret: string;
    challenge_hex: string;
    ip_bind_hex: string;
    result_hex: string;
    server_state_hex: string;
  };
  canonical: {
    base: string;
    signature_hex: string;
    v3_decoy: string;
    v4_execution: string;
    v5_identity: string;
  };
  server_state_mac: {
    key_hex: string;
    record_meta_input: string;
    record_meta_hex: string;
    consumed_result_input: string;
    consumed_result_hex: string;
  };
  records: GoldenRecord[];
}

export interface GoldenRecord {
  name: string;
  record: Record<string, unknown>;
  token_b64: string;
  expected: { ok: boolean; code?: string; decoyField?: string };
  verify_opts: Record<string, unknown>;
}

/** The PHP-issued golden vectors (records, tokens, keys, MACs). */
export function goldenVectors(): GoldenVectors {
  return readFixture('golden-php-vectors.json') as GoldenVectors;
}

export interface ExecutionCorpus {
  nonce: string;
  cases: { name: string; version: number; program: string; trace: string; expected: string }[];
}

export function executionCorpus(): ExecutionCorpus {
  return readFixture('execution-differential-corpus.json') as ExecutionCorpus;
}

/**
 * The frozen test clock: the golden records were issued once by the
 * PHP core, so every test that redeems them travels back to the
 * issuance era on both clocks (the TTL clock and the microsecond
 * receipt clock).
 */
export interface FrozenClock {
  now: () => number;
  nowNs: number;
}

export function frozenClock(record: { issuedAt: number; issuedAtNs: number }): FrozenClock {
  return { now: () => record.issuedAt + 10, nowNs: record.issuedAtNs + 2_000_000 };
}
