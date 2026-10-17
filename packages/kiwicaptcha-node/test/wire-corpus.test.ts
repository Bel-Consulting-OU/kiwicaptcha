import assert from 'node:assert/strict';
import { test } from 'node:test';

import { readFixture } from './corpus.js';
import { decodeToken, DecodeError, type DecodeErrorCode } from '../src/token.js';
import { scoreTelemetry } from '../src/telemetry.js';

interface ExpectAccept {
  verdict: 'accept';
  counter: number;
  duration_ms: number;
  execution_digest: string | null;
  execution_trace: string | null;
  rsw_proof: string | null;
  telemetry?: unknown;
  telemetry_score?: boolean;
}

interface ExpectReject {
  verdict: 'reject';
  class: string;
}

interface CorpusRow {
  id: string;
  attack_class: string;
  raw: string;
  note: string;
  expect: ExpectAccept | ExpectReject;
}

const CORPUS = readFixture('wire-hostile-corpus.json') as {
  counts: { total: number };
  vectors: CorpusRow[];
};

function classify(code: DecodeErrorCode): string {
  switch (code) {
    case 'invalid_base64':
      return 'base64';
    case 'invalid_utf8':
      return 'utf8';
    case 'invalid_counter':
    case 'counter_exceeds_solver_maximum':
      return 'counter';
    case 'invalid_duration':
      return 'duration';
    default:
      return 'malformed';
  }
}

test('the shared hostile wire corpus is broad', () => {
  assert.ok(CORPUS.counts.total >= 100, 'the corpus must stay broad');
});

for (const row of CORPUS.vectors) {
  test(`wire corpus: ${row.id}`, () => {
    if (row.expect.verdict === 'accept') {
      const token = decodeToken(row.raw);
      assert.equal(token.counter, row.expect.counter, row.id);
      assert.equal(token.durationMs, row.expect.duration_ms, row.id);
      assert.equal(token.executionDigest, row.expect.execution_digest, row.id);
      assert.equal(token.executionTrace, row.expect.execution_trace, row.id);
      assert.equal(token.rswProof, row.expect.rsw_proof, row.id);
      if ('telemetry' in row.expect) {
        assert.deepStrictEqual(token.telemetry, row.expect.telemetry, `${row.id}: telemetry value`);
      }
      if ('telemetry_score' in row.expect) {
        assert.equal(
          scoreTelemetry(
            token.telemetry,
            token.durationMs,
            token.telemetryEtFloatSpellings,
          ),
          row.expect.telemetry_score,
          `${row.id}: telemetry score`,
        );
      }
      return;
    }

    assert.throws(
      () => decodeToken(row.raw),
      (error: unknown) => {
        assert.ok(error instanceof DecodeError, `${row.id}: a typed rejection is required`);
        if (row.expect.verdict === 'reject' && row.expect.class !== 'any') {
          assert.equal(classify(error.code), row.expect.class, row.id);
        }
        return true;
      },
      `${row.id}: the Node decoder accepted a hostile row`,
    );
  });
}
