import assert from 'node:assert/strict';
import { test } from 'node:test';

import { readFixture } from './corpus.js';
import { challengeRecordFromJson } from '../src/record.js';
import { verifyRecordSignature } from '../src/verify.js';

interface SignatureRow {
  id: string;
  record: unknown;
  challenge: string;
  verify_secret: string;
  verify_tenant: string | null;
  expect: 'accept' | 'reject';
}

const CORPUS = readFixture('wire-signature-corpus.json') as {
  counts: { total: number };
  vectors: SignatureRow[];
};

test('the shared challenge-signature corpus is broad', () => {
  assert.ok(CORPUS.counts.total >= 40, 'the signature corpus must stay broad');
});

for (const row of CORPUS.vectors) {
  test(`signature corpus: ${row.id}`, () => {
    const record = challengeRecordFromJson(row.record);
    assert.equal(record.challenge, row.challenge, row.id);
    const config = { tenantId: row.verify_tenant } as never;
    const verified = verifyRecordSignature(
      config,
      record,
      Buffer.from(row.verify_secret, 'utf8'),
    );
    assert.equal(verified, row.expect === 'accept', row.id);
  });
}
