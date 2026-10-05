import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readProtocol } from './corpus.js';
import {
  KiwiOutcomes,
  OUTCOMES,
  OUTCOME_MAP_VERSION,
  allOutcomeMappings,
  outcomeMapping,
  accepts,
  validateOutcomeHandle,
  markKind,
  hasLedgerAction,
  ledgerDimensions,
  identityDimensions,
  markKey,
  defaultIdempotencyKey,
  type OutcomeHandle,
  type OutcomeSink,
} from '../src/outcomes.js';

/**
 * The outcomes mapping vectors: every row of the shared protocol
 * corpus (protocol/risk-v1/outcomes-vectors.json) asserted against the
 * Node mapping table, then the sink-driven report flow.
 */

interface OutcomeVector {
  outcome: string;
  handle: { dimension: string; id: string };
  accepted: boolean;
  channel_value?: number;
  ledger_action?: string | null;
  mark_kind?: string | null;
  mark_key?: string | null;
  server_confirmed?: boolean;
  may_subtract_risk?: boolean;
  writes_abuse_mark?: boolean;
  reject?: string;
}

function sinkRecording(): OutcomeSink & { calls: string[]; marks: Map<string, string>; ledgers: Map<string, boolean> } {
  const calls: string[] = [];
  const marks = new Map<string, string>();
  const ledgers = new Map<string, boolean>();
  return {
    calls,
    marks,
    ledgers,
    async confirmLedger(id, legitimate) {
      calls.push(`ledger:${id}:${legitimate ? 'L' : 'A'}`);
      ledgers.set(id, legitimate);
      return 1;
    },
    async recordFeedback(channel, idempotencyKey, handle) {
      calls.push(`feedback:${channel}:${idempotencyKey}:${handle.dimension}`);
    },
    async writeMark(key, kind) {
      calls.push(`mark:${key}:${kind}`);
      marks.set(key, kind);
      return 1;
    },
    async forgetMark(key) {
      calls.push(`forget:${key}`);
      return marks.delete(key) ? 1 : 0;
    },
  };
}

test('the mapping table is total, versioned and matches every vector row', () => {
  const vectors = readProtocol('risk-v1/outcomes-vectors.json') as {
    version: number;
    handles: Record<string, string>;
    vectors: OutcomeVector[];
  };
  assert.equal(vectors.version, OUTCOME_MAP_VERSION);
  assert.equal(OUTCOMES.length, 8);
  assert.equal(allOutcomeMappings().length, 8);
  for (const mapping of allOutcomeMappings()) {
    assert.equal(typeof mapping.channel, 'number');
    assert.ok(mapping.acceptedHandles.length > 0);
  }
  for (const vector of vectors.vectors) {
    const mapping = outcomeMapping(vector.outcome as never);
    if (!vector.accepted) {
      // Two rejection classes: the handle dimension is not accepted,
      // or the raw id is not the pseudonym shape the dimension carries.
      if (vector.reject === 'handle') {
        assert.equal(accepts(mapping, vector.handle.dimension as never), false, `${vector.outcome}/${vector.handle.dimension}`);
      } else if (vector.reject === 'identifier') {
        assert.throws(
          () => validateOutcomeHandle(vector.handle as OutcomeHandle),
          RangeError,
          `${vector.outcome}/${vector.handle.dimension}/${vector.handle.id}`,
        );
      } else {
        assert.fail(`unknown reject class: ${String(vector.reject)}`);
      }
      continue;
    }
    assert.doesNotThrow(() => validateOutcomeHandle(vector.handle as OutcomeHandle));
    assert.equal(accepts(mapping, vector.handle.dimension as never), true, `${vector.outcome}/${vector.handle.dimension}`);
    assert.equal(mapping.channel, vector.channel_value, `${vector.outcome} channel`);
    assert.equal(mapping.serverConfirmed, vector.server_confirmed, `${vector.outcome} polarity`);
    assert.equal(mapping.maySubtractRisk, vector.may_subtract_risk, `${vector.outcome} trust`);
    assert.equal(mapping.writesAbuseMark, vector.writes_abuse_mark, `${vector.outcome} marks`);
    if (vector.ledger_action === 'L') {
      assert.equal(mapping.ledgerLegitimate, true);
      assert.equal(hasLedgerAction(mapping), true);
    } else if (vector.ledger_action === 'A') {
      assert.equal(mapping.ledgerLegitimate, false);
      assert.equal(hasLedgerAction(mapping), true);
    } else {
      assert.equal(mapping.ledgerLegitimate, null);
      assert.equal(hasLedgerAction(mapping), false);
    }
    assert.equal(markKind(mapping), vector.mark_kind ?? null, `${vector.outcome} mark kind`);
    if (vector.mark_key !== null && vector.mark_key !== undefined) {
      assert.equal(markKey('d', vector.handle.dimension as never, vector.handle.id), vector.mark_key);
    }
  }
});

test('the trust and abuse polarity classes are disjoint', () => {
  for (const mapping of allOutcomeMappings()) {
    if (mapping.maySubtractRisk) {
      assert.equal(mapping.writesAbuseMark, false, `${mapping.outcome}: trust never writes abuse marks`);
      assert.equal(mapping.serverConfirmed, true, `${mapping.outcome}: trust is server-confirmed only`);
    }
    if (mapping.writesAbuseMark) {
      assert.equal(mapping.maySubtractRisk, false, `${mapping.outcome}: abuse never lowers risk`);
    }
  }
  assert.deepEqual(ledgerDimensions(), ['nonce', 'decisionId']);
  assert.deepEqual(identityDimensions(), ['principal', 'target', 'session', 'agent']);
});

test('report resolves ledger and identity handles through the sink', async () => {
  const sink = sinkRecording();
  const outcomes = new KiwiOutcomes(sink, 'd');
  const principal = '9f1c4a7e2b8d63f05a1e9c4d7b2e6f18';
  const receipt = await outcomes.report('confirmedLegitimate', { dimension: 'decisionId', id: 'd4e5f60718293a4b5c6d7e8f90a1b2c3' }, 'idem-1');
  assert.equal(receipt.outcome, 'confirmedLegitimate');
  assert.equal(receipt.ledgerStatus, 1);
  assert.equal(receipt.marksWritten, 0);
  assert.deepEqual(sink.calls, [
    'ledger:d4e5f60718293a4b5c6d7e8f90a1b2c3:L',
    'feedback:12:idem-1:decisionId',
  ]);

  const abuse = await outcomes.report('chargeback', { dimension: 'principal', id: principal });
  assert.equal(abuse.marksWritten, 1);
  assert.equal(abuse.ledgerStatus, null);
  assert.ok(sink.marks.get(markKey('d', 'principal', principal)) === 'chargeback');
  assert.ok(sink.calls.some((call) => call.startsWith('feedback:13:')));
  assert.equal(defaultIdempotencyKey({ dimension: 'principal', id: principal }).length, 32);

  const forgotten = await outcomes.forget({ dimension: 'principal', id: principal });
  assert.equal(forgotten, 1);
  const ledgerForget = await outcomes.forget({ dimension: 'nonce', id: 'n-1' });
  assert.equal(ledgerForget, 0);
});

test('a rejected handle dimension throws a typed range error', async () => {
  const sink = sinkRecording();
  const outcomes = new KiwiOutcomes(sink);
  await assert.rejects(
    outcomes.report('stepUpCompleted', { dimension: 'decisionId', id: 'd-1' }),
    /cannot be reported on a decisionId handle/,
  );
  await assert.rejects(
    outcomes.report('authenticationFailure', { dimension: 'nonce', id: 'n-1' }),
    /cannot be reported on a nonce handle/,
  );
});

test('every trust outcome can ride every handle, abuse marks land keyed', async () => {
  const sink = sinkRecording();
  const outcomes = new KiwiOutcomes(sink, 'tenant-x');
  const handles: OutcomeHandle[] = [
    { dimension: 'nonce', id: '0f1e2d3c4b5a69788796a5b4c3d2e1f0' },
    { dimension: 'decisionId', id: 'd4e5f60718293a4b5c6d7e8f90a1b2c3' },
    { dimension: 'principal', id: '9f1c4a7e2b8d63f05a1e9c4d7b2e6f18' },
    { dimension: 'target', id: '5e2a9b4c1d7f38e6a0b5c9d2e4f6a813' },
    { dimension: 'session', id: 'c7b3e1f9a5d24708b6e0c8a2f4d69123' },
    { dimension: 'agent', id: 'backfill-bot' },
  ];
  for (const outcome of OUTCOMES) {
    for (const handle of handles) {
      const mapping = outcomeMapping(outcome);
      if (!accepts(mapping, handle.dimension)) {
        await assert.rejects(outcomes.report(outcome, handle), RangeError);
        continue;
      }
      const receipt = await outcomes.report(outcome, handle);
      assert.equal(receipt.outcome, outcome);
      if (markKind(mapping) !== null && identityDimensions().includes(handle.dimension)) {
        assert.ok(sink.marks.has(markKey('tenant-x', handle.dimension, handle.id)));
      }
    }
  }
});
