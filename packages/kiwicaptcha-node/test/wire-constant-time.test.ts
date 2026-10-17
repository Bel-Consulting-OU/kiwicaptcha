import assert from 'node:assert/strict';
import { test } from 'node:test';

import { timingSafeEqualsHex } from '../src/mac.js';

const LENGTH = 16_384;
const ROUNDS = 30;
const CALLS = 50;

let sink = false;

function measure(compare: (a: string, b: string) => boolean, a: string, b: string): number {
  let best = Number.POSITIVE_INFINITY;
  for (let round = 0; round < ROUNDS; round += 1) {
    const start = process.hrtime.bigint();
    for (let call = 0; call < CALLS; call += 1) {
      sink = compare(a, b);
    }
    best = Math.min(best, Number(process.hrtime.bigint() - start) / CALLS);
  }
  return best;
}

function leaking(a: string, b: string): boolean {
  for (let index = 0; index < a.length; index += 1) {
    if (a.charCodeAt(index) !== b.charCodeAt(index)) {
      return false;
    }
  }
  return true;
}

test('the secret comparison does not leak the mismatch position', () => {
  const first = 'a'.repeat(LENGTH);
  const head = `b${first.slice(1)}`;
  const last = `${first.slice(0, -1)}b`;

  // Warm both comparators first: the first rounds pay JIT and IC
  // costs, and measuring the noise floor on the leaking comparator
  // before warmup inflated it enough to hide the positive control.
  measure(leaking, first, first);
  measure(timingSafeEqualsHex, first, first);

  // The noise floor is the jitter of the comparator under test, not of
  // the intentionally leaking positive control.
  const noiseA = measure(timingSafeEqualsHex, first, first);
  const noiseB = measure(timingSafeEqualsHex, first, first);
  const noise = Math.max(1, Math.abs(noiseA - noiseB));

  const leakFirst = measure(leaking, first, head);
  const leakLast = measure(leaking, first, last);
  const leakDelta = Math.abs(leakLast - leakFirst);
  assert.ok(
    leakDelta > Math.max(noise * 10, 1_000),
    `the measurement must see an early exit (first=${leakFirst}ns last=${leakLast}ns noise=${noise}ns)`,
  );

  const realFirst = measure(timingSafeEqualsHex, first, head);
  const realLast = measure(timingSafeEqualsHex, first, last);
  const realDelta = Math.abs(realLast - realFirst);
  const budget = Math.max(noise * 10, realFirst * 0.2, 2_000);
  assert.ok(
    realDelta <= budget,
    `timingSafeEqualsHex leaked the mismatch position (first=${realFirst}ns last=${realLast}ns noise=${noise}ns)`,
  );
  assert.equal(sink, false);
});
