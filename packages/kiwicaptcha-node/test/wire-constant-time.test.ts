import assert from 'node:assert/strict';
import { test } from 'node:test';

import { timingSafeEqualsHex } from '../src/mac.js';

// Measurement design (required structure):
//   - randomized A/B ordering per paired iteration (seeded mulberry32);
//   - N paired samples (>= 2000), warm-up iterations discarded;
//   - robust statistic: median of signed paired deltas + MAD;
//   - three comparators in one run: POSITIVE (deliberately leaky),
//     NEGATIVE (identical inputs), PRODUCTION (timingSafeEqualsHex);
//   - verdict:
//       positive NOT distinguishable  -> INCONCLUSIVE note, PASS
//       (negative distinguishable also means the host cannot measure
//        -> INCONCLUSIVE note, PASS; never fail production on it)
//       positive YES + production NO  -> PASS
//       positive YES + production YES -> FAIL with both effect sizes.
//
// Threshold rule (one simple robust rule, documented): let d_i be the
// signed paired deltas (arm1 - arm2), med = median(d_i),
// MAD = median(|d_i - med|). An arm pair is DISTINGUISHABLE iff
//     |med| > 6 * max(MAD, 1ns).
// A constant-time comparator has med ~ 0 under randomized ordering;
// a variable-time one has |med| ~ the cost of the skipped work, which
// for a 16 KiB early-exit scan dwarfs 6xMAD at N >= 2000.

const LENGTH = 16_384;
const N = 2_000;
const WARMUP = 200;
const K_MAD = 6;

let sink = false;

type Compare = (a: string, b: string) => boolean;

/** Seeded PRNG so the A/B order randomization is reproducible. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

/** Deliberately leaky comparator: early-exit on first difference. */
function leaking(a: string, b: string): boolean {
  for (let index = 0; index < a.length; index += 1) {
    if (a.charCodeAt(index) !== b.charCodeAt(index)) {
      return false;
    }
  }
  return true;
}

function timeOnce(compare: Compare, a: string, b: string): number {
  const start = process.hrtime.bigint();
  sink = compare(a, b);
  return Number(process.hrtime.bigint() - start);
}

function median(values: number[]): number {
  const sorted = [...values].sort((x, y) => x - y);
  const mid = sorted.length >> 1;
  const lo = sorted[mid - 1] ?? 0;
  const hi = sorted[mid] ?? 0;
  return sorted.length % 2 === 1 ? hi : (lo + hi) / 2;
}

interface PairedStats {
  median: number;
  mad: number;
  threshold: number;
  distinguishable: boolean;
}

/**
 * Paired A/B measurement with randomized execution order.
 * arm1 and arm2 may run in either order each iteration; the signed delta
 * is always (arm1 - arm2), so a true effect keeps a consistent sign.
 */
function measurePaired(
  compare: Compare,
  a1: string,
  b1: string,
  a2: string,
  b2: string,
  rand: () => number,
): PairedStats {
  for (let i = 0; i < WARMUP; i += 1) {
    timeOnce(compare, a1, b1);
    timeOnce(compare, a2, b2);
  }
  const deltas: number[] = [];
  for (let i = 0; i < N; i += 1) {
    let d: number;
    if (rand() < 0.5) {
      const t1 = timeOnce(compare, a1, b1);
      const t2 = timeOnce(compare, a2, b2);
      d = t1 - t2;
    } else {
      const t2 = timeOnce(compare, a2, b2);
      const t1 = timeOnce(compare, a1, b1);
      d = t1 - t2;
    }
    deltas.push(d);
  }
  const med = median(deltas);
  const mad = median(deltas.map((d) => Math.abs(d - med)));
  const threshold = K_MAD * Math.max(mad, 1);
  return { median: med, mad, threshold, distinguishable: Math.abs(med) > threshold };
}

function describe(name: string, s: PairedStats): string {
  return `${name}: median=${s.median.toFixed(1)}ns MAD=${s.mad.toFixed(1)}ns threshold=${s.threshold.toFixed(1)}ns distinguishable=${s.distinguishable}`;
}

test('the secret comparison does not leak the mismatch position', () => {
  const first = 'a'.repeat(LENGTH);
  const head = `b${first.slice(1)}`;
  const last = `${first.slice(0, -1)}b`;
  const rand = mulberry32(0x5eed1a7e);

  // POSITIVE CONTROL: same leaky comparator, mismatch at first vs last byte.
  const positive = measurePaired(leaking, first, head, first, last, rand);
  // NEGATIVE CONTROL: two identical-input comparisons of the leaky comparator.
  const negative = measurePaired(leaking, first, first, first, first, rand);
  // PRODUCTION: the comparator under test, mismatch at first vs last byte.
  const production = measurePaired(
    timingSafeEqualsHex,
    first,
    head,
    first,
    last,
    rand,
  );

  const report = [
    describe('positive control (leaky, head vs tail mismatch)', positive),
    describe('negative control (identical inputs)', negative),
    describe('production (timingSafeEqualsHex, head vs tail mismatch)', production),
  ].join('\n');

  // The machine cannot measure if the leaky early-exit is invisible under
  // the same statistic, or if identical-input arms look different (broken
  // noise characterization on this host). Never fail production for that.
  if (!positive.distinguishable || negative.distinguishable) {
    console.error(`INCONCLUSIVE: this host cannot characterize timing under the ${K_MAD}xMAD rule; production is NOT failed.\n${report}`);
    assert.equal(sink, false);
    return;
  }

  if (production.distinguishable) {
    assert.fail(
      `timingSafeEqualsHex leaked the mismatch position.\n${report}`,
    );
  }

  // positive distinguishable + production indistinguishable -> PASS
  console.error(`timing measurement OK:\n${report}`);
  assert.equal(sink, false);
});
