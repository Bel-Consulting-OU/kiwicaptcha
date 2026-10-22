/**
 * The shared Interactive-Client Lifecycle v1 vectors against the RN
 * binding's pure decision (the Android reference mirrored exactly):
 * every vector in protocol/interactive-client-v1/lifecycle-vectors.json
 * must resolve to its expected {deliver, deliverAtMs, reason}.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  EXPIRY_SAFETY_MARGIN_MS,
  deliveryDecision,
  expiresAtMs,
  minSubmitAtMs,
} from "../src/lifecycle.js";

interface LifecycleVector {
  name: string;
  receivedAtMs: number;
  ttlSecs: number;
  minDurationMs: number;
  solveFinishedAtMs: number;
  nowMs: number;
  cancelled: boolean;
  expect: { deliver: boolean; deliverAtMs: number; reason: string };
}

function loadVectors(): LifecycleVector[] {
  // npm test runs with the package root as cwd.
  const path = join(
    process.cwd(),
    "..",
    "..",
    "protocol",
    "interactive-client-v1",
    "lifecycle-vectors.json",
  );
  return JSON.parse(readFileSync(path, "utf8")) as LifecycleVector[];
}

describe("interactive-client lifecycle v1 (RN)", () => {
  test("every shared vector resolves to the expected decision", () => {
    const vectors = loadVectors();
    expect(vectors.length).toBeGreaterThanOrEqual(10);
    for (const vector of vectors) {
      const got = deliveryDecision(
        vector.receivedAtMs,
        vector.ttlSecs,
        vector.minDurationMs,
        vector.solveFinishedAtMs,
        vector.nowMs,
        vector.cancelled,
      );
      expect({ name: vector.name, ...got }).toEqual({ name: vector.name, ...vector.expect });
    }
  });

  test("the pinned boundaries hold on their own", () => {
    // A challenge without a TTL never expires...
    expect(expiresAtMs(1000, 0)).toBeGreaterThan(Number.MAX_SAFE_INTEGER - 1);
    // ...and the deadline is parse + ttl - the 1 s margin.
    expect(expiresAtMs(1000, 30)).toBe(1000 + 30000 - EXPIRY_SAFETY_MARGIN_MS);
    expect(minSubmitAtMs(1000, 250)).toBe(1250);

    const received = 1_000_000;
    // now == expiresAtMs is expired (the >= gate).
    const expires = expiresAtMs(received, 120);
    const atDeadline = deliveryDecision(received, 120, 0, received + 400, expires, false);
    expect(atDeadline).toEqual({ deliver: false, deliverAtMs: 0, reason: "expired" });
    const justBefore = deliveryDecision(received, 120, 0, received + 400, expires - 1, false);
    expect(justBefore.reason).toBe("deliver");

    // now == minSubmitAtMs delivers (due from the floor onward).
    const atFloor = deliveryDecision(received, 120, 250, received + 100, received + 250, false);
    expect(atFloor).toEqual({ deliver: true, deliverAtMs: received + 250, reason: "deliver" });
    const beforeFloor = deliveryDecision(received, 120, 250, received + 100, received + 249, false);
    expect(beforeFloor).toEqual({
      deliver: false,
      deliverAtMs: received + 250,
      reason: "defer",
    });

    // Cancellation wins over everything.
    expect(deliveryDecision(received, 120, 0, received + 1, received + 1, true)).toEqual({
      deliver: false,
      deliverAtMs: 0,
      reason: "cancelled",
    });
  });
});
