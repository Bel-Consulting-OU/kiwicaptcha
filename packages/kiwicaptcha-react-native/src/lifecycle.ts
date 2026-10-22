/**
 * The pure delivery decision of the Interactive-Client Lifecycle v1
 * contract (protocol/interactive-client-v1): whether a finished solve
 * may deliver its token now, must defer until a future instant, or has
 * lost the expiry race. Deterministic, dependency-free, and pinned by
 * the shared vectors every binding tests against — the mirror of the
 * Android reference (`KiwiLifecycle`), byte-for-byte on evaluation
 * order and boundary semantics.
 */

/** The delivery decision of one lifecycle checkpoint. */
export interface DeliveryDecision {
  /** Whether the token may be delivered at `deliverAtMs`'s instant. */
  deliver: boolean;
  /**
   * The delivery instant: `nowMs` on "deliver", the scheduled future
   * instant on "defer", `0` on "expired"/"cancelled".
   */
  deliverAtMs: number;
  /** "deliver" | "defer" | "expired" | "cancelled". */
  reason: "deliver" | "defer" | "expired" | "cancelled";
}

/** The fixed safety margin between the client and server expiry. */
export const EXPIRY_SAFETY_MARGIN_MS = 1000;

/** The absolute deadline: parse time + TTL - the safety margin. A
 * challenge without a TTL (`ttlSecs == 0`) never expires. */
export function expiresAtMs(receivedAtMs: number, ttlSecs: number): number {
  return ttlSecs > 0 ? receivedAtMs + ttlSecs * 1000 - EXPIRY_SAFETY_MARGIN_MS : Number.MAX_SAFE_INTEGER;
}

/** The delivery floor: parse time + the challenge's minimum duration. */
export function minSubmitAtMs(receivedAtMs: number, minDurationMs: number): number {
  return receivedAtMs + Math.max(0, minDurationMs);
}

/**
 * Whether the generation whose solve finished at `solveFinishedAtMs`
 * may deliver, checked at `nowMs`.
 *
 * The shared contract's evaluation order, first match wins:
 * cancelled → expired (floor at/after deadline; solve at/after
 * deadline; `now` at/after deadline) → deliver at
 * `max(solveFinishedAtMs, minSubmitAtMs)` if reached, else defer.
 * Boundaries: `now == expiresAtMs` is expired, `now == minSubmitAtMs`
 * delivers. `ttlSecs == 0` is no expiry: the decision rides
 * min-duration alone.
 *
 * `solveFinishedAtMs` may lie in the future relative to `nowMs` (a
 * checkpoint taken while the solve is still running); the decision
 * then defers to the solve's finish.
 */
export function deliveryDecision(
  receivedAtMs: number,
  ttlSecs: number,
  minDurationMs: number,
  solveFinishedAtMs: number,
  nowMs: number,
  cancelled = false,
): DeliveryDecision {
  if (cancelled) {
    return { deliver: false, deliverAtMs: 0, reason: "cancelled" };
  }
  const hasExpiry = ttlSecs > 0;
  if (hasExpiry) {
    const expiresAt = expiresAtMs(receivedAtMs, ttlSecs);
    if (minSubmitAtMs(receivedAtMs, minDurationMs) >= expiresAt) {
      return { deliver: false, deliverAtMs: 0, reason: "expired" };
    }
    if (solveFinishedAtMs >= expiresAt) {
      return { deliver: false, deliverAtMs: 0, reason: "expired" };
    }
    if (nowMs >= expiresAt) {
      return { deliver: false, deliverAtMs: 0, reason: "expired" };
    }
  }
  const deliverAt = Math.max(solveFinishedAtMs, minSubmitAtMs(receivedAtMs, minDurationMs));
  if (nowMs >= deliverAt) {
    return { deliver: true, deliverAtMs: nowMs, reason: "deliver" };
  }
  return { deliver: false, deliverAtMs: deliverAt, reason: "defer" };
}
