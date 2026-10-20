/// The Interactive-Client Lifecycle v1 delivery decision
/// (protocol/interactive-client-v1): whether a finished solve may hand
/// over its token now, must defer until a future instant, or has lost
/// the expiry race. Deterministic, dependency-free, and pinned by the
/// shared vectors in lifecycle-vectors.json — the same records the
/// Android (`KiwiLifecycleTest`) and iOS suites run, so the semantics
/// cannot drift between bindings.
library kiwicaptcha.lifecycle;

/// The one delivery decision: `reason` is
/// `"deliver" | "defer" | "expired" | "cancelled"`. Conventions:
/// `"deliver"` reports the delivery instant (`nowMs`), `"defer"` the
/// scheduled future instant, `"expired"`/`"cancelled"` report 0 (never
/// delivered).
class KiwiDeliveryDecision {
  final bool deliver;
  final int deliverAtMs;
  final String reason;

  const KiwiDeliveryDecision(this.deliver, this.deliverAtMs, this.reason);

  @override
  String toString() =>
      'KiwiDeliveryDecision(deliver: $deliver, deliverAtMs: $deliverAtMs, reason: $reason)';
}

/// The fixed safety margin between the client and server expiry:
/// `expiresAtMs = receivedAtMs + ttlSecs*1000 - 1000`, so the client
/// never races the server's own expiry verdict down to the wire.
const int kiwiExpirySafetyMarginMs = 1000;

const String kiwiReasonDeliver = 'deliver';
const String kiwiReasonDefer = 'defer';
const String kiwiReasonExpired = 'expired';
const String kiwiReasonCancelled = 'cancelled';

/// The largest 64-bit signed integer: [kiwiExpiresAtMs] reports it for
/// a `ttlSecs == 0` challenge (no expiry at all — the gate never
/// fires), keeping the arithmetic the same shape as the Android
/// `Long.MAX_VALUE` spelling.
const int kiwiNoExpiryMs = 0x7FFFFFFFFFFFFFFF;

/// The absolute deadline: parse time + TTL - the safety margin. A
/// challenge without a TTL (`ttlSecs == 0`) never expires.
int kiwiExpiresAtMs(int receivedAtMs, int ttlSecs) =>
    ttlSecs > 0
        ? receivedAtMs + ttlSecs * 1000 - kiwiExpirySafetyMarginMs
        : kiwiNoExpiryMs;

/// The delivery floor: parse time + the challenge's minimum duration.
/// A negative `minDurationMs` is treated as 0.
int kiwiMinSubmitAtMs(int receivedAtMs, int minDurationMs) =>
    receivedAtMs + (minDurationMs < 0 ? 0 : minDurationMs);

/// Whether the generation whose solve finished at [solveFinishedAtMs]
/// may deliver, checked at [nowMs].
///
/// The shared contract's evaluation order, first match wins:
///
/// 1. [cancelled] → `{false, 0, "cancelled"}`.
/// 2. With an expiry (`ttlSecs > 0`):
///    a. `minSubmitAtMs >= expiresAtMs` → expired;
///    b. `solveFinishedAtMs >= expiresAtMs` → expired;
///    c. `nowMs >= expiresAtMs` → expired.
/// 3. `deliverAtMs = max(solveFinishedAtMs, minSubmitAtMs)`; reached
///    (`nowMs >= deliverAtMs`) → `{true, nowMs, "deliver"}`, else
///    `{false, deliverAtMs, "defer"}`.
///
/// Boundaries, pinned by the shared vectors: `nowMs == expiresAtMs` is
/// **expired** (the gate is `>=`), `nowMs == minSubmitAtMs`
/// **delivers**. `ttlSecs == 0` is no expiry: the decision rides
/// min-duration alone. [solveFinishedAtMs] may lie in the future
/// relative to [nowMs] (a checkpoint taken while the solve is still
/// running); the decision then defers to the solve's finish.
KiwiDeliveryDecision kiwiDeliveryDecision(
  int receivedAtMs,
  int ttlSecs,
  int minDurationMs,
  int solveFinishedAtMs,
  int nowMs, {
  bool cancelled = false,
}) {
  if (cancelled) {
    return const KiwiDeliveryDecision(false, 0, kiwiReasonCancelled);
  }
  if (ttlSecs > 0) {
    final expiresAt = kiwiExpiresAtMs(receivedAtMs, ttlSecs);
    if (kiwiMinSubmitAtMs(receivedAtMs, minDurationMs) >= expiresAt) {
      return const KiwiDeliveryDecision(false, 0, kiwiReasonExpired);
    }
    if (solveFinishedAtMs >= expiresAt) {
      return const KiwiDeliveryDecision(false, 0, kiwiReasonExpired);
    }
    if (nowMs >= expiresAt) {
      return const KiwiDeliveryDecision(false, 0, kiwiReasonExpired);
    }
  }
  final minSubmitAt = kiwiMinSubmitAtMs(receivedAtMs, minDurationMs);
  final deliverAt = solveFinishedAtMs > minSubmitAt ? solveFinishedAtMs : minSubmitAt;
  if (nowMs >= deliverAt) {
    return KiwiDeliveryDecision(true, nowMs, kiwiReasonDeliver);
  }
  return KiwiDeliveryDecision(false, deliverAt, kiwiReasonDefer);
}
