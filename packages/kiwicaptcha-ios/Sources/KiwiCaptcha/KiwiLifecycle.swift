import Foundation

/// The Interactive-Client Lifecycle v1 clock arithmetic, as one pure
/// helper every client implements and tests against the shared vectors
/// (protocol/interactive-client-v1/lifecycle-vectors.json).
///
/// The contract:
/// - `receivedAtMs` is the wall-clock millisecond captured immediately
///   after the challenge JSON parses; the expiry clock starts there,
///   never after solving.
/// - `expiresAtMs = receivedAtMs + ttlSecs*1000 - 1000`: a fixed 1 s
///   safety margin. A challenge without a TTL never expires.
/// - `minSubmitAtMs = receivedAtMs + minDurationMs`, 0 when absent: a
///   solve finishing earlier has its delivery delayed to that floor.
/// - A solve races expiry: finishing at or after `expiresAtMs`, being
///   gated to at or after `expiresAtMs` (minSubmitAtMs >= expiresAtMs),
///   or being evaluated at or after `expiresAtMs` is never delivered —
///   the reason is "expired".
///
/// Semantics (pinned by the shared vectors):
/// - `deliverAtMs = max(solveFinishedAtMs, minSubmitAtMs)`: the
///   earliest wall-clock moment the token may be handed over.
/// - `reason == "deliver"` with `deliver == true` when the evaluation
///   moment `nowMs` is at or past `deliverAtMs` (boundary equality
///   delivers); otherwise `reason == "defer"` with `deliver == false`
///   and the future `deliverAtMs` to wait for, cancellably.
/// - `reason == "expired"` reports `deliver == false, deliverAtMs == 0`.
/// - `"cancelled"` is the caller-side case (the solve stopped at a
///   probe checkpoint): it never reaches this helper and delivers
///   nothing — the vectors pin its expectation shape.
public enum KiwiLifecycle {

    /// `expiresAtMs`: parse time + TTL minus the fixed 1 s safety
    /// margin. `Int64.max` when the challenge carries no TTL (it never
    /// expires).
    public static func expiresAt(receivedAtMs: Int64, ttlSecs: Int64) -> Int64 {
        guard ttlSecs > 0 else { return Int64.max }
        // &* and &+ keep the helper total on hostile inputs; real TTLs
        // are orders of magnitude below overflow.
        return receivedAtMs &+ ttlSecs &* 1000 &- 1000
    }

    /// `minSubmitAtMs`: parse time + the issued minimum duration, 0
    /// when the challenge carries none.
    public static func minSubmitAt(receivedAtMs: Int64, minDurationMs: Int64) -> Int64 {
        guard minDurationMs > 0 else { return 0 }
        return receivedAtMs &+ minDurationMs
    }

    /// The delivery decision for one solve generation.
    ///
    /// - Parameters:
    ///   - receivedAtMs: wall clock immediately after the challenge
    ///     JSON parsed.
    ///   - ttlSecs: the challenge TTL in seconds (0 when absent).
    ///   - minDurationMs: the issued minimum solve duration in ms (0
    ///     when absent).
    ///   - solveFinishedAtMs: wall clock when the proof was complete.
    ///   - nowMs: wall clock at the moment the decision is evaluated
    ///     (a solve checkpoint or the pre-delivery gate).
    /// - Returns: `(deliver, deliverAtMs, reason)` with reason one of
    ///   `"deliver"`, `"defer"`, `"expired"` (and `"cancelled"` handled
    ///   by the caller, never produced here). `defer` says the token
    ///   is finished but held: wait until `deliverAtMs`, cancellably,
    ///   then re-decide. `expired` reports `deliverAtMs == 0`.
    public static func deliveryDecision(
        receivedAtMs: Int64,
        ttlSecs: Int64,
        minDurationMs: Int64,
        solveFinishedAtMs: Int64,
        nowMs: Int64
    ) -> (deliver: Bool, deliverAtMs: Int64, reason: String) {
        let expiresAtMs = expiresAt(receivedAtMs: receivedAtMs, ttlSecs: ttlSecs)
        let minSubmitAtMs = minSubmitAt(receivedAtMs: receivedAtMs, minDurationMs: minDurationMs)
        // The earliest moment the token may be handed over: after the
        // solve finished and after the issued minimum duration.
        let deliverAtMs = max(solveFinishedAtMs, minSubmitAtMs)

        func expired() -> (deliver: Bool, deliverAtMs: Int64, reason: String) {
            (false, 0, "expired")
        }

        if expiresAtMs != Int64.max {
            // A gate that could only land at or after the deadline is
            // dead up front: the token would arrive after expiry.
            if minSubmitAtMs != 0, minSubmitAtMs >= expiresAtMs { return expired() }
            // The solve itself lost the race against expiry.
            if solveFinishedAtMs >= expiresAtMs { return expired() }
            // The evaluation checkpoint is at or past the deadline.
            if nowMs >= expiresAtMs { return expired() }
        }

        if nowMs < deliverAtMs {
            // Held: the min-submit floor (or the solve finish itself,
            // for a checkpoint evaluated mid-flight) is still ahead.
            return (false, deliverAtMs, "defer")
        }
        return (true, deliverAtMs, "deliver")
    }
}
