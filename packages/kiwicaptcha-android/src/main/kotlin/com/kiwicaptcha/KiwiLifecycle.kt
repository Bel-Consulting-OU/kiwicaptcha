package com.kiwicaptcha

/**
 * The pure delivery decision of the Interactive-Client Lifecycle v1
 * contract (protocol/interactive-client-v1): whether a finished solve
 * may deliver its token now, must defer until a future instant, or has
 * lost the expiry race. Deterministic, dependency-free, and pinned by
 * the shared vectors the whole repo tests against.
 */
public data class KiwiDeliveryDecision(
    public val deliver: Boolean,
    public val deliverAtMs: Long,
    /** "deliver" | "defer" | "expired" | "cancelled". */
    public val reason: String,
)

/**
 * The Interactive-Client Lifecycle v1 deadlines and delivery gate.
 *
 * - [expiresAtMs] is `receivedAtMs + ttlSecs*1000 - 1000` — the fixed
 *   1 s safety margin — computed from the instant the challenge JSON
 *   parsed (never from the solve start). `ttlSecs == 0` means no
 *   expiry: [expiresAtMs] reports [Long.MAX_VALUE] and the gate never
 *   fires.
 * - [minSubmitAtMs] is `receivedAtMs + minDurationMs`, the delivery
 *   floor a too-fast solve must wait out.
 *
 * The widget's rule of life: never deliver a token after
 * `expiresAtMs`. At every checkpoint — solve probes included — a
 * generation whose clock passed the deadline is invalidated, `onVerify`
 * is suppressed, and the widget surfaces the expired state.
 */
public object KiwiLifecycle {

    /** The fixed safety margin between the client and server expiry. */
    public const val EXPIRY_SAFETY_MARGIN_MS: Long = 1_000L

    public const val REASON_DELIVER: String = "deliver"
    public const val REASON_DEFER: String = "defer"
    public const val REASON_EXPIRED: String = "expired"
    public const val REASON_CANCELLED: String = "cancelled"

    /** The absolute deadline: parse time + TTL - the safety margin.
     * A challenge without a TTL (`ttlSecs == 0`) never expires. */
    public fun expiresAtMs(receivedAtMs: Long, ttlSecs: Long): Long =
        if (ttlSecs > 0) receivedAtMs + ttlSecs * 1000 - EXPIRY_SAFETY_MARGIN_MS else Long.MAX_VALUE

    /** The delivery floor: parse time + the challenge's minimum duration. */
    public fun minSubmitAtMs(receivedAtMs: Long, minDurationMs: Long): Long =
        receivedAtMs + minDurationMs.coerceAtLeast(0)

    /**
     * Whether the generation whose solve finished at
     * [solveFinishedAtMs] may deliver, checked at [nowMs].
     *
     * The shared contract's evaluation order, first match wins:
     * cancelled → expired (floor at/after deadline; solve at/after
     * deadline; `now` at/after deadline) → deliver at
     * `max(solveFinishedAtMs, minSubmitAtMs)` if reached, else defer.
     * Boundaries: `now == expiresAtMs` is expired, `now ==
     * minSubmitAtMs` delivers. `ttlSecs == 0` is no expiry: the
     * decision rides min-duration alone.
     *
     * [solveFinishedAtMs] may lie in the future relative to [nowMs]
     * (a checkpoint taken while the solve is still running); the
     * decision then defers to the solve's finish.
     */
    public fun deliveryDecision(
        receivedAtMs: Long,
        ttlSecs: Long,
        minDurationMs: Long,
        solveFinishedAtMs: Long,
        nowMs: Long,
        cancelled: Boolean = false,
    ): KiwiDeliveryDecision {
        if (cancelled) return KiwiDeliveryDecision(false, 0L, REASON_CANCELLED)
        val hasExpiry = ttlSecs > 0
        if (hasExpiry) {
            val expiresAt = expiresAtMs(receivedAtMs, ttlSecs)
            if (minSubmitAtMs(receivedAtMs, minDurationMs) >= expiresAt) {
                return KiwiDeliveryDecision(false, 0L, REASON_EXPIRED)
            }
            if (solveFinishedAtMs >= expiresAt) {
                return KiwiDeliveryDecision(false, 0L, REASON_EXPIRED)
            }
            if (nowMs >= expiresAt) {
                return KiwiDeliveryDecision(false, 0L, REASON_EXPIRED)
            }
        }
        val deliverAt = maxOf(solveFinishedAtMs, minSubmitAtMs(receivedAtMs, minDurationMs))
        return if (nowMs >= deliverAt) {
            KiwiDeliveryDecision(true, nowMs, REASON_DELIVER)
        } else {
            KiwiDeliveryDecision(false, deliverAt, REASON_DEFER)
        }
    }
}
