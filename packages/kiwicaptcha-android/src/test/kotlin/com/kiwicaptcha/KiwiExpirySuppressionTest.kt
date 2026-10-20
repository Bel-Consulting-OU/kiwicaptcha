package com.kiwicaptcha

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The expiry race of the Interactive-Client Lifecycle v1 contract,
 * exercised through the exact seams [KiwiCaptchaView] wires together:
 * the solver's cooperative cancellation probe (checked against the
 * parse-time deadline) and the [KiwiLifecycle] delivery gate.
 *
 * The View widget itself (coroutine wiring, state labels) needs the
 * instrumented Android environment and this module deliberately
 * carries no Robolectric, so the coroutine wrapper is not unit-tested
 * here — what is pinned is the suppression decision: a solve that
 * loses the expiry race raises the typed Cancelled error, no token is
 * ever produced, and the lifecycle gate reads expired at the deadline.
 */
class KiwiExpirySuppressionTest {

    private val nonce = "A".repeat(43) + "="

    @Test
    fun aSolveThatLosesTheExpiryRaceIsCancelledAndNeverDelivered() {
        // ttl 1 s puts the deadline (with the fixed 1 s safety margin)
        // exactly at parse time: the probe fires at the solver's entry
        // checkpoint, before a single hash is spent.
        val challenge = KiwiChallenge(
            nonce = nonce,
            salt = "AAECAw==",
            algorithm = "sha256",
            mKib = 0,
            t = 1,
            p = 1,
            targetBits = 20,
            prefix = "kiwi|login|",
            ttlSecs = 1,
        )
        val receivedAtMs = System.currentTimeMillis()
        val expiresAtMs = KiwiLifecycle.expiresAtMs(receivedAtMs, challenge.ttlSecs)

        var delivered: String? = null
        var suppressedByCancelled = false
        try {
            // The view's solver call: the probe watches the parse-time
            // deadline (plus the job/generation conditions, absent in
            // this seam).
            val solution = KiwiSolver.solve(
                challenge,
                isCancelled = { System.currentTimeMillis() >= expiresAtMs },
            )
            // The view's delivery path — never reached for a generation
            // whose deadline has passed.
            delivered = KiwiToken.encode(challenge, solution)
        } catch (e: KiwiSolveError.Cancelled) {
            suppressedByCancelled = true
        }

        assertTrue("the solve must stop with the typed cancelled error", suppressedByCancelled)
        assertNull("no token may exist for an expired generation", delivered)

        // The lifecycle gate agrees at the deadline: expired, onVerify
        // suppressed, and the widget surfaces the expired state.
        val now = System.currentTimeMillis()
        val decision = KiwiLifecycle.deliveryDecision(
            receivedAtMs,
            challenge.ttlSecs,
            challenge.minDurationMs,
            solveFinishedAtMs = now,
            nowMs = now,
        )
        assertEquals(KiwiLifecycle.REASON_EXPIRED, decision.reason)
        assertEquals(false, decision.deliver)
    }

    @Test
    fun aSolveThatWinsTheExpiryRaceDeliversAndTheGateStaysOpen() {
        // A generous TTL with the same search: the deadline stays far
        // away, the identical probe never fires, and the solve completes.
        val challenge = KiwiChallenge(
            nonce = nonce,
            salt = "AAECAw==",
            algorithm = "sha256",
            mKib = 0,
            t = 1,
            p = 1,
            targetBits = 8,
            prefix = "kiwi|login|",
            ttlSecs = 120,
        )
        val receivedAtMs = System.currentTimeMillis()
        val expiresAtMs = KiwiLifecycle.expiresAtMs(receivedAtMs, challenge.ttlSecs)

        val solution = KiwiSolver.solve(
            challenge,
            isCancelled = { System.currentTimeMillis() >= expiresAtMs },
        )
        assertEquals(45L, solution.counter)

        val finishedAt = System.currentTimeMillis()
        val decision = KiwiLifecycle.deliveryDecision(
            receivedAtMs,
            challenge.ttlSecs,
            challenge.minDurationMs,
            finishedAt,
            finishedAt,
        )
        assertEquals(KiwiLifecycle.REASON_DELIVER, decision.reason)
        assertEquals(true, decision.deliver)
    }
}
