package com.kiwicaptcha

import android.content.Context
import android.content.res.Configuration
import android.graphics.Color
import android.os.Build
import android.util.AttributeSet
import android.util.TypedValue
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The classic Android widget: a status view that acquires, solves and
 * expires a challenge on a background thread, and reports the token to
 * the app through [onVerify]. The solve runs off the main thread; the
 * UI updates hop back through [withContext].
 *
 * The coroutine flow implements the Interactive-Client Lifecycle v1
 * contract (protocol/interactive-client-v1): the expiry clock starts
 * the instant the challenge JSON parses, the expiry timer races the
 * solve (and wins by stopping it through the solver's cooperative
 * cancellation probe), a too-fast solve is held until
 * `minDurationMs`, and only the newest generation may emit a token or
 * a state — everything from superseded or expired generations is
 * suppressed.
 */
public class KiwiCaptchaView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {

    public var endpoint: String = ""
    public var scope: String = "login"
    public var sitekey: String? = null

    public var onVerify: ((String) -> Unit)? = null
    public var onError: ((String) -> Unit)? = null
    public var onExpire: (() -> Unit)? = null

    public var token: String = ""
        private set

    private val statusLabel = TextView(context)
    private val badgeLabel = TextView(context)
    private val progress = ProgressBar(context, null, android.R.attr.progressBarStyleHorizontal)
    private val retryButton = Button(context)
    private val scope1 = CoroutineScope(Dispatchers.Main)
    private var job: Job? = null
    private var expiry: Job? = null

    /** Monotonically increasing handle minted per run: only the newest
     * generation may emit state, callbacks or tokens. */
    private var generation: Int = 0

    init {
        orientation = VERTICAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(48, 24, 48, 24)
        val primary = resolvePrimaryTextColor()
        statusLabel.text = "Security Check"
        // sp text sizes; the color comes from the theme's
        // textColorPrimary (dark-quirk-safe fallback), never hardcoded.
        statusLabel.textSize = 16f
        statusLabel.setTextColor(primary)
        statusLabel.contentDescription = "KiwiCaptcha security check"
        badgeLabel.text = "Idle"
        badgeLabel.textSize = 12f
        badgeLabel.setTextColor(primary)
        applyStateDescription(badgeLabel, "Idle")
        retryButton.text = "Retry"
        retryButton.textSize = 14f
        // The Retry control stays independently focusable for keyboard
        // and switch access, never folded into the status text.
        retryButton.isFocusable = true
        retryButton.isClickable = true
        retryButton.visibility = GONE
        retryButton.setOnClickListener { start() }
        addView(statusLabel)
        addView(badgeLabel)
        addView(progress)
        addView(retryButton)
    }

    /** Acquire and solve a challenge. Safe to call again: the previous
     * run is cancelled first (and superseded by generation). */
    public fun start() {
        job?.cancel()
        expiry?.cancel()
        token = ""
        val thisGeneration = ++generation
        renderState("Working")
        progress.progress = 0
        retryButton.visibility = GONE
        val client = KiwiClient(endpoint, sitekey)
        val scopeName = scope
        job = scope1.launch {
            try {
                val challenge = withContext(Dispatchers.IO) { client.fetchChallenge(scopeName) }
                // Lifecycle v1: the expiry clock starts the instant the
                // challenge JSON parses — never after solving.
                val receivedAtMs = System.currentTimeMillis()
                val ttl = challenge.ttlSecs
                val expiresAtMs = KiwiLifecycle.expiresAtMs(receivedAtMs, ttl)
                val minSubmitAtMs = KiwiLifecycle.minSubmitAtMs(receivedAtMs, challenge.minDurationMs)
                if (superseded(thisGeneration)) return@launch

                // The expiry timer arms at parse time and races the
                // solve; a solve that loses the race is cancelled
                // through the probe below and never delivered.
                if (ttl > 0) {
                    expiry = scope1.launch {
                        while (true) {
                            val remaining = expiresAtMs - System.currentTimeMillis()
                            if (remaining <= 0) break
                            delay(remaining)
                        }
                        expireIfCurrent(thisGeneration)
                    }
                }

                val solution = withContext(Dispatchers.Default) {
                    KiwiSolver.solve(
                        challenge,
                        isCancelled = {
                            !isActive ||
                                superseded(thisGeneration) ||
                                (ttl > 0 && System.currentTimeMillis() >= expiresAtMs)
                        },
                    )
                }
                if (superseded(thisGeneration)) return@launch

                // Delivery gating (Lifecycle v1): the decision is taken
                // at the solve's finish instant against the deadlines
                // computed at parse time. "expired" suppresses the
                // token and lets the already-armed timer surface the
                // state; "defer" holds delivery until minSubmitAtMs.
                val finishedAtMs = System.currentTimeMillis()
                var decision = KiwiLifecycle.deliveryDecision(
                    receivedAtMs,
                    ttl,
                    challenge.minDurationMs,
                    finishedAtMs,
                    finishedAtMs,
                )
                when (decision.reason) {
                    KiwiLifecycle.REASON_EXPIRED -> return@launch
                    KiwiLifecycle.REASON_DEFER -> {
                        renderState("Solved")
                        while (decision.reason == KiwiLifecycle.REASON_DEFER) {
                            val nowMs = System.currentTimeMillis()
                            decision = KiwiLifecycle.deliveryDecision(
                                receivedAtMs,
                                ttl,
                                challenge.minDurationMs,
                                finishedAtMs,
                                nowMs,
                                cancelled = superseded(thisGeneration),
                            )
                            when (decision.reason) {
                                KiwiLifecycle.REASON_DELIVER -> break
                                KiwiLifecycle.REASON_DEFER ->
                                    // Cancellable slices, re-checked
                                    // against the wall clock.
                                    delay(minOf(decision.deliverAtMs - nowMs, 250))
                                else -> return@launch // expired or cancelled while waiting
                            }
                        }
                    }
                }
                // Final gate before onVerify: never deliver at or past
                // the deadline.
                if (ttl > 0 && System.currentTimeMillis() >= expiresAtMs) return@launch
                deliver(thisGeneration, challenge, solution)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (t: Throwable) {
                if (superseded(thisGeneration)) return@launch
                if (t is KiwiSolveError.Cancelled) {
                    // The probe fired: a newer generation owns the
                    // widget, or the solve lost the expiry race and the
                    // still-armed timer surfaces the expired state.
                    return@launch
                }
                token = ""
                renderState("Failed")
                progress.progress = 0
                retryButton.visibility = VISIBLE
                onError?.invoke(t.message ?: "solve failed")
            }
        }
    }

    private fun superseded(g: Int): Boolean = g != generation

    private fun deliver(g: Int, challenge: KiwiChallenge, solution: KiwiSolution) {
        if (superseded(g)) return
        val packed = KiwiToken.encode(challenge, solution)
        token = packed
        renderState("Success")
        progress.progress = 100
        onVerify?.invoke(packed)
    }

    private fun expireIfCurrent(g: Int) {
        if (superseded(g)) return
        token = ""
        renderState("Expired")
        retryButton.visibility = VISIBLE
        onExpire?.invoke()
    }

    /** Surface one widget state: visible text plus the accessibility
     * plumbing (contentDescription, stateDescription on API 30+, and a
     * live announcement) for solving/solved/expired/failed. */
    private fun renderState(state: String) {
        badgeLabel.text = state
        applyStateDescription(badgeLabel, state)
        announceStateChange(state)
    }

    /** The only live-announcement mechanism available across the whole
     * minSdk 24..35 range; soft-deprecated on the newest platforms
     * without a View-level replacement. */
    @Suppress("DEPRECATION")
    private fun announceStateChange(state: String) {
        announceForAccessibility(state)
    }

    private fun applyStateDescription(view: TextView, state: String) {
        if (Build.VERSION.SDK_INT >= 30) view.stateDescription = state
        view.contentDescription = state
    }

    /**
     * The status color: `android.R.attr.textColorPrimary` resolved from
     * the widget's theme, with a dark-quirk-safe fallback for device
     * themes that lose the attribute — light default in day mode, white
     * in night mode — so the label is never invisible.
     */
    private fun resolvePrimaryTextColor(): Int {
        try {
            val value = TypedValue()
            if (context.theme.resolveAttribute(android.R.attr.textColorPrimary, value, true)) {
                if (value.type >= TypedValue.TYPE_FIRST_COLOR_INT &&
                    value.type <= TypedValue.TYPE_LAST_COLOR_INT
                ) {
                    return value.data
                }
                val resid = if (value.resourceId != 0) value.resourceId else value.data
                val array = context.obtainStyledAttributes(resid, intArrayOf(android.R.attr.textColorPrimary))
                try {
                    val color = array.getColor(0, Int.MIN_VALUE)
                    if (color != Int.MIN_VALUE) return color
                } finally {
                    array.recycle()
                }
            }
        } catch (_: Exception) {
            // fall through to the quirk-safe default
        }
        val nightMask = context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK
        return if (nightMask == Configuration.UI_MODE_NIGHT_YES) Color.WHITE else Color.BLACK
    }

    override fun onDetachedFromWindow() {
        // Supersede whatever is in flight, then cancel it.
        generation++
        job?.cancel()
        expiry?.cancel()
        super.onDetachedFromWindow()
    }
}
