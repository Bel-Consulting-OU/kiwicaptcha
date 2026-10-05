package com.kiwicaptcha

import android.content.Context
import android.graphics.Color
import android.util.AttributeSet
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The classic Android widget: a status view that acquires, solves and
 * expires a challenge on a background thread, and reports the token to
 * the app through [onVerify]. The solve runs off the main thread; the
 * UI updates hop back through [withContext].
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

    init {
        orientation = VERTICAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(48, 24, 48, 24)
        statusLabel.text = "Security Check"
        statusLabel.setTextColor(Color.BLACK)
        badgeLabel.text = "Idle"
        badgeLabel.textSize = 12f
        retryButton.text = "Retry"
        retryButton.visibility = GONE
        retryButton.setOnClickListener { start() }
        addView(statusLabel)
        addView(badgeLabel)
        addView(progress)
        addView(retryButton)
    }

    /** Acquire and solve a challenge. Safe to call again: the previous
     * run is cancelled first. */
    public fun start() {
        job?.cancel()
        expiry?.cancel()
        token = ""
        badgeLabel.text = "Working"
        progress.progress = 0
        retryButton.visibility = GONE
        val client = KiwiClient(endpoint, sitekey)
        val scopeName = scope
        job = scope1.launch {
            try {
                val challenge = withContext(Dispatchers.IO) { client.fetchChallenge(scopeName) }
                val solution = withContext(Dispatchers.Default) { KiwiSolver.solve(challenge) }
                val packed = KiwiToken.encode(challenge, solution)
                token = packed
                badgeLabel.text = "Success"
                progress.progress = 100
                onVerify?.invoke(packed)
                val ttl = challenge.ttlSecs
                if (ttl > 0) {
                    expiry = scope1.launch {
                        kotlinx.coroutines.delay(ttl * 1000)
                        expire()
                    }
                }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (t: Throwable) {
                token = ""
                badgeLabel.text = "Failed"
                retryButton.visibility = VISIBLE
                onError?.invoke(t.message ?: "solve failed")
            }
        }
    }

    private fun expire() {
        token = ""
        badgeLabel.text = "Expired"
        retryButton.visibility = VISIBLE
        onExpire?.invoke()
    }

    override fun onDetachedFromWindow() {
        job?.cancel()
        expiry?.cancel()
        super.onDetachedFromWindow()
    }
}
