package com.kiwicaptcha

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

/**
 * The Jetpack Compose widget. State is Compose-owned; the solve runs on
 * the Default dispatcher (a background thread, never the UI thread and
 * never a WebView), and the token surfaces through [onVerify].
 */
@Composable
public fun KiwiCaptcha(
    endpoint: String,
    scope: String,
    sitekey: String? = null,
    autoStart: Boolean = true,
    onVerify: (String) -> Unit,
    onError: (String) -> Unit = {},
    onExpire: () -> Unit = {},
) {
    var status by remember { mutableStateOf("Idle") }
    var progress by remember { mutableStateOf(0f) }
    var attempt by remember { mutableStateOf(0) }
    var failed by remember { mutableStateOf(false) }

    // Interactive-Client Lifecycle v1 (protocol/interactive-client-v1):
    // the expiry clock starts at challenge parse and races the solve;
    // delivery waits for the server's minimum-duration floor; only the
    // newest generation (this LaunchedEffect's coroutine) emits.
    LaunchedEffect(endpoint, scope, sitekey, attempt) {
        if (!autoStart && attempt == 0) return@LaunchedEffect
        val generation = this
        failed = false
        status = "Working"
        try {
            val client = KiwiClient(endpoint, sitekey)
            val challenge = withContext(Dispatchers.IO) { client.fetchChallenge(scope) }
            val receivedAtMs = System.currentTimeMillis()
            val expiresAtMs = KiwiLifecycle.expiresAtMs(receivedAtMs, challenge.ttlSecs)
            val minSubmitAtMs = KiwiLifecycle.minSubmitAtMs(receivedAtMs, challenge.minDurationMs)
            val solution = withContext(Dispatchers.Default) {
                // coroutineContext reaches the LaunchedEffect job inside
                // withContext, so cancellation of a superseded generation
                // and the wall-clock deadline both stop the CPU work.
                KiwiSolver.solve(challenge, isCancelled = {
                    !generation.isActive || System.currentTimeMillis() >= expiresAtMs
                })
            }
            val nowMs = System.currentTimeMillis()
            val decision = KiwiLifecycle.deliveryDecision(
                receivedAtMs, challenge.ttlSecs, challenge.minDurationMs, nowMs, nowMs,
            )
            if (!decision.deliver) {
                status = "Expired"
                failed = true
                onExpire()
                return@LaunchedEffect
            }
            if (decision.deliverAtMs > nowMs) {
                // Cancellable: a restart or dispose cancels the deferral.
                delay(decision.deliverAtMs - nowMs)
                if (System.currentTimeMillis() >= expiresAtMs) {
                    status = "Expired"
                    failed = true
                    onExpire()
                    return@LaunchedEffect
                }
            }
            val token = KiwiToken.encode(challenge, solution)
            progress = 1f
            status = "Success"
            onVerify(token)
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (t: Throwable) {
            status = "Failed"
            failed = true
            onError(t.message ?: "solve failed")
        }
    }

    Column(modifier = Modifier.fillMaxWidth().padding(8.dp)) {
        Text("Security Check")
        Text(status)
        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        )
        if (failed) {
            Button(onClick = { attempt++ }) { Text("Retry") }
        }
    }
}
