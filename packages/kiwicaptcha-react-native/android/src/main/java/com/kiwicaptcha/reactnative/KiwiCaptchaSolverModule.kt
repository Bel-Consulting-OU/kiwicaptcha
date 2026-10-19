package com.kiwicaptcha.reactnative

import com.facebook.react.bridge.Callback
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The Android KiwiCaptchaSolver native module (docs/NATIVE.md is the
 * authoritative spec). The bridge name is exactly what the JS layer
 * looks up: `NativeModules.KiwiCaptchaSolver` / TurboModuleRegistry.
 *
 * One asynchronous method, JSON in, JSON out, strings across the
 * bridge, solved on this module's own background thread — never the JS
 * thread, never the UI thread:
 *
 * ```
 * solve(challengeJson: string): Promise<string>
 * solveWithProgress(challengeJson: string, onProgress: (info: {attempted: number}) => void): Promise<string>
 * ```
 *
 * SHA-256 challenges are solved natively (see [KiwiSolverCore]);
 * argon2id and rsw are refused with the `UNSUPPORTED_ALGORITHM` code
 * and the JS orchestration surfaces `solver-unavailable`. Every
 * rejection carries a typed refusal code from
 * [KiwiRefusalException].
 */
class KiwiCaptchaSolverModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = NAME

    /**
     * A dedicated single-thread executor: proof of work is CPU-bound,
     * so one worker serializes solves and keeps every loop off the JS
     * and UI threads. Shutdown in [invalidate] with the context.
     */
    private val executor: ExecutorService =
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "KiwiCaptchaSolver").apply { isDaemon = true }
        }

    @ReactMethod
    fun solve(challengeJson: String, promise: Promise) {
        executor.execute {
            try {
                promise.resolve(KiwiSolverCore.solve(challengeJson))
            } catch (t: Throwable) {
                reject(promise, t)
            }
        }
    }

    /**
     * The optional progress channel. The native side owns the cadence
     * (KiwiSolverCore: at most one report per 1024 attempts and 100 ms,
     * plus the winning report — never once per hash); the JS side
     * re-gates at 100 ms and drops duplicates, so the bridge can never
     * flood the JS thread either.
     */
    @ReactMethod
    fun solveWithProgress(challengeJson: String, onProgress: Callback, promise: Promise) {
        executor.execute {
            try {
                promise.resolve(
                    KiwiSolverCore.solve(challengeJson) { attempted ->
                        onProgress.invoke(attempted)
                    },
                )
            } catch (t: Throwable) {
                reject(promise, t)
            }
        }
    }

    override fun invalidate() {
        super.invalidate()
        executor.shutdownNow()
    }

    private fun reject(promise: Promise, t: Throwable) {
        val refusal = t as? KiwiRefusalException
        promise.reject(
            refusal?.refusal ?: "SOLVER_FAILED",
            t.message ?: t.toString(),
            t,
        )
    }

    internal companion object {
        /** The exact name src/solve.ts looks up. */
        const val NAME = "KiwiCaptchaSolver"
    }
}
