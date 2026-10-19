package com.kiwicaptcha.reactnative

/**
 * A refused challenge or a failed solve, carrying the machine-readable
 * refusal code the promise rejects with (the JS orchestration maps every
 * rejection to `KiwiSolveError` with `refusal: "solver-unavailable"`;
 * the code stays on the JS `Error.code` for diagnostics).
 */
public class KiwiRefusalException(public val refusal: String, message: String) :
    Exception(message) {
    public companion object {
        public const val MALFORMED: String = "MALFORMED"
        public const val DIFFICULTY_BEYOND_CAP: String = "DIFFICULTY_BEYOND_CAP"
        public const val UNSUPPORTED_ALGORITHM: String = "UNSUPPORTED_ALGORITHM"
        public const val EXECUTION_UNSUPPORTED: String = "EXECUTION_UNSUPPORTED"

        /** The 20,000,000-hash search window closed without a winner. */
        public const val EXHAUSTED: String = "EXHAUSTED"
    }
}
