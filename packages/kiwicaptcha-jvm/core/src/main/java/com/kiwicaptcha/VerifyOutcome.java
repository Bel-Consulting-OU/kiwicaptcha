package com.kiwicaptcha;

import java.util.Objects;

/**
 * The result of one solution verification. A valid outcome exposes the
 * nonce, the consumed record's application transaction binding, the
 * server-measured solve duration and the authenticated honeypot field
 * name. Every field is the zero value on a non-valid outcome; the
 * solve duration is also unset on a stored-result replay, whose
 * receipt is not the solve's endpoint.
 */
public final class VerifyOutcome {
    /** Whether the proof verified. */
    public final boolean valid;
    /** The typed failure, null on a valid outcome. */
    public final VerifyError error;
    /** The token decoder's reason on a malformed_token failure. */
    public final String detail;
    /** The verified nonce. */
    public final String nonce;
    /** The consumed record's application transaction binding. */
    public final String requestBinding;
    /** Whether this outcome replayed a stored consumed result. */
    public final boolean fromStoredResult;
    /** The server-measured solve duration in milliseconds. */
    public final long solveDurationMs;
    /** Whether a solve duration was measured. */
    public final boolean solveDurationSet;
    /** The authenticated honeypot field name. */
    public final String decoyField;

    private VerifyOutcome(boolean valid, VerifyError error, String detail, String nonce,
                          String requestBinding, boolean fromStoredResult,
                          long solveDurationMs, boolean solveDurationSet, String decoyField) {
        this.valid = valid;
        this.error = error;
        this.detail = detail;
        this.nonce = nonce;
        this.requestBinding = requestBinding;
        this.fromStoredResult = fromStoredResult;
        this.solveDurationMs = solveDurationMs;
        this.solveDurationSet = solveDurationSet;
        this.decoyField = decoyField;
    }

    /** Builds the success shape. */
    public static VerifyOutcome valid(String nonce, String requestBinding, boolean fromStoredResult,
                                      long solveDurationMs, boolean solveDurationSet, String decoyField) {
        return new VerifyOutcome(true, null, "", nonce, requestBinding, fromStoredResult,
                solveDurationMs, solveDurationSet, decoyField);
    }

    /** Builds one typed failure. */
    public static VerifyOutcome invalid(VerifyError error) {
        return new VerifyOutcome(false, Objects.requireNonNull(error), "", "", "", false, 0, false, "");
    }

    /** Builds the malformed_token failure with the decoder's reason. */
    public static VerifyOutcome malformedToken(String detail) {
        return new VerifyOutcome(false, VerifyError.MALFORMED_TOKEN, detail, "", "", false, 0, false, "");
    }

    /** Whether the proof verified. */
    public boolean ok() {
        return valid;
    }

    /** The machine readable error code, empty when valid. */
    public String code() {
        return valid ? "" : error.code();
    }

    @Override
    public String toString() {
        if (valid) {
            return "VerifyOutcome(valid=true, nonce redacted)";
        }
        return "VerifyOutcome(valid=false, error=" + error.code() + ")";
    }
}
