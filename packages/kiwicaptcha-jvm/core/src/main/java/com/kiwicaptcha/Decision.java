package com.kiwicaptcha;

import java.util.Map;

/**
 * The contract level answer of verify: the shared server SDK shape
 * {ok, disposition, decision_handle, price}.
 *
 * Disposition is allow when the proof verified, deny for a definitive
 * rejection, and retry for a transient condition. decisionHandle is
 * the verified nonce, the canonical replay id the outcomes ledger
 * addresses. price is the work ladder rung the challenge carried,
 * derived from its authenticated parameters.
 */
public final class Decision {
    /** Dispositions of the contract level answer. */
    public static final String DISPOSITION_ALLOW = "allow";
    public static final String DISPOSITION_DENY = "deny";
    public static final String DISPOSITION_RETRY = "retry";

    /**
     * The transient conditions where the same token may legitimately
     * be resubmitted once the backend recovers.
     */
    private static final Map<VerifyError, Boolean> RETRY_CODES = Map.of(
            VerifyError.STORAGE_UNAVAILABLE, true,
            VerifyError.CAPACITY_EXCEEDED, true,
            VerifyError.ADMISSION_UNAVAILABLE, true,
            VerifyError.CONSUME_INDETERMINATE, true);

    /** Whether the proof verified. */
    public final boolean ok;
    /** allow, deny or retry. */
    public final String disposition;
    /** The verified nonce, empty on a failure. */
    public final String decisionHandle;
    /** The work ladder rung of the challenge, empty on a failure. */
    public final String price;
    /** The machine readable failure code, empty when ok. */
    public final String error;
    /** The full underlying outcome. */
    public final VerifyOutcome outcome;

    private Decision(boolean ok, String disposition, String decisionHandle, String price,
                     String error, VerifyOutcome outcome) {
        this.ok = ok;
        this.disposition = disposition;
        this.decisionHandle = decisionHandle;
        this.price = price;
        this.error = error;
        this.outcome = outcome;
    }

    /** Maps a verify outcome onto the decision plane. */
    public static Decision fromOutcome(VerifyOutcome outcome, String price) {
        if (outcome.valid) {
            return new Decision(true, DISPOSITION_ALLOW, outcome.nonce, price, "", outcome);
        }
        String disposition = RETRY_CODES.containsKey(outcome.error) ? DISPOSITION_RETRY : DISPOSITION_DENY;
        return new Decision(false, disposition, "", "", outcome.code(), outcome);
    }

    /**
     * Names the work ladder rung of one record's authenticated
     * parameters. The sha rungs carry their difficulty, the argon
     * rungs their memory, and the sequential time-lock rung is rsw.
     */
    public static String priceRung(String algorithm, int targetBits, int mKib) {
        return switch (algorithm) {
            case "sha256" -> "sha" + targetBits;
            case "argon2id" -> "argon" + mKib;
            default -> "rsw";
        };
    }
}
