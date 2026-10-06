package com.kiwicaptcha;

/**
 * One machine readable failure of the verify path. Every value is a
 * stable snake_case wire code, the vocabulary shared with the php enum
 * and the Rust code mapping; logs, metrics and cross-service consumers
 * switch on the code without parsing prose.
 */
public enum VerifyError {
    BAD_SIGNATURE("bad_signature", "challenge signature is invalid"),
    EXPIRED("expired", "challenge has expired"),
    WRONG_SCOPE("wrong_scope", "challenge was issued for a different scope"),
    REQUIRED_SCOPE("required_scope", "the scope option is required: verify refuses to accept a token for any scope"),
    IP_MISMATCH("ip_mismatch", "challenge was issued to a different client ip"),
    MISSING_CLIENT_IP("missing_client_ip", "challenge is ip-bound but no client ip was supplied"),
    WRONG_REGION("wrong_region", "challenge was issued for a different region"),
    WRONG_ISSUER("wrong_issuer", "challenge was issued by a different deployment"),
    WRONG_POLICY_VERSION("wrong_policy_version", "challenge was issued under a different security-policy epoch"),
    UNKNOWN_KID("unknown_kid", "unknown signing key id"),
    TOO_FAST("too_fast", "solution arrived faster than the theoretical minimum, server measured"),
    INSUFFICIENT_WORK("insufficient_work", "solution does not meet the difficulty target"),
    MALFORMED_RECORD("malformed_record", "stored challenge record is malformed"),
    RECORD_NOT_FOUND("record_not_found", "challenge record not found, unknown or already deleted"),
    MALFORMED_TOKEN("malformed_token", "solution token is malformed"),
    UNSUPPORTED_ARGON2("unsupported_argon2_params", "argon2id parameters exceed the supported process ceilings"),
    TOO_MANY_ATTEMPTS("too_many_attempts", "too many verification attempts"),
    TELEMETRY_REJECTED("telemetry_rejected", "bot-signal telemetry rejected the solution"),
    CAPACITY_EXCEEDED("capacity_exceeded", "verification capacity exceeded, try again shortly"),
    ADMISSION_UNAVAILABLE("admission_unavailable", "verification admission backend unavailable, try again shortly"),
    STORAGE_UNAVAILABLE("storage_unavailable", "verification storage backend unavailable, try again shortly"),
    CONSUME_INDETERMINATE("consume_indeterminate", "verification storage response indeterminate, the challenge may or may not have been consumed"),
    ALREADY_CONSUMED("already_consumed", "the challenge was already consumed by a different logical operation"),
    REQUEST_BINDING("request_binding_mismatch", "the challenge is not bound to the expected application transaction"),
    EXECUTION_MISMATCH("execution_mismatch", "the execution digest does not match the expected program trace of the challenge"),
    UNSUPPORTED_RSW_PARAMS("unsupported_rsw_params", "the rsw challenge cannot be verified: this verifier is not configured with the matching rsw trapdoor, or the signed sequential cost is outside the supported bounds");

    private final String code;
    private final String description;

    VerifyError(String code, String description) {
        this.code = code;
        this.description = description;
    }

    /** The wire code of this failure. */
    /** The enum member of one wire code, or null outside the vocabulary. */
    public static VerifyError fromCodeOrNull(String code) {
        for (VerifyError candidate : values()) {
            if (candidate.code.equals(code)) {
                return candidate;
            }
        }
        return null;
    }

    public String code() {
        return code;
    }

    /** The operator facing explanation; switch on the code, not this. */
    public String description() {
        return description;
    }

    /**
     * Whether this failure is exempt from the one-shot policy. The
     * exempt set describes the original redemption's circumstances: the
     * signed expiry, the network binding, the missing client ip, and
     * the client side telemetry evidence. A consumed record failing one
     * of them may still resolve through the consumed branch. Every
     * security verdict stands regardless of a matching operation
     * identity.
     */
    public boolean isReplayExempt() {
        return this == EXPIRED || this == IP_MISMATCH
                || this == MISSING_CLIENT_IP || this == TELEMETRY_REJECTED;
    }
}
