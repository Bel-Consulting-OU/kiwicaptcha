package com.kiwicaptcha;

/**
 * The wire constants of the shared server SDK contract. The values are
 * pinned by the protocol corpora every implementation accepts, so the
 * record language stays identical across the languages.
 */
public final class Kiwi {
    private Kiwi() {}

    /** Minimum master secret length in bytes. */
    public static final int MIN_SECRET_BYTES = 32;

    /** Minimum execution key length in bytes. */
    public static final int MIN_EXECUTION_KEY_BYTES = 32;

    /** Hard ceiling for issued sha256 difficulty. */
    public static final int MAX_SHA_TARGET_BITS = 20;

    /** Ceiling for issued argon2id difficulty. */
    public static final int MAX_ARGON2_TARGET_BITS = 10;

    /** Absolute stored-record difficulty floor. */
    public static final int MIN_DIFFICULTY = 1;

    /** Absolute stored-record difficulty ceiling. */
    public static final int MAX_DIFFICULTY = 20;

    /** Hard ceiling for a stored record lifetime, in seconds. */
    public static final int MAX_TTL_SECS = 300;

    /** Floor for the rsw sequential squaring count. */
    public static final int MIN_RSW_T = 10_000;

    /** Ceiling for the rsw sequential squaring count. */
    public static final int MAX_RSW_T = 300_000;

    /** Canonical target_bits pin carried by an rsw record. */
    public static final int RSW_TARGET_BITS_PIN = 1;

    /** Maximum wire string length of any record field. */
    public static final int MAX_STRING_BYTES = 4096;

    /** Decoyless, identityless, executionless canonical version. */
    public static final int BASE_PROTOCOL_VERSION = 2;

    /** Decoy-capable canonical version. */
    public static final int DECOY_PROTOCOL_VERSION = 3;

    /** Execution-capable canonical version. */
    public static final int EXECUTION_PROTOCOL_VERSION = 4;

    /** Identity-bearing rsw canonical version. */
    public static final int RSW_IDENTITY_PROTOCOL_VERSION = 5;

    /** Maximum accepted protocol version. */
    public static final int MAX_PROTOCOL_VERSION = 5;

    /** Execution-dimension grammar ceiling. */
    public static final int MAX_EXECUTION_VERSION = 6;

    /** Maximum tolerated future issuance skew, in seconds. */
    public static final int MAX_CLOCK_SKEW = 60;

    /** Host clock skew tolerance for the minimum duration check, in microseconds. */
    public static final long SKEW_TOLERANCE_US = 5_000_000L;

    /** Argon2id process ceilings, applied after signature authentication. */
    public static final int MIN_ARGON_MEMORY_KIB = 8;
    public static final int MAX_ARGON_MEMORY_KIB = 65_536;
    public static final int MIN_ARGON_TIME = 3;
    public static final int MAX_ARGON_TIME = 16;
    public static final int MIN_PARALLELISM = 1;
    public static final int MAX_PARALLELISM = 4;

    /** Solver search ceiling shared with the widget and the wasm core. */
    public static final int MAX_SOLVER_COUNTER = 20_000_000;

    /** Hard ceiling for the client reported token duration. */
    public static final int MAX_DURATION_MS = 3_600_000;

    /** Decoded nonce length in bytes. */
    public static final int NONCE_B64_BYTES = 32;

    /** Decoded record salt length in bytes. */
    public static final int SALT_B64_BYTES = 16;

    /** Maximum wire length of one raw solution token. */
    public static final int MAX_TOKEN_BYTES = 32_768;

    /** Maximum base64 length of one execution trace segment. */
    public static final int MAX_TRACE_B64_LENGTH = 10_924;

    /** Byte ceiling of one stored envelope. */
    public static final int ENVELOPE_MAX_BYTES = 131_072;

    /** Redis key prefix of the shipped adapter, shared across the SDKs. */
    public static final String ENVELOPE_DEFAULT_PREFIX = "kiwicaptcha:";

    /** Retention margin, in seconds, added to the signed lifetime. */
    public static final int REDIS_STORAGE_TTL = 60;

    // Key derivation labels, byte-identical across every SDK.
    public static final String HKDF_DEPLOY_SALT = "kiwicaptcha/deploy-salt/v1";
    public static final String INFO_CHALLENGE_SIGN = "kiwi/v2/challenge-sign";
    public static final String INFO_IP_BIND = "kiwi/v2/ip-bind";
    public static final String INFO_RESULT_TOKEN = "kiwi/v2/result-token";
    public static final String INFO_SERVER_STATE = "kiwi/v2/server-state";
    public static final String INFO_TENANT_ROOT_PREFIX = "kiwi/v2/tenant/";
    public static final String RECORD_META_DOMAIN = "kiwi/record-meta/v1";
    public static final String CONSUMED_RESULT_DOMAIN = "kiwi/consumed-result/v1";
    public static final String IP_BIND_DOMAIN = "kiwicaptcha/ip-bind/v2";
}
