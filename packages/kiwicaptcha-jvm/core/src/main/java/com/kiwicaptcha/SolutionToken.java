package com.kiwicaptcha;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * The client submitted solution token and its wire grammar, a port of
 * the php SolutionToken. The wire format is
 * base64(nonce "." counter "." duration_ms "." telemetry_json
 * ["." execution_digest[":" execution_trace]] ["." rsw_proof]).
 * The telemetry segment may contain dots, so decoding splits on all
 * dots and peels the optional suffix segments right to left,
 * independently. The rsw final value peels first, exactly when the
 * last segment is 512 lowercase hex. The execution evidence segment
 * that precedes it peels next. The unarmed token keeps the exact four
 * segment shape.
 *
 * Numeric segments are canonical decimal: digits only, a leading zero
 * rejected unless the whole segment is exactly "0", so each value has
 * exactly one wire spelling in every implementation.
 */
public final class SolutionToken {
    /** Decode failure reasons, identical to the php codes. */
    public static final String DECODE_ERR_INVALID_BASE64 = "invalid_base64";
    public static final String DECODE_ERR_INVALID_UTF8 = "invalid_utf8";
    public static final String DECODE_ERR_MALFORMED = "malformed";
    public static final String DECODE_ERR_INVALID_COUNTER = "invalid_counter";
    public static final String DECODE_ERR_INVALID_COUNT = "counter exceeds solver maximum";
    public static final String DECODE_ERR_INVALID_DUR = "invalid_duration";

    /** The decoded nonce. */
    public final String nonce;
    /** The proof-of-work counter. */
    public final long counter;
    /** The client reported solve duration. */
    public final long durationMs;
    /** The telemetry object, always a json object on the wire. */
    public final JsonObject telemetry;
    /** The optional 64 hex execution digest. */
    public final String executionDigest;
    /** The optional unpadded base64url execution trace. */
    public final String executionTrace;
    /** The optional 512 hex rsw final value. */
    public final String rswProof;

    private SolutionToken(String nonce, long counter, long durationMs, JsonObject telemetry,
                          String executionDigest, String executionTrace, String rswProof) {
        this.nonce = nonce;
        this.counter = counter;
        this.durationMs = durationMs;
        this.telemetry = telemetry;
        this.executionDigest = executionDigest;
        this.executionTrace = executionTrace;
        this.rswProof = rswProof;
    }

    /**
     * A solution token wire grammar failure. The code is the machine
     * readable reason carried as the malformed_token outcome detail.
     */
    public static final class DecodeException extends RuntimeException {
        /** The machine readable reason. */
        public final String code;

        DecodeException(String code) {
            super("kiwicaptcha: token decode error: " + code);
            this.code = code;
        }
    }

    /** The telemetry boolean of the key, or null when absent or not boolean. */
    public Boolean telemetryBool(String key) {
        return telemetry == null ? null : telemetry.boolOrNull(key);
    }

    /**
     * Assembles the canonical wire bytes. The telemetry segment is
     * always a json object, so an empty object encodes as {} and never
     * []. The execution trace travels as unpadded base64url; a
     * standard base64 trace is translated, never double encoded. An
     * unarmed token stays byte identical to the four segment shape.
     */
    public String encode() {
        StringBuilder plain = new StringBuilder();
        plain.append(nonce).append('.').append(counter).append('.').append(durationMs).append('.')
                .append(telemetry.encode());
        if (!executionDigest.isEmpty()) {
            plain.append('.').append(executionDigest);
            if (!executionTrace.isEmpty()) {
                String translated = executionTrace.replace('+', '-').replace('/', '_');
                int end = translated.length();
                while (end > 0 && translated.charAt(end - 1) == '=') {
                    end--;
                }
                translated = translated.substring(0, end);
                plain.append(':').append(translated);
            }
        }
        if (!rswProof.isEmpty()) {
            plain.append('.').append(rswProof);
        }
        return Base64.getEncoder().encodeToString(plain.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Parses wire bytes and throws a typed DecodeException on any
     * grammar violation.
     */
    public static SolutionToken decode(String raw) {
        if (raw.length() > Kiwi.MAX_TOKEN_BYTES) {
            throw new DecodeException(DECODE_ERR_MALFORMED);
        }
        byte[] plainBytes = Canonical.b64CanonicalDecode(raw);
        if (plainBytes == null) {
            throw new DecodeException(DECODE_ERR_INVALID_BASE64);
        }
        if (!isUtf8(plainBytes)) {
            throw new DecodeException(DECODE_ERR_INVALID_UTF8);
        }
        String plain = new String(plainBytes, StandardCharsets.UTF_8);
        String[] parts = plain.split("\\.", -1);
        if (parts.length < 4) {
            throw new DecodeException(DECODE_ERR_MALFORMED);
        }
        int end = parts.length;
        String rswProof = "";
        String executionDigest = "";
        String executionTrace = "";
        if (end >= 5 && isHexN(parts[end - 1], 512)) {
            rswProof = parts[end - 1];
            end--;
        }
        if (end >= 5) {
            String segment = parts[end - 1];
            int colon = segment.indexOf(':');
            String digestPart = colon >= 0 ? segment.substring(0, colon) : segment;
            if (isHexN(digestPart, 64)) {
                executionDigest = digestPart;
                if (colon >= 0) {
                    executionTrace = segment.substring(colon + 1);
                    if (!canonicalB64UrlCheck(executionTrace)) {
                        throw new DecodeException(DECODE_ERR_MALFORMED);
                    }
                }
                end--;
            }
        }
        String telemetryStr = String.join(".", Arrays.copyOfRange(parts, 3, end));
        String nonce = parts[0];
        String counterStr = parts[1];
        String durationStr = parts[2];

        // The nonce is base64 of 32 random bytes: exactly 44 chars with
        // one padding character. The shape check alone is not enough,
        // so the canonical re-encode check pins exactly one wire
        // spelling.
        if (nonce.length() != 44 || !nonce.endsWith("=") || nonce.indexOf('-') >= 0 || nonce.indexOf('_') >= 0) {
            throw new DecodeException(DECODE_ERR_MALFORMED);
        }
        byte[] nonceBytes = Canonical.b64CanonicalDecode(nonce);
        if (nonceBytes == null || nonceBytes.length != Kiwi.NONCE_B64_BYTES) {
            throw new DecodeException(DECODE_ERR_MALFORMED);
        }
        long counter = canonicalDecimal(counterStr);
        if (counter < 0) {
            throw new DecodeException(DECODE_ERR_INVALID_COUNTER);
        }
        if (counterStr.length() > 8 || counter >= Kiwi.MAX_SOLVER_COUNTER) {
            throw new DecodeException(DECODE_ERR_INVALID_COUNT);
        }
        long duration = canonicalDecimal(durationStr);
        if (duration < 0) {
            throw new DecodeException(DECODE_ERR_INVALID_DUR);
        }
        if (duration > Kiwi.MAX_DURATION_MS) {
            throw new DecodeException(DECODE_ERR_INVALID_DUR);
        }
        JsonObject telemetry;
        try {
            telemetry = JsonObject.parseObject(telemetryStr);
        } catch (RuntimeException e) {
            throw new DecodeException(DECODE_ERR_MALFORMED);
        }
        if (!executionDigest.isEmpty() && !isHexN(executionDigest, 64)) {
            throw new DecodeException(DECODE_ERR_MALFORMED);
        }
        return new SolutionToken(nonce, counter, duration, telemetry,
                executionDigest, executionTrace, rswProof);
    }

    /** Assembles one solution token, the mirror of decode for tests and native solvers. */
    public static SolutionToken create(String nonce, long counter, long durationMs, JsonObject telemetry,
                                       String executionDigest, String executionTrace, String rswProof) {
        if (telemetry == null) {
            telemetry = new JsonObject();
        }
        return new SolutionToken(nonce, counter, durationMs, telemetry,
                executionDigest == null ? "" : executionDigest,
                executionTrace == null ? "" : executionTrace,
                rswProof == null ? "" : rswProof);
    }

    static boolean isDigits(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    /** Canonical decimal: digits only, no leading zero unless exactly "0". */
    static long canonicalDecimal(String s) {
        if (!isDigits(s)) {
            return -1;
        }
        if (s.length() > 1 && s.charAt(0) == '0') {
            return -1;
        }
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    static boolean isHexN(String s, int n) {
        if (s.length() != n) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
                return false;
            }
        }
        return true;
    }

    static String b64UrlToStandard(String trace) {
        String standard = trace.replace('-', '+').replace('_', '/');
        int pad = (4 - standard.length() % 4) % 4;
        return standard + "=".repeat(pad);
    }

    /** Requires one canonical unpadded base64url spelling, the driver's format. */
    static boolean canonicalB64UrlCheck(String trace) {
        if (trace.isEmpty() || trace.length() > Kiwi.MAX_TRACE_B64_LENGTH) {
            return false;
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(b64UrlToStandard(trace));
        } catch (IllegalArgumentException e) {
            return false;
        }
        String reencoded = Base64.getEncoder().encodeToString(decoded);
        reencoded = reencoded.replace('+', '-').replace('/', '_');
        int end = reencoded.length();
        while (end > 0 && reencoded.charAt(end - 1) == '=') {
            end--;
        }
        return reencoded.substring(0, end).equals(trace);
    }

    private static boolean isUtf8(byte[] bytes) {
        int i = 0;
        while (i < bytes.length) {
            int b = bytes[i] & 0xff;
            if (b < 0x80) {
                i++;
                continue;
            }
            int length;
            int lowerBound;
            if ((b & 0xe0) == 0xc0) {
                length = 2;
                lowerBound = 0x80;
            } else if ((b & 0xf0) == 0xe0) {
                length = 3;
                lowerBound = 0x800;
            } else if ((b & 0xf8) == 0xf0) {
                length = 4;
                lowerBound = 0x10000;
            } else {
                return false;
            }
            if (i + length > bytes.length) {
                return false;
            }
            int cp = b & (0xff >> (length + 1));
            for (int j = 1; j < length; j++) {
                int cb = bytes[i + j] & 0xff;
                if ((cb & 0xc0) != 0x80) {
                    return false;
                }
                cp = (cp << 6) | (cb & 0x3f);
            }
            if (cp < lowerBound || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
                return false;
            }
            i += length;
        }
        return true;
    }
}
