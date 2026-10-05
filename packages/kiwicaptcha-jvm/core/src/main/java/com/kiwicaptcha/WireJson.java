package com.kiwicaptcha;

import java.util.Map;

/**
 * Envelope encoding helpers: the stored document is emitted in the
 * canonical key order with the compact separators and the ascii
 * escaping of the reference writers, so an envelope written by this
 * SDK is byte-compatible with the php and Python ones.
 */
public final class WireJson {
    private WireJson() {}

    /** The runtime marker keys that ride beside the record fields. */
    public static final String[] ENVELOPE_RUNTIME_KEYS = {
        "state", "consumed_result", "operation_identity", "resume_owner", "resume_until",
    };

    /** Encodes one envelope document in the canonical key order. */
    public static String encodeEnvelope(Map<String, Object> envelope) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean[] first = {true};
        for (String key : ChallengeRecord.WIRE_KEYS) {
            emit(sb, first, envelope, key);
        }
        for (String key : ENVELOPE_RUNTIME_KEYS) {
            emit(sb, first, envelope, key);
        }
        if (!first[0]) {
            // Every envelope key must come from the fixed orderings
            // above; a foreign key would silently reorder the document.
            for (String name : envelope.keySet()) {
                if (!ChallengeRecord.WIRE_KEYS.contains(name) && !runtimeKey(name)) {
                    throw new IllegalArgumentException(
                            "kiwicaptcha: envelope carries a key outside the wire schema: " + name);
                }
            }
        }
        sb.append('}');
        return sb.toString();
    }

    private static boolean runtimeKey(String name) {
        for (String key : ENVELOPE_RUNTIME_KEYS) {
            if (key.equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static void emit(StringBuilder sb, boolean[] first, Map<String, Object> envelope, String name) {
        if (!envelope.containsKey(name)) {
            return;
        }
        if (!first[0]) {
            sb.append(',');
        }
        first[0] = false;
        JsonObject.writeJsonString(sb, name);
        sb.append(':');
        writeWireValue(sb, envelope.get(name));
    }

    static void writeWireValue(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Boolean b) {
            sb.append(b ? "true" : "false");
        } else if (value instanceof String s) {
            JsonObject.writeJsonString(sb, s);
        } else if (value instanceof Integer i) {
            sb.append(i);
        } else if (value instanceof Long l) {
            sb.append(l);
        } else if (value instanceof JsonNumber n) {
            sb.append(n.raw);
        } else {
            throw new IllegalArgumentException("kiwicaptcha: envelope value of unsupported type");
        }
    }

    /** Encodes one json string value. */
    public static String encodeJsonString(String value) {
        return JsonObject.encodeStatic(value);
    }
}
