package com.kiwicaptcha;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The server side challenge state persisted by the storage backend.
 * The JSON keys mirror the Rust serde schema one to one, so a Java
 * service and a php or Rust service share the same records.
 *
 * Optional fields use the empty string as the unset sentinel: the
 * identifier alphabets never admit an empty value on the wire, so the
 * mapping is total. Protocol versions 1 through 5 are accepted and the
 * protocol versus extension grammar is total: v1 and v2 carry neither
 * extension, v3 requires the decoy and carries no execution, v4
 * requires the execution triplet and may carry the decoy, and v5
 * requires the rsw identity.
 */
public final class ChallengeRecord {
    public String nonce = "";
    public String scope = "";
    public String bindingTag = "";
    public long issuedAt;
    public long expiresAt;
    public String algorithm = "";
    public int mKib;
    public int t;
    public int p;
    public int targetBits;
    public String salt = "";
    public String prefix = "";
    public String challenge = "";
    public int minDurationMs;

    public long issuedAtNs;
    public int protocolVersion;
    public String region = "";
    public int policyVersion;
    public String requestBinding = "";
    public String issuer = "";
    public int kid;
    public String hostname = "";

    public String decoyField = "";
    public String executionProgram = "";
    public int executionVersion;
    public String executionCommitment = "";
    public String rswModulusSha256 = "";
    public String serverMac = "";

    /** A strict wire schema violation. */
    public static final class MalformedRecordException extends RuntimeException {
        public MalformedRecordException(String reason) {
            super("kiwicaptcha: malformed record: " + reason);
        }
    }

    /** The legacy v1 name of the binding tag. */
    public String ipHash() {
        return bindingTag;
    }

    /** Degrades an unset epoch to the default 1, the Rust reader's view. */
    public int policyVersionOrOne() {
        return policyVersion == 0 ? 1 : policyVersion;
    }

    /** Degrades an unset key id to the default 1. */
    public int kidOrOne() {
        return kid == 0 ? 1 : kid;
    }

    /**
     * The one protocol versus extension matrix every boundary applies,
     * so the decoder and the verifier can never disagree about which
     * records are structurally valid.
     */
    public static boolean protocolExtensionGrammarOk(int protocolVersion, boolean decoyPresent,
                                                     boolean executionPresent, boolean rswIdentityPresent) {
        return switch (protocolVersion) {
            case 1 -> !decoyPresent && !executionPresent && !rswIdentityPresent;
            case Kiwi.BASE_PROTOCOL_VERSION -> !decoyPresent && !executionPresent;
            case Kiwi.DECOY_PROTOCOL_VERSION -> decoyPresent && !executionPresent;
            case Kiwi.EXECUTION_PROTOCOL_VERSION -> executionPresent;
            case Kiwi.RSW_IDENTITY_PROTOCOL_VERSION -> rswIdentityPresent;
            default -> false;
        };
    }

    /** The narrow security identifier alphabet with a length cap. */
    public static boolean isValidIdentifier(String value, int maxBytes) {
        if (value.isEmpty() || value.length() > maxBytes) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == ':' || c == '-';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /**
     * The honeypot field name alphabet: 1 to 64 bytes of
     * [A-Za-z0-9_-]. The alphabet excludes the canonical separators,
     * so a stored name can never alter the structure of the signed
     * payload.
     */
    public static boolean isValidDecoyFieldName(String value) {
        if (value.isEmpty() || value.length() > 64) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '_' || c == '-';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    static boolean isHex64(String value) {
        if (value.length() != 64) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
                return false;
            }
        }
        return true;
    }

    /** The wire keys of the canonical schema, in emission order. */
    public static final List<String> WIRE_KEYS = List.of(
            "nonce", "scope", "binding_tag", "issued_at", "expires_at",
            "algorithm", "m_kib", "t", "p", "target_bits", "salt", "prefix",
            "challenge", "min_duration_ms", "issued_at_ns", "protocol_version",
            "attempts_used", "region", "policy_version", "request_binding",
            "issuer", "kid", "hostname", "decoy_field", "execution_program",
            "execution_version", "execution_commitment", "rsw_modulus_sha256",
            "server_mac");

    private static final List<String> REQUIRED_KEYS = List.of(
            "nonce", "scope", "binding_tag", "issued_at", "expires_at",
            "algorithm", "m_kib", "t", "p", "target_bits", "salt", "prefix",
            "challenge", "min_duration_ms");

    private static final long U32_MAX = 4_294_967_295L;
    private static final long U64_MAX = Long.MAX_VALUE;

    /**
     * Renders the canonical wire schema for storage. The legacy
     * ip_hash key is never emitted beside binding_tag, and the
     * optional extension keys are omitted when unset, so unarmed
     * records keep the exact pre-extension byte format.
     */
    public Map<String, Object> toWireMap() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("nonce", nonce);
        data.put("scope", scope);
        data.put("binding_tag", bindingTag);
        data.put("issued_at", issuedAt);
        data.put("expires_at", expiresAt);
        data.put("algorithm", algorithm);
        data.put("m_kib", mKib);
        data.put("t", t);
        data.put("p", p);
        data.put("target_bits", targetBits);
        data.put("salt", salt);
        data.put("prefix", prefix);
        data.put("challenge", challenge);
        data.put("min_duration_ms", minDurationMs);
        data.put("issued_at_ns", issuedAtNs);
        data.put("protocol_version", protocolVersion);
        data.put("attempts_used", 0);
        data.put("region", jsonNullString(region));
        data.put("policy_version", policyVersionOrOne());
        data.put("request_binding", jsonNullString(requestBinding));
        data.put("issuer", jsonNullString(issuer));
        data.put("kid", kidOrOne());
        data.put("hostname", jsonNullString(hostname));
        if (!decoyField.isEmpty()) {
            data.put("decoy_field", decoyField);
        }
        if (!executionProgram.isEmpty()) {
            data.put("execution_program", executionProgram);
        }
        if (executionVersion != 0) {
            data.put("execution_version", executionVersion);
        }
        if (!executionCommitment.isEmpty()) {
            data.put("execution_commitment", executionCommitment);
        }
        if (!rswModulusSha256.isEmpty()) {
            data.put("rsw_modulus_sha256", rswModulusSha256);
        }
        if (!serverMac.isEmpty()) {
            data.put("server_mac", serverMac);
        }
        return data;
    }

    private static Object jsonNullString(String value) {
        return value.isEmpty() ? null : value;
    }

    /**
     * Emits the wire schema in the canonical key order, with json null
     * for the always present option fields, byte-compatible with the
     * php and Rust writers.
     */
    public String marshalJson() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean[] first = {true};
        writeField(sb, first, "nonce", JsonObject.encodeStatic(nonce));
        writeField(sb, first, "scope", JsonObject.encodeStatic(scope));
        writeField(sb, first, "binding_tag", JsonObject.encodeStatic(bindingTag));
        writeField(sb, first, "issued_at", String.valueOf(issuedAt));
        writeField(sb, first, "expires_at", String.valueOf(expiresAt));
        writeField(sb, first, "algorithm", JsonObject.encodeStatic(algorithm));
        writeField(sb, first, "m_kib", String.valueOf(mKib));
        writeField(sb, first, "t", String.valueOf(t));
        writeField(sb, first, "p", String.valueOf(p));
        writeField(sb, first, "target_bits", String.valueOf(targetBits));
        writeField(sb, first, "salt", JsonObject.encodeStatic(salt));
        writeField(sb, first, "prefix", JsonObject.encodeStatic(prefix));
        writeField(sb, first, "challenge", JsonObject.encodeStatic(challenge));
        writeField(sb, first, "min_duration_ms", String.valueOf(minDurationMs));
        writeField(sb, first, "issued_at_ns", String.valueOf(issuedAtNs));
        writeField(sb, first, "protocol_version", String.valueOf(protocolVersion));
        writeField(sb, first, "attempts_used", "0");
        writeField(sb, first, "region", nullableString(region));
        writeField(sb, first, "policy_version", String.valueOf(policyVersionOrOne()));
        writeField(sb, first, "request_binding", nullableString(requestBinding));
        writeField(sb, first, "issuer", nullableString(issuer));
        writeField(sb, first, "kid", String.valueOf(kidOrOne()));
        writeField(sb, first, "hostname", nullableString(hostname));
        if (!decoyField.isEmpty()) {
            writeField(sb, first, "decoy_field", JsonObject.encodeStatic(decoyField));
        }
        if (!executionProgram.isEmpty()) {
            writeField(sb, first, "execution_program", JsonObject.encodeStatic(executionProgram));
        }
        if (executionVersion != 0) {
            writeField(sb, first, "execution_version", String.valueOf(executionVersion));
        }
        if (!executionCommitment.isEmpty()) {
            writeField(sb, first, "execution_commitment", JsonObject.encodeStatic(executionCommitment));
        }
        if (!rswModulusSha256.isEmpty()) {
            writeField(sb, first, "rsw_modulus_sha256", JsonObject.encodeStatic(rswModulusSha256));
        }
        if (!serverMac.isEmpty()) {
            writeField(sb, first, "server_mac", JsonObject.encodeStatic(serverMac));
        }
        sb.append('}');
        return sb.toString();
    }

    private static void writeField(StringBuilder sb, boolean[] first, String name, String raw) {
        if (!first[0]) {
            sb.append(',');
        }
        first[0] = false;
        JsonObject.writeJsonString(sb, name);
        sb.append(':').append(raw);
    }

    private static String nullableString(String v) {
        return v.isEmpty() ? "null" : JsonObject.encodeStatic(v);
    }

    /**
     * The strict serde mirror parser over stored bytes. It accepts
     * exactly what the Rust ChallengeRecord parser accepts, including
     * the legacy ip_hash alias, which must never appear beside
     * binding_tag. Unknown keys, partial execution triplets, forbidden
     * protocol and extension combinations, duplicate keys and
     * out-of-range integers are rejected.
     */
    public static ChallengeRecord parse(byte[] data) {
        Object value;
        try {
            value = StrictJson.decode(data);
        } catch (RuntimeException e) {
            throw new MalformedRecordException(e.getMessage());
        }
        if (!(value instanceof Map)) {
            throw new MalformedRecordException("a record must decode from a json object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) value;
        return fromMap(map);
    }

    /** Parses one record from an already decoded strict map. */
    public static ChallengeRecord fromMap(Map<String, Object> data) {
        for (String key : data.keySet()) {
            if (!key.equals("ip_hash") && !WIRE_KEYS.contains(key)) {
                throw new MalformedRecordException("unknown record key: " + key);
            }
        }
        boolean hasBinding = data.containsKey("binding_tag");
        Object rawBinding = data.get("binding_tag");
        if (data.containsKey("ip_hash")) {
            if (hasBinding) {
                throw new MalformedRecordException("binding_tag and ip_hash are duplicate fields");
            }
            rawBinding = data.get("ip_hash");
            hasBinding = true;
        }
        for (String field : REQUIRED_KEYS) {
            if (field.equals("binding_tag")) {
                if (!hasBinding) {
                    throw new MalformedRecordException("missing record field: " + field);
                }
                continue;
            }
            if (!data.containsKey(field)) {
                throw new MalformedRecordException("missing record field: " + field);
            }
        }
        String nonce = requireString(data, "nonce");
        String scope = requireString(data, "scope");
        String bindingTag = wireString(rawBinding, "binding_tag");
        String salt = requireString(data, "salt");
        String prefix = requireString(data, "prefix");
        String challenge = requireString(data, "challenge");
        long issuedAt = wireInt(data.get("issued_at"), "issued_at", 0, U64_MAX);
        long expiresAt = wireInt(data.get("expires_at"), "expires_at", 0, U64_MAX);
        long minDurationMs = wireInt(data.get("min_duration_ms"), "min_duration_ms", 0, U64_MAX);
        long issuedAtNs = 0;
        if (data.containsKey("issued_at_ns")) {
            issuedAtNs = wireInt(data.get("issued_at_ns"), "issued_at_ns", 0, U64_MAX);
        }
        long mKib = wireInt(data.get("m_kib"), "m_kib", 0, U32_MAX);
        long t = wireInt(data.get("t"), "t", 0, U32_MAX);
        long p = wireInt(data.get("p"), "p", 0, U32_MAX);
        long targetBits = wireInt(data.get("target_bits"), "target_bits", 0, U32_MAX);
        if (data.containsKey("attempts_used")) {
            wireInt(data.get("attempts_used"), "attempts_used", 0, U32_MAX);
        }
        long policyVersion = 1;
        if (data.containsKey("policy_version")) {
            policyVersion = wireInt(data.get("policy_version"), "policy_version", 0, U32_MAX);
        }
        long kid = 1;
        if (data.containsKey("kid")) {
            kid = wireInt(data.get("kid"), "kid", 0, U32_MAX);
        }
        long protocolVersion = 1;
        if (data.containsKey("protocol_version")) {
            protocolVersion = wireInt(data.get("protocol_version"), "protocol_version", 1, Kiwi.MAX_PROTOCOL_VERSION);
        }
        String algorithm = requireString(data, "algorithm");
        if (!algorithm.equals("sha256") && !algorithm.equals("argon2id") && !algorithm.equals("rsw")) {
            throw new MalformedRecordException("invalid algorithm: " + algorithm);
        }
        String region = optionalIdentifier(data, "region", 64);
        String requestBinding = optionalIdentifier(data, "request_binding", 128);
        String issuer = optionalIdentifier(data, "issuer", 128);
        String decoyField = "";
        Object decoyValue = data.get("decoy_field");
        if (decoyValue != null) {
            decoyField = wireString(decoyValue, "decoy_field");
            if (!isValidDecoyFieldName(decoyField)) {
                throw new MalformedRecordException("invalid decoy field name");
            }
        }
        String executionProgram = "";
        Object programValue = data.get("execution_program");
        if (programValue != null) {
            executionProgram = wireString(programValue, "execution_program");
            if (executionProgram.length() > ExecutionProgram.MAX_PROGRAM_BASE64) {
                throw new MalformedRecordException("execution_program exceeds the wire cap");
            }
            if (!ExecutionProgram.isValidExecutionProgram(executionProgram)) {
                throw new MalformedRecordException("invalid execution program");
            }
        }
        boolean hasExecutionVersion = false;
        long executionVersion = 0;
        Object versionValue = data.get("execution_version");
        if (versionValue != null) {
            hasExecutionVersion = true;
            executionVersion = wireInt(versionValue, "execution_version", 0, 255);
            if (executionVersion < 1 || executionVersion > Kiwi.MAX_EXECUTION_VERSION) {
                throw new MalformedRecordException("invalid execution version: " + executionVersion);
            }
        }
        boolean hasExecutionCommitment = false;
        String executionCommitment = "";
        Object commitmentValue = data.get("execution_commitment");
        if (commitmentValue != null) {
            hasExecutionCommitment = true;
            executionCommitment = wireString(commitmentValue, "execution_commitment");
            if (!isHex64(executionCommitment)) {
                throw new MalformedRecordException("invalid execution commitment");
            }
        }
        if (!executionProgram.isEmpty() || hasExecutionVersion || hasExecutionCommitment) {
            if (executionProgram.isEmpty() || !hasExecutionVersion || !hasExecutionCommitment) {
                throw new MalformedRecordException("incomplete execution fields");
            }
            if (!ExecutionProgram.commitment(executionProgram).equals(executionCommitment)) {
                throw new MalformedRecordException("execution commitment mismatch");
            }
        }
        String rswIdentity = parseRswIdentity(data, algorithm, protocolVersion);
        if (!protocolExtensionGrammarOk((int) protocolVersion, !decoyField.isEmpty(),
                !executionProgram.isEmpty(), !rswIdentity.isEmpty())) {
            throw new MalformedRecordException("invalid protocol and extension combination: " + protocolVersion);
        }
        String serverMac = "";
        Object macValue = data.get("server_mac");
        if (macValue != null) {
            serverMac = wireString(macValue, "server_mac");
            if (!isHex64(serverMac)) {
                throw new MalformedRecordException("server_mac must be 64 lowercase hex characters");
            }
        }
        String hostname = "";
        Object hostnameValue = data.get("hostname");
        if (hostnameValue != null) {
            hostname = wireString(hostnameValue, "hostname");
            if (hostname.isEmpty()) {
                throw new MalformedRecordException("hostname must be a non-empty string or null");
            }
            for (int i = 0; i < hostname.length(); i++) {
                char c = hostname.charAt(i);
                if (c <= 0x20 || c == 0x7f) {
                    throw new MalformedRecordException("hostname must carry no whitespace or control characters");
                }
            }
        }
        ChallengeRecord record = new ChallengeRecord();
        record.nonce = nonce;
        record.scope = scope;
        record.bindingTag = bindingTag;
        record.issuedAt = issuedAt;
        record.expiresAt = expiresAt;
        record.algorithm = algorithm;
        record.mKib = (int) mKib;
        record.t = (int) t;
        record.p = (int) p;
        record.targetBits = (int) targetBits;
        record.salt = salt;
        record.prefix = prefix;
        record.challenge = challenge;
        record.minDurationMs = (int) minDurationMs;
        record.issuedAtNs = issuedAtNs;
        record.protocolVersion = (int) protocolVersion;
        record.region = region;
        record.policyVersion = (int) policyVersion;
        record.requestBinding = requestBinding;
        record.issuer = issuer;
        record.kid = (int) kid;
        record.hostname = hostname;
        record.decoyField = decoyField;
        record.executionProgram = executionProgram;
        record.executionVersion = (int) executionVersion;
        record.executionCommitment = executionCommitment;
        record.rswModulusSha256 = rswIdentity;
        record.serverMac = serverMac;
        return record;
    }

    private static String parseRswIdentity(Map<String, Object> data, String algorithm, long protocolVersion) {
        Object value = data.get("rsw_modulus_sha256");
        if (value == null) {
            return "";
        }
        String identity = wireString(value, "rsw_modulus_sha256");
        if (!isHex64(identity)) {
            throw new MalformedRecordException("rsw_modulus_sha256 must be 64 lowercase hex characters");
        }
        if (!algorithm.equals("rsw")) {
            throw new MalformedRecordException("rsw_modulus_sha256 may only ride an rsw record");
        }
        if (protocolVersion == 1) {
            throw new MalformedRecordException("rsw_modulus_sha256 may not ride the v1 canonical");
        }
        return identity;
    }

    private static String requireString(Map<String, Object> data, String field) {
        if (!data.containsKey(field)) {
            throw new MalformedRecordException("missing record field: " + field);
        }
        return wireString(data.get(field), field);
    }

    private static String wireString(Object value, String field) {
        if (!(value instanceof String text)) {
            throw new MalformedRecordException(field + " must be a string");
        }
        if (text.length() > Kiwi.MAX_STRING_BYTES) {
            throw new MalformedRecordException(field + " exceeds the " + Kiwi.MAX_STRING_BYTES + " byte wire cap");
        }
        return text;
    }

    private static long wireInt(Object value, String field, long min, long max) {
        long parsed;
        if (value instanceof JsonNumber number) {
            try {
                parsed = number.longValue();
            } catch (NumberFormatException e) {
                throw new MalformedRecordException(field + " must be an integer within " + min + ".." + max);
            }
        } else if (value instanceof Long l) {
            parsed = l;
        } else if (value instanceof Integer i) {
            parsed = i;
        } else {
            throw new MalformedRecordException(field + " must be an integer within " + min + ".." + max);
        }
        if (parsed < min || parsed > max) {
            throw new MalformedRecordException(field + " must be an integer within " + min + ".." + max);
        }
        return parsed;
    }

    private static String optionalIdentifier(Map<String, Object> data, String field, int cap) {
        Object value = data.get(field);
        if (value == null) {
            return "";
        }
        String text = wireString(value, field);
        if (!isValidIdentifier(text, cap)) {
            throw new MalformedRecordException(field + " must match the narrow identifier alphabet");
        }
        return text;
    }
}
