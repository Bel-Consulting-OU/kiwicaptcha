package com.kiwicaptcha;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * The signed canonical payload, revision 4, byte-identical with the
 * php Issuer and the Rust canonical_signing_input_v2:
 *
 * v4|protocol_version|nonce|scope|binding_tag|issued_at|expires_at|
 * algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|
 * policy_version|request_binding|issuer|kid[|d=decoy][|e=v,hex]
 * [|r=hex][|m=1]
 *
 * Unset optional fields render as the empty segment. Every armed
 * extension is appended tagged in capability order, and the record
 * metadata mac marker lands last, so stripping the mac breaks the
 * signature.
 */
public final class Canonical {
    private Canonical() {}

    /** Raised when exactly one half of the execution commitment pair is presented. */
    public static final class ExecutionPairException extends RuntimeException {
        public ExecutionPairException() {
            super("kiwicaptcha: execution_version and execution_commitment must be passed together");
        }
    }

    /** Raised for an input that is not a plain IPv4 or IPv6 address. */
    public static final class InvalidIpException extends RuntimeException {
        public InvalidIpException() {
            super("kiwicaptcha: invalid ip address");
        }
    }

    /** Raised when a master secret is below the 32-byte entropy floor. */
    public static final class SecretTooShortException extends RuntimeException {
        public SecretTooShortException() {
            super("kiwicaptcha: the master secret must be at least " + Kiwi.MIN_SECRET_BYTES + " bytes");
        }
    }

    /** CanonicalPayload with the execution pair arity error issuers must respect. */
    public static String canonicalPayloadChecked(int protocolVersion, String nonce, String scope,
            String bindingTag, long issuedAt, long expiresAt, String algorithm,
            int mKib, int t, int p, int targetBits, String salt, int minDurationMs,
            String region, int policyVersion, String requestBinding, String issuer, int kid,
            String decoyField, int executionVersion, String executionCommitment,
            String rswModulusSha256, boolean serverMacCommitted) {
        if ((executionVersion != 0) != (executionCommitment != null && !executionCommitment.isEmpty())) {
            throw new ExecutionPairException();
        }
        return canonicalPayload(protocolVersion, nonce, scope, bindingTag, issuedAt, expiresAt,
                algorithm, mKib, t, p, targetBits, salt, minDurationMs, region, policyVersion,
                requestBinding, issuer, kid, decoyField, executionVersion, executionCommitment,
                rswModulusSha256, serverMacCommitted);
    }

    /** Builds the revision 4 canonical payload string. */
    public static String canonicalPayload(int protocolVersion, String nonce, String scope,
            String bindingTag, long issuedAt, long expiresAt, String algorithm,
            int mKib, int t, int p, int targetBits, String salt, int minDurationMs,
            String region, int policyVersion, String requestBinding, String issuer, int kid,
            String decoyField, int executionVersion, String executionCommitment,
            String rswModulusSha256, boolean serverMacCommitted) {
        StringBuilder b = new StringBuilder(256);
        b.append("v4|").append(protocolVersion).append('|').append(nonce).append('|')
                .append(scope).append('|').append(bindingTag).append('|')
                .append(issuedAt).append('|').append(expiresAt).append('|')
                .append(algorithm).append('|').append(mKib).append('|')
                .append(t).append('|').append(p).append('|').append(targetBits).append('|')
                .append(salt).append('|').append(minDurationMs).append('|')
                .append(region).append('|').append(policyVersion).append('|')
                .append(requestBinding).append('|').append(issuer).append('|').append(kid);
        if (decoyField != null && !decoyField.isEmpty()) {
            b.append("|d=").append(decoyField);
        }
        boolean executionPresent = (executionVersion != 0)
                || (executionCommitment != null && !executionCommitment.isEmpty());
        if (executionPresent) {
            b.append("|e=").append(executionVersion).append(',')
                    .append(executionCommitment == null ? "" : executionCommitment);
        }
        if (rswModulusSha256 != null && !rswModulusSha256.isEmpty()) {
            b.append("|r=").append(rswModulusSha256);
        }
        if (serverMacCommitted) {
            b.append("|m=1");
        }
        return b.toString();
    }

    /**
     * Strict canonical standard base64 decode: the input must be
     * exactly the canonical padded encoding of its bytes. Returns null
     * instead of throwing.
     */
    public static byte[] b64CanonicalDecode(String raw) {
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(raw);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!Base64.getEncoder().encodeToString(decoded).equals(raw)) {
            return null;
        }
        return decoded;
    }

    /** The legacy v1 canonical: four untagged segments. */
    public static String legacyV1Payload(String nonce, String scope, String ipHash, long issuedAt) {
        return nonce + "|" + scope + "|" + ipHash + "|" + issuedAt;
    }

    /** The legacy v1 signature: the hex hmac under the master secret directly. */
    public static String signPayloadV1(String payload, String secretKey) {
        return hmacHex(secretKey.getBytes(StandardCharsets.UTF_8), payload);
    }

    /**
     * The v2 signature: the hex hmac under the derived challenge
     * purpose key. The master secret is never used directly as the
     * signing key.
     */
    public static String signPayloadV2(String payload, String secretKey, String tenantId) {
        DerivedKeys keys = DerivedKeys.fromMaster(secretKey, tenantId);
        return hmacHex(keys.challengeKey, payload);
    }

    /** Returns the hex tag after the last dot of the challenge string. */
    public static String signatureFromChallenge(String challenge) {
        int dot = challenge.lastIndexOf('.');
        if (dot < 0) {
            return "";
        }
        return challenge.substring(dot + 1);
    }

    /** The legacy v1 binding value: the sha256 hex of secret plus ip. */
    public static String hashIpV1(String ip, String secret) {
        return hex(sha256((secret + ip).getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * The family byte plus the packed bytes of one address: 0x04 plus
     * the 4-byte form, or 0x06 plus the 16-byte form. An IPv4-mapped
     * or deprecated IPv4-compatible IPv6 form folds to its 4-byte
     * form, so two textual spellings of one address produce the same
     * bytes. A zoned IPv6 literal is rejected.
     */
    public static byte[] canonicalIpFamily(String ip) {
        if (ip.indexOf('%') >= 0) {
            throw new InvalidIpException();
        }
        if (ip.indexOf(':') >= 0) {
            byte[] raw = parseIpv6(ip);
            boolean allZeroTop = true;
            for (int i = 0; i < 10; i++) {
                if (raw[i] != 0) {
                    allZeroTop = false;
                    break;
                }
            }
            boolean mapped = allZeroTop && raw[10] == (byte) 0xff && raw[11] == (byte) 0xff;
            boolean compatiblePrefix = allZeroTop && raw[10] == 0 && raw[11] == 0;
            int low = ((raw[12] & 0xff) << 24) | ((raw[13] & 0xff) << 16)
                    | ((raw[14] & 0xff) << 8) | (raw[15] & 0xff);
            boolean compatible = compatiblePrefix && low != 0 && low != 1;
            if (mapped || compatible) {
                byte[] out = new byte[5];
                out[0] = 0x04;
                System.arraycopy(raw, 12, out, 1, 4);
                return out;
            }
            byte[] out = new byte[17];
            out[0] = 0x06;
            System.arraycopy(raw, 0, out, 1, 16);
            return out;
        }
        byte[] four = parseIpv4(ip);
        byte[] out = new byte[5];
        out[0] = 0x04;
        System.arraycopy(four, 0, out, 1, 4);
        return out;
    }

    /**
     * The v2 binding tag: a nonce bound hmac over the canonical ip
     * bytes, keyed by the ip binding purpose key. The tag is a nonce
     * bound hmac, never a stable ip derived identifier.
     */
    public static String bindingTag(String nonce, String ip, String secret, String tenantId) {
        byte[] family = canonicalIpFamily(ip);
        DerivedKeys keys = DerivedKeys.fromMaster(secret, tenantId);
        Mac mac = hmac(keys.ipBindKey);
        mac.update((Kiwi.IP_BIND_DOMAIN + "\u0000" + nonce + "\u0000").getBytes(StandardCharsets.UTF_8));
        mac.update(family);
        return hex(mac.doFinal());
    }

    /** Constant-time byte equality over the utf-8 encodings of two strings. */
    public static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /** Constant-time byte array equality. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /** Counts the leading zero bits of a digest in big-endian bit order. */
    public static int leadingZeroBits(byte[] digest) {
        int count = 0;
        for (byte b : digest) {
            int by = b & 0xff;
            if (by == 0) {
                count += 8;
                continue;
            }
            while ((by & 0x80) == 0) {
                count++;
                by <<= 1;
            }
            break;
        }
        return count;
    }

    /**
     * Whether the signed canonical carries the m=1 marker. The marker
     * is parsed from the challenge string itself, never inferred from
     * the stored mac presence, so an m=1 record must carry a valid mac
     * regardless of any stored value.
     */
    public static boolean signedCanonicalCommitsRecordMeta(String challenge) {
        int dot = challenge.lastIndexOf('.');
        if (dot < 0) {
            return false;
        }
        byte[] canonical = b64CanonicalDecode(challenge.substring(0, dot));
        if (canonical == null) {
            return false;
        }
        String text = new String(canonical, StandardCharsets.UTF_8);
        return text.startsWith("v4|") && text.endsWith("|m=1");
    }

    /** Assembles the record metadata mac input. */
    public static String recordMetaInput(String challenge, long issuedAtNs, String hostname) {
        StringBuilder sb = new StringBuilder();
        sb.append(Kiwi.RECORD_META_DOMAIN).append('\n');
        macLengthPrefix(sb, challenge);
        sb.append('\n').append(issuedAtNs).append('\n');
        macOptional(sb, hostname);
        return sb.toString();
    }

    /** Assembles the consumed result mac input. */
    public static String consumedResultInput(String challenge, boolean valid, String binding,
                                             String operationIdentity) {
        StringBuilder sb = new StringBuilder();
        sb.append(Kiwi.CONSUMED_RESULT_DOMAIN).append('\n');
        macLengthPrefix(sb, challenge);
        sb.append('\n').append(valid ? "1" : "0").append('\n');
        macOptional(sb, binding);
        sb.append('\n');
        macOptional(sb, operationIdentity);
        return sb.toString();
    }

    static void macLengthPrefix(StringBuilder sb, String value) {
        sb.append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value);
    }

    static void macOptional(StringBuilder sb, String value) {
        if (value == null || value.isEmpty()) {
            sb.append("0");
            return;
        }
        sb.append("1:");
        macLengthPrefix(sb, value);
    }

    /** The server state purpose key of the secret and tenant pair. */
    public static byte[] serverStateMacKey(String secret, String tenantId) {
        return DerivedKeys.fromMaster(secret, tenantId).serverStateKey;
    }

    /** Computes the record metadata mac. */
    public static String serverStateMacRecordMeta(byte[] key, String challenge, long issuedAtNs,
                                                  String hostname) {
        return hmacHex(key, recordMetaInput(challenge, issuedAtNs, hostname));
    }

    /** Computes the consumed result mac. */
    public static String serverStateMacConsumedResult(byte[] key, String challenge, boolean valid,
                                                      String binding, String operationIdentity) {
        return hmacHex(key, consumedResultInput(challenge, valid, binding, operationIdentity));
    }

    /**
     * Recomputes the expected signature of a record and compares it
     * constant-time. Protocol v1 uses the legacy canonical signed
     * under the master secret; v2 and above use the full parameter
     * canonical signed under the derived challenge key. The signed m=1
     * marker requires a valid record metadata mac; a record signed
     * without the marker accepts an absent mac and always verifies a
     * present one.
     */
    public static boolean verifyRecordSignature(ChallengeRecord record, String secretKey, String tenantId) {
        boolean commitsMac = signedCanonicalCommitsRecordMeta(record.challenge);
        String expected;
        if (record.protocolVersion == 1) {
            expected = signPayloadV1(
                    legacyV1Payload(record.nonce, record.scope, record.bindingTag, record.issuedAt),
                    secretKey);
        } else {
            String payload;
            try {
                payload = canonicalPayloadChecked(
                        record.protocolVersion, record.nonce, record.scope, record.bindingTag,
                        record.issuedAt, record.expiresAt, record.algorithm, record.mKib, record.t,
                        record.p, record.targetBits, record.salt, record.minDurationMs, record.region,
                        record.policyVersionOrOne(), record.requestBinding, record.issuer,
                        record.kidOrOne(), record.decoyField, record.executionVersion,
                        record.executionCommitment, record.rswModulusSha256, commitsMac);
            } catch (RuntimeException e) {
                return false;
            }
            expected = signPayloadV2(payload, secretKey, tenantId);
        }
        if (!constantTimeEquals(expected, signatureFromChallenge(record.challenge))) {
            return false;
        }
        byte[] key = serverStateMacKey(secretKey, tenantId);
        String computed = serverStateMacRecordMeta(key, record.challenge, record.issuedAtNs, record.hostname);
        if (commitsMac) {
            return !record.serverMac.isEmpty() && constantTimeEquals(computed, record.serverMac);
        }
        return record.serverMac.isEmpty() || constantTimeEquals(computed, record.serverMac);
    }

    /** One sha256 digest over the input bytes. */
    public static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new IllegalStateException("sha256 unavailable", e);
        }
    }

    static Mac hmac(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (Exception e) {
            throw new IllegalStateException("hmac unavailable", e);
        }
    }

    static String hmacHex(byte[] key, String input) {
        return hex(hmac(key).doFinal(input.getBytes(StandardCharsets.UTF_8)));
    }

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] parseIpv4(String ip) {
        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4) {
            throw new InvalidIpException();
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String part = parts[i];
            if (part.isEmpty() || part.length() > 3) {
                throw new InvalidIpException();
            }
            if (part.length() > 1 && part.charAt(0) == '0') {
                throw new InvalidIpException();
            }
            for (int j = 0; j < part.length(); j++) {
                char c = part.charAt(j);
                if (c < '0' || c > '9') {
                    throw new InvalidIpException();
                }
            }
            int value;
            try {
                value = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                throw new InvalidIpException();
            }
            if (value > 255) {
                throw new InvalidIpException();
            }
            out[i] = (byte) value;
        }
        return out;
    }

    /**
     * Parses a strict plain IPv6 literal into its 16 packed bytes. One
     * :: compression is allowed, an embedded ipv4 tail folds into the
     * last two groups, and every other shape is rejected.
     */
    private static byte[] parseIpv6(String ip) {
        long[] groups = new long[8];
        int doubleColon = ip.indexOf("::");
        if (doubleColon >= 0) {
            if (ip.indexOf("::", doubleColon + 1) >= 0) {
                throw new InvalidIpException();
            }
            String left = ip.substring(0, doubleColon);
            String right = ip.substring(doubleColon + 2);
            int head = parseGroupRun(left, groups, 0);
            int rightCount = right.isEmpty() ? 0 : countGroups(right);
            int tail = 8 - rightCount;
            if (head + rightCount > 7) {
                throw new InvalidIpException();
            }
            parseGroupRun(right, groups, tail);
            return packGroups(groups);
        }
        if (ip.indexOf('.') >= 0) {
            int sep = ip.lastIndexOf(':');
            String headPart = sep >= 0 ? ip.substring(0, sep) : "";
            String fourPart = sep >= 0 ? ip.substring(sep + 1) : ip;
            byte[] four = parseIpv4(fourPart);
            groups[6] = (long) (four[0] & 0xff) * 256 + (four[1] & 0xff);
            groups[7] = (long) (four[2] & 0xff) * 256 + (four[3] & 0xff);
            int head = headPart.isEmpty() ? 6 : parseGroupRun(headPart, groups, 0);
            if (head != 6) {
                throw new InvalidIpException();
            }
            return packGroups(groups);
        }
        if (parseGroupRun(ip, groups, 0) != 8) {
            throw new InvalidIpException();
        }
        return packGroups(groups);
    }

    /** Parses one colon run of groups into groups starting at offset, returning the next offset. */
    private static int parseGroupRun(String text, long[] groups, int offset) {
        if (text.isEmpty()) {
            return offset;
        }
        String[] parts = text.split(":", -1);
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            int index = offset + i;
            if (part.indexOf('.') >= 0) {
                if (index + 2 > 8) {
                    throw new InvalidIpException();
                }
                byte[] four = parseIpv4(part);
                groups[index] = (long) (four[0] & 0xff) * 256 + (four[1] & 0xff);
                groups[index + 1] = (long) (four[2] & 0xff) * 256 + (four[3] & 0xff);
                if (i != parts.length - 1) {
                    throw new InvalidIpException();
                }
                return index + 2;
            }
            if (part.isEmpty() || part.length() > 4) {
                throw new InvalidIpException();
            }
            int value = 0;
            for (int j = 0; j < part.length(); j++) {
                int digit = Character.digit(part.charAt(j), 16);
                if (digit < 0) {
                    throw new InvalidIpException();
                }
                value = value * 16 + digit;
            }
            if (index > 7) {
                throw new InvalidIpException();
            }
            groups[index] = value;
        }
        return offset + parts.length;
    }

    private static int countGroups(String text) {
        String[] parts = text.split(":", -1);
        int count = 0;
        for (int i = 0; i < parts.length; i++) {
            count += parts[i].indexOf('.') >= 0 ? 2 : 1;
        }
        return count;
    }

    private static byte[] packGroups(long[] groups) {
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[i * 2] = (byte) (groups[i] >> 8);
            out[i * 2 + 1] = (byte) groups[i];
        }
        return out;
    }
}
