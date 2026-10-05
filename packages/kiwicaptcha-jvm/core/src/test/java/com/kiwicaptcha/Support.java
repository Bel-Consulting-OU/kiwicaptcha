package com.kiwicaptcha;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

/**
 * Shared test support: the canonical vectors, the corpus paths and
 * the record and token builders every suite composes. The vector
 * values are the Rust-generated protocol corpus the php and Go suites
 * pin, so every implementation holds one acceptance split.
 */
final class Support {
    private Support() {}

    static final String TEST_SECRET = "0123456789abcdef0123456789abcdef";
    static final String TEST_CLIENT_IP = "203.0.113.7";
    static final long TEST_ISSUED_AT = 1_800_000_000L;
    static final long TEST_NOW = 1_800_000_100L;
    static final String TEST_IP_HASH =
            "9c50b8d493de847656a168d0408bd4455994df2fc0b1e94bab5a85d64850034b";

    /** One entry of the Rust-generated canonical corpus. */
    record ProtocolVector(String nonce, String challenge, String salt, String prefix,
                          String algorithm, int mKib, int t, int p, int targetBits, int counter) {}

    static final ProtocolVector SHA_VECTOR = new ProtocolVector(
            "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
            "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58"
                    + "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
                    + "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
                    + "dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba",
            "phUfA189G9A5KMv3r+wzLA==",
            "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58"
                    + "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
                    + "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
                    + "dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba"
                    + "|phUfA189G9A5KMv3r+wzLA==|",
            "sha256", 0, 1, 1, 8, 158);

    static final ProtocolVector ARGON2_VECTOR = new ProtocolVector(
            "Sn89Ua2qPftlfNO2K9jZSWB52OpcuYwRD1kf2GDhAX4=",
            "U244OVVhMnFQZnRsZk5PMks5alpTV0I1Mk9wY3VZd1JEMWtmMkdEaEFYND18bG9naW58"
                    + "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
                    + "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
                    + "2757c7cdabe01a52d31cb91900d64eaaae881dd25353dd79267ce35298b3c239",
            "6HL5BOgvD4ryefTBPNhS8A==",
            "U244OVVhMnFQZnRsZk5PMks5alpTV0I1Mk9wY3VZd1JEMWtmMkdEaEFYND18bG9naW58"
                    + "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
                    + "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
                    + "2757c7cdabe01a52d31cb91900d64eaaae881dd25353dd79267ce35298b3c239"
                    + "|6HL5BOgvD4ryefTBPNhS8A==|",
            "argon2id", 64, 3, 1, 4, 21);

    static ChallengeRecord vectorRecord(ProtocolVector vector) {
        ChallengeRecord record = new ChallengeRecord();
        record.nonce = vector.nonce();
        record.scope = "login";
        record.bindingTag = TEST_IP_HASH;
        record.issuedAt = TEST_ISSUED_AT;
        record.expiresAt = TEST_ISSUED_AT + 120;
        record.algorithm = vector.algorithm();
        record.mKib = vector.mKib();
        record.t = vector.t();
        record.p = vector.p();
        record.targetBits = vector.targetBits();
        record.salt = vector.salt();
        record.prefix = vector.prefix();
        record.challenge = vector.challenge();
        record.minDurationMs = 0;
        record.issuedAtNs = TEST_ISSUED_AT * 1_000_000;
        record.protocolVersion = 1;
        return record;
    }

    static String vectorToken(ProtocolVector vector, long counter, int durationMs) {
        JsonObject telemetry = JsonObject.of(
                "wd", false,
                "me", new JsonNumber("3"),
                "ke", new JsonNumber("1"),
                "et", java.util.List.of(new JsonNumber("100"), new JsonNumber("250"), new JsonNumber("480")));
        long effectiveCounter = counter < 0 ? vector.counter() : counter;
        int effectiveDuration = durationMs < 0 ? 5000 : durationMs;
        return SolutionToken.create(vector.nonce(), effectiveCounter, effectiveDuration,
                telemetry, "", "", "").encode();
    }

    /** One mint option set for the record builder. */
    static final class MintOptions {
        byte[] nonceBytes = deterministicBytes(32);
        byte[] saltBytes = deterministicBytes(16);
        String scope = "login";
        String bindingIp = "";
        String requestBinding = "";
        long issuedAt = TEST_ISSUED_AT;
        long ttl = 120;
        String algorithm = "sha256";
        int mKib = 1;
        int t = 1;
        int targetBits = 4;
        int minDurationMs = 0;
        String region = "";
        int policyVersion = 1;
        String issuer = "";
        int kid = 1;
        int protocolVersion = 2;
        String decoyField = "";
        String hostname = "";
        boolean mintMetaMac;
        String tenantId = "";
        String executionProgram = "";
    }

    private static byte[] deterministicBytes(int n) {
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) i;
        }
        return out;
    }

    static ChallengeRecord mintRecord(MintOptions options) {
        String nonce = Base64.getEncoder().encodeToString(options.nonceBytes);
        String salt = Base64.getEncoder().encodeToString(options.saltBytes);
        long expiresAt = options.issuedAt + options.ttl;
        long issuedAtNs = options.issuedAt * 1_000_000;
        String bindingTag = "";
        if (options.protocolVersion == 1) {
            bindingTag = Canonical.hex(Canonical.sha256(
                    (TEST_SECRET + clientOrDefaultIp(options)).getBytes(StandardCharsets.UTF_8)));
        } else if (!options.bindingIp.isEmpty()) {
            bindingTag = Canonical.bindingTag(nonce, clientOrDefaultIp(options), TEST_SECRET, options.tenantId);
        }
        String payload = Canonical.canonicalPayloadChecked(
                options.protocolVersion, nonce, options.scope, bindingTag, options.issuedAt, expiresAt,
                options.algorithm, options.mKib, options.t, 1, options.targetBits, salt,
                options.minDurationMs, options.region, options.policyVersion, options.requestBinding,
                options.issuer, options.kid, options.decoyField,
                executionVersionFor(options), executionCommitmentFor(options), "",
                options.mintMetaMac);
        String signature = Canonical.signPayloadV2(payload, TEST_SECRET, options.tenantId);
        String challenge = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + "." + signature;
        String serverMac = "";
        if (options.mintMetaMac) {
            byte[] key = Canonical.serverStateMacKey(TEST_SECRET, options.tenantId);
            serverMac = Canonical.serverStateMacRecordMeta(key, challenge, issuedAtNs, options.hostname);
        }
        ChallengeRecord record = new ChallengeRecord();
        record.nonce = nonce;
        record.scope = options.scope;
        record.bindingTag = bindingTag;
        record.issuedAt = options.issuedAt;
        record.expiresAt = expiresAt;
        record.algorithm = options.algorithm;
        record.mKib = options.mKib;
        record.t = options.t;
        record.p = 1;
        record.targetBits = options.targetBits;
        record.salt = salt;
        record.prefix = challenge + "|" + salt + "|";
        record.challenge = challenge;
        record.minDurationMs = options.minDurationMs;
        record.issuedAtNs = issuedAtNs;
        record.protocolVersion = options.protocolVersion;
        record.region = options.region;
        record.policyVersion = options.policyVersion;
        record.requestBinding = options.requestBinding;
        record.issuer = options.issuer;
        record.kid = options.kid;
        record.hostname = options.hostname;
        record.decoyField = options.decoyField;
        record.executionProgram = options.executionProgram;
        record.executionVersion = executionVersionFor(options);
        record.executionCommitment = executionCommitmentFor(options);
        record.serverMac = serverMac;
        return record;
    }

    private static String clientOrDefaultIp(MintOptions options) {
        return options.bindingIp.isEmpty() ? TEST_CLIENT_IP : options.bindingIp;
    }

    private static int executionVersionFor(MintOptions options) {
        return options.executionProgram.isEmpty() ? 0 : 1;
    }

    private static String executionCommitmentFor(MintOptions options) {
        return options.executionProgram.isEmpty() ? "" : ExecutionProgram.commitment(options.executionProgram);
    }

    /** Builds one well-formed v1 program blob: eight add records. */
    static String minimalProgramB64(String scope, String action) {
        byte[] scopeBytes = scope.getBytes(StandardCharsets.UTF_8);
        byte[] actionBytes = action.getBytes(StandardCharsets.UTF_8);
        byte[] body = new byte[2 + scopeBytes.length + actionBytes.length + 3 + 8 * 9];
        int offset = 0;
        body[offset++] = 1;
        body[offset++] = (byte) scopeBytes.length;
        System.arraycopy(scopeBytes, 0, body, offset, scopeBytes.length);
        offset += scopeBytes.length;
        body[offset++] = (byte) actionBytes.length;
        System.arraycopy(actionBytes, 0, body, offset, actionBytes.length);
        offset += actionBytes.length;
        body[offset++] = 1;
        body[offset++] = 8;
        for (int i = 0; i < 8; i++) {
            body[offset++] = 0;
            body[offset++] = (byte) (i + 1);
            body[offset++] = 0;
            body[offset++] = 0;
            body[offset++] = 0;
            body[offset++] = 1;
            body[offset++] = 0;
            body[offset++] = 0;
            body[offset++] = 0;
        }
        return Base64.getEncoder().encodeToString(body);
    }

    /** Searches the sha256 counter to the target difficulty. */
    static int solveSha(String prefix, String saltB64, int targetBits) {
        byte[] saltBytes = Base64.getDecoder().decode(saltB64);
        int counter = 0;
        while (true) {
            byte[] prefixBytes = (prefix + counter).getBytes(StandardCharsets.UTF_8);
            byte[] input = new byte[prefixBytes.length + saltBytes.length];
            System.arraycopy(prefixBytes, 0, input, 0, prefixBytes.length);
            System.arraycopy(saltBytes, 0, input, prefixBytes.length, saltBytes.length);
            byte[] digest = Canonical.sha256(input);
            if (Canonical.leadingZeroBits(digest) >= targetBits) {
                return counter;
            }
            counter++;
        }
    }

    /** Searches the argon2id counter to the target difficulty. */
    static int solveArgon2(String prefix, String saltB64, int targetBits, int t, int mKib) {
        byte[] saltBytes = Base64.getDecoder().decode(saltB64);
        int counter = 0;
        while (true) {
            byte[] digest = Argon2id.derive((prefix + counter).getBytes(StandardCharsets.UTF_8),
                    saltBytes, t, mKib, 1, 32, new byte[0], new byte[0]);
            if (Canonical.leadingZeroBits(digest) >= targetBits) {
                return counter;
            }
            counter++;
        }
    }

    /** Performs the client's T sequential squarings. */
    static String solveRsw(String prefix, String nonce, java.math.BigInteger n, int t) {
        java.math.BigInteger value = Rsw.deriveBase(prefix, nonce, n);
        for (int i = 0; i < t; i++) {
            value = value.multiply(value).mod(n);
        }
        return Rsw.proofHex(value);
    }

    static Verifier newTestVerifier(Verifier.Config config, long now) {
        config.nowSecs = () -> now;
        // The store keeps the wall clock: the vector records live in a
        // future issuance window, so they never evict mid-suite.
        try {
            return new Verifier(new MemoryStore(), config);
        } catch (RuntimeException e) {
            throw new IllegalStateException(e);
        }
    }

    static void storeRecord(Store.StoreAdapter store, ChallengeRecord record) {
        ((Store.Storer) store).storeRecord(record);
    }

    static void requireCode(VerifyOutcome outcome, VerifyError expected) {
        if (outcome.valid) {
            throw new AssertionError("expected " + expected.code() + ", got a valid outcome");
        }
        if (outcome.error != expected) {
            throw new AssertionError("expected " + expected.code() + ", got " + outcome.code()
                    + " (detail " + outcome.detail + ")");
        }
    }

    static void requireValid(VerifyOutcome outcome) {
        if (!outcome.valid) {
            throw new AssertionError("expected a valid outcome, got " + outcome.code()
                    + " (detail " + outcome.detail + ")");
        }
    }

    /** Walks up from the working directory to locate the shared protocol corpus. */
    static Path protocolPath(String relative) {
        Path dir = new File(System.getProperty("user.dir")).getAbsoluteFile().toPath();
        while (dir != null) {
            Path candidate = dir.resolve("protocol").resolve(relative);
            if (Files.exists(candidate)) {
                return candidate;
            }
            dir = dir.getParent();
        }
        return null;
    }

    static Path protocolPathOrSkip(String relative) {
        Path found = protocolPath(relative);
        if (found == null) {
            throw new org.opentest4j.TestAbortedException(
                    "the shared protocol corpus is not present: " + relative);
        }
        return found;
    }

    static Path testdataPath(String relative) {
        Path dir = new File(System.getProperty("user.dir")).getAbsoluteFile().toPath();
        while (dir != null) {
            Path candidate = dir.resolve("testdata").resolve(relative);
            if (Files.exists(candidate)) {
                return candidate;
            }
            dir = dir.getParent();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> readGolden(String name) {
        Path path = testdataPath(name);
        if (path == null) {
            throw new IllegalStateException("golden fixture " + name + " not found");
        }
        try {
            return (Map<String, Object>) StrictJson.decode(Files.readAllBytes(path));
        } catch (IOException e) {
            throw new IllegalStateException("golden fixture " + name, e);
        }
    }

    /** The committed PHP-issued golden vector document, shared by the suites. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> goldenVectors() {
        return (Map<String, Object>) readGolden("golden/golden-php-vectors.json");
    }

    static String goldenString(Map<String, Object> document, String key) {
        return String.valueOf(document.get(key));
    }

    static String sha256Hex(String value) {
        return Canonical.hex(Canonical.sha256(value.getBytes(StandardCharsets.UTF_8)));
    }
}
