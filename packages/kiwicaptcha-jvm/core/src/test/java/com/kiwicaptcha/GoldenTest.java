package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The committed PHP-issued golden vectors, driven end to end: every
 * record is minted by the real php Issuer with its sealed
 * record-metadata mac, so the verdicts here pin this SDK against the
 * canonical core, not against this SDK's own minting.
 */
class GoldenTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> recordMap(Map<String, Object> entry) {
        return (Map<String, Object>) entry.get("record");
    }

    /** The verify call assembled from the fixture's opts: a config plus options pair. */
    record VerifyCall(Verifier.Config config, Verifier.Options options) {}

    @SuppressWarnings("unchecked")
    private static VerifyCall verifyCall(Map<String, Object> entry) {
        Object rawOpts = entry.get("verify_opts");
        // The php writer emits a php empty array as a json list, so an
        // empty opts row carries [] rather than {}.
        @SuppressWarnings("unchecked")
        Map<String, Object> verifyOpts = rawOpts instanceof Map
                ? (Map<String, Object>) rawOpts
                : Map.of();
        Verifier.Config config = new Verifier.Config();
        Verifier.Options options = new Verifier.Options();
        options.secretKey = Support.TEST_SECRET;
        options.expectedScope = stringOrEmpty(verifyOpts.get("expected_scope"));
        options.clientIp = stringOrEmpty(verifyOpts.get("client_ip"));
        config.expectedIssuer = stringOrEmpty(verifyOpts.get("expected_issuer"));
        if (verifyOpts.containsKey("expected_policy_version")) {
            config.expectedPolicyVersion = ((JsonNumber) verifyOpts.get("expected_policy_version")).intValue();
        }
        if (verifyOpts.containsKey("expected_request_binding")) {
            options.bindingExpectation = Verifier.RequestBindingExpectation.exact(
                    String.valueOf(verifyOpts.get("expected_request_binding")));
        }
        if (verifyOpts.containsKey("now_ns")) {
            options.nowNs = ((JsonNumber) verifyOpts.get("now_ns")).longValue();
            options.nowNsSet = true;
        }
        if (verifyOpts.containsKey("region")) {
            config.region = String.valueOf(verifyOpts.get("region"));
        }
        if (verifyOpts.containsKey("secrets_by_kid")) {
            Map<String, Object> secrets = (Map<String, Object>) verifyOpts.get("secrets_by_kid");
            java.util.Map<Integer, String> byKid = new java.util.HashMap<>();
            for (Map.Entry<String, Object> kid : secrets.entrySet()) {
                byKid.put(Integer.parseInt(kid.getKey()), String.valueOf(kid.getValue()));
            }
            config.secretsByKid = byKid;
        }
        if (verifyOpts.containsKey("rsw")) {
            Map<String, Object> rsw = (Map<String, Object>) verifyOpts.get("rsw");
            config.rswModulusN = String.valueOf(rsw.get("modulus_n"));
            config.rswLambda = String.valueOf(rsw.get("lambda"));
        }
        return new VerifyCall(config, options);
    }

    private static String stringOrEmpty(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    @Test
    void everyGoldenVectorResolvesToItsPinnedVerdict() {
        Map<String, Object> golden = Support.goldenVectors();
        @SuppressWarnings("unchecked")
        List<Object> records = (List<Object>) golden.get("records");
        for (Object item : records) {
            @SuppressWarnings("unchecked")
            Map<String, Object> entry = (Map<String, Object>) item;
            String name = String.valueOf(entry.get("name"));
            ChallengeRecord record = ChallengeRecord.fromMap(recordMap(entry));
            VerifyCall call = verifyCall(entry);
            // The php issuance ran live, so the verdict clock pins to
            // the record's own issuance second: deterministic replay.
            call.config().nowSecs = () -> record.issuedAt;
            Verifier verifier = new Verifier(new MemoryStore(() -> record.issuedAt), call.config());
            Support.storeRecord(verifier.storage(), record);
            VerifyOutcome outcome = verifier.verify(String.valueOf(entry.get("token_b64")), call.options());
            @SuppressWarnings("unchecked")
            Map<String, Object> expected = (Map<String, Object>) entry.get("expected");
            boolean expectedOk = Boolean.TRUE.equals(expected.get("ok"));
            if (expectedOk) {
                assertTrue(outcome.valid, name + ": expected ok, got " + outcome.code());
                if (expected.containsKey("decoyField")) {
                    assertEquals(String.valueOf(expected.get("decoyField")), outcome.decoyField, name);
                }
            } else {
                assertEquals(String.valueOf(expected.get("code")), outcome.code(), name);
            }
        }
    }

    @Test
    void provenanceNamesThePhpIssuer() {
        Map<String, Object> golden = Support.goldenVectors();
        @SuppressWarnings("unchecked")
        Map<String, Object> provenance = (Map<String, Object>) golden.get("provenance");
        assertTrue(String.valueOf(provenance.get("issuer")).contains("php Issuer"));
        assertTrue(provenance.containsKey("generator"));
        assertEquals(Support.TEST_SECRET, String.valueOf(provenance.get("secret")));
    }

    @Test
    void shaPlainGoldenReplaysAsAlreadyConsumed() {
        Map<String, Object> entry = goldenEntry("sha_plain");
        ChallengeRecord record = ChallengeRecord.fromMap(recordMap(entry));
        Verifier.Config config = new Verifier.Config();
        config.nowSecs = () -> record.issuedAt;
        Verifier verifier = new Verifier(new MemoryStore(() -> record.issuedAt), config);
        Support.storeRecord(verifier.storage(), record);
        String token = String.valueOf(entry.get("token_b64"));
        Verifier.Options options = new Verifier.Options();
        options.secretKey = Support.TEST_SECRET;
        options.expectedScope = "login";
        options.nowNs = record.issuedAtNs + 3_000_000;
        options.nowNsSet = true;
        Support.requireValid(verifier.verify(token, options));
        Support.requireCode(verifier.verify(token, options), VerifyError.ALREADY_CONSUMED);
    }

    @Test
    void argon2idGoldenCarriesAVerifyingProof() {
        Map<String, Object> entry = goldenEntry("argon2id");
        ChallengeRecord record = ChallengeRecord.fromMap(recordMap(entry));
        SolutionToken token = SolutionToken.decode(String.valueOf(entry.get("token_b64")));
        // The committed token solves the record: the SDK's own argon2id
        // recompute accepts it inside the verifier.
        Verifier.Config config = new Verifier.Config();
        config.nowSecs = () -> record.issuedAt;
        Verifier verifier = new Verifier(new MemoryStore(() -> record.issuedAt), config);
        Support.storeRecord(verifier.storage(), record);
        Verifier.Options options = new Verifier.Options();
        options.secretKey = Support.TEST_SECRET;
        options.expectedScope = "login";
        Support.requireValid(verifier.verify(token.encode(), options));
    }

    @Test
    void goldenDirectoryIsSelfContained() {
        Path golden = Support.testdataPath("golden/golden-php-vectors.json");
        assertNotNull(golden, "the golden vectors must be committed beside the suites");
        assertTrue(golden.toFile().length() > 1000);
    }

    private static Map<String, Object> goldenEntry(String name) {
        Map<String, Object> golden = Support.goldenVectors();
        @SuppressWarnings("unchecked")
        List<Object> records = (List<Object>) golden.get("records");
        for (Object item : records) {
            @SuppressWarnings("unchecked")
            Map<String, Object> entry = (Map<String, Object>) item;
            if (name.equals(String.valueOf(entry.get("name")))) {
                return entry;
            }
        }
        throw new AssertionError("missing golden entry " + name);
    }
}
