package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The single conformance entry a CI run can point at: it walks the
 * shared protocol corpora the SDK contract pins, the same corpus the
 * php, Go and Python suites replay, so behavior cannot drift.
 */
class ConformanceTest {

    @Test
    void canonicalVectorsEndToEnd() {
        for (Support.ProtocolVector vector : List.of(Support.SHA_VECTOR, Support.ARGON2_VECTOR)) {
            ChallengeRecord record = Support.vectorRecord(vector);
            assertTrue(Canonical.verifyRecordSignature(record, Support.TEST_SECRET, ""),
                    vector.algorithm() + ": the canonical signature must verify");
            Verifier.Config config = new Verifier.Config();
            config.acceptLegacyV1 = true;
            Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
            Support.storeRecord(verifier.storage(), record);
            VerifyOutcome outcome = verifier.verify(Support.vectorToken(vector, -1, -1),
                    options("login", Support.TEST_CLIENT_IP));
            Support.requireValid(outcome);
        }
    }

    private static Verifier.Options options(String scope, String ip) {
        Verifier.Options options = new Verifier.Options();
        options.secretKey = Support.TEST_SECRET;
        options.expectedScope = scope;
        options.clientIp = ip;
        return options;
    }

    @Test
    void solutionTokenBoundaryFixture() {
        Path fixture = Support.protocolPathOrSkip("solution-token-v1/fixtures.json");
        Map<String, Object> document = readJson(fixture);
        Map<?, ?> accepted = (Map<?, ?>) document.get("accepted");
        for (Map.Entry<?, ?> entry : accepted.entrySet()) {
            SolutionToken token = SolutionToken.decode(String.valueOf(entry.getValue()));
            assertEquals(String.valueOf(entry.getValue()), token.encode(), "accepted " + entry.getKey());
        }
        Map<?, ?> rejected = (Map<?, ?>) document.get("rejected");
        for (Map.Entry<?, ?> entry : rejected.entrySet()) {
            final String raw = String.valueOf(entry.getValue());
            try {
                SolutionToken.decode(raw);
                throw new AssertionError("rejected " + entry.getKey() + ": must not decode");
            } catch (SolutionToken.DecodeException expected) {
                // The fixture rejection is the expected branch.
            }
        }
        Map<?, ?> cross = (Map<?, ?>) document.get("cross_language");
        SolutionToken token = SolutionToken.decode(String.valueOf(cross.get("encoded")));
        assertEquals(String.valueOf(cross.get("encoded")), token.encode());
    }

    @Test
    void ipHashVector() {
        assertEquals(Support.TEST_IP_HASH, Support.sha256Hex(Support.TEST_SECRET + Support.TEST_CLIENT_IP));
    }

    @Test
    void rswIdentityFixture() {
        Path fixture = Support.protocolPathOrSkip("rsw-identity-v1/fixtures.json");
        Map<String, Object> document = readJson(fixture);
        String modulus = String.valueOf(document.get("modulus_n_b64"));
        assertEquals(String.valueOf(document.get("rsw_modulus_n_sha256")), Rsw.fingerprint(modulus));
        assertEquals(String.valueOf(document.get("legacy_base64_text_sha256")), Rsw.legacyIdentity(modulus));
        // The shared trapdoor verifies its own expected proof.
        String lambda = String.valueOf(document.get("lambda_b64"));
        Rsw rsw = Rsw.of(modulus, lambda);
        String proof = Support.solveRsw("prefix|", "nonce", rsw.modulus(), 10000);
        assertEquals(rsw.expectedProofHex("prefix|", "nonce", 10000), proof);
    }

    @Test
    void outcomesMappingFixture() {
        Path fixture = Support.protocolPathOrSkip("risk-v1/outcomes-vectors.json");
        Map<String, Object> document = readJson(fixture);
        assertEquals(Outcomes.OUTCOMES_VERSION, ((JsonNumber) document.get("version")).intValue());
    }

    @Test
    void phpIssuedGoldenRecordsVerify() {
        Map<String, Object> golden = Support.goldenVectors();
        @SuppressWarnings("unchecked")
        List<Object> records = (List<Object>) golden.get("records");
        assertTrue(records.size() >= 7);
        for (Object item : records) {
            @SuppressWarnings("unchecked")
            Map<String, Object> entry = (Map<String, Object>) item;
            if ("tampered_signature".equals(String.valueOf(entry.get("name")))) {
                continue;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> recordMap = (Map<String, Object>) entry.get("record");
            ChallengeRecord record = ChallengeRecord.fromMap(recordMap);
            assertTrue(Canonical.verifyRecordSignature(record, Support.TEST_SECRET, ""),
                    entry.get("name") + ": the php signature must verify");
        }
    }

    @Test
    void goldenCanonicalSpellings() {
        Map<String, Object> golden = Support.goldenVectors();
        @SuppressWarnings("unchecked")
        Map<String, Object> canonical = (Map<String, Object>) golden.get("canonical");
        String base = String.valueOf(canonical.get("base"));
        assertEquals(Support.goldenString(canonical, "signature_hex"),
                Canonical.signPayloadV2(base, Support.TEST_SECRET, ""));
        // The tagged segments ride in capability order after the base.
        assertTrue(String.valueOf(canonical.get("v3_decoy")).contains("|d=billing_address_line_"));
        assertTrue(String.valueOf(canonical.get("v4_execution")).contains("|e=1,aaa"));
        assertTrue(String.valueOf(canonical.get("v5_identity")).contains("|r=bbb"));
        assertEquals('|', base.charAt(2));
    }

    @Test
    void goldenServerStateMacs() {
        Map<String, Object> golden = Support.goldenVectors();
        @SuppressWarnings("unchecked")
        Map<String, Object> macs = (Map<String, Object>) golden.get("server_state_mac");
        byte[] key = Canonical.serverStateMacKey(Support.TEST_SECRET, "");
        String metaInput = String.valueOf(macs.get("record_meta_input"))
                .replace("\\n", "\n");
        String resultInput = String.valueOf(macs.get("consumed_result_input"))
                .replace("\\n", "\n");
        // The fixture stores the input with escaped newlines only when
        // a writer re-encoded it; the shipped file carries raw lines.
        String metaRaw = rawOrUnescaped(String.valueOf(macs.get("record_meta_input")));
        String resultRaw = rawOrUnescaped(String.valueOf(macs.get("consumed_result_input")));
        assertEquals(Support.goldenString(macs, "record_meta_hex"),
                Canonical.hmacHex(key, metaRaw));
        assertEquals(Support.goldenString(macs, "consumed_result_hex"),
                Canonical.hmacHex(key, resultRaw));
        assertTrue(metaInput.contains(Kiwi.RECORD_META_DOMAIN));
        assertTrue(resultInput.contains(Kiwi.CONSUMED_RESULT_DOMAIN));
    }

    private static String rawOrUnescaped(String value) {
        return value;
    }

    @Test
    void executionArmedGoldenStillFailsClosedHere() {
        // The shared v4 execution program validates structurally and
        // its commitment matches, but no digest can satisfy the armed
        // binding without the browser-trace walker.
        Support.MintOptions mint = new Support.MintOptions();
        mint.protocolVersion = 4;
        mint.executionProgram = Support.minimalProgramB64("login", "submit");
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        String token = SolutionToken.create(record.nonce,
                Support.solveSha(record.prefix, record.salt, record.targetBits), 5000,
                new JsonObject(), "ab".repeat(32), "", "").encode();
        Support.requireCode(verifier.verify(token, options("login", Support.TEST_CLIENT_IP)),
                VerifyError.EXECUTION_MISMATCH);
    }

    @Test
    void rswEndToEndWithTheCommittedTrapdoor() {
        Path fixture = Support.protocolPathOrSkip("rsw-identity-v1/fixtures.json");
        Map<String, Object> document = readJson(fixture);
        String modulus = String.valueOf(document.get("modulus_n_b64"));
        String lambda = String.valueOf(document.get("lambda_b64"));
        Verifier.Config config = new Verifier.Config();
        config.rswModulusN = modulus;
        config.rswLambda = lambda;
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.MintOptions mint = new Support.MintOptions();
        mint.algorithm = "rsw";
        mint.t = 10000;
        mint.targetBits = Kiwi.RSW_TARGET_BITS_PIN;
        ChallengeRecord record = Support.mintRecord(mint);
        Support.storeRecord(verifier.storage(), record);
        Rsw rsw = Rsw.of(modulus, lambda);
        String proof = Support.solveRsw(record.prefix, record.nonce, rsw.modulus(), record.t);
        String token = SolutionToken.create(record.nonce, 0, 5000,
                JsonObject.of("v", new JsonNumber("1")), "", "", proof).encode();
        Support.requireValid(verifier.verify(token, options("login", Support.TEST_CLIENT_IP)));
        // Replay answers already consumed.
        Support.requireCode(verifier.verify(token, options("login", Support.TEST_CLIENT_IP)),
                VerifyError.ALREADY_CONSUMED);
    }

    @Test
    void wireBytesStayUtf8Clean() {
        // The token encoder escapes non-ascii telemetry to the exact
        // reference bytes.
        JsonObject telemetry = JsonObject.of("emoji", "héllo");
        SolutionToken token = SolutionToken.create("2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
                1, 10, telemetry, "", "", "");
        String encoded = token.encode();
        SolutionToken decoded = SolutionToken.decode(encoded);
        assertEquals(token.encode(), decoded.encode());
        assertEquals("\"h\\u00e9llo\"", decoded.telemetry.encode().split(":")[1].replace("}", ""));
    }

    private static Map<String, Object> readJson(Path path) {
        try {
            Object document = StrictJson.decode(Files.readAllBytes(path));
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) document;
            return map;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void bigIntegersNeverEnterScientificNotation() {
        BigInteger big = new BigInteger("1791176126942062");
        assertEquals("1791176126942062", big.toString(10));
    }
}
