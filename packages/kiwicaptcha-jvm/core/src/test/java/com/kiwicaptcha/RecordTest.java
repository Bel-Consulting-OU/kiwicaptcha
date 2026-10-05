package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The strict record parser, the canonical schema and the grammar matrix. */
class RecordTest {

    @Test
    void parserRoundTripsTheWireSchema() {
        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        ChallengeRecord parsed = ChallengeRecord.parse(record.marshalJson().getBytes(StandardCharsets.UTF_8));
        assertEquals(record.nonce, parsed.nonce);
        assertEquals(record.scope, parsed.scope);
        assertEquals(record.bindingTag, parsed.bindingTag);
        assertEquals(record.issuedAt, parsed.issuedAt);
        assertEquals(record.expiresAt, parsed.expiresAt);
        assertEquals(record.mKib, parsed.mKib);
        assertEquals(record.protocolVersion, parsed.protocolVersion);
        assertEquals(record.policyVersionOrOne(), parsed.policyVersionOrOne());
        assertEquals(record.kidOrOne(), parsed.kidOrOne());
        assertEquals(record.marshalJson(), parsed.marshalJson());
    }

    @Test
    void extensionKeysOmitWhenUnset() {
        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        String json = record.marshalJson();
        assertFalse(json.contains("decoy_field"));
        assertFalse(json.contains("execution_program"));
        assertFalse(json.contains("rsw_modulus_sha256"));
        assertFalse(json.contains("server_mac"));
        // The nullable schema keys always render.
        assertTrue(json.contains("\"region\":null"));
        assertTrue(json.contains("\"attempts_used\":0"));
    }

    @Test
    void legacyIpHashAliasAcceptedAlone() {
        Map<String, Object> data = Support.mintRecord(new Support.MintOptions()).toWireMap();
        data.remove("binding_tag");
        data.put("ip_hash", "tag");
        ChallengeRecord parsed = ChallengeRecord.fromMap(data);
        assertEquals("tag", parsed.bindingTag);
    }

    @Test
    void ipHashBesideBindingTagRefused() {
        Map<String, Object> data = Support.mintRecord(new Support.MintOptions()).toWireMap();
        data.put("ip_hash", "tag");
        assertThrows(ChallengeRecord.MalformedRecordException.class, () -> ChallengeRecord.fromMap(data));
    }

    @Test
    void unknownKeyRefused() {
        Map<String, Object> data = Support.mintRecord(new Support.MintOptions()).toWireMap();
        data.put("foreign", 1);
        assertThrows(ChallengeRecord.MalformedRecordException.class, () -> ChallengeRecord.fromMap(data));
    }

    @Test
    void missingRequiredKeyRefused() {
        Map<String, Object> data = Support.mintRecord(new Support.MintOptions()).toWireMap();
        data.remove("nonce");
        assertThrows(ChallengeRecord.MalformedRecordException.class, () -> ChallengeRecord.fromMap(data));
    }

    @Test
    void duplicateJsonKeysRefused() {
        String record = Support.mintRecord(new Support.MintOptions()).marshalJson();
        String duplicated = record.replace("\"nonce\":", "\"scope\":");
        assertThrows(RuntimeException.class,
                () -> ChallengeRecord.parse(duplicated.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void trailingBytesRefused() {
        String record = Support.mintRecord(new Support.MintOptions()).marshalJson() + "x";
        assertThrows(RuntimeException.class,
                () -> ChallengeRecord.parse(record.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void invalidAlgorithmRefused() {
        Map<String, Object> data = Support.mintRecord(new Support.MintOptions()).toWireMap();
        data.put("algorithm", "scrypt");
        assertThrows(ChallengeRecord.MalformedRecordException.class, () -> ChallengeRecord.fromMap(data));
    }

    @Test
    void ttlCeilingRefused() {
        Support.MintOptions options = new Support.MintOptions();
        options.ttl = Kiwi.MAX_TTL_SECS + 1;
        ChallengeRecord record = Support.mintRecord(options);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        assertFalse(verifier.validateRecord(record));
    }

    @Test
    void difficultyRangeRefused() {
        Support.MintOptions options = new Support.MintOptions();
        options.targetBits = Kiwi.MAX_DIFFICULTY + 1;
        ChallengeRecord record = Support.mintRecord(options);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        assertFalse(verifier.validateRecord(record));
    }

    @Test
    void protocolGrammarMatrix() {
        assertTrue(ChallengeRecord.protocolExtensionGrammarOk(1, false, false, false));
        assertFalse(ChallengeRecord.protocolExtensionGrammarOk(1, true, false, false));
        assertTrue(ChallengeRecord.protocolExtensionGrammarOk(2, false, false, false));
        assertFalse(ChallengeRecord.protocolExtensionGrammarOk(2, true, false, false));
        assertTrue(ChallengeRecord.protocolExtensionGrammarOk(3, true, false, false));
        assertFalse(ChallengeRecord.protocolExtensionGrammarOk(3, false, false, false));
        assertTrue(ChallengeRecord.protocolExtensionGrammarOk(4, false, true, false));
        assertTrue(ChallengeRecord.protocolExtensionGrammarOk(4, true, true, false));
        assertFalse(ChallengeRecord.protocolExtensionGrammarOk(4, false, false, false));
        assertTrue(ChallengeRecord.protocolExtensionGrammarOk(5, false, false, true));
        assertFalse(ChallengeRecord.protocolExtensionGrammarOk(5, false, false, false));
        assertFalse(ChallengeRecord.protocolExtensionGrammarOk(6, false, false, false));
    }

    @Test
    void partialExecutionTripletRefused() {
        Support.MintOptions options = new Support.MintOptions();
        options.executionProgram = Support.minimalProgramB64("login", "submit");
        ChallengeRecord record = Support.mintRecord(options);
        Map<String, Object> data = record.toWireMap();
        data.remove("execution_commitment");
        assertThrows(ChallengeRecord.MalformedRecordException.class, () -> ChallengeRecord.fromMap(data));
    }

    @Test
    void executionCommitmentMismatchRefused() {
        Support.MintOptions options = new Support.MintOptions();
        options.executionProgram = Support.minimalProgramB64("login", "submit");
        ChallengeRecord record = Support.mintRecord(options);
        Map<String, Object> data = record.toWireMap();
        data.put("execution_commitment", "aa".repeat(32));
        assertThrows(ChallengeRecord.MalformedRecordException.class, () -> ChallengeRecord.fromMap(data));
    }

    @Test
    void identifierAlphabets() {
        assertTrue(ChallengeRecord.isValidIdentifier("login.v2-x_y:z", 128));
        assertFalse(ChallengeRecord.isValidIdentifier("", 128));
        assertFalse(ChallengeRecord.isValidIdentifier("space out", 128));
        assertFalse(ChallengeRecord.isValidIdentifier("a".repeat(129), 128));
        assertTrue(ChallengeRecord.isValidDecoyFieldName("office_contact_email_2d128c0075ba08fd"));
        assertFalse(ChallengeRecord.isValidDecoyFieldName("bad.dot"));
        assertFalse(ChallengeRecord.isValidDecoyFieldName("bad colon:"));
    }

    @Test
    void rswIdentityRules() {
        Map<String, Object> data = Support.mintRecord(new Support.MintOptions()).toWireMap();
        data.put("rsw_modulus_sha256", "ab".repeat(32));
        data.put("algorithm", "sha256");
        assertThrows(ChallengeRecord.MalformedRecordException.class, () -> ChallengeRecord.fromMap(data));
    }

    @Test
    void largeIssuedAtNsSurvivesTheRoundTrip() {
        Support.MintOptions options = new Support.MintOptions();
        options.mintMetaMac = true;
        ChallengeRecord record = Support.mintRecord(options);
        ChallengeRecord parsed = ChallengeRecord.parse(record.marshalJson().getBytes(StandardCharsets.UTF_8));
        assertEquals(record.issuedAtNs, parsed.issuedAtNs);
        // Scientific notation would break the strict parser; the wire
        // spelling is decimal.
        assertFalse(record.marshalJson().contains("e15"));
        assertTrue(record.marshalJson().contains("\"issued_at_ns\":" + record.issuedAtNs));
    }

    @Test
    void wireEnvelopeOrderIsCanonical() {
        Support.MintOptions options = new Support.MintOptions();
        ChallengeRecord record = Support.mintRecord(options);
        var envelope = record.toWireMap();
        envelope.put("state", "pending");
        envelope.put("consumed_result", null);
        envelope.put("operation_identity", null);
        String encoded = WireJson.encodeEnvelope(envelope);
        String expectedStart = "{\"nonce\":\"" + record.nonce + "\",\"scope\":\"login\"";
        assertTrue(encoded.startsWith(expectedStart));
        assertTrue(encoded.endsWith(",\"state\":\"pending\",\"consumed_result\":null,\"operation_identity\":null}"));
        // The stored-envelope decoder strips the runtime markers
        // before the strict record parser sees the document.
        ChallengeRecord reparsed = ChallengeRecord.parse(stripRuntimeMarkers(encoded).getBytes(StandardCharsets.UTF_8));
        assertEquals(record.nonce, reparsed.nonce);
    }

    private static String stripRuntimeMarkers(String envelope) {
        int recordEnd = envelope.lastIndexOf(",\"state\"");
        return envelope.substring(0, recordEnd) + "}";
    }

    @Test
    void foreignEnvelopeKeyRefused() {
        Support.MintOptions options = new Support.MintOptions();
        ChallengeRecord record = Support.mintRecord(options);
        var envelope = record.toWireMap();
        envelope.put("foreign_key", 1);
        assertThrows(RuntimeException.class, () -> WireJson.encodeEnvelope(envelope));
    }

    @Test
    void operationIdentityRules() {
        assertEquals("", Store.validateOperationIdentity(""));
        assertEquals("op-1", Store.validateOperationIdentity("op-1"));
        assertThrows(Store.OperationIdentityException.class, () -> Store.validateOperationIdentity("op 1"));
        assertThrows(Store.OperationIdentityException.class,
                () -> Store.validateOperationIdentity("a".repeat(129)));
    }

    @Test
    void canonicalIpFamilies() {
        byte[] v4 = Canonical.canonicalIpFamily("203.0.113.7");
        assertEquals(0x04, v4[0]);
        assertEquals(5, v4.length);
        byte[] v6 = Canonical.canonicalIpFamily("2001:db8::1");
        assertEquals(0x06, v6[0]);
        assertEquals(17, v6.length);
        // Mapped folds to the four byte form.
        byte[] mapped = Canonical.canonicalIpFamily("::ffff:203.0.113.7");
        assertArrayEquals(v4, mapped);
        byte[] dotted = Canonical.canonicalIpFamily("203.0.113.7");
        assertArrayEquals(dotted, mapped);
        // IPv4-compatible folds too, except the unspecified and loopback.
        assertArrayEquals(v4, Canonical.canonicalIpFamily("::203.0.113.7"));
        assertEquals(0x06, Canonical.canonicalIpFamily("::1")[0]);
        assertEquals(0x06, Canonical.canonicalIpFamily("::")[0]);
        assertThrows(Canonical.InvalidIpException.class, () -> Canonical.canonicalIpFamily("example.com"));
        assertThrows(Canonical.InvalidIpException.class, () -> Canonical.canonicalIpFamily("fe80::1%eth0"));
        assertThrows(Canonical.InvalidIpException.class, () -> Canonical.canonicalIpFamily("999.1.1.1"));
        assertThrows(Canonical.InvalidIpException.class, () -> Canonical.canonicalIpFamily("010.1.1.1"));
        assertThrows(Canonical.InvalidIpException.class, () -> Canonical.canonicalIpFamily("1:2:3"));
    }

    private static void assertArrayEquals(byte[] expected, byte[] actual) {
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    void legacyV1SignatureAndIpHash() {
        String payload = Canonical.legacyV1Payload("nonce", "scope", "tag", 111);
        String signature = Canonical.signPayloadV1(payload, Support.TEST_SECRET);
        assertEquals(Support.sha256Hex(Support.TEST_SECRET + "203.0.113.7"), Support.TEST_IP_HASH);
        ChallengeRecord record = new ChallengeRecord();
        record.protocolVersion = 1;
        record.nonce = "nonce";
        record.scope = "scope";
        record.bindingTag = "tag";
        record.issuedAt = 111;
        record.expiresAt = 231;
        record.algorithm = "sha256";
        record.salt = Base64.getEncoder().encodeToString(new byte[16]);
        record.challenge = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + "." + signature;
        record.prefix = record.challenge + "|" + record.salt + "|";
        record.targetBits = 1;
        assertTrue(Canonical.verifyRecordSignature(record, Support.TEST_SECRET, ""));
        assertFalse(Canonical.verifyRecordSignature(record, "other-secret-other-secret-other-3", ""));
    }
}
