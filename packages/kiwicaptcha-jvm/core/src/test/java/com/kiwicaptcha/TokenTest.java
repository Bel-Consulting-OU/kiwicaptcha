package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** The solution token wire grammar and its round trips. */
class TokenTest {

    @Test
    void unarmedTokenRoundTrips() {
        SolutionToken token = SolutionToken.create(
                "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=", 158, 5000,
                JsonObject.of("wd", false, "me", new JsonNumber("3")), "", "", "");
        String encoded = token.encode();
        SolutionToken decoded = SolutionToken.decode(encoded);
        assertEquals(token.nonce, decoded.nonce);
        assertEquals(token.counter, decoded.counter);
        assertEquals(token.durationMs, decoded.durationMs);
        assertEquals(encoded, decoded.encode());
        assertEquals("{\"wd\":false,\"me\":3}", decoded.telemetry.encode());
    }

    @Test
    void armedTokenPeelsRightToLeft() {
        String digest = "ab".repeat(32);
        String trace = "dGVzdA";
        SolutionToken token = SolutionToken.create("2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
                1, 10, JsonObject.of("me", new JsonNumber("1")), digest, trace, "ff".repeat(256));
        SolutionToken decoded = SolutionToken.decode(token.encode());
        assertEquals(digest, decoded.executionDigest);
        assertEquals(trace, decoded.executionTrace);
        assertEquals("ff".repeat(256), decoded.rswProof);
        assertEquals(token.encode(), decoded.encode());
    }

    @Test
    void executionDigestOnlyPeels() {
        String digest = "ab".repeat(32);
        SolutionToken token = SolutionToken.create("2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
                1, 10, JsonObject.of("me", new JsonNumber("1")), digest, "", "");
        SolutionToken decoded = SolutionToken.decode(token.encode());
        assertEquals(digest, decoded.executionDigest);
        assertEquals("", decoded.executionTrace);
        assertEquals(token.encode(), decoded.encode());
    }

    @Test
    void rswProofPeelsBeforeExecution() {
        String digest = "ab".repeat(32);
        SolutionToken token = SolutionToken.create("2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
                0, 10, JsonObject.of("me", new JsonNumber("1")), digest, "", "cc".repeat(256));
        SolutionToken decoded = SolutionToken.decode(token.encode());
        assertEquals(digest, decoded.executionDigest);
        assertEquals("cc".repeat(256), decoded.rswProof);
    }

    @Test
    void telemetryWithDotsSurvivesTheSplit() {
        SolutionToken token = SolutionToken.create("2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
                1, 10, JsonObject.of("a.b", "c.d", "e", new JsonNumber("2")), "", "", "");
        SolutionToken decoded = SolutionToken.decode(token.encode());
        assertEquals("c.d", decoded.telemetry.get("a.b"));
        assertEquals(token.encode(), decoded.encode());
    }

    @Test
    void canonicalDecimalRules() {
        assertEquals(-1L, SolutionToken.canonicalDecimal(""));
        assertEquals(-1L, SolutionToken.canonicalDecimal("01"));
        assertEquals(-1L, SolutionToken.canonicalDecimal("1a"));
        assertEquals(0L, SolutionToken.canonicalDecimal("0"));
        assertEquals(158L, SolutionToken.canonicalDecimal("158"));
    }

    @Test
    void decodeErrorCodes() {
        assertEquals(SolutionToken.DECODE_ERR_INVALID_BASE64, decodeReason("not-a-token"));
        assertEquals(SolutionToken.DECODE_ERR_INVALID_BASE64, decodeReason("bm90LWEtdG9rZW4"));
        // Canonical base64 of a three-segment plain text is malformed.
        assertEquals(SolutionToken.DECODE_ERR_MALFORMED, decodeReason("YS5iLmM="));
        // A nonce of the wrong length is malformed.
        assertEquals(SolutionToken.DECODE_ERR_MALFORMED, decodeReason(
                SolutionToken.create("short", 1, 1, new JsonObject(), "", "", "").encode()));
        // A leading-zero counter is an invalid counter.
        String leadingZero = java.util.Base64.getEncoder().encodeToString(
                "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=.01.1.{}".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8));
        assertEquals(SolutionToken.DECODE_ERR_INVALID_COUNTER, decodeReason(leadingZero));
        // A counter at the solver ceiling exceeds the count cap.
        assertEquals(SolutionToken.DECODE_ERR_INVALID_COUNT, decodeReason(
                SolutionToken.create("2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
                        Kiwi.MAX_SOLVER_COUNTER, 1, new JsonObject(), "", "", "").encode()));
        // A duration beyond the cap is invalid.
        assertEquals(SolutionToken.DECODE_ERR_INVALID_DUR, decodeReason(
                SolutionToken.create("2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
                        1, Kiwi.MAX_DURATION_MS + 1, new JsonObject(), "", "", "").encode()));
        // An array telemetry payload fails closed.
        String arrayTelemetry = java.util.Base64.getEncoder().encodeToString(
                "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=.1.1.[1,2]".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8));
        assertEquals(SolutionToken.DECODE_ERR_MALFORMED, decodeReason(arrayTelemetry));
    }

    private static String decodeReason(String raw) {
        try {
            SolutionToken.decode(raw);
        } catch (SolutionToken.DecodeException e) {
            return e.code;
        }
        throw new AssertionError("expected a decode failure for " + raw);
    }

    @Test
    void arrayTelemetryNeverDecodes() {
        String plain = "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=.1.1.[]";
        String encoded = java.util.Base64.getEncoder().encodeToString(plain.getBytes());
        assertThrows(SolutionToken.DecodeException.class, () -> SolutionToken.decode(encoded));
    }

    @Test
    void oversizedTokenRefused() {
        String raw = "a".repeat(Kiwi.MAX_TOKEN_BYTES + 1);
        assertThrows(SolutionToken.DecodeException.class, () -> SolutionToken.decode(raw));
    }

    @Test
    void executionTraceMustBeCanonicalBase64Url() {
        String digest = "ab".repeat(32);
        String badTrace = "dGVzdA==";
        String plain = "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=.1.1.{\"me\":1}."
                + digest + ":" + badTrace;
        String encoded = java.util.Base64.getEncoder().encodeToString(plain.getBytes());
        assertThrows(SolutionToken.DecodeException.class, () -> SolutionToken.decode(encoded));
    }

    @Test
    void tokenFixtureAcceptedAndRejected() {
        Path fixture = Support.protocolPathOrSkip("solution-token-v1/fixtures.json");
        Map<String, Object> document = StrictJsonMap(fixture);
        Map<?, ?> accepted = (Map<?, ?>) document.get("accepted");
        for (Map.Entry<?, ?> entry : accepted.entrySet()) {
            SolutionToken token = SolutionToken.decode(String.valueOf(entry.getValue()));
            assertEquals(String.valueOf(entry.getValue()), token.encode(), "accepted " + entry.getKey());
        }
        Map<?, ?> rejected = (Map<?, ?>) document.get("rejected");
        for (Map.Entry<?, ?> entry : rejected.entrySet()) {
            final String raw = String.valueOf(entry.getValue());
            assertThrows(SolutionToken.DecodeException.class, () -> SolutionToken.decode(raw),
                    "rejected " + entry.getKey());
        }
        Map<?, ?> cross = (Map<?, ?>) document.get("cross_language");
        SolutionToken token = SolutionToken.decode(String.valueOf(cross.get("encoded")));
        assertEquals(String.valueOf(cross.get("encoded")), token.encode());
    }

    @Test
    void telemetryPreservesKeyOrderAndNumberSpelling() {
        JsonObject telemetry = JsonObject.parseObject("{\"b\":2,\"a\":1.50,\"c\":[1,2]}");
        assertEquals(List.of("b", "a", "c"), telemetry.keys());
        assertEquals("{\"b\":2,\"a\":1.50,\"c\":[1,2]}", telemetry.encode());
    }

    @Test
    void duplicateTelemetryKeysKeepFirstPositionLastValue() {
        JsonObject telemetry = JsonObject.parseObject("{\"a\":1,\"b\":2,\"a\":3}");
        assertEquals(List.of("a", "b"), telemetry.keys());
        assertEquals("3", ((JsonNumber) telemetry.get("a")).raw);
    }

    @Test
    void trailingBytesAfterTelemetryRefused() {
        assertThrows(RuntimeException.class, () -> JsonObject.parseObject("{} {}"));
        assertThrows(RuntimeException.class, () -> JsonObject.parseObject("[1]"));
        assertThrows(RuntimeException.class, () -> JsonObject.parseObject("{\"a\":}"));
    }

    private static Map<String, Object> StrictJsonMap(Path fixture) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> document = (Map<String, Object>) StrictJson.decode(
                    java.nio.file.Files.readAllBytes(fixture));
            return document;
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
