package com.kiwicaptcha;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * The shared hostile wire corpus against the JVM decoder.
 *
 * <p>The fixture is expanded by the PHP generator and read byte-for-byte by every
 * hosted SDK suite; the expected verdicts are the reference decoder's.
 */
final class WireHostileCorpusTest {
    private static JsonObject corpus() throws Exception {
        try (InputStream stream =
                WireHostileCorpusTest.class.getResourceAsStream("/wire-hostile-corpus.json")) {
            assertNotNull(stream, "the wire corpus fixture must exist");
            return JsonObject.parseObject(new String(stream.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    private static String classify(String code) {
        return switch (code) {
            case SolutionToken.DECODE_ERR_INVALID_BASE64 -> "base64";
            case SolutionToken.DECODE_ERR_INVALID_UTF8 -> "utf8";
            case SolutionToken.DECODE_ERR_INVALID_COUNTER,
                    SolutionToken.DECODE_ERR_INVALID_COUNT -> "counter";
            case SolutionToken.DECODE_ERR_INVALID_DUR -> "duration";
            default -> "malformed";
        };
    }

    private static String optional(Object value) {
        return value == null ? "" : (String) value;
    }

    @Test
    void oversizedCounterSpellingIsACeilingRejection() {
        // The ceiling rejection outranks a native long overflow: a nine
        // or more digit spelling is a solver-ceiling failure, never a
        // syntax failure.
        String nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        for (String counter : new String[] {
            "9223372036854775808", "18446744073709551616", "9".repeat(100)
        }) {
            String raw = java.util.Base64.getEncoder().encodeToString(
                    (nonce + "." + counter + ".2.{}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            SolutionToken.DecodeException error = assertThrows(
                    SolutionToken.DecodeException.class, () -> SolutionToken.decode(raw));
            assertEquals(SolutionToken.DECODE_ERR_INVALID_COUNT, error.code, counter);
        }
    }

    @TestFactory
    Stream<DynamicTest> everyCorpusRowHasTheReferenceVerdict() throws Exception {
        JsonObject document = corpus();
        JsonObject counts = (JsonObject) document.get("counts");
        assertTrue(((JsonNumber) counts.get("total")).intValue() >= 100, "the corpus must stay broad");

        @SuppressWarnings("unchecked")
        List<Object> rows = (List<Object>) document.get("vectors");
        return rows.stream().map(Object.class::cast).map(rowValue -> {
            JsonObject row = (JsonObject) rowValue;
            String id = (String) row.get("id");
            return DynamicTest.dynamicTest(id, () -> verifyRow(id, row));
        });
    }

    private void verifyRow(String id, JsonObject row) {
        String raw = (String) row.get("raw");
        JsonObject expected = (JsonObject) row.get("expect");
        String verdict = (String) expected.get("verdict");

        if ("accept".equals(verdict)) {
            SolutionToken token = SolutionToken.decode(raw);
            assertEquals(
                    ((JsonNumber) expected.get("counter")).longValue(), token.counter, id);
            assertEquals(
                    ((JsonNumber) expected.get("duration_ms")).longValue(), token.durationMs, id);
            assertEquals(optional(expected.get("execution_digest")), token.executionDigest, id);
            assertEquals(optional(expected.get("execution_trace")), token.executionTrace, id);
            assertEquals(optional(expected.get("rsw_proof")), token.rswProof, id);
            Object telemetry = expected.get("telemetry");
            if (telemetry != null) {
                assertEquals(
                        ((JsonObject) telemetry).encode(),
                        token.telemetry.encode(),
                        id + ": telemetry value");
            }
            Object telemetryScore = expected.get("telemetry_score");
            if (telemetryScore != null) {
                assertEquals(
                        telemetryScore,
                        Telemetry.scoreTelemetry(token.telemetry, token.durationMs),
                        id + ": telemetry score");
            }
            return;
        }

        SolutionToken.DecodeException error = assertThrows(
                SolutionToken.DecodeException.class,
                () -> SolutionToken.decode(raw),
                id + ": the JVM decoder accepted a hostile row");
        String wanted = (String) expected.get("class");
        if (!"any".equals(wanted)) {
            assertEquals(wanted, classify(error.code), id);
        }
    }
}
