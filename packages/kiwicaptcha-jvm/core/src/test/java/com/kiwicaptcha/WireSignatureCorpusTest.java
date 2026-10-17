package com.kiwicaptcha;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * The shared challenge-signature corpus against the JVM verifier.
 *
 * <p>The fixture is expanded by the PHP generator and read byte-for-byte by every
 * hosted SDK suite; the expected verdicts are the reference verifier's.
 */
final class WireSignatureCorpusTest {
    private static JsonObject corpus() throws Exception {
        try (InputStream stream =
                WireSignatureCorpusTest.class.getResourceAsStream("/wire-signature-corpus.json")) {
            assertNotNull(stream, "the signature corpus fixture must exist");
            return JsonObject.parseObject(new String(stream.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> toMap(JsonObject object) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (String key : object.keys()) {
            Object value = object.get(key);
            if (value instanceof JsonObject nested) {
                value = toMap(nested);
            } else if (value instanceof List<?> list) {
                value = list.stream()
                        .map(item -> item instanceof JsonObject nested ? toMap(nested) : item)
                        .toList();
            }
            map.put(key, value);
        }
        return map;
    }

    @TestFactory
    Stream<DynamicTest> everyCorpusRowHasTheReferenceVerdict() throws Exception {
        JsonObject document = corpus();
        JsonObject counts = (JsonObject) document.get("counts");
        assertTrue(((JsonNumber) counts.get("total")).intValue() >= 40, "the corpus must stay broad");

        @SuppressWarnings("unchecked")
        List<Object> rows = (List<Object>) document.get("vectors");
        return rows.stream().map(Object.class::cast).map(rowValue -> {
            JsonObject row = (JsonObject) rowValue;
            String id = (String) row.get("id");
            return DynamicTest.dynamicTest(id, () -> {
                ChallengeRecord record = ChallengeRecord.fromMap(toMap((JsonObject) row.get("record")));
                assertEquals((String) row.get("challenge"), record.challenge, id);
                boolean verified = Canonical.verifyRecordSignature(
                        record,
                        (String) row.get("verify_secret"),
                        (String) row.get("verify_tenant"));
                assertEquals("accept".equals(row.get("expect")), verified, id);
            });
        });
    }
}
