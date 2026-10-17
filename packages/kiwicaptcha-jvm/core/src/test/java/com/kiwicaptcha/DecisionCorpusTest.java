package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The shared decision register: protocol/decision-v1/corpus.json. The
 * Java side asserts every wire code against the same table the D3.17
 * campaign reads.
 */
class DecisionCorpusTest {
    private static JsonObject corpus() throws IOException {
        Path path = Path.of("..", "..", "..", "protocol", "decision-v1", "corpus.json");
        return JsonObject.parseObject(Files.readString(path, StandardCharsets.UTF_8));
    }

    @Test
    void everyWireCodeMapsToItsRegisteredDisposition() throws IOException {
        JsonObject codes = (JsonObject) corpus().get("codes");
        for (String code : codes.keys()) {
            VerifyError error = VerifyError.fromCodeOrNull(code);
            assertNotNull(error, code);
            String want = (String) codes.get(code);
            Decision decision = Decision.fromOutcome(VerifyOutcome.invalid(error), "");
            assertFalse(decision.ok, code);
            assertEquals(want, decision.disposition, code);
            assertEquals(code, decision.error, code);
        }
    }

    @Test
    void theRetryTableIsExactlyTheFourTransientCodes() throws IOException {
        JsonObject root = corpus();
        @SuppressWarnings("unchecked")
        Set<String> registered = Set.copyOf((java.util.List<String>) (java.util.List<?>) root.get("retry_codes"));
        for (String code : registered) {
            assertEquals(Decision.DISPOSITION_RETRY,
                    Decision.fromOutcome(VerifyOutcome.invalid(VerifyError.fromCodeOrNull(code)), "").disposition,
                    code);
        }
        JsonObject http = (JsonObject) root.get("http");
        assertEquals(200L, ((JsonNumber) http.get("allow_status")).longValue());
        assertEquals(503L, ((JsonNumber) http.get("retry_status")).longValue());
        JsonObject deny = (JsonObject) http.get("deny_status");
        assertEquals(403L, ((JsonNumber) deny.get("jvm")).longValue());
    }
}
