package com.kiwicaptcha.servlet;

import com.kiwicaptcha.JsonObject;
import com.kiwicaptcha.VerifyError;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The shared token authority matrix from protocol/decision-v1/
 * corpus.json, driven through the resolver the servlet filter and the
 * Spring interceptor share.
 */
class TokenSourceResolverTest {
    private static JsonObject corpus() throws IOException {
        Path path = Path.of("..", "..", "..", "protocol", "decision-v1", "corpus.json");
        return JsonObject.parseObject(Files.readString(path, StandardCharsets.UTF_8));
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        for (Object item : (List<?>) value) {
            out.add((String) item);
        }
        return out;
    }

    @Test
    void everyAuthorityRowResolvesUnderRejectOnConflict() throws IOException {
        JsonObject authority = (JsonObject) corpus().get("authority");
        assertEquals("token_source_conflict", authority.get("conflict_code"));
        assertEquals("malformed_token", authority.get("missing_code"));
        for (Object entry : (List<?>) authority.get("matrix")) {
            JsonObject row = (JsonObject) entry;
            String name = (String) row.get("case");
            TokenSourceResolver.Result result = TokenSourceResolver.resolveValues(
                    strings(row.get("header")),
                    strings(row.get("form")),
                    strings(row.get("query")));
            switch ((String) row.get("verdict")) {
                case "verify" -> {
                    assertTrue(result.ok(), name);
                    assertEquals(row.get("token"), result.token, name);
                }
                case "conflict" -> {
                    assertEquals(VerifyError.TOKEN_SOURCE_CONFLICT, result.error, name);
                    assertNull(result.token, name);
                }
                default -> assertEquals(VerifyError.MALFORMED_TOKEN, result.error, name);
            }
        }
    }
}
