package com.kiwicaptcha;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Pattern;

/**
 * The execution delegation plane of the JVM SDK: an execution-armed
 * record demands the browser-trace walker, an oracle this SDK does not
 * carry. The default policy fails every armed record closed
 * ({@code execution_mismatch}, documented). The sidecar policy
 * delegates that single verification to a co-located
 * kiwicaptcha-verifier sidecar over HTTP: the sidecar carries the full
 * Rust core with the real execution verifier, consumes the record
 * (single-use semantics preserved: the sidecar consumes, this SDK
 * never double-consumes) and answers the provider-shaped verdict
 * mapped back into this SDK's vocabulary.
 *
 * Trust boundary: the sidecar decides acceptances, so it must be
 * co-located and trusted to the same standard as the verifier itself.
 * The bearer credential is sent per request, and a refused credential
 * denies instead of retrying into an untrusted verifier.
 */
public final class ExecutionPolicy {
    /** The kiwicaptcha-verifier base URL; empty keeps the fail-closed default. */
    public final String sidecarUrl;

    /** The sidecar's own credential, sent as the Authorization bearer. */
    public final String bearerToken;

    /** The bounded budget of one delegation call in milliseconds. */
    public final int timeoutMs;

    private static final Pattern JSON_STRING =
            Pattern.compile("\"kiwi-code\"\\s*:\\s*\"([a-z0-9_]+)\"");
    private static final Pattern JSON_SUCCESS =
            Pattern.compile("\"success\"\\s*:\\s*(true|false)");

    public ExecutionPolicy(String sidecarUrl, String bearerToken, int timeoutMs) {
        this.sidecarUrl = sidecarUrl == null ? "" : sidecarUrl;
        this.bearerToken = bearerToken == null ? "" : bearerToken;
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : 5000;
    }

    /** Whether the policy delegates the execution-armed dimension. */
    public boolean enabled() {
        return !sidecarUrl.trim().isEmpty();
    }

    /**
     * Hands one execution-armed verification to the sidecar. Answers
     * {@code ["ok", ""]} on acceptance, or {@code ["deny", code]} where
     * the code is the shared wire vocabulary carried through; the
     * transport failures fail closed ({@code storage_unavailable}
     * keeps the retry disposition with the record intact). The response
     * body is read with the regex surface, not a JSON tree: the
     * sidecar's answer is a flat provider document this SDK trusts
     * because it owns the sidecar, and the module carries no JSON
     * dependency.
     */
    public String[] delegate(String rawToken, String scope, String clientIp) {
        String body = "{\"token\":\"" + JsonString.escape(rawToken)
                + "\",\"scope\":\"" + JsonString.escape(scope) + "\""
                + (clientIp == null || clientIp.isEmpty()
                        ? "" : ",\"remoteip\":\"" + JsonString.escape(clientIp) + "\"")
                + "}";
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(sidecarUrl.trim().replaceAll("/+$", "") + "/verify"))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (!bearerToken.isEmpty()) {
            builder.header("authorization", "Bearer " + bearerToken);
        }
        HttpResponse<String> response;
        try {
            response = HttpClient.newHttpClient()
                    .send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            return new String[]{"deny", "storage_unavailable"};
        }
        int status = response.statusCode();
        if (status == 401 || status == 403) {
            // The sidecar refused the credential: never retry into an
            // untrusted verifier, fail closed with a deny.
            return new String[]{"deny", "execution_mismatch"};
        }
        if (status >= 500) {
            return new String[]{"deny", "storage_unavailable"};
        }
        if (status != 200) {
            return new String[]{"deny", "execution_mismatch"};
        }
        String text = response.body();
        java.util.regex.Matcher success = JSON_SUCCESS.matcher(text);
        if (success.find() && "true".equals(success.group(1))) {
            return new String[]{"ok", ""};
        }
        java.util.regex.Matcher code = JSON_STRING.matcher(text);
        if (code.find()) {
            return new String[]{"deny", code.group(1)};
        }
        return new String[]{"deny", "execution_mismatch"};
    }

    /** The JSON string escaping of one field value. */
    static final class JsonString {
        private JsonString() {
        }

        static String escape(String value) {
            StringBuilder out = new StringBuilder(value.length() + 8);
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                switch (c) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    case '\n' -> out.append("\\n");
                    case '\r' -> out.append("\\r");
                    case '\t' -> out.append("\\t");
                    default -> {
                        if (c < 0x20) {
                            out.append(String.format("\\u%04x", (int) c));
                        } else {
                            out.append(c);
                        }
                    }
                }
            }
            return out.toString();
        }
    }
}
