package ee.bel.kiwi.keycloak;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * The kiwi verify client: dependency-free (java.net.http plus a
 * hand-rolled JSON encoder), so the pure decision surface compiles
 * and tests with the JDK alone. The wire contract is the verifier
 * sidecar's POST /verify: {"token","scope","remoteip"} with an
 * optional bearer, answered by the provider siteverify JSON.
 */
public final class KiwiVerifyClient {

    /** The outcome of one verify call. */
    public record Result(boolean ok, String code, int upstreamStatus) {
        public static final Result UNAVAILABLE = new Result(false, "verify_unavailable", 0);
        public static final Result UNREADABLE = new Result(false, "verify_unreadable", 0);
    }

    private final HttpClient http;

    public KiwiVerifyClient() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build());
    }

    public KiwiVerifyClient(HttpClient http) {
        this.http = http;
    }

    /**
     * Verify one token for one scope.
     *
     * @param verifyUrl  the kiwi verify endpoint
     * @param bearer     the bearer credential, empty for none
     * @param token      the challenge token
     * @param scope      the challenge scope
     * @param clientIp   the ip bound into the verify call
     * @return the outcome; a transport failure, a 5xx or a 401/404 is
     *         verify_unavailable (the flow must fail closed)
     */
    public Result verify(String verifyUrl, String bearer, String token, String scope, String clientIp) {
        String body = "{\"token\":\"" + jsonEscape(token) + "\",\"scope\":\"" + jsonEscape(scope)
                + "\",\"remoteip\":\"" + jsonEscape(clientIp) + "\"}";
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(verifyUrl))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (bearer != null && !bearer.isEmpty()) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        HttpResponse<String> response;
        try {
            response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            return Result.UNAVAILABLE;
        }
        int status = response.statusCode();
        if (status == 0 || status >= 500 || status == 401 || status == 404) {
            return Result.UNAVAILABLE;
        }
        if (responseBodyHasSuccess(response.body())) {
            return new Result(true, "verified", status);
        }
        return new Result(false, "challenge_failed", status);
    }

    /**
     * Whether the provider siteverify JSON body carries success true.
     * A tiny scanner, not a full parser: enough for the one field,
     * tolerant of whitespace and field order.
     */
    public static boolean responseBodyHasSuccess(String body) {
        if (body == null) {
            return false;
        }
        int idx = body.indexOf("\"success\"");
        if (idx < 0) {
            return false;
        }
        int i = idx + "\"success\"".length();
        while (i < body.length() && Character.isWhitespace(body.charAt(i))) {
            i++;
        }
        if (i >= body.length() || body.charAt(i) != ':') {
            return false;
        }
        i++;
        while (i < body.length() && Character.isWhitespace(body.charAt(i))) {
            i++;
        }
        return body.startsWith("true", i);
    }



    /**
     * The first present token from the shared source list: the
     * X-Kiwi-Token header, then the incumbent form fields.
     */
    public static String extractToken(String headerToken, List<String> formFieldNames, java.util.function.Function<String, String> readFormField) {
        if (headerToken != null && !headerToken.isBlank()) {
            return headerToken.trim();
        }
        for (String field : formFieldNames) {
            String value = readFormField.apply(field);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    /** The incumbent response field names the shims maintain. */
    public static List<String> tokenFieldNames() {
        List<String> fields = new ArrayList<>();
        fields.add("kiwi__token");
        fields.add("g-recaptcha-response");
        fields.add("h-captcha-response");
        fields.add("cf-turnstile-response");
        fields.add("frc-captcha-solution");
        fields.add("altcha");
        return fields;
    }

    static String jsonEscape(String value) {
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
