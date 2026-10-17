package ee.bel.kiwi.keycloak;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
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
        // A pass requires the upstream to say success on a 2xx status:
        // a redirect (3xx) or any other non-2xx carrying a
        // success-shaped body is a status/body mismatch and fails
        // closed.
        if (status >= 200 && status <= 299 && responseBodyHasSuccess(response.body())) {
            return new Result(true, "verified", status);
        }
        return new Result(false, "challenge_failed", status);
    }

    /**
     * Whether the provider siteverify JSON body carries success true.
     * A real (strict, recursive-descent) JSON parser: the whole body
     * must parse as one JSON object and its top-level "success" member
     * must be the JSON boolean {@code true}. A substring scanner would
     * accept bodies a JSON parser rejects (truncated documents,
     * trailing garbage, {@code "success":"true"} string lookalikes),
     * and a non-JSON body is a refusal, never a pass.
     */
    public static boolean responseBodyHasSuccess(String body) {
        if (body == null) {
            return false;
        }
        Object parsed;
        try {
            parsed = Json.parse(body);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (!(parsed instanceof java.util.Map<?, ?> object)) {
            return false;
        }
        return Boolean.TRUE.equals(object.get("success"));
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

    /**
     * The client ip bound into the verify call.
     *
     * <p>With {@code trustProxy} off (the default) the socket peer is
     * returned and every forwarding header is ignored, so a
     * client-supplied X-Forwarded-For can never choose the binding.
     *
     * <p>With it on, the rightmost X-Forwarded-For hop is used: that
     * is the value the nearest trusted proxy appended, so a forged
     * leftmost entry is ignored. With no chain, X-Real-IP is the
     * fallback. A malformed header or hop falls back to the peer.
     * Enable the switch only behind a reverse proxy that appends (or
     * overwrites) the header; without such a proxy the header is
     * client-controlled.
     *
     * <p>A missing or malformed socket peer resolves to the empty
     * string (fail closed): the caller refuses the request rather than
     * inventing an address.
     */
    public static String resolveClientIp(String remoteAddr, String forwardedFor, String realIp, boolean trustProxy) {
        String peer = canonicalIp(remoteAddr);
        if (peer == null) {
            return "";
        }
        if (!trustProxy) {
            return peer;
        }
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            if (hasControl(forwardedFor)) {
                return peer;
            }
            String[] hops = forwardedFor.split(",", -1);
            String candidate = canonicalIp(hops[hops.length - 1]);
            return candidate == null ? peer : candidate;
        }
        if (realIp != null && !realIp.isBlank() && !hasControl(realIp)) {
            String candidate = canonicalIp(realIp);
            if (candidate != null) {
                return candidate;
            }
        }
        return peer;
    }

    /**
     * The canonical text of one IP literal, or null. Bare IPv4, an
     * IPv4 address with a port, and a bracketed IPv6 address with an
     * optional port are accepted; hostnames, zone identifiers,
     * obfuscated tokens and malformed ports are refused, and no DNS
     * lookup ever runs on untrusted input.
     */
    private static String canonicalIp(String identifier) {
        String value = identifier == null ? "" : identifier.trim();
        if (value.isEmpty() || value.equalsIgnoreCase("unknown") || value.startsWith("_") || hasControl(value)) {
            return null;
        }
        String candidate = value;
        if (candidate.startsWith("[")) {
            int closing = candidate.indexOf(']');
            if (closing < 0) {
                return null;
            }
            String suffix = candidate.substring(closing + 1);
            if (!suffix.isEmpty() && !portSuffix(suffix)) {
                return null;
            }
            candidate = candidate.substring(1, closing);
        } else if (count(candidate, ':') == 1) {
            int colon = candidate.indexOf(':');
            String host = candidate.substring(0, colon);
            if (isIpv4(host) && portSuffix(candidate.substring(colon))) {
                candidate = host;
            }
        }
        if (isIpv4(candidate)) {
            return normalizeIpv4(candidate);
        }
        if (!isIpv6(candidate)) {
            return null;
        }
        try {
            return InetAddress.getByName(candidate).getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static boolean hasControl(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                return true;
            }
        }
        return false;
    }

    private static int count(String value, char needle) {
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == needle) {
                count++;
            }
        }
        return count;
    }

    private static boolean isIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !isAsciiDigits(part)) {
                return false;
            }
            if (Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }

    private static String normalizeIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        StringBuilder out = new StringBuilder(value.length());
        for (String part : parts) {
            if (out.length() > 0) {
                out.append('.');
            }
            out.append(Integer.parseInt(part));
        }
        return out.toString();
    }

    /**
     * A conservative IPv6 check: the token may only contain hex
     * digits, colons and dots (the IPv4-mapped spelling), so
     * {@link InetAddress#getByName(String)} is only ever handed an IP
     * literal and can never resolve a hostname.
     */
    private static boolean isIpv6(String value) {
        if (value.indexOf(':') < 0) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.digit(c, 16) < 0 && c != ':' && c != '.') {
                return false;
            }
        }
        try {
            return InetAddress.getByName(value) instanceof Inet6Address;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Exactly ":" plus a decimal port in the 1..65535 range, the same
     * grammar the other platform clients apply.
     */
    private static boolean portSuffix(String suffix) {
        if (suffix.isEmpty() || suffix.charAt(0) != ':') {
            return false;
        }
        String digits = suffix.substring(1);
        if (digits.isEmpty() || digits.length() > 5 || !isAsciiDigits(digits)) {
            return false;
        }
        int port = Integer.parseInt(digits);
        return port >= 1 && port <= 65535;
    }

    private static boolean isAsciiDigits(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return !value.isEmpty();
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
