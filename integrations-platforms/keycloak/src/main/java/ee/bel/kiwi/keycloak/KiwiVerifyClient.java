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
     * The client ip bound into the verify call, resolved through the
     * shared trusted-proxy walk: the socket peer wins unless the peer
     * sits inside the trusted proxy CIDR list (the default empty list
     * trusts nobody, so a forged X-Forwarded-For never moves the
     * binding). The chain is walked right to left through the trusted
     * hops and X-Real-IP is honored when no chain exists.
     *
     * @param remoteAddr     the socket peer text
     * @param forwardedFor   the merged X-Forwarded-For value
     * @param realIp         the X-Real-IP value, null when absent
     * @param trustedProxies the comma-separated trusted-proxy CIDRs
     */
    public static String clientIp(String remoteAddr, String forwardedFor, String realIp, String trustedProxies) {
        String peer = remoteAddr == null || remoteAddr.isBlank() ? "127.0.0.1" : remoteAddr.trim();
        List<String> cidrs = parseCidrs(trustedProxies);
        if (cidrs.isEmpty()) {
            return peer;
        }
        String peerCanonical = canonicalIp(peer);
        boolean peerTrusted = peerCanonical != null && inTrusted(peerCanonical, cidrs);
        String forwarded = forwardedFor == null ? "" : forwardedFor.trim();
        if (forwarded.isEmpty()) {
            if (!peerTrusted) {
                return peer;
            }
            String candidate = realIp == null ? "" : realIp.trim();
            if (candidate.isEmpty() || candidate.matches("[\\x00-\\x1F\\x7F]")) {
                return peer;
            }
            String canonical = canonicalIp(candidate);
            return canonical != null ? canonical : peer;
        }
        if (forwarded.matches(".*[\\x00-\\x1F\\x7F].*") || !peerTrusted) {
            return peer;
        }
        String[] hops = forwarded.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String canonical = canonicalIp(hops[i]);
            if (canonical == null) {
                // An unparsable hop terminates the trust chain: who
                // lies beyond it cannot be established, so the peer
                // falls back.
                return peer;
            }
            if (!inTrusted(canonical, cidrs)) {
                return canonical;
            }
        }
        return peer;
    }

    /** The comma-separated CIDR text as a list; blanks dropped. */
    static List<String> parseCidrs(String csv) {
        List<String> cidrs = new ArrayList<>();
        if (csv == null) {
            return cidrs;
        }
        for (String candidate : csv.split(",")) {
            String trimmed = candidate.trim();
            if (!trimmed.isEmpty()) {
                cidrs.add(trimmed);
            }
        }
        return cidrs;
    }

    /**
     * The canonical IP text of one forwarded node, or null when it is
     * not a genuine address: bare IPv4, IPv4 with a port, bracketed
     * IPv6 with an optional port; unknown, obfuscated tokens and
     * malformed ports refuse; IPv4-mapped IPv6 normalizes to IPv4.
     */
    static String canonicalIp(String identifier) {
        if (identifier == null) {
            return null;
        }
        String value = identifier.trim();
        if (value.isEmpty() || value.equals("unknown") || value.startsWith("_")) {
            return null;
        }
        String candidate = value;
        if (candidate.startsWith("[")) {
            int closing = candidate.indexOf(']');
            if (closing < 0) {
                return null;
            }
            String suffix = candidate.substring(closing + 1);
            if (!suffix.isEmpty() && !isPortSuffix(suffix)) {
                return null;
            }
            candidate = candidate.substring(1, closing);
        } else if (candidate.chars().filter(c -> c == ':').count() == 1) {
            // IPv4 with a port: the port splits only when the left
            // side is a valid IPv4 and the port is a genuine number.
            String[] parts = candidate.split(":", -1);
            if (parts.length == 2 && isStrictIpv4(parts[0]) && isPortSuffix(":" + parts[1])) {
                candidate = parts[0];
            }
        }
        if (candidate.indexOf(':') >= 0 && candidate.chars().filter(c -> c == ':').count() < 2) {
            String[] parts = candidate.split(":", -1);
            if (isStrictIpv4(parts[parts.length - 1])) {
                candidate = String.join(":", java.util.Arrays.copyOfRange(parts, 0, parts.length - 1));
            }
        }
        if (!candidate.contains(":") && !DOTTED_QUAD.matcher(candidate).matches()) {
            return null;
        }
        InetAddress parsed = parseAddress(candidate);
        if (parsed == null) {
            return null;
        }
        byte[] bytes = parsed.getAddress();
        if (bytes.length == 16 && isMappedBytes(bytes)) {
            return dottedQuad(bytes, 12);
        }
        return parsed.getHostAddress();
    }

    private static final java.util.regex.Pattern DOTTED_QUAD = java.util.regex.Pattern.compile(
            "\\A(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}\\Z");

    /** The strict address parse: literals only, zones refused. */
    private static InetAddress parseAddress(String text) {
        String trimmed = text == null ? "" : text.trim();
        if (trimmed.isEmpty() || trimmed.indexOf('%') >= 0) {
            return null;
        }
        try {
            return InetAddress.getByName(trimmed);
        } catch (java.net.UnknownHostException e) {
            return null;
        }
    }

    private static boolean isMappedBytes(byte[] bytes) {
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF;
    }

    private static String dottedQuad(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) + "." + (bytes[offset + 1] & 0xFF)
                + "." + (bytes[offset + 2] & 0xFF) + "." + (bytes[offset + 3] & 0xFF);
    }

    private static boolean isStrictIpv4(String text) {
        return text != null && DOTTED_QUAD.matcher(text).matches();
    }

    private static boolean isPortSuffix(String suffix) {
        if (suffix.length() < 2 || suffix.charAt(0) != ':') {
            return false;
        }
        String digits = suffix.substring(1);
        if (digits.length() > 5 || !digits.chars().allMatch(Character::isDigit)) {
            return false;
        }
        int port = Integer.parseInt(digits);
        return port >= 1 && port <= 65535;
    }

    /**
     * Whether one canonical IP text sits inside any trusted CIDR. Host
     * bits set in a CIDR are masked away, and an IPv4-mapped IPv6
     * address matches in its IPv4 form.
     */
    static boolean inTrusted(String ip, List<String> cidrs) {
        InetAddress parsed = parseAddress(ip);
        if (parsed == null) {
            return false;
        }
        byte[] address = parsed.getAddress();
        for (String cidr : cidrs) {
            String trimmed = cidr.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int slash = trimmed.lastIndexOf('/');
            String networkText = slash < 0 ? trimmed : trimmed.substring(0, slash).trim();
            String lengthText = slash < 0 ? null : trimmed.substring(slash + 1).trim();
            InetAddress network = parseAddress(networkText);
            if (network == null) {
                continue;
            }
            byte[] networkBytes = network.getAddress();
            if (networkBytes.length != address.length) {
                continue;
            }
            int bits = address.length * 8;
            int prefixLength = bits;
            if (lengthText != null) {
                if (!lengthText.chars().allMatch(Character::isDigit)) {
                    continue;
                }
                prefixLength = Integer.parseInt(lengthText);
                if (prefixLength < 0 || prefixLength > bits) {
                    continue;
                }
            }
            int fullBytes = prefixLength / 8;
            int remainder = prefixLength % 8;
            boolean matches = true;
            for (int i = 0; i < fullBytes && matches; i++) {
                matches = networkBytes[i] == address[i];
            }
            if (matches && remainder > 0 && fullBytes < address.length) {
                int mask = 0xFF << (8 - remainder);
                matches = (networkBytes[fullBytes] & mask) == (address[fullBytes] & mask);
            }
            if (matches) {
                return true;
            }
        }
        return false;
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
