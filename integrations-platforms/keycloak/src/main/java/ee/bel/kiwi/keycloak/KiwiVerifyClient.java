package ee.bel.kiwi.keycloak;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

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



    /** The typed outcome of the token authority rule. */
    public record TokenResolution(String token, String code) {
    }

    /** The corpus code for a request that carries no token value at all. */
    public static final String CODE_MALFORMED_TOKEN = "malformed_token";

    /**
     * The corpus code for a request carrying two or more distinct token
     * values: refused before any token is verified.
     */
    public static final String CODE_TOKEN_SOURCE_CONFLICT = "token_source_conflict";

    /**
     * The shared token authority rule, pinned by
     * protocol/decision-v1/corpus.json: every non-empty value is
     * collected from all three sources (the X-Kiwi-Token header lines,
     * the incumbent form fields, the same-named query parameters),
     * repeated values included. Zero distinct values are
     * {@link #CODE_MALFORMED_TOKEN}, one distinct value is the token
     * however many sources carry it, and two or more distinct values
     * refuse the request with {@link #CODE_TOKEN_SOURCE_CONFLICT}
     * before any token is verified, so a trusted gateway's header can
     * never be shadowed by an attacker-controlled form field.
     *
     * @param headerValues every X-Kiwi-Token header line value
     * @param formValues   every value of the token form fields
     * @param queryValues  every value of the token query parameters
     */
    public static TokenResolution resolveTokenValues(List<String> headerValues, List<String> formValues, List<String> queryValues) {
        Set<String> distinct = new LinkedHashSet<>();
        List<List<String>> sources = new ArrayList<>(3);
        sources.add(headerValues);
        sources.add(formValues);
        sources.add(queryValues);
        for (List<String> source : sources) {
            if (source == null) {
                continue;
            }
            for (String value : source) {
                if (value == null) {
                    continue;
                }
                String trimmed = value.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                distinct.add(trimmed);
                if (distinct.size() > 1) {
                    return new TokenResolution(null, CODE_TOKEN_SOURCE_CONFLICT);
                }
            }
        }
        if (distinct.isEmpty()) {
            return new TokenResolution(null, CODE_MALFORMED_TOKEN);
        }
        return new TokenResolution(distinct.iterator().next(), null);
    }

    /**
     * Every token value of the X-Kiwi-Token header lines. Duplicate
     * header lines arrive as separate list entries; a single line may
     * itself carry a comma-joined list (some surfaces merge repeated
     * lines), and the token alphabet has no comma, so the split loses
     * nothing.
     */
    public static List<String> splitTokenHeaderLines(List<String> lines) {
        List<String> values = new ArrayList<>();
        if (lines == null) {
            return values;
        }
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            for (String part : line.split(",")) {
                String value = part.trim();
                if (!value.isEmpty()) {
                    values.add(value);
                }
            }
        }
        return values;
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
     * One masked trusted prefix: the canonical network bytes (4 for
     * IPv4, 16 for IPv6) and the prefix length in bits.
     */
    private record TrustedPrefix(byte[] network, int prefixLength) {
    }

    /**
     * The client ip bound into the verify call, resolved through the
     * shared trusted-proxy walk. {@code tools/client-ip/test-vectors.json}
     * is the executable contract, and this resolver must answer every
     * scenario exactly as the go and dotnet SDK resolvers do:
     *
     * <ul>
     * <li>an empty trusted list trusts nobody: the socket peer is the
     * answer (returned verbatim) and every forwarding header is
     * ignored, so a client-supplied X-Forwarded-For can never choose
     * the binding;</li>
     * <li>the immediate socket peer must itself sit inside a trusted
     * prefix before any header is honored;</li>
     * <li>with a trusted peer the X-Forwarded-For chain is walked right
     * to left: an entry inside the trust list is skipped, the first
     * untrusted entry wins, and an entry that fails strict IP parsing
     * terminates the walk and falls back to the peer (fail closed,
     * never an older attacker-chosen entry);</li>
     * <li>a chain whose every entry is trusted falls back to the
     * peer;</li>
     * <li>X-Real-IP is honored only when the peer is trusted and no
     * non-empty chain exists; an unparseable X-Real-IP falls back to
     * the peer;</li>
     * <li>raw control bytes anywhere in a forwarding header refuse that
     * header (the peer wins), and repeated X-Forwarded-For or X-Real-IP
     * header lines are parser ambiguity (one intermediary reads the
     * first line, another the last): the peer wins;</li>
     * <li>canonical IP parsing throughout: IPv4-mapped IPv6 normalizes
     * to its IPv4 form before trust comparisons, host bits set in a
     * CIDR are masked away, malformed CIDR entries are skipped (a typo
     * can never widen the trust boundary).</li>
     * </ul>
     *
     * <p>A peer that is not a genuine IP address (a unix socket path,
     * for example) is never trusted and is returned verbatim; a missing
     * peer resolves to the empty string (fail closed): the caller
     * refuses the request rather than inventing an address.
     *
     * @param remoteAddr         the socket peer text
     * @param forwardedForLines  every X-Forwarded-For header line
     * @param realIpLines        every X-Real-IP header line
     * @param trustedCidrs       the trusted CIDR list; empty trusts nobody
     */
    public static String resolveClientIp(String remoteAddr, List<String> forwardedForLines, List<String> realIpLines, List<String> trustedCidrs) {
        String peer = remoteAddr == null ? "" : remoteAddr.trim();
        List<TrustedPrefix> prefixes = trustedPrefixes(trustedCidrs);
        if (prefixes.isEmpty()) {
            return peer;
        }
        // A repeated forwarding header is parser ambiguity: one
        // intermediary reads the first line, another the last, so no
        // header-derived identity is trustworthy and the peer wins.
        List<String> xffLines = visibleLines(forwardedForLines);
        List<String> realLines = visibleLines(realIpLines);
        if (xffLines.size() > 1 || realLines.size() > 1) {
            return peer;
        }
        // A peer that is not a genuine address is never trusted.
        String peerCanonical = canonicalIp(peer);
        boolean peerTrusted = peerCanonical != null && canonicalWithinTrust(peerCanonical, prefixes);
        String header = xffLines.isEmpty() ? "" : xffLines.get(0).trim();
        if (header.isEmpty()) {
            if (!peerTrusted) {
                return peer;
            }
            String candidate = realLines.isEmpty() ? "" : realLines.get(0).trim();
            if (candidate.isEmpty() || hasControl(candidate)) {
                return peer;
            }
            String canonical = canonicalIp(candidate);
            return canonical == null ? peer : canonical;
        }
        if (hasControl(header) || !peerTrusted) {
            return peer;
        }
        String[] hops = header.split(",", -1);
        for (int i = hops.length - 1; i >= 0; i--) {
            String canonical = canonicalIp(hops[i]);
            if (canonical == null) {
                // An unparsable hop terminates the trust chain: who
                // lies beyond it cannot be established, so the peer
                // falls back instead of an older attacker-chosen
                // entry.
                return peer;
            }
            if (!canonicalWithinTrust(canonical, prefixes)) {
                return canonical;
            }
        }
        return peer;
    }

    /** Whether one IP text sits inside any of the given trusted CIDRs. */
    public static boolean inTrusted(String ipText, List<String> trustedCidrs) {
        String canonical = canonicalIp(ipText);
        return canonical != null && canonicalWithinTrust(canonical, trustedPrefixes(trustedCidrs));
    }

    /** Whether already canonical text (the output of canonicalIp,
     * always parseable) sits inside any parsed trusted prefix. A text
     * that does not re-parse fails closed (never trusted). */
    private static boolean canonicalWithinTrust(String canonical, List<TrustedPrefix> prefixes) {
        byte[] address = addressBytes(canonical);
        if (address == null) {
            return false;
        }
        for (TrustedPrefix prefix : prefixes) {
            if (prefixContains(address, prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The parsed trusted prefixes. Entries that fail to parse are
     * skipped, so a typo can never widen the trust boundary; a bare
     * address entry is the host route for that address.
     */
    private static List<TrustedPrefix> trustedPrefixes(List<String> cidrs) {
        List<TrustedPrefix> prefixes = new ArrayList<>();
        if (cidrs == null) {
            return prefixes;
        }
        for (String cidr : cidrs) {
            if (cidr == null) {
                continue;
            }
            String trimmed = cidr.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String networkText = trimmed;
            Integer prefixLength = null;
            int slash = trimmed.lastIndexOf('/');
            if (slash >= 0) {
                networkText = trimmed.substring(0, slash).trim();
                String lengthText = trimmed.substring(slash + 1).trim();
                if (!isAsciiDigits(lengthText)) {
                    continue;
                }
                prefixLength = Integer.valueOf(lengthText);
            }
            String canonical = canonicalIp(networkText);
            if (canonical == null) {
                continue;
            }
            int bits = canonical.indexOf(':') >= 0 ? 128 : 32;
            int length = prefixLength == null ? bits : prefixLength;
            if (length < 0 || length > bits) {
                continue;
            }
            prefixes.add(masked(new TrustedPrefix(addressBytes(canonical), length)));
        }
        return prefixes;
    }

    /** The prefix with its host bits masked away. */
    private static TrustedPrefix masked(TrustedPrefix prefix) {
        byte[] network = prefix.network().clone();
        int full = prefix.prefixLength() / 8;
        int remainder = prefix.prefixLength() % 8;
        for (int i = full; i < network.length; i++) {
            network[i] = 0;
        }
        if (remainder > 0 && full < network.length) {
            network[full] = (byte) (network[full] & ((0xFF << (8 - remainder)) & 0xFF));
        }
        return new TrustedPrefix(network, prefix.prefixLength());
    }

    private static boolean prefixContains(byte[] address, TrustedPrefix prefix) {
        byte[] network = prefix.network();
        if (address.length != network.length) {
            return false;
        }
        int full = prefix.prefixLength() / 8;
        for (int i = 0; i < full; i++) {
            if (address[i] != network[i]) {
                return false;
            }
        }
        int remainder = prefix.prefixLength() % 8;
        if (remainder > 0) {
            int mask = (0xFF << (8 - remainder)) & 0xFF;
            if ((address[full] & mask) != (network[full] & mask)) {
                return false;
            }
        }
        return true;
    }

    private static byte[] addressBytes(String canonical) {
        if (canonical.indexOf(':') >= 0) {
            return parseIpv6(canonical);
        }
        String[] parts = canonical.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            try {
                out[i] = (byte) Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return out;
    }

    private static List<String> visibleLines(List<String> lines) {
        List<String> visible = new ArrayList<>();
        if (lines == null) {
            return visible;
        }
        for (String line : lines) {
            if (line != null && !line.trim().isEmpty()) {
                visible.add(line);
            }
        }
        return visible;
    }

    /**
     * The canonical text of one IP literal, or null. Bare IPv4, an
     * IPv4 address with a port, and a bracketed IPv6 address with an
     * optional port are accepted; hostnames, zone identifiers,
     * obfuscated tokens, leading-zero octets, decimal integer
     * shorthand and malformed ports are refused, and no DNS lookup
     * ever runs on untrusted input. IPv4-mapped IPv6 normalizes to its
     * IPv4 form.
     */
    static String canonicalIp(String identifier) {
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
        if (candidate.indexOf(':') >= 0) {
            byte[] bytes = parseIpv6(candidate);
            return bytes == null ? null : canonicalIpv6Text(bytes);
        }
        if (!isIpv4(candidate)) {
            return null;
        }
        return normalizeIpv4(candidate);
    }

    /**
     * A strict IPv6 parser: lowercase or uppercase hex groups, at most
     * one "::" compression (which must stand for at least one group),
     * an optional embedded strict IPv4 tail, no zone identifier.
     * Returns the 16 address bytes, or null. Only ever handed text
     * that the caller has confined to hex digits, colons and dots, so
     * no hostname ever reaches a resolver.
     */
    private static byte[] parseIpv6(String value) {
        if (value.isEmpty() || value.indexOf('%') >= 0) {
            return null;
        }
        int compression = value.indexOf("::");
        if (compression >= 0 && value.indexOf("::", compression + 1) >= 0) {
            return null;
        }
        String head = compression < 0 ? value : value.substring(0, compression);
        String tail = compression < 0 ? null : value.substring(compression + 2);
        List<String> headGroups = sideGroups(head);
        List<String> tailGroups = tail == null ? new ArrayList<>() : sideGroups(tail);
        if (headGroups == null || tailGroups == null) {
            return null;
        }
        int groups = headGroups.size() + tailGroups.size();
        int slots = 0;
        for (int i = 0; i < groups; i++) {
            String piece = i < headGroups.size() ? headGroups.get(i) : tailGroups.get(i - headGroups.size());
            if (piece.indexOf('.') >= 0) {
                if (i != groups - 1 || !isIpv4(piece)) {
                    return null;
                }
                slots += 2;
            } else {
                if (piece.length() > 4 || !isHexDigits(piece)) {
                    return null;
                }
                slots += 1;
            }
        }
        if (compression < 0 ? slots != 8 : slots > 7) {
            return null;
        }
        byte[] out = new byte[16];
        int headBytes = sideBytes(headGroups);
        int tailBytes = sideBytes(tailGroups);
        if (headBytes + tailBytes > 16) {
            return null;
        }
        writeSide(headGroups, out, 0);
        writeSide(tailGroups, out, 16 - tailBytes);
        return out;
    }

    /** The hex groups of one side of the "::", or null. An empty side
     * contributes nothing; an empty or malformed piece inside a side is
     * invalid (so ":x", "x:" and ":::" all refuse). */
    private static List<String> sideGroups(String side) {
        List<String> groups = new ArrayList<>();
        if (side.isEmpty()) {
            return groups;
        }
        for (String piece : side.split(":", -1)) {
            if (piece.isEmpty()) {
                return null;
            }
            groups.add(piece);
        }
        return groups;
    }

    private static int sideBytes(List<String> groups) {
        int bytes = 0;
        for (String piece : groups) {
            bytes += piece.indexOf('.') >= 0 ? 4 : 2;
        }
        return bytes;
    }

    private static void writeSide(List<String> groups, byte[] out, int offset) {
        int index = offset;
        for (String piece : groups) {
            if (piece.indexOf('.') >= 0) {
                String[] parts = piece.split("\\.", -1);
                for (String part : parts) {
                    out[index++] = (byte) Integer.parseInt(part);
                }
            } else {
                int value = Integer.parseInt(piece, 16);
                out[index++] = (byte) (value >> 8);
                out[index++] = (byte) value;
            }
        }
    }

    /**
     * The canonical RFC 5952 text of 16 address bytes: lowercase hex
     * groups without leading zeros, the leftmost longest run of two or
     * more zero groups compressed to "::", and an IPv4-mapped address
     * normalized to its dotted IPv4 form.
     */
    private static String canonicalIpv6Text(byte[] bytes) {
        boolean mapped = bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF;
        if (mapped) {
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    mapped = false;
                    break;
                }
            }
        }
        if (mapped) {
            return (bytes[12] & 0xFF) + "." + (bytes[13] & 0xFF) + "." + (bytes[14] & 0xFF) + "." + (bytes[15] & 0xFF);
        }
        String[] groups = new String[8];
        int bestStart = -1;
        int bestLength = 0;
        int currentStart = -1;
        int currentLength = 0;
        for (int i = 0; i < 8; i++) {
            int value = ((bytes[i * 2] & 0xFF) << 8) | (bytes[i * 2 + 1] & 0xFF);
            groups[i] = Integer.toHexString(value);
            if (value == 0) {
                if (currentStart < 0) {
                    currentStart = i;
                }
                currentLength++;
                if (currentLength > bestLength) {
                    bestStart = currentStart;
                    bestLength = currentLength;
                }
            } else {
                currentStart = -1;
                currentLength = 0;
            }
        }
        if (bestLength < 2) {
            return String.join(":", groups);
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < bestStart; i++) {
            if (i > 0) {
                out.append(':');
            }
            out.append(groups[i]);
        }
        out.append("::");
        for (int i = bestStart + bestLength; i < 8; i++) {
            if (i > bestStart + bestLength) {
                out.append(':');
            }
            out.append(groups[i]);
        }
        return out.toString();
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

    /**
     * The strict dotted-quad grammar only: four decimal octets 0..255,
     * no leading zeros (so "01.2.3.4" and the decimal integer
     * shorthand are refused, exactly as in the other SDK resolvers).
     */
    private static boolean isIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !isAsciiDigits(part)) {
                return false;
            }
            if (part.length() > 1 && part.charAt(0) == '0') {
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

    /** Non-empty, 1..4 hex digits: one IPv6 group. */
    private static boolean isHexDigits(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) {
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
