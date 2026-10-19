package ee.bel.kiwi.keycloak;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;

/**
 * The plain-JDK test of the kiwi verify client: the decision surface
 * (status mapping, body scanning), the token authority rule (the
 * collect/distinct/conflict matrix of
 * protocol/decision-v1/corpus.json), the client-ip resolver (every
 * scenario of the shared tools/client-ip/test-vectors.json matrix,
 * parameterized over that file like the go and dotnet SDK suites),
 * JSON escaping, plus a live round trip against a local HttpServer
 * stub. Run after a javac of the three files (see README.md).
 */
public final class KiwiVerifyClientTest {

    private static int failures = 0;
    private static int checks = 0;

    private static void check(String name, boolean condition) {
        checks++;
        if (!condition) {
            failures++;
            System.err.println("FAIL: " + name);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Object> listOf(Object value) {
        return (List<Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapOf(Object value) {
        return (Map<String, Object>) value;
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        for (Object entry : listOf(value)) {
            out.add((String) entry);
        }
        return out;
    }

    /** The shared client-ip vectors: an explicit system property first
     * (the run-all harness passes it, so the cwd never matters), then
     * an upward search from the working directory. */
    private static Path sharedVectors() throws IOException {
        String configured = System.getProperty("kiwi.test.vectors");
        if (configured != null && !configured.isBlank() && Files.exists(Path.of(configured))) {
            return Path.of(configured);
        }
        Path dir = Path.of("").toAbsolutePath();
        while (dir != null) {
            Path candidate = dir.resolve("tools").resolve("client-ip").resolve("test-vectors.json");
            if (Files.exists(candidate)) {
                return candidate;
            }
            dir = dir.getParent();
        }
        throw new IOException(
                "tools/client-ip/test-vectors.json not found above " + Path.of("").toAbsolutePath()
                        + " (pass -Dkiwi.test.vectors=...)");
    }

    public static void main(String[] args) throws Exception {
        // Decision surface without network: parse the provider body
        // with a real JSON parser, never a substring scan.
        check("success body is detected", KiwiVerifyClient.responseBodyHasSuccess("{\"success\":true,\"error-codes\":[]}"));
        check("failure body is rejected", !KiwiVerifyClient.responseBodyHasSuccess("{\"success\":false}"));
        check("whitespace tolerance", KiwiVerifyClient.responseBodyHasSuccess("{ \"success\" : true }"));
        check("success in a string is not success", !KiwiVerifyClient.responseBodyHasSuccess("{\"x\":\"success:true\"}"));
        check("empty body is rejected", !KiwiVerifyClient.responseBodyHasSuccess(""));
        check("string success is not boolean success", !KiwiVerifyClient.responseBodyHasSuccess("{\"success\":\"true\"}"));
        check("nested success does not count", !KiwiVerifyClient.responseBodyHasSuccess("{\"error\":{\"success\":true}}"));
        check("truncated body is rejected", !KiwiVerifyClient.responseBodyHasSuccess("{\"success\":true"));
        check("trailing garbage is rejected", !KiwiVerifyClient.responseBodyHasSuccess("{\"success\":true} extra"));
        check("number one is not success", !KiwiVerifyClient.responseBodyHasSuccess("{\"success\":1}"));
        check("duplicate success keys fail closed", !KiwiVerifyClient.responseBodyHasSuccess("{\"success\":true,\"success\":false}"));
        check("bare true is not an object", !KiwiVerifyClient.responseBodyHasSuccess("true"));

        // The token authority rule: every non-empty value from every
        // source is collected and must agree (the matrix of
        // protocol/decision-v1/corpus.json). Zero distinct values are
        // malformed, one distinct value verifies however many sources
        // carry it, two or more distinct values conflict before any
        // verification.
        check("no token anywhere is malformed",
                resolution(null, List.of(), List.of()).code().equals(KiwiVerifyClient.CODE_MALFORMED_TOKEN));
        check("blank values are no token",
                resolution(List.of("  ", ""), List.of(""), List.of()).code().equals(KiwiVerifyClient.CODE_MALFORMED_TOKEN));
        check("header only verifies",
                "A".equals(resolution(List.of("A"), List.of(), List.of()).token()));
        check("form only verifies",
                "A".equals(resolution(List.of(), List.of("A"), List.of()).token()));
        check("query only verifies",
                "A".equals(resolution(List.of(), List.of(), List.of("A")).token()));
        check("header a form b conflicts",
                conflict(resolution(List.of("A"), List.of("B"), List.of())));
        check("header a query b conflicts",
                conflict(resolution(List.of("A"), List.of(), List.of("B"))));
        check("form a query b conflicts",
                conflict(resolution(List.of(), List.of("A"), List.of("B"))));
        check("two distinct header lines conflict",
                conflict(resolution(List.of("A", "B"), List.of(), List.of())));
        check("two distinct form values conflict",
                conflict(resolution(List.of(), List.of("A", "B"), List.of())));
        check("two distinct query values conflict",
                conflict(resolution(List.of(), List.of(), List.of("A", "B"))));
        check("same token in every source verifies",
                "A".equals(resolution(List.of("A"), List.of("A"), List.of("A")).token()));
        check("same value repeated in the header verifies",
                "A".equals(resolution(List.of("A", "A"), List.of(), List.of()).token()));
        check("same value repeated as a form array verifies",
                "A".equals(resolution(List.of(), List.of("A", "A"), List.of()).token()));
        check("same value repeated as a query array verifies",
                "A".equals(resolution(List.of(), List.of(), List.of("A", "A")).token()));
        check("a comma-joined header line splits into values",
                conflict(resolution(KiwiVerifyClient.splitTokenHeaderLines(List.of("A, B")), List.of(), List.of())));
        check("a comma-joined header line with one value verifies",
                "A".equals(resolution(KiwiVerifyClient.splitTokenHeaderLines(List.of(" A ")), List.of(), List.of()).token()));
        check("whitespace around one value is trimmed",
                "A".equals(resolution(List.of(" A "), List.of("A"), List.of()).token()));

        // Client-ip binding: the shared trusted-proxy walk. The direct
        // reachability rule first: an empty trusted list (the default)
        // binds the socket peer and ignores every forwarding header,
        // and an immediate peer outside the configured CIDRs never
        // unlocks the headers, not even when other ranges are trusted.
        check("an empty trusted list binds the socket peer",
                "192.0.2.9".equals(KiwiVerifyClient.resolveClientIp(
                        "192.0.2.9", List.of("203.0.113.7"), List.of("203.0.113.8"), List.of())));
        check("a null trusted list binds the socket peer",
                "192.0.2.9".equals(KiwiVerifyClient.resolveClientIp(
                        "192.0.2.9", List.of("203.0.113.7"), List.of(), null)));
        check("an untrusted peer ignores a forwarded chain even with trusted cidrs configured",
                "203.0.113.50".equals(KiwiVerifyClient.resolveClientIp(
                        "203.0.113.50", List.of("10.0.0.9, 1.2.3.4"), List.of(), List.of("10.0.0.0/24"))));
        check("an untrusted peer ignores x-real-ip even with trusted cidrs configured",
                "203.0.113.50".equals(KiwiVerifyClient.resolveClientIp(
                        "203.0.113.50", List.of(), List.of("1.2.3.4"), List.of("198.51.100.0/24"))));
        check("a trusted peer takes the first untrusted hop left of it",
                "203.0.113.7".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.9", List.of("203.0.113.7, 10.0.0.9"), List.of(), List.of("10.0.0.0/24"))));
        check("the walk stops at the first untrusted hop",
                "1.2.3.4".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.9", List.of("198.51.100.5, 1.2.3.4, 10.0.1.8, 10.0.0.9"), List.of(),
                        List.of("10.0.0.0/24", "10.0.1.0/24"))));
        check("an ipv4 hop with a port is canonicalized",
                "203.0.113.7".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.9", List.of("203.0.113.7:443, 10.0.0.9"), List.of(), List.of("10.0.0.0/24"))));
        check("x-real-ip is the no-chain fallback",
                "198.51.100.9".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.9", List.of(), List.of("198.51.100.9"), List.of("10.0.0.0/24"))));
        check("a malformed hop fails closed to the peer",
                "10.0.0.9".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.9", List.of("203.0.113.7, garbage!!"), List.of(), List.of("10.0.0.0/24"))));
        check("a control character in the chain fails closed to the peer",
                "10.0.0.9".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.9", List.of("203.0.113.7\r\nX-Evil: 1"), List.of(), List.of("10.0.0.0/24"))));
        check("two x-forwarded-for lines are parser ambiguity: the peer wins",
                "10.0.0.9".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.9", List.of("198.51.100.5, 10.0.0.9", "1.2.3.4"), List.of(), List.of("10.0.0.0/24"))));
        check("two x-real-ip lines are parser ambiguity: the peer wins",
                "10.0.0.9".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.9", List.of("198.51.100.5, 10.0.0.9"), List.of("1.2.3.4", "1.2.3.5"),
                        List.of("10.0.0.0/24"))));
        check("a missing peer with trusted cidrs fails closed",
                "".equals(KiwiVerifyClient.resolveClientIp(null, List.of("203.0.113.7"), List.of(), List.of("10.0.0.0/24"))));
        check("a missing peer without trusted cidrs fails closed",
                "".equals(KiwiVerifyClient.resolveClientIp(null, List.of(), List.of(), List.of())));
        check("a peer that is not an ip is never trusted and is returned verbatim",
                "unix-socket".equals(KiwiVerifyClient.resolveClientIp(
                        "unix-socket", List.of("1.2.3.4"), List.of(), List.of("10.0.0.0/24"))));
        check("malformed cidr entries are skipped, never widened",
                "10.0.0.9".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.9", List.of("1.2.3.4"), List.of(), List.of("not-a-cidr", "300.0.0.0/24", "10.0.0.0/99"))));

        // The shared client-ip test vectors, parameterized over
        // tools/client-ip/test-vectors.json exactly like the go and
        // dotnet suites. The Keycloak surface (jakarta MultivaluedMap)
        // sees every X-Forwarded-For header line, so the duplicate
        // scenario asserts the duplicate-visible expectation.
        Path vectors = sharedVectors();
        Object parsed = Json.parse(Files.readString(vectors, StandardCharsets.UTF_8));
        Map<String, Object> document = mapOf(parsed);
        int cidrCases = 0;
        for (Object row : listOf(document.get("cidr_cases"))) {
            Map<String, Object> cidrCase = mapOf(row);
            String cidr = (String) cidrCase.get("cidr");
            String ip = (String) cidrCase.get("ip");
            boolean matches = (Boolean) cidrCase.get("matches");
            check("cidr vector " + cidr + " vs " + ip,
                    KiwiVerifyClient.inTrusted(ip, List.of(cidr)) == matches);
            cidrCases++;
        }
        check("the cidr vector set is non-trivial", cidrCases >= 15);

        int scenarios = 0;
        for (Object row : listOf(document.get("scenarios"))) {
            Map<String, Object> scenario = mapOf(row);
            String id = (String) scenario.get("id");
            String peer = (String) scenario.get("peer");
            Object xffLines = scenario.get("xff_lines");
            List<String> forwarded = xffLines == null ? List.of() : strings(xffLines);
            Object realIp = scenario.get("real_ip");
            List<String> realIpLines = realIp == null ? List.of() : List.of((String) realIp);
            List<String> trusted = strings(scenario.get("trusted"));
            String expected = (String) scenario.get("expected");
            String resolved = KiwiVerifyClient.resolveClientIp(peer, forwarded, realIpLines, trusted);
            check("scenario " + id, expected.equals(resolved));
            scenarios++;
        }
        check("the scenario vector set is non-trivial", scenarios >= 33);

        // Canonical IP edges, the same grammar the dotnet suite pins.
        check("ipv4 with a port canonicalizes", "192.0.2.10".equals(KiwiVerifyClient.canonicalIp(" 192.0.2.10:4711 ")));
        check("uppercase ipv6 canonicalizes compressed", "2001:db8::1".equals(KiwiVerifyClient.canonicalIp("[2001:DB8::1]")));
        check("bracketed ipv6 with a port canonicalizes", "2001:db8::1".equals(KiwiVerifyClient.canonicalIp("[2001:db8::1]:4711")));
        check("ipv4-mapped ipv6 normalizes", "198.51.100.5".equals(KiwiVerifyClient.canonicalIp("::ffff:198.51.100.5")));
        check("long ipv6 spelling compresses", "2001:db8::1".equals(KiwiVerifyClient.canonicalIp("2001:0db8:0:0:0:0:0:1")));
        check("empty is not an ip", KiwiVerifyClient.canonicalIp("") == null);
        check("unknown is not an ip", KiwiVerifyClient.canonicalIp("unknown") == null);
        check("obfuscated tokens are not ips", KiwiVerifyClient.canonicalIp("_obfuscated") == null);
        check("a malformed port refuses", KiwiVerifyClient.canonicalIp("[2001:db8::1]:notaport") == null);
        check("trailing garbage after a bracket refuses", KiwiVerifyClient.canonicalIp("[2001:db8::1]garbage") == null);
        check("port zero refuses", KiwiVerifyClient.canonicalIp("1.2.3.4:0") == null);
        check("an ipv4 tail on one colon refuses", KiwiVerifyClient.canonicalIp("0:1.2.3.4") == null);
        check("five octets refuse", KiwiVerifyClient.canonicalIp("1.2.3.4.5") == null);
        check("decimal integer shorthand refuses", KiwiVerifyClient.canonicalIp("3232235521") == null);
        check("leading-zero octets refuse", KiwiVerifyClient.canonicalIp("01.2.3.4") == null);
        check("a zone identifier refuses", KiwiVerifyClient.canonicalIp("fe80::1%eth0") == null);
        check("a hostname refuses", KiwiVerifyClient.canonicalIp("example.com") == null);
        check("ipv6 port-like text without brackets stays an address",
                "1:2:3:4:5:6:7:8".equals(KiwiVerifyClient.canonicalIp("1:2:3:4:5:6:7:8")));

        // JSON escaping.
        check("quotes escaped", KiwiVerifyClient.jsonEscape("a\"b\\c\nd").equals("a\\\"b\\\\c\\nd"));

        // Live round trips against a local stub.
        AtomicReference<String> seenAuth = new AtomicReference<>("");
        AtomicReference<String> seenBody = new AtomicReference<>("");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/verify", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            seenBody.set(body);
            seenAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            boolean ok = body.contains("good-token");
            byte[] payload = (ok ? "{\"success\":true}" : "{\"success\":false}").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, payload.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(payload);
            }
        });
        server.createContext("/down", exchange -> exchange.sendResponseHeaders(503, -1));
        server.start();
        int port = server.getAddress().getPort();

        KiwiVerifyClient client = new KiwiVerifyClient();
        KiwiVerifyClient.Result result = client.verify(
                "http://127.0.0.1:" + port + "/verify", "sekrit", "good-token", "login", "192.0.2.9");
        check("live verify succeeds", result.ok() && "verified".equals(result.code()));
        check("live request carries the bearer", "Bearer sekrit".equals(seenAuth.get()));
        check("live request carries the token and ip",
                seenBody.get().contains("good-token") && seenBody.get().contains("192.0.2.9"));

        result = client.verify("http://127.0.0.1:" + port + "/verify", "", "stale-token", "login", "192.0.2.9");
        check("live failed challenge denies", !result.ok() && "challenge_failed".equals(result.code()));

        result = client.verify("http://127.0.0.1:" + port + "/down", "", "good-token", "login", "192.0.2.9");
        check("live 5xx fails closed", !result.ok() && "verify_unavailable".equals(result.code()));

        result = client.verify("http://127.0.0.1:1/verify", "", "good-token", "login", "192.0.2.9");
        check("unreachable deployment fails closed", !result.ok() && "verify_unavailable".equals(result.code()));

        server.stop(0);

        System.out.println(checks + " checks, " + failures + " failures");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static KiwiVerifyClient.TokenResolution resolution(List<String> header, List<String> form, List<String> query) {
        return KiwiVerifyClient.resolveTokenValues(header, form, query);
    }

    private static boolean conflict(KiwiVerifyClient.TokenResolution resolution) {
        return KiwiVerifyClient.CODE_TOKEN_SOURCE_CONFLICT.equals(resolution.code());
    }
}
