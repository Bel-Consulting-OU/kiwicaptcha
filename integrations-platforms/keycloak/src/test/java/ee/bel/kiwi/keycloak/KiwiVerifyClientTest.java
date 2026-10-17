package ee.bel.kiwi.keycloak;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;

/**
 * The plain-JDK test of the kiwi verify client: the decision surface
 * (status mapping, body scanning), token extraction, ip binding,
 * JSON escaping, plus a live round trip against a local HttpServer
 * stub. Run after a javac of the two files (see README.md).
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

        // Token extraction order: header first, then the field list.
        var fields = KiwiVerifyClient.tokenFieldNames();
        check("field list is the incumbent set", fields.contains("kiwi__token") && fields.contains("g-recaptcha-response"));
        check("header wins", "hdr".equals(KiwiVerifyClient.extractToken(" hdr ", fields, f -> "form-token")));
        check("native field first", "native".equals(KiwiVerifyClient.extractToken(null, fields,
                f -> f.equals("kiwi__token") ? "native" : "other")));
        check("incumbent field found", "legacy".equals(KiwiVerifyClient.extractToken(null, fields,
                f -> f.equals("h-captcha-response") ? "legacy" : null)));
        check("missing token is null", KiwiVerifyClient.extractToken("  ", fields, f -> null) == null);

        // Ip binding: the forwarding-header resolver is explicit and
        // opt-in. Off (the default) the socket peer wins and headers
        // are ignored; on, the rightmost hop appended by the nearest
        // proxy is taken, so a client-supplied leftmost entry can
        // never choose the binding.
        check("trustProxy off binds the socket peer",
                "192.0.2.9".equals(KiwiVerifyClient.resolveClientIp(
                        "192.0.2.9", "203.0.113.7", "203.0.113.8", false)));
        check("trustProxy takes the rightmost forwarded hop",
                "203.0.113.7".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.1", "6.6.6.6, 203.0.113.7", null, true)));
        check("a client-supplied leftmost entry is ignored",
                "198.51.100.4".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.1", "6.6.6.6, 198.51.100.4", null, true)));
        check("an IPv4 hop with a port is canonicalized",
                "203.0.113.7".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.1", "203.0.113.7:443", null, true)));
        check("X-Real-IP is the no-chain fallback",
                "198.51.100.9".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.1", null, "198.51.100.9", true)));
        check("a malformed hop falls back to the peer",
                "10.0.0.1".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.1", "203.0.113.7, garbage!!", null, true)));
        check("a control character in the chain falls back to the peer",
                "10.0.0.1".equals(KiwiVerifyClient.resolveClientIp(
                        "10.0.0.1", "203.0.113.7\r\nX-Evil: 1", null, true)));
        check("a missing peer fails closed",
                "".equals(KiwiVerifyClient.resolveClientIp(null, "203.0.113.7", null, true)));
        check("a malformed peer fails closed",
                "".equals(KiwiVerifyClient.resolveClientIp("not-an-ip", null, null, false)));

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
}
