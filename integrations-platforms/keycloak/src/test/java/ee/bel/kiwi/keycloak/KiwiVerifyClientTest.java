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
        // Decision surface without network: scan the provider body.
        check("success body is detected", KiwiVerifyClient.responseBodyHasSuccess("{\"success\":true,\"error-codes\":[]}"));
        check("failure body is rejected", !KiwiVerifyClient.responseBodyHasSuccess("{\"success\":false}"));
        check("whitespace tolerance", KiwiVerifyClient.responseBodyHasSuccess("{ \"success\" : true }"));
        check("success in a string is not success", !KiwiVerifyClient.responseBodyHasSuccess("{\"x\":\"success:true\"}"));
        check("empty body is rejected", !KiwiVerifyClient.responseBodyHasSuccess(""));

        // Token extraction order: header first, then the field list.
        var fields = KiwiVerifyClient.tokenFieldNames();
        check("field list is the incumbent set", fields.contains("kiwi__token") && fields.contains("g-recaptcha-response"));
        check("header wins", "hdr".equals(KiwiVerifyClient.extractToken(" hdr ", fields, f -> "form-token")));
        check("native field first", "native".equals(KiwiVerifyClient.extractToken(null, fields,
                f -> f.equals("kiwi__token") ? "native" : "other")));
        check("incumbent field found", "legacy".equals(KiwiVerifyClient.extractToken(null, fields,
                f -> f.equals("h-captcha-response") ? "legacy" : null)));
        check("missing token is null", KiwiVerifyClient.extractToken("  ", fields, f -> null) == null);

        // Ip binding: the client must never parse forwarding headers
        // again — the authenticator passes Keycloak's socket peer (the
        // value KC_PROXY adjusts) straight through.
        check("no forwarding-header parser remains",
                java.util.Arrays.stream(KiwiVerifyClient.class.getDeclaredMethods())
                        .noneMatch(m -> m.getName().equals("clientIp")));

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
