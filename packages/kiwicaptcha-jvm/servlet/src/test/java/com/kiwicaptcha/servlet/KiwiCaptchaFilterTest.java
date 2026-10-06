package com.kiwicaptcha.servlet;

import com.kiwicaptcha.Canonical;
import com.kiwicaptcha.ChallengeRecord;
import com.kiwicaptcha.Decision;
import com.kiwicaptcha.JsonNumber;
import com.kiwicaptcha.JsonObject;
import com.kiwicaptcha.Kiwi;
import com.kiwicaptcha.MemoryStore;
import com.kiwicaptcha.SolutionToken;
import com.kiwicaptcha.Verifier;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The servlet auto-verify pipeline over a hand-rolled harness. */
class KiwiCaptchaFilterTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef";
    private static final long ISSUED_AT = 1_800_000_000L;

    private record Result(int status, String body, boolean proceeded, Decision decision) {}

    /** Mints one self-signed sha256 record with the public core API only. */
    private static ChallengeRecord mint() {
        byte[] nonceBytes = new byte[Kiwi.NONCE_B64_BYTES];
        byte[] saltBytes = new byte[Kiwi.SALT_B64_BYTES];
        for (int i = 0; i < nonceBytes.length; i++) {
            nonceBytes[i] = (byte) i;
        }
        for (int i = 0; i < saltBytes.length; i++) {
            saltBytes[i] = (byte) (i + 100);
        }
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);
        String salt = Base64.getEncoder().encodeToString(saltBytes);
        long expiresAt = ISSUED_AT + 120;
        String payload = Canonical.canonicalPayloadChecked(2, nonce, "login", "", ISSUED_AT,
                expiresAt, "sha256", 1, 1, 1, 1, salt, 0, "", 1, "", "", 1, "", 0, "", "", false);
        String signature = Canonical.signPayloadV2(payload, SECRET, "");
        String challenge = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + "." + signature;
        ChallengeRecord record = new ChallengeRecord();
        record.nonce = nonce;
        record.scope = "login";
        record.issuedAt = ISSUED_AT;
        record.expiresAt = expiresAt;
        record.algorithm = "sha256";
        record.mKib = 1;
        record.t = 1;
        record.p = 1;
        record.targetBits = 1;
        record.salt = salt;
        record.prefix = challenge + "|" + salt + "|";
        record.challenge = challenge;
        record.issuedAtNs = ISSUED_AT * 1_000_000;
        record.protocolVersion = 2;
        record.policyVersion = 1;
        record.kid = 1;
        return record;
    }

    private static String tokenFor(ChallengeRecord record) {
        return SolutionToken.create(record.nonce,
                solveSha(record.prefix, record.salt, record.targetBits), 5000,
                JsonObject.of("v", new JsonNumber("1")), "", "", "").encode();
    }

    private static int solveSha(String prefix, String saltB64, int targetBits) {
        byte[] saltBytes = Base64.getDecoder().decode(saltB64);
        for (int counter = 0; ; counter++) {
            byte[] prefixBytes = (prefix + counter).getBytes(StandardCharsets.UTF_8);
            byte[] input = new byte[prefixBytes.length + saltBytes.length];
            System.arraycopy(prefixBytes, 0, input, 0, prefixBytes.length);
            System.arraycopy(saltBytes, 0, input, prefixBytes.length, saltBytes.length);
            if (Canonical.leadingZeroBits(Canonical.sha256(input)) >= targetBits) {
                return counter;
            }
        }
    }

    private static Verifier newVerifier(long now) {
        Verifier.Config config = new Verifier.Config();
        config.nowSecs = () -> now;
        return new Verifier(new MemoryStore(), config);
    }

    private Result run(KiwiCaptchaFilter filter, MockHttp.Request request) throws Exception {
        MockHttp.Response response = new MockHttp.Response();
        AtomicBoolean proceeded = new AtomicBoolean();
        filter.doFilter(request, response, (req, res) -> proceeded.set(true));
        Decision decision = (Decision) request.getAttribute(KiwiCaptchaFilter.DECISION_ATTRIBUTE);
        return new Result(response.status(), response.body(), proceeded.get(), decision);
    }

    @Test
    void validTokenProceedsAndRidesTheDecision() throws Exception {
        Verifier verifier = newVerifier(ISSUED_AT);
        ChallengeRecord record = mint();
        KiwiCaptchaFilter filter = new KiwiCaptchaFilter(verifier, SECRET, "login");
        verifier.storage().find(record.nonce);
        ((com.kiwicaptcha.Store.Storer) verifier.storage()).storeRecord(record);
        MockHttp.Request request = new MockHttp.Request("POST", "/api/submit")
                .header(KiwiCaptchaFilter.TOKEN_HEADER, tokenFor(record));
        Result result = run(filter, request);
        assertTrue(result.proceeded());
        assertEquals(200, result.status());
        assertNotNull(result.decision());
        assertEquals(Decision.DISPOSITION_ALLOW, result.decision().disposition);
    }

    @Test
    void missingTokenIsForbidden() throws Exception {
        KiwiCaptchaFilter filter = new KiwiCaptchaFilter(newVerifier(ISSUED_AT), SECRET, "login");
        Result result = run(filter, new MockHttp.Request("POST", "/api/submit"));
        assertEquals(403, result.status());
        assertTrue(result.body().contains("malformed_token"));
        assertTrue(result.body().contains("\"disposition\":\"deny\""));
    }

    @Test
    void formFieldAndQuerySourcesResolve() throws Exception {
        Verifier verifier = newVerifier(ISSUED_AT);
        KiwiCaptchaFilter filter = new KiwiCaptchaFilter(verifier, SECRET, "login");
        ChallengeRecord first = mint();
        ((com.kiwicaptcha.Store.Storer) verifier.storage()).storeRecord(first);
        MockHttp.Request form = new MockHttp.Request("POST", "/api/submit")
                .formBody(Map.of(KiwiCaptchaFilter.TOKEN_FIELD, tokenFor(first)));
        assertTrue(run(filter, form).proceeded());

        ChallengeRecord second = mint();
        ((com.kiwicaptcha.Store.Storer) verifier.storage()).storeRecord(second);
        MockHttp.Request query = new MockHttp.Request("POST", "/api/submit")
                .parameter(KiwiCaptchaFilter.TOKEN_FIELD, tokenFor(second));
        assertTrue(run(filter, query).proceeded());

        // The form-sourced token burned: a fresh replay request is a
        // 403 deny from the retained consumed record.
        MockHttp.Request replayRequest = new MockHttp.Request("POST", "/api/submit")
                .formBody(Map.of(KiwiCaptchaFilter.TOKEN_FIELD, tokenFor(first)));
        Result replay = run(filter, replayRequest);
        assertEquals(403, replay.status());
        assertTrue(replay.body().contains("already_consumed"));
    }

    @Test
    void definitiveDenyAnswersForbidden() throws Exception {
        Verifier verifier = newVerifier(ISSUED_AT);
        ChallengeRecord record = mint();
        KiwiCaptchaFilter filter = new KiwiCaptchaFilter(verifier, SECRET, "login");
        ((com.kiwicaptcha.Store.Storer) verifier.storage()).storeRecord(record);
        MockHttp.Request wrongScope = new MockHttp.Request("POST", "/api/submit")
                .header(KiwiCaptchaFilter.TOKEN_HEADER, tokenFor(record))
                .header("X-Kiwi-Token", "");
        // The header source wins when present; an empty header falls
        // through to the field sources, so drive the scope denial with
        // the verifier expectation instead.
        KiwiCaptchaFilter strict = new KiwiCaptchaFilter(verifier, SECRET, "comment");
        Result result = run(strict, new MockHttp.Request("POST", "/api/submit")
                .parameter(KiwiCaptchaFilter.TOKEN_FIELD, tokenFor(record)));
        assertEquals(403, result.status());
        assertTrue(result.body().contains("wrong_scope"));
    }

    @Test
    void pathPredicateSkipsUnprotectedRoutes() throws Exception {
        KiwiCaptchaFilter filter = new KiwiCaptchaFilter(newVerifier(ISSUED_AT), SECRET, "login",
                path -> path.startsWith("api/protected"), java.util.List.of(), null);
        Result result = run(filter, new MockHttp.Request("GET", "/api/open"));
        assertTrue(result.proceeded());
        assertEquals(200, result.status());
    }

    @Test
    void customDenialRendererWins() throws Exception {
        KiwiCaptchaFilter filter = new KiwiCaptchaFilter(newVerifier(ISSUED_AT), SECRET, "login",
                null, java.util.List.of(), (request, response, decision) -> response.sendRedirect("/login"));
        MockHttp.Response response = new MockHttp.Response();
        filter.doFilter(new MockHttp.Request("POST", "/api/submit"), response, (req, res) -> {});
        assertEquals(302, response.status());
        assertEquals("/login", response.getHeader("Location"));
    }

    @Test
    void filterRunsOncePerRequest() throws Exception {
        Verifier verifier = newVerifier(ISSUED_AT);
        ChallengeRecord record = mint();
        KiwiCaptchaFilter filter = new KiwiCaptchaFilter(verifier, SECRET, "login");
        ((com.kiwicaptcha.Store.Storer) verifier.storage()).storeRecord(record);
        MockHttp.Request request = new MockHttp.Request("POST", "/api/submit")
                .header(KiwiCaptchaFilter.TOKEN_HEADER, tokenFor(record));
        run(filter, request);
        // A second chain pass on the same request object must not
        // re-verify: the decision attribute marks the request done.
        MockHttp.Response response = new MockHttp.Response();
        AtomicBoolean proceeded = new AtomicBoolean();
        filter.doFilter(request, response, (req, res) -> proceeded.set(true));
        assertTrue(proceeded.get());
        assertEquals(200, response.status());
    }

    @Test
    void clientIpResolution() {
        MockHttp.Request direct = new MockHttp.Request("POST", "/x");
        assertEquals("127.0.0.1", KiwiCaptchaFilter.clientIpFromRequest(direct, java.util.List.of()));
        MockHttp.Request forwarded = new MockHttp.Request("POST", "/x")
                .header("X-Forwarded-For", "203.0.113.9, 10.0.0.1");
        // The peer must sit inside the trust list before any
        // forwarded header is read at all.
        assertEquals("127.0.0.1", KiwiCaptchaFilter.clientIpFromRequest(forwarded, java.util.List.of("10.0.0.0/24")));
        MockHttp.Request trusted = new MockHttp.Request("POST", "/x")
                .remoteAddr("10.0.0.9")
                .header("X-Forwarded-For", "203.0.113.9, 10.0.0.9");
        assertEquals("203.0.113.9", KiwiCaptchaFilter.clientIpFromRequest(trusted, java.util.List.of("10.0.0.0/24")));
        assertEquals("10.0.0.9", KiwiCaptchaFilter.clientIpFromRequest(trusted, java.util.List.of()));
    }
}
