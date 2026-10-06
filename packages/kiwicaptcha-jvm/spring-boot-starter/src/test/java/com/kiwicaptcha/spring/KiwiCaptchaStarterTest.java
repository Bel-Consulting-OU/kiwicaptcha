package com.kiwicaptcha.spring;

import com.kiwicaptcha.spring.MockHttp;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The starter surface over the hand-rolled servlet harness: the
 * property mapping, the auto-configuration wiring and the MVC
 * interceptor behavior. The beans are exercised directly, so no
 * spring-test dependency is needed.
 */
class KiwiCaptchaStarterTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef";
    private static final long ISSUED_AT = 1_800_000_000L;

    @Test
    void propertiesMapOntoTheCoreSettings() {
        KiwiCaptchaProperties properties = new KiwiCaptchaProperties();
        properties.setSecret(SECRET);
        properties.setStore("memory://");
        properties.setScopes(java.util.List.of("login"));
        properties.setProfile("argon16");
        properties.setExpectedScope("login");
        properties.setRegion("eu");
        properties.setExpectedPolicyVersion(3);
        properties.setPolicyVersionFloor(2);
        assertEquals("memory://", properties.getStore());
        assertEquals(java.util.List.of("login"), properties.getScopes());
        assertEquals("argon16", properties.getProfile());
        com.kiwicaptcha.Settings settings = properties.toSettings();
        assertEquals(SECRET, settings.secret);
        assertEquals("eu", settings.region);
        assertEquals(3, settings.expectedPolicyVersion);
        assertEquals(2, settings.policyVersionFloor);
    }

    @Test
    void propertiesBuildVerifier() {
        KiwiCaptchaProperties properties = new KiwiCaptchaProperties();
        properties.setSecret(SECRET);
        assertNotNull(properties.buildVerifier());
    }

    @Test
    void autoConfigurationWiresFilterRegistration() {
        KiwiCaptchaProperties properties = new KiwiCaptchaProperties();
        properties.setSecret(SECRET);
        KiwiCaptchaAutoConfiguration configuration = new KiwiCaptchaAutoConfiguration();
        com.kiwicaptcha.Verifier verifier = configuration.kiwiVerifier(properties);
        assertNotNull(verifier);
        var registration = configuration.kiwiCaptchaFilter(verifier, properties);
        assertFalse(registration.getUrlPatterns().isEmpty());
        assertEquals("/*", registration.getUrlPatterns().iterator().next());
    }

    @Test
    void autoConfigurationBacksOffWithoutASecret() {
        // The @ConditionalOnProperty gate is declared on the class; a
        // missing secret means the deployment wires its own beans.
        KiwiCaptchaProperties properties = new KiwiCaptchaProperties();
        assertEquals("", properties.getSecret());
        assertTrue(KiwiCaptchaAutoConfiguration.class
                .isAnnotationPresent(org.springframework.boot.autoconfigure.condition.ConditionalOnProperty.class));
    }

    @Test
    void interceptorVerifiesAndDenies() throws Exception {
        KiwiCaptchaProperties properties = new KiwiCaptchaProperties();
        properties.setSecret(SECRET);
        com.kiwicaptcha.Verifier verifier = properties.buildVerifier();
        KiwiTokenInterceptor interceptor = new KiwiTokenInterceptor(verifier, SECRET, "login", java.util.List.of());
        MockHttp.Request request = new MockHttp.Request("POST", "/api/submit");
        MockHttp.Response response = new MockHttp.Response();
        boolean proceeded = interceptor.preHandle(request, response, new Object());
        assertFalse(proceeded);
        assertEquals(403, response.status());
        assertTrue(response.body().contains("malformed_token"));
    }

    @Test
    void interceptorAcceptsAQueryToken() throws Exception {
        // The verifier clock pins to the issuance window, as a real
        // deployment's hosts stay NTP-synced with the issuer.
        com.kiwicaptcha.Verifier.Config config = new com.kiwicaptcha.Verifier.Config();
        config.nowSecs = () -> ISSUED_AT;
        com.kiwicaptcha.Verifier verifier = new com.kiwicaptcha.Verifier(
                new com.kiwicaptcha.MemoryStore(), config);
        KiwiTokenInterceptor interceptor = new KiwiTokenInterceptor(verifier, SECRET, "login", java.util.List.of());
        ChallengeMinter.Minted minted = ChallengeMinter.mint(ISSUED_AT);
        ((com.kiwicaptcha.Store.Storer) verifier.storage()).storeRecord(minted.record());
        MockHttp.Request request = new MockHttp.Request("POST", "/api/submit")
                .parameter("kiwi_token", minted.token());
        MockHttp.Response response = new MockHttp.Response();
        boolean proceeded = interceptor.preHandle(request, response, new Object());
        assertTrue(proceeded);
        assertEquals(200, response.status());
        assertNotNull(request.getAttribute("com.kiwicaptcha.decision"));
    }

    /** Self-signed record minting with the public core API. */
    static final class ChallengeMinter {
        record Minted(com.kiwicaptcha.ChallengeRecord record, String token) {}

        static Minted mint(long issuedAt) {
            byte[] nonceBytes = new byte[com.kiwicaptcha.Kiwi.NONCE_B64_BYTES];
            byte[] saltBytes = new byte[com.kiwicaptcha.Kiwi.SALT_B64_BYTES];
            for (int i = 0; i < nonceBytes.length; i++) {
                nonceBytes[i] = (byte) i;
            }
            for (int i = 0; i < saltBytes.length; i++) {
                saltBytes[i] = (byte) (i + 100);
            }
            String nonce = java.util.Base64.getEncoder().encodeToString(nonceBytes);
            String salt = java.util.Base64.getEncoder().encodeToString(saltBytes);
            long expiresAt = issuedAt + 120;
            String payload = com.kiwicaptcha.Canonical.canonicalPayloadChecked(2, nonce, "login", "",
                    issuedAt, expiresAt, "sha256", 1, 1, 1, 1, salt, 0, "", 1, "", "", 1, "", 0, "", "", false);
            String signature = com.kiwicaptcha.Canonical.signPayloadV2(payload, SECRET, "");
            String challenge = java.util.Base64.getEncoder()
                    .encodeToString(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    + "." + signature;
            com.kiwicaptcha.ChallengeRecord record = new com.kiwicaptcha.ChallengeRecord();
            record.nonce = nonce;
            record.scope = "login";
            record.issuedAt = issuedAt;
            record.expiresAt = expiresAt;
            record.algorithm = "sha256";
            record.mKib = 1;
            record.t = 1;
            record.p = 1;
            record.targetBits = 1;
            record.salt = salt;
            record.prefix = challenge + "|" + salt + "|";
            record.challenge = challenge;
            record.issuedAtNs = issuedAt * 1_000_000;
            record.protocolVersion = 2;
            record.policyVersion = 1;
            record.kid = 1;
            // Search the counter to the target the way the widget does.
            long counter = 0;
            byte[] proofSalt = java.util.Base64.getDecoder().decode(salt);
            while (true) {
                byte[] prefixBytes = (record.prefix + counter).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] input = new byte[prefixBytes.length + saltBytes.length];
                System.arraycopy(prefixBytes, 0, input, 0, prefixBytes.length);
                System.arraycopy(proofSalt, 0, input, prefixBytes.length, proofSalt.length);
                if (com.kiwicaptcha.Canonical.leadingZeroBits(
                        com.kiwicaptcha.Canonical.sha256(input)) >= record.targetBits) {
                    break;
                }
                counter++;
            }
            String token = com.kiwicaptcha.SolutionToken.create(nonce, counter, 1500,
                    com.kiwicaptcha.JsonObject.of("v", new com.kiwicaptcha.JsonNumber("1")),
                    "", "", "").encode();
            return new Minted(record, token);
        }
    }
}
