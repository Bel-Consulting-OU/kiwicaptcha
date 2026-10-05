package com.kiwicaptcha;

import java.util.List;
import java.util.Locale;

/**
 * Deployment settings: the four-setting quickstart and the verifier
 * factory. Settings carries the deployment inputs the SDK needs at
 * boot: the signing secret, the store url, the accepted scopes and
 * the profile naming the challenge budget the deployment issues.
 * Everything else stays optional.
 */
public final class Settings {
    /** The hmac master secret, at least 32 bytes. */
    public String secret = "";
    /** A store url: memory:// (the default) or redis://host. */
    public String store = "memory://";
    /** The accepted challenge scopes; an empty list accepts any scope. */
    public List<String> scopes = List.of();
    /** The deployment's issuance budget: standard, argon16, argon32 or argon64. */
    public String profile = "standard";
    /** Pins the expected deployment region when set. */
    public String region = "";
    /** Pins the security-policy epoch when set; floor declares the rollout window below it. */
    public int expectedPolicyVersion;
    public int policyVersionFloor;
    /** Pins the deployment issuer when set. */
    public String expectedIssuer = "";
    /** Scopes the derived purpose keys when set. */
    public String tenantId = "";
    /** Opens the bounded v1 migration window. */
    public boolean acceptLegacyV1;

    /** The named challenge budgets, mirroring the issuance-side profiles. */
    public static final List<String> PROFILES = List.of("standard", "argon16", "argon32", "argon64");

    /** Reports whether the profile names a shipped budget. */
    public static boolean profileKnown(String profile) {
        return PROFILES.contains(profile);
    }

    /** Wires the settings into a verifier over the store the url selects. */
    public Verifier buildVerifier() {
        if (secret.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < Kiwi.MIN_SECRET_BYTES) {
            throw new Canonical.SecretTooShortException();
        }
        if (!profileKnown(profile)) {
            throw new IllegalArgumentException(
                    "kiwicaptcha: the profile must be one of standard, argon16, argon32, argon64");
        }
        Verifier.Config config = new Verifier.Config();
        config.acceptLegacyV1 = acceptLegacyV1;
        config.region = region;
        config.expectedPolicyVersion = expectedPolicyVersion;
        config.policyVersionFloor = policyVersionFloor;
        config.expectedIssuer = expectedIssuer;
        config.tenantId = tenantId;
        Verifier.Config validated = Verifier.validateConfig(config);
        Store.StoreAdapter storage = openStore(store);
        return new Verifier(storage, validated);
    }

    /**
     * Builds a store adapter from a url. memory:// builds the
     * in-process store and redis://host:port or rediss:// builds the
     * shared backend over the shipped wire protocol client. The empty
     * url defaults to memory://. A sqlite:// url is refused with a
     * pointer to the deployment options documented in the readme.
     */
    public static Store.StoreAdapter openStore(String url) {
        String scheme = url == null ? "" : url;
        int idx = scheme.indexOf("://");
        if (idx >= 0) {
            scheme = scheme.substring(0, idx);
        }
        return switch (scheme.toLowerCase(Locale.ROOT)) {
            case "", "memory" -> new MemoryStore();
            case "redis", "rediss" -> new RedisStore(RespClient.dial(url), Kiwi.ENVELOPE_DEFAULT_PREFIX);
            case "sqlite" -> throw new IllegalArgumentException(
                    "kiwicaptcha: the core artifact stays dependency-free, so a sqlite:// url needs the "
                            + "optional kiwicaptcha-stores-sqlite module (sqlite-jdbc); depend on it and build "
                            + "SqliteStore from com.kiwicaptcha.stores.sqlite directly, or wire its adapter into "
                            + "the Verifier yourself");
            default -> throw new IllegalArgumentException(
                    "kiwicaptcha: unsupported store url scheme: use memory:// or redis://");
        };
    }
}
