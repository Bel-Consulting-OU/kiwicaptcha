package com.kiwicaptcha.spring;

import com.kiwicaptcha.Settings;
import com.kiwicaptcha.Verifier;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The four-setting quickstart as Spring configuration properties,
 * under the kiwicaptcha.* namespace: kiwicaptcha.secret,
 * kiwicaptcha.store, kiwicaptcha.scopes and kiwicaptcha.profile
 * carry a deployment; the expectation knobs stay optional.
 */
@ConfigurationProperties(prefix = "kiwicaptcha")
public class KiwiCaptchaProperties {
    /** The hmac master secret, at least 32 bytes. */
    private String secret = "";
    /** A store url: memory:// (the default) or redis://host:port. */
    private String store = "memory://";
    /** The accepted challenge scopes; an empty list accepts any scope. */
    private java.util.List<String> scopes = new java.util.ArrayList<>();
    /** The deployment's issuance budget: standard, argon16, argon32 or argon64. */
    private String profile = "standard";
    /** Pins the expected deployment region when set. */
    private String region = "";
    /** Pins the security-policy epoch when set. */
    private int expectedPolicyVersion;
    /** Declares the rollout window below the expected epoch. */
    private int policyVersionFloor;
    /** Pins the deployment issuer when set. */
    private String expectedIssuer = "";
    /** Scopes the derived purpose keys when set. */
    private String tenantId = "";
    /** Opens the bounded v1 migration window. */
    private boolean acceptLegacyV1;
    /** The route scope the middleware pins, empty accepts any. */
    private String expectedScope = "";
    /** The trusted-proxy CIDR list; empty (the default) never trusts a forwarded header. */
    private java.util.List<String> trustedProxies = new java.util.ArrayList<>();
    /** The servlet url patterns the filter protects. */
    private java.util.List<String> urlPatterns = new java.util.ArrayList<>(java.util.List.of("/*"));

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getStore() {
        return store;
    }

    public void setStore(String store) {
        this.store = store;
    }

    public java.util.List<String> getScopes() {
        return scopes;
    }

    public void setScopes(java.util.List<String> scopes) {
        this.scopes = scopes;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public int getExpectedPolicyVersion() {
        return expectedPolicyVersion;
    }

    public void setExpectedPolicyVersion(int expectedPolicyVersion) {
        this.expectedPolicyVersion = expectedPolicyVersion;
    }

    public int getPolicyVersionFloor() {
        return policyVersionFloor;
    }

    public void setPolicyVersionFloor(int policyVersionFloor) {
        this.policyVersionFloor = policyVersionFloor;
    }

    public String getExpectedIssuer() {
        return expectedIssuer;
    }

    public void setExpectedIssuer(String expectedIssuer) {
        this.expectedIssuer = expectedIssuer;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public boolean isAcceptLegacyV1() {
        return acceptLegacyV1;
    }

    public void setAcceptLegacyV1(boolean acceptLegacyV1) {
        this.acceptLegacyV1 = acceptLegacyV1;
    }

    public String getExpectedScope() {
        return expectedScope;
    }

    public void setExpectedScope(String expectedScope) {
        this.expectedScope = expectedScope;
    }

    public java.util.List<String> getTrustedProxies() {
        return trustedProxies;
    }

    public void setTrustedProxies(java.util.List<String> trustedProxies) {
        this.trustedProxies = trustedProxies;
    }

    public java.util.List<String> getUrlPatterns() {
        return urlPatterns;
    }

    public void setUrlPatterns(java.util.List<String> urlPatterns) {
        this.urlPatterns = urlPatterns;
    }

    /** Maps the properties onto the core Settings. */
    public Settings toSettings() {
        Settings settings = new Settings();
        settings.secret = secret;
        settings.store = store;
        settings.scopes = scopes;
        settings.profile = profile;
        settings.region = region;
        settings.expectedPolicyVersion = expectedPolicyVersion;
        settings.policyVersionFloor = policyVersionFloor;
        settings.expectedIssuer = expectedIssuer;
        settings.tenantId = tenantId;
        settings.acceptLegacyV1 = acceptLegacyV1;
        return settings;
    }

    /** Builds the verifier the middleware shares. */
    public Verifier buildVerifier() {
        return toSettings().buildVerifier();
    }
}
