package com.kiwicaptcha;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * The doctor checks: one surface that validates a deployment. The
 * command form lives in DoctorMain and runs four checks against a
 * deployment description: the settings shape, the secret length, a
 * full store roundtrip (store, find, consume, commit, delete) and the
 * proof budget of the configured profile. Exit code 0 means every
 * check passed.
 */
public final class Doctor {
    private Doctor() {}

    /** One named check result. */
    public static final class Check {
        public final String name;
        public final boolean ok;
        public final String detail;

        public Check(String name, boolean ok, String detail) {
            this.name = name;
            this.ok = ok;
            this.detail = detail;
        }
    }

    private record ProfileBudget(String algorithm, int bits, int memoryKib) {}

    /** The named challenge budgets mirror the issuance-side profiles. */
    private static ProfileBudget profileBudget(String profile) {
        return switch (profile) {
            case "standard" -> new ProfileBudget("sha256", 12, 0);
            case "argon16" -> new ProfileBudget("argon2id", 8, 16);
            case "argon32" -> new ProfileBudget("argon2id", 6, 32);
            case "argon64" -> new ProfileBudget("argon2id", 4, 64);
            default -> null;
        };
    }

    /** Validates the settings shape and the secret length. */
    public static Check checkSettings(String secret, String profile) {
        if (secret.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < Kiwi.MIN_SECRET_BYTES) {
            return new Check("settings", false,
                    "the secret must be at least " + Kiwi.MIN_SECRET_BYTES + " bytes");
        }
        if (Settings.profileKnown(profile)) {
            return new Check("settings", true, "the settings shape is valid");
        }
        return new Check("settings", false,
                "the profile must be one of standard, argon16, argon32, argon64");
    }

    /** Mints a locally signed self-check record that never leaves the store. */
    static ChallengeRecord doctorSelfCheckRecord() {
        String secret = "kiwicaptcha-doctor-self-check-secret-0000";
        byte[] nonceBytes = new byte[Kiwi.NONCE_B64_BYTES];
        byte[] saltBytes = new byte[Kiwi.SALT_B64_BYTES];
        new SecureRandom().nextBytes(nonceBytes);
        new SecureRandom().nextBytes(saltBytes);
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);
        String salt = Base64.getEncoder().encodeToString(saltBytes);
        long now = System.currentTimeMillis() / 1000;
        long expires = now + 60;
        String payload = Canonical.canonicalPayload(2, nonce, "doctor", "", now, expires,
                "sha256", 1, 1, 1, 1, salt, 0, "", 1, "", "", 1, "", 0, "", "", false);
        String signature = Canonical.signPayloadV2(payload, secret, "");
        String challenge = payload + "." + signature;
        ChallengeRecord record = new ChallengeRecord();
        record.nonce = nonce;
        record.scope = "doctor";
        record.issuedAt = now;
        record.expiresAt = expires;
        record.algorithm = "sha256";
        record.mKib = 1;
        record.t = 1;
        record.p = 1;
        record.targetBits = 1;
        record.salt = salt;
        record.prefix = challenge + "|" + salt + "|";
        record.challenge = challenge;
        record.protocolVersion = 2;
        record.policyVersion = 1;
        record.kid = 1;
        return record;
    }

    /** Opens the store url and runs a full one-shot roundtrip. */
    public static Check checkStore(String storeUrl) {
        Store.StoreAdapter storage;
        try {
            storage = Settings.openStore(storeUrl);
        } catch (RuntimeException e) {
            return new Check("store", false, "the store did not open: " + e.getMessage());
        }
        ChallengeRecord record;
        try {
            record = doctorSelfCheckRecord();
        } catch (RuntimeException e) {
            return new Check("store", false, "the self-check record failed: " + e.getMessage());
        }
        if (!(storage instanceof Store.Storer storer)) {
            return new Check("store", false, "the store cannot accept records");
        }
        try {
            storer.storeRecord(record);
        } catch (RuntimeException e) {
            return new Check("store", false, "the store rejected the record: " + e.getMessage());
        }
        ChallengeRecord found;
        try {
            found = storage.find(record.nonce);
        } catch (RuntimeException e) {
            return new Check("store", false, "the store read failed: " + e.getMessage());
        }
        if (found == null) {
            return new Check("store", false, "the store lost the record");
        }
        Store.ConsumedRecord consumed;
        try {
            consumed = storage.consume(record.nonce);
        } catch (RuntimeException e) {
            return new Check("store", false, "the consume failed: " + e.getMessage());
        }
        if (consumed == null || !consumed.consumedNow) {
            return new Check("store", false, "the consume transition did not win");
        }
        boolean committed;
        try {
            committed = storage.commitResult(record.nonce, true, "");
        } catch (RuntimeException e) {
            return new Check("store", false, "the commit failed: " + e.getMessage());
        }
        if (!committed) {
            return new Check("store", false, "the commit refused");
        }
        boolean deleted;
        try {
            deleted = storage.delete(record.nonce);
        } catch (RuntimeException e) {
            return new Check("store", false, "the delete failed: " + e.getMessage());
        }
        if (!deleted) {
            return new Check("store", false, "the delete refused");
        }
        return new Check("store", true, "the store roundtrip is one-shot and clean");
    }

    /** Validates every configured scope. */
    public static Check checkScopes(List<String> scopes) {
        for (String scope : scopes) {
            if (!ChallengeRecord.isValidIdentifier(scope, 128)) {
                return new Check("scopes", false, "the scope " + scope + " is not a valid identifier");
            }
        }
        if (scopes.isEmpty()) {
            return new Check("scopes", true, "no scopes configured (every scope is accepted)");
        }
        StringBuilder detail = new StringBuilder("every scope is a valid identifier:");
        for (String scope : scopes) {
            detail.append(' ').append(scope);
        }
        return new Check("scopes", true, detail.toString());
    }

    /** Measures the proof budget of the configured profile. */
    public static Check checkProofBudget(String profile) {
        ProfileBudget budget = profileBudget(profile);
        if (budget == null) {
            return new Check("proof_budget", false,
                    "the profile must be one of standard, argon16, argon32, argon64");
        }
        byte[] salt = new byte[Kiwi.SALT_B64_BYTES];
        long started = System.currentTimeMillis();
        if (budget.algorithm().equals("sha256")) {
            String prefix = "doctor|";
            for (int counter = 0; counter <= 2_000_000; counter++) {
                byte[] digest = Canonical.sha256((prefix + counter + new String(salt, java.nio.charset.StandardCharsets.ISO_8859_1))
                        .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
                if (Canonical.leadingZeroBits(digest) >= budget.bits()) {
                    long elapsed = System.currentTimeMillis() - started;
                    return new Check("proof_budget", true,
                            "sha256 at " + budget.bits() + " bits solved in " + elapsed
                                    + " ms (" + counter + " iterations)");
                }
            }
            return new Check("proof_budget", false, "the sha256 budget search ran away");
        }
        Argon2id.derive("doctor".getBytes(java.nio.charset.StandardCharsets.UTF_8), salt,
                3, budget.memoryKib(), 1, 32, new byte[0], new byte[0]);
        long elapsed = System.currentTimeMillis() - started;
        return new Check("proof_budget", true,
                "argon2id m=" + budget.memoryKib() + " t=3 derived in " + elapsed
                        + " ms; the " + profile + " rung accepts " + budget.bits() + " target bits");
    }

    /** Executes every check and reports them in order. */
    public static List<Check> run(String secret, String storeUrl, List<String> scopes, String profile) {
        List<Check> results = new ArrayList<>();
        results.add(checkSettings(secret, profile));
        results.add(checkStore(storeUrl));
        results.add(checkScopes(scopes));
        results.add(checkProofBudget(profile));
        return results;
    }
}
