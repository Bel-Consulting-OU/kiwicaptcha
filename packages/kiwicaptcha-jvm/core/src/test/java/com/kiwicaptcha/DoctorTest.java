package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The doctor checks and the settings factory. */
class DoctorTest {

    @Test
    void settingsCheck() {
        assertFalse(Doctor.checkSettings("short", "standard").ok);
        assertFalse(Doctor.checkSettings(Support.TEST_SECRET, "scrypt").ok);
        assertTrue(Doctor.checkSettings(Support.TEST_SECRET, "standard").ok);
        assertTrue(Doctor.checkSettings(Support.TEST_SECRET, "argon64").ok);
    }

    @Test
    void storeCheckMemory() {
        Doctor.Check check = Doctor.checkStore("memory://");
        assertTrue(check.ok, check.detail);
    }

    @Test
    void storeCheckBadUrl() {
        assertFalse(Doctor.checkStore("bogus://").ok);
        assertFalse(Doctor.checkStore("sqlite://x").ok);
    }

    @Test
    void scopesCheck() {
        assertTrue(Doctor.checkScopes(List.of()).ok);
        assertTrue(Doctor.checkScopes(List.of("login", "comment")).ok);
        assertFalse(Doctor.checkScopes(List.of("bad scope")).ok);
    }

    @Test
    void proofBudgetSha() {
        Doctor.Check check = Doctor.checkProofBudget("standard");
        assertTrue(check.ok, check.detail);
    }

    @Test
    void proofBudgetArgon() {
        Doctor.Check check = Doctor.checkProofBudget("argon16");
        assertTrue(check.ok, check.detail);
        assertFalse(Doctor.checkProofBudget("scrypt").ok);
    }

    @Test
    void doctorRunOrder() {
        List<Doctor.Check> results = Doctor.run(Support.TEST_SECRET, "memory://", List.of("login"), "standard");
        assertEquals(4, results.size());
        assertEquals("settings", results.get(0).name);
        assertEquals("store", results.get(1).name);
        assertEquals("scopes", results.get(2).name);
        assertEquals("proof_budget", results.get(3).name);
    }

    @Test
    void selfCheckRecordVerifies() {
        ChallengeRecord record = Doctor.doctorSelfCheckRecord();
        assertTrue(Canonical.verifyRecordSignature(record, "kiwicaptcha-doctor-self-check-secret-0000", ""));
    }

    @Test
    void settingsBuildVerifierMemory() {
        Settings settings = new Settings();
        settings.secret = Support.TEST_SECRET;
        settings.store = "memory://";
        settings.profile = "standard";
        Verifier verifier = settings.buildVerifier();
        assertNotNull(verifier.storage());
    }

    @Test
    void settingsBuildVerifierBadProfile() {
        Settings settings = new Settings();
        settings.secret = Support.TEST_SECRET;
        settings.profile = "scrypt";
        assertThrows(RuntimeException.class, () -> settings.buildVerifier());
    }

    @Test
    void settingsBuildVerifierShortSecret() {
        Settings settings = new Settings();
        settings.secret = "short";
        assertThrows(RuntimeException.class, () -> settings.buildVerifier());
    }
}
