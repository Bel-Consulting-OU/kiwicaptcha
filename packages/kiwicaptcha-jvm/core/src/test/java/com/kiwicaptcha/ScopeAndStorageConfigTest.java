package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The configured scope allowlist and the storage seam of
 * {@link Verifier.Config}.
 */
class ScopeAndStorageConfigTest {

    private static String tokenFor(ChallengeRecord record) {
        return SolutionToken.create(record.nonce,
                Support.solveSha(record.prefix, record.salt, record.targetBits), 5000,
                new JsonObject(), "", "", "").encode();
    }

    private static Verifier.Options options(String expectedScope) {
        Verifier.Options options = new Verifier.Options();
        options.secretKey = Support.TEST_SECRET;
        options.expectedScope = expectedScope;
        options.clientIp = Support.TEST_CLIENT_IP;
        return options;
    }

    @Test
    void allowlistAllowsAConfiguredScope() {
        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        Verifier.Config config = new Verifier.Config();
        config.scopes = List.of("login", "comment");
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireValid(verifier.verify(tokenFor(record), options("login")));
    }

    @Test
    void allowlistRejectsAnExpectedScopeOutsideTheSet() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.scope = "signup";
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config config = new Verifier.Config();
        config.scopes = List.of("login", "comment");
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        // The record and the expected scope agree; only the allowlist
        // refuses, with the existing wrong_scope code.
        Support.requireCode(verifier.verify(tokenFor(record), options("signup")),
                VerifyError.WRONG_SCOPE);
    }

    @Test
    void emptyAllowlistAcceptsAnyScope() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.scope = "signup";
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireValid(verifier.verify(tokenFor(record), options("signup")));
    }

    @Test
    void settingsCarryTheAllowlistIntoTheVerifier() {
        Settings settings = new Settings();
        settings.secret = Support.TEST_SECRET;
        settings.store = "memory://";
        settings.scopes = List.of("login");
        settings.profile = "standard";
        Verifier verifier = settings.buildVerifier();
        Support.MintOptions mint = new Support.MintOptions();
        mint.scope = "comment";
        // The settings-built verifier runs on the wall clock.
        mint.issuedAt = System.currentTimeMillis() / 1000 - 10;
        ChallengeRecord record = Support.mintRecord(mint);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenFor(record), options("comment")),
                VerifyError.WRONG_SCOPE);
    }

    @Test
    void configOnlyConstructionUsesTheConfigStorage() {
        Verifier.Config config = new Verifier.Config();
        config.storage = new MemoryStore();
        config.nowSecs = () -> Support.TEST_NOW;
        Verifier verifier = new Verifier(config);
        assertSame(config.storage, verifier.storage());

        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        Support.storeRecord(verifier.storage(), record);
        Support.requireValid(verifier.verify(tokenFor(record), options("login")));
    }

    @Test
    void matchingStorageArgumentsAreAccepted() {
        MemoryStore storage = new MemoryStore();
        Verifier.Config config = new Verifier.Config();
        config.storage = storage;
        assertSame(storage, new Verifier(storage, config).storage());
    }

    @Test
    void conflictingStorageArgumentsAreRejected() {
        Verifier.Config config = new Verifier.Config();
        config.storage = new MemoryStore();
        Verifier.VerifierBuildException raised = assertThrows(
                Verifier.VerifierBuildException.class,
                () -> new Verifier(new MemoryStore(), config));
        assertTrue(raised.getMessage().contains("disagree"), raised.getMessage());
    }

    @Test
    void missingStoreArgumentsAreRejected() {
        assertThrows(Verifier.VerifierBuildException.class,
                () -> new Verifier(new Verifier.Config()));
        assertThrows(Verifier.VerifierBuildException.class,
                () -> new Verifier((Store.StoreAdapter) null, new Verifier.Config()));
        assertNotNull(new Verifier(new MemoryStore(), new Verifier.Config()).storage());
    }

    @Test
    void doctorStillValidatesScopes() {
        assertTrue(Doctor.checkScopes(List.of()).ok);
        assertTrue(Doctor.checkScopes(List.of("login", "comment")).ok);
        assertEquals(false, Doctor.checkScopes(List.of("bad scope")).ok);
    }
}
