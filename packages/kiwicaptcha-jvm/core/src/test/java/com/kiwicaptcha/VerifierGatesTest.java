package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The drivable error codes, the gate order and the one-shot model. */
class VerifierGatesTest {
    private static final long GOLDEN_ISSUED_AT = 1_900_000_000L;

    private static String tokenForRecord(ChallengeRecord record) {
        return SolutionToken.create(record.nonce,
                Support.solveSha(record.prefix, record.salt, record.targetBits), 5000,
                JsonObject.of("me", new JsonNumber("1")), "", "", "").encode();
    }

    private static Verifier.Options options(String scope, String clientIp) {
        Verifier.Options options = new Verifier.Options();
        options.secretKey = Support.TEST_SECRET;
        options.expectedScope = scope;
        options.clientIp = clientIp;
        return options;
    }

    @Test
    void goldenSha256EndToEnd() {
        Map<String, Object> golden = Support.readGolden("golden/golden_sha256_v2.json");
        ChallengeRecord record = goldenRecord(golden);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), GOLDEN_ISSUED_AT);
        Support.storeRecord(verifier.storage(), record);
        String token = SolutionToken.create(record.nonce,
                Support.solveSha(record.prefix, record.salt, record.targetBits), 5000,
                new JsonObject(), "", "", "").encode();
        VerifyOutcome outcome = verifier.verify(token, options("login", "198.51.100.7"));
        Support.requireValid(outcome);
        assertEquals(record.nonce, outcome.nonce);
        assertEquals("sha8", Decision.priceRung(record.algorithm, record.targetBits, record.mKib));
    }

    static ChallengeRecord goldenRecord(Map<String, Object> golden) {
        @SuppressWarnings("unchecked")
        Map<String, Object> recordMap = (Map<String, Object>) golden.get("record");
        return ChallengeRecord.fromMap(recordMap);
    }

    @Test
    void malformedToken() {
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        VerifyOutcome outcome = verifier.verify("not-a-token", options(null, null));
        Support.requireCode(outcome, VerifyError.MALFORMED_TOKEN);
        assertEquals(SolutionToken.DECODE_ERR_INVALID_BASE64, outcome.detail);
    }

    @Test
    void recordNotFound() {
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        String token = SolutionToken.create(Support.SHA_VECTOR.nonce(), 1, 1, new JsonObject(), "", "", "").encode();
        Support.requireCode(verifier.verify(token, options(null, null)), VerifyError.RECORD_NOT_FOUND);
    }

    @Test
    void badSignature() {
        Support.MintOptions mint = new Support.MintOptions();
        ChallengeRecord record = Support.mintRecord(mint);
        // The scope is signed, so rewriting it breaks the hmac while
        // every structural check still passes.
        record.scope = "logi";
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("", Support.TEST_CLIENT_IP)),
                VerifyError.BAD_SIGNATURE);
    }

    @Test
    void expired() {
        Support.MintOptions mint = new Support.MintOptions();
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_ISSUED_AT + 121);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.EXPIRED);
    }

    @Test
    void futureIssuance() {
        Support.MintOptions mint = new Support.MintOptions();
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(),
                Support.TEST_ISSUED_AT - Kiwi.MAX_CLOCK_SKEW - 1);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.EXPIRED);
    }

    @Test
    void wrongScope() {
        Support.MintOptions mint = new Support.MintOptions();
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("comment", Support.TEST_CLIENT_IP)),
                VerifyError.WRONG_SCOPE);
    }

    @Test
    void missingScopeOptionIsTheTypedRequiredScopeRefusal() {
        Support.MintOptions mint = new Support.MintOptions();
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        // The empty scope option accepts nothing: the typed refusal
        // replaces the lax any-scope acceptance.
        Support.requireCode(verifier.verify(tokenForRecord(record), options("", Support.TEST_CLIENT_IP)),
                VerifyError.REQUIRED_SCOPE);
    }

    @Test
    void missingClientIp() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.bindingIp = Support.TEST_CLIENT_IP;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", null)),
                VerifyError.MISSING_CLIENT_IP);
        // The retry path keeps the record so the caller can retry with the ip.
        assertNotNull(verifier.storage().find(record.nonce));
    }

    @Test
    void ipMismatch() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.bindingIp = Support.TEST_CLIENT_IP;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", "192.0.2.9")),
                VerifyError.IP_MISMATCH);
    }

    @Test
    void wrongRegion() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.region = "eu";
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config config = new Verifier.Config();
        config.region = "us";
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.WRONG_REGION);
    }

    @Test
    void wrongIssuer() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.issuer = "staging";
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config config = new Verifier.Config();
        config.expectedIssuer = "prod";
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.WRONG_ISSUER);
    }

    @Test
    void unboundRecordFailsARegionBoundVerifier() {
        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        Verifier.Config config = new Verifier.Config();
        config.region = "eu";
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.WRONG_REGION);
    }

    @Test
    void wrongPolicyVersion() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.policyVersion = 2;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config config = new Verifier.Config();
        config.expectedPolicyVersion = 3;
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.WRONG_POLICY_VERSION);
    }

    @Test
    void policyRolloutWindowAcceptsAndRejects() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.policyVersion = 2;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config flooredConfig = new Verifier.Config();
        flooredConfig.expectedPolicyVersion = 3;
        flooredConfig.policyVersionFloor = 2;
        Verifier floored = Support.newTestVerifier(flooredConfig, Support.TEST_NOW);
        Support.storeRecord(floored.storage(), record);
        Support.requireValid(floored.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)));

        Verifier.Config strictConfig = new Verifier.Config();
        strictConfig.expectedPolicyVersion = 3;
        Verifier strict = Support.newTestVerifier(strictConfig, Support.TEST_NOW);
        Support.storeRecord(strict.storage(), record);
        Support.requireCode(strict.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.WRONG_POLICY_VERSION);

        // A floor above the expected epoch accepts nothing.
        Verifier.Config invertedConfig = new Verifier.Config();
        invertedConfig.expectedPolicyVersion = 2;
        invertedConfig.policyVersionFloor = 3;
        Verifier inverted = Support.newTestVerifier(invertedConfig, Support.TEST_NOW);
        Support.storeRecord(inverted.storage(), record);
        Support.requireCode(inverted.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.WRONG_POLICY_VERSION);
    }

    @Test
    void revokedKid() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.kid = 2;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config config = new Verifier.Config();
        config.secretsByKid = Map.of(1, Support.TEST_SECRET, 2, Support.TEST_SECRET);
        config.revokedKids = Map.of(2, true);
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.UNKNOWN_KID);
    }

    @Test
    void forwardKidGuard() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.kid = 3;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config config = new Verifier.Config();
        config.secretsByKid = Map.of(1, Support.TEST_SECRET);
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.UNKNOWN_KID);
    }

    @Test
    void kidRotationSelectsTheSecret() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.kid = 2;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config config = new Verifier.Config();
        config.secretsByKid = Map.of(1, "other-secret-other-secret-other-32", 2, Support.TEST_SECRET);
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Verifier.Options opts = options("login", Support.TEST_CLIENT_IP);
        opts.secretKey = "unused";
        Support.requireValid(verifier.verify(tokenForRecord(record), opts));
    }

    @Test
    void unsupportedArgon2Params() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.algorithm = "argon2id";
        mint.mKib = 131072;
        mint.t = 3;
        mint.targetBits = 4;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.UNSUPPORTED_ARGON2);
    }

    @Test
    void unsupportedRswParams() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.algorithm = "rsw";
        mint.t = Kiwi.MIN_RSW_T - 1;
        mint.targetBits = Kiwi.RSW_TARGET_BITS_PIN;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.UNSUPPORTED_RSW_PARAMS);
    }

    @Test
    void tooFast() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.minDurationMs = 5000;
        mint.mintMetaMac = true;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_ISSUED_AT);
        Support.storeRecord(verifier.storage(), record);
        Verifier.Options fast = options("login", Support.TEST_CLIENT_IP);
        fast.nowNs = record.issuedAtNs + 1_000_000;
        fast.nowNsSet = true;
        Support.requireCode(verifier.verify(tokenForRecord(record), fast), VerifyError.TOO_FAST);
        // Past the floor the same token verifies.
        ChallengeRecord fresh = Support.mintRecord(mint);
        Support.storeRecord(verifier.storage(), fresh);
        Verifier.Options slow = options("login", Support.TEST_CLIENT_IP);
        slow.nowNs = fresh.issuedAtNs + 6_000_000;
        slow.nowNsSet = true;
        Support.requireValid(verifier.verify(tokenForRecord(fresh), slow));
    }

    @Test
    void unmeasuredFloorFailsClosed() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.minDurationMs = 5000;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_ISSUED_AT);
        Support.storeRecord(verifier.storage(), record);
        Verifier.Options opts = options("login", Support.TEST_CLIENT_IP);
        opts.nowNs = record.issuedAtNs + 6_000_000;
        opts.nowNsSet = true;
        Support.requireCode(verifier.verify(tokenForRecord(record), opts), VerifyError.MALFORMED_RECORD);
    }

    @Test
    void insufficientWork() {
        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        String token = SolutionToken.create(record.nonce, 0, 5000, new JsonObject(), "", "", "").encode();
        Support.requireCode(verifier.verify(token, options("login", Support.TEST_CLIENT_IP)),
                VerifyError.INSUFFICIENT_WORK);
        // The deterministic invalid outcome replays without re-deriving.
        Store.ConsumedRecord replay = verifier.storage().consume(record.nonce);
        assertNotNull(replay);
        Support.requireCode(verifier.verify(token, options("login", Support.TEST_CLIENT_IP)),
                VerifyError.INSUFFICIENT_WORK);
    }

    @Test
    void requestBindingMismatch() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.requestBinding = "tx-123";
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Verifier.Options wrong = options("login", Support.TEST_CLIENT_IP);
        wrong.bindingExpectation = Verifier.RequestBindingExpectation.exact("tx-999");
        Support.requireCode(verifier.verify(tokenForRecord(record), wrong), VerifyError.REQUEST_BINDING);
        // The record burned on the first attempt: mint a fresh one.
        ChallengeRecord fresh = Support.mintRecord(mint);
        Support.storeRecord(verifier.storage(), fresh);
        Verifier.Options right = options("login", Support.TEST_CLIENT_IP);
        right.bindingExpectation = Verifier.RequestBindingExpectation.exact("tx-123");
        Support.requireValid(verifier.verify(tokenForRecord(fresh), right));
    }

    @Test
    void unboundRecordUnderAPresentedBinding() {
        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Verifier.Options expecting = options("login", Support.TEST_CLIENT_IP);
        expecting.bindingExpectation = Verifier.RequestBindingExpectation.exact("tx-123");
        Support.requireCode(verifier.verify(tokenForRecord(record), expecting), VerifyError.REQUEST_BINDING);
        // The legacy mode passes the unbound record.
        ChallengeRecord fresh = Support.mintRecord(new Support.MintOptions());
        Support.storeRecord(verifier.storage(), fresh);
        Verifier.Options legacy = options("login", Support.TEST_CLIENT_IP);
        legacy.bindingExpectation = Verifier.RequestBindingExpectation.legacy("tx-123");
        Support.requireValid(verifier.verify(tokenForRecord(fresh), legacy));
    }

    @Test
    void executionArmedFailsClosed() {
        Map<String, Object> golden = Support.readGolden("golden/golden_execution_v4.json");
        ChallengeRecord record = goldenRecord(golden);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), GOLDEN_ISSUED_AT);
        Support.storeRecord(verifier.storage(), record);
        String token = SolutionToken.create(record.nonce,
                Support.solveSha(record.prefix, record.salt, record.targetBits), 5000,
                new JsonObject(), "ab".repeat(32), "", "").encode();
        Support.requireCode(verifier.verify(token, options("login", "198.51.100.7")),
                VerifyError.EXECUTION_MISMATCH);
    }

    @Test
    void strayExecutionEvidence() {
        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        String token = SolutionToken.create(record.nonce,
                Support.solveSha(record.prefix, record.salt, record.targetBits), 5000,
                new JsonObject(), "ab".repeat(32), "", "").encode();
        Support.requireCode(verifier.verify(token, options("login", Support.TEST_CLIENT_IP)),
                VerifyError.EXECUTION_MISMATCH);
    }

    @Test
    void telemetryRejectedAndEmptyPayload() {
        Support.MintOptions mint = new Support.MintOptions();
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        // An empty telemetry payload is itself a bot signal.
        String token = SolutionToken.create(record.nonce,
                Support.solveSha(record.prefix, record.salt, record.targetBits), 5000,
                new JsonObject(), "", "", "").encode();
        Verifier.Options strict = options("login", Support.TEST_CLIENT_IP);
        strict.enforceTelemetry = true;
        Support.requireCode(verifier.verify(token, strict), VerifyError.TELEMETRY_REJECTED);
        // Perfectly uniform event intervals trip the timing signal.
        var events = new java.util.ArrayList<Object>();
        for (int i = 0; i < 30; i++) {
            events.add(new JsonNumber(String.valueOf(i * 10)));
        }
        ChallengeRecord fresh = Support.mintRecord(mint);
        Support.storeRecord(verifier.storage(), fresh);
        String tokenUniform = SolutionToken.create(fresh.nonce,
                Support.solveSha(fresh.prefix, fresh.salt, fresh.targetBits), 5000,
                JsonObject.of("et", events), "", "", "").encode();
        Support.requireCode(verifier.verify(tokenUniform, strict), VerifyError.TELEMETRY_REJECTED);
        // Organic timings pass.
        var organic = new java.util.ArrayList<Object>();
        for (int i = 0; i < 30; i++) {
            organic.add(new JsonNumber(String.valueOf(i * i + 3)));
        }
        ChallengeRecord third = Support.mintRecord(mint);
        Support.storeRecord(verifier.storage(), third);
        String tokenOrganic = SolutionToken.create(third.nonce,
                Support.solveSha(third.prefix, third.salt, third.targetBits), 5000,
                JsonObject.of("et", organic), "", "", "").encode();
        Support.requireValid(verifier.verify(tokenOrganic, strict));
    }

    @Test
    void capacityExceeded() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.algorithm = "argon2id";
        mint.mKib = 8;
        mint.t = 3;
        mint.targetBits = 1;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config config = new Verifier.Config();
        config.argonGate = new Verifier.ExhaustionGate();
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.CAPACITY_EXCEEDED);
        // Exhaustion never consumes: the client can retry.
        assertNotNull(verifier.storage().find(record.nonce));
    }

    @Test
    void admissionBackendFailure() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.algorithm = "argon2id";
        mint.mKib = 8;
        mint.t = 3;
        mint.targetBits = 1;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier.Config config = new Verifier.Config();
        config.argonGate = new Verifier.AdmissionGate() {
            @Override
            public Object acquire() {
                throw new IllegalStateException("backend down");
            }

            @Override
            public void release(Object lease) {
                // Never reached.
            }
        };
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.ADMISSION_UNAVAILABLE);
    }

    @Test
    void storageUnavailable() {
        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        Store.StoreAdapter failing = new Store.StoreAdapter() {
            @Override
            public ChallengeRecord find(String nonce) {
                throw new Store.StorageUnavailableException("down");
            }

            @Override
            public boolean delete(String nonce) {
                throw new Store.StorageUnavailableException("down");
            }

            @Override
            public Store.ConsumedRecord consume(String nonce) {
                throw new Store.StorageUnavailableException("down");
            }

            @Override
            public boolean commitResult(String nonce, boolean valid, String binding) {
                throw new Store.StorageUnavailableException("down");
            }
        };
        Verifier verifier = new Verifier(failing, new Verifier.Config());
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.STORAGE_UNAVAILABLE);
    }

    @Test
    void cancelledRecordAnswersNotFound() {
        ChallengeRecord record = Support.mintRecord(new Support.MintOptions());
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        ((Store.Cancellable) verifier.storage()).cancel(record.nonce);
        Support.requireCode(verifier.verify(tokenForRecord(record), options("login", Support.TEST_CLIENT_IP)),
                VerifyError.RECORD_NOT_FOUND);
    }

    @Test
    void consumedIdentityGate() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.bindingIp = Support.TEST_CLIENT_IP;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        String token = tokenForRecord(record);
        Verifier.Options first = options("login", Support.TEST_CLIENT_IP);
        first.operationIdentity = "op-1";
        Support.requireValid(verifier.verify(token, first));
        // The stored success replays only to the exact logical operation.
        Verifier.Options replay = options("login", Support.TEST_CLIENT_IP);
        replay.operationIdentity = "op-1";
        VerifyOutcome replayOutcome = verifier.verify(token, replay);
        Support.requireValid(replayOutcome);
        assertTrue(replayOutcome.fromStoredResult);
        assertFalse(replayOutcome.solveDurationSet);
        Support.requireCode(verifier.verify(token, options("login", Support.TEST_CLIENT_IP)),
                VerifyError.ALREADY_CONSUMED);
        Verifier.Options other = options("login", Support.TEST_CLIENT_IP);
        other.operationIdentity = "op-2";
        Support.requireCode(verifier.verify(token, other), VerifyError.ALREADY_CONSUMED);
        // The ip binding is a replay-exempt circumstance: on a consumed
        // record it routes into the identity-gated consumed branch, so
        // the proven operation replays even from another network path.
        Verifier.Options elsewhere = options("login", "192.0.2.9");
        elsewhere.operationIdentity = "op-1";
        Support.requireValid(verifier.verify(token, elsewhere));
        // A hard verdict is different: the stored success never replays
        // around a security failure. Scope is a hard invariant.
        Verifier.Options hardScope = options("comment", Support.TEST_CLIENT_IP);
        hardScope.operationIdentity = "op-1";
        Support.requireCode(verifier.verify(token, hardScope), VerifyError.WRONG_SCOPE);
    }

    @Test
    void argon2VectorEndToEnd() {
        ChallengeRecord record = Support.vectorRecord(Support.ARGON2_VECTOR);
        Verifier.Config config = new Verifier.Config();
        config.acceptLegacyV1 = true;
        Verifier verifier = Support.newTestVerifier(config, Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireValid(verifier.verify(Support.vectorToken(Support.ARGON2_VECTOR, -1, -1),
                options("login", Support.TEST_CLIENT_IP)));
    }

    @Test
    void solveDurationMeasured() {
        Support.MintOptions mint = new Support.MintOptions();
        mint.mintMetaMac = true;
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_ISSUED_AT);
        Support.storeRecord(verifier.storage(), record);
        Verifier.Options opts = options("login", Support.TEST_CLIENT_IP);
        opts.nowNs = record.issuedAtNs + 12_500_000;
        opts.nowNsSet = true;
        VerifyOutcome outcome = verifier.verify(tokenForRecord(record), opts);
        Support.requireValid(outcome);
        assertTrue(outcome.solveDurationSet);
        assertEquals(12_500, outcome.solveDurationMs);
        // Without the metadata mac the measured duration is withheld.
        ChallengeRecord unmacced = Support.mintRecord(new Support.MintOptions());
        Verifier second = Support.newTestVerifier(new Verifier.Config(), Support.TEST_ISSUED_AT);
        Support.storeRecord(second.storage(), unmacced);
        Verifier.Options opts2 = options("login", Support.TEST_CLIENT_IP);
        opts2.nowNs = unmacced.issuedAtNs + 12_500_000;
        opts2.nowNsSet = true;
        VerifyOutcome outcome2 = second.verify(tokenForRecord(unmacced), opts2);
        Support.requireValid(outcome2);
        assertFalse(outcome2.solveDurationSet);
    }

    @Test
    void legacyV1Gate() {
        ChallengeRecord record = Support.vectorRecord(Support.SHA_VECTOR);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        Support.requireCode(verifier.verify(Support.vectorToken(Support.SHA_VECTOR, -1, -1),
                options("login", Support.TEST_CLIENT_IP)), VerifyError.MALFORMED_RECORD);
        Verifier.Config accepting = new Verifier.Config();
        accepting.acceptLegacyV1 = true;
        Verifier open = Support.newTestVerifier(accepting, Support.TEST_NOW);
        Support.storeRecord(open.storage(), record);
        Support.requireValid(open.verify(Support.vectorToken(Support.SHA_VECTOR, -1, -1),
                options("login", Support.TEST_CLIENT_IP)));
    }

    @Test
    void exactlyOnceUnderConcurrency() throws Exception {
        Support.MintOptions mint = new Support.MintOptions();
        ChallengeRecord record = Support.mintRecord(mint);
        Verifier verifier = Support.newTestVerifier(new Verifier.Config(), Support.TEST_NOW);
        Support.storeRecord(verifier.storage(), record);
        String token = tokenForRecord(record);
        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> workers = new java.util.ArrayList<>();
        AtomicInteger winners = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            Thread worker = new Thread(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    return;
                }
                VerifyOutcome outcome = verifier.verify(token, options("login", Support.TEST_CLIENT_IP));
                if (outcome.valid) {
                    winners.incrementAndGet();
                }
            });
            workers.add(worker);
            worker.start();
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }
        assertEquals(1, winners.get());
    }

    @Test
    void decisionPlane() {
        VerifyOutcome valid = VerifyOutcome.valid("nonce", "binding", false, 0, false, "");
        Decision decision = Decision.fromOutcome(valid, "sha8");
        assertTrue(decision.ok);
        assertEquals(Decision.DISPOSITION_ALLOW, decision.disposition);
        assertEquals("nonce", decision.decisionHandle);
        assertEquals("sha8", decision.price);
        Decision denied = Decision.fromOutcome(VerifyOutcome.invalid(VerifyError.WRONG_SCOPE), "");
        assertFalse(denied.ok);
        assertEquals(Decision.DISPOSITION_DENY, denied.disposition);
        assertEquals("wrong_scope", denied.error);
        Decision retry = Decision.fromOutcome(VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE), "");
        assertEquals(Decision.DISPOSITION_RETRY, retry.disposition);
        assertNull(valid.error);
    }

    private static String buildProgramB64(int opVersion, int[] opcodes, int[][] operands) {
        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        body.write(1); // format version
        body.write(5);
        body.write("login".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, 5);
        body.write(3);
        body.write("act".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, 3);
        body.write(opVersion);
        body.write(opcodes.length);
        for (int i = 0; i < opcodes.length; i++) {
            body.write(opcodes[i]);
            for (int b : operands[i]) {
                body.write(b);
            }
        }
        return java.util.Base64.getEncoder().encodeToString(body.toByteArray());
    }

    private static int[] idOperand() {
        return new int[] {4, 'a', 'b', 'c', 'd'};
    }

    private static int[] concat(int[] a, int... rest) {
        int[] out = java.util.Arrays.copyOf(a, a.length + rest.length);
        System.arraycopy(rest, 0, out, a.length, rest.length);
        return out;
    }

    @Test
    void versionSixProbeOperandsParseAndVersionFiveRefusesThem() {
        int[] add = new int[] {1, 0, 0, 0, 1, 0, 0, 0};
        int[] css = concat(idOperand(), 7, 3);
        int[] mut = concat(idOperand(), 1, 2, 5);
        int[] evp = concat(idOperand(), 9);
        int[] rng = concat(idOperand(), 4, 5, 6);
        int[] iob = concat(idOperand(), 8, 1);
        int[] opcodes = {45, 46, 47, 48, 49, 0, 0, 0};
        int[][] operands = {css, mut, evp, rng, iob, add, add, add};
        String program = buildProgramB64(6, opcodes, operands);
        org.junit.jupiter.api.Assertions.assertTrue(
                com.kiwicaptcha.ExecutionProgram.isValidExecutionProgram(program),
                "the version-6 probe program must parse");
        org.junit.jupiter.api.Assertions.assertFalse(
                com.kiwicaptcha.ExecutionProgram.isValidExecutionProgram(buildProgramB64(5, opcodes, operands)),
                "the version-5 ceiling must refuse the version-6 probes");
        // A truncated probe operand is refused.
        org.junit.jupiter.api.Assertions.assertFalse(
                com.kiwicaptcha.ExecutionProgram.isValidExecutionProgram(buildProgramB64(
                        6,
                        new int[] {45, 0, 0, 0, 0, 0, 0, 0},
                        new int[][] {idOperand(), add, add, add, add, add, add, add})),
                "a truncated version-6 probe operand must be refused");
    }

    @Test
    void issuerGuardRefusesUnverifiableRungs() {
        org.junit.jupiter.api.Assertions.assertTrue(Settings.rungVerifiable(16 * 1024, 3, 1));
        org.junit.jupiter.api.Assertions.assertTrue(Settings.rungVerifiable(64 * 1024, 3, 1));
        org.junit.jupiter.api.Assertions.assertFalse(Settings.rungVerifiable(64 * 1024, 2, 1));
        org.junit.jupiter.api.Assertions.assertFalse(Settings.rungVerifiable(64 * 1024, 3, 2));
        Settings bad = new Settings();
        bad.secret = "0123456789abcdef0123456789abcdef";
        bad.profile = "argon128";
        bad.store = "memory://";
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, bad::buildVerifier);
        Settings good = new Settings();
        good.secret = "0123456789abcdef0123456789abcdef";
        good.profile = "argon64";
        good.store = "memory://";
        org.junit.jupiter.api.Assertions.assertNotNull(good.buildVerifier());
    }
}
