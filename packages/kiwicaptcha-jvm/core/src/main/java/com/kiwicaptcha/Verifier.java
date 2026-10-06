package com.kiwicaptcha;

import java.util.Map;
import java.util.function.LongSupplier;

/**
 * The solution verifier: the exact cheap-gate order and the consumed
 * resolution of the php Verifier, over the storage seam.
 *
 * The gate order is normative: nonce match, structure, protocol gate,
 * kid revocation, kid resolution, signature, argon2id ceilings, rsw
 * bounds, ttl, scope, request binding, ip binding, region, policy
 * epoch, issuer, execution binding and minimum duration. The policy
 * epoch carries the rollout-floor window. Then comes the opt-in
 * telemetry gate, the terminal-state resolution, the admission gate,
 * consume, proof, the post-derive final revalidation and the result
 * commit.
 *
 * Verify is pure-local: it never calls out to any network service.
 * The only side effects are the storage transitions the one-shot
 * model requires. Execution-armed records (the signed e= commitment)
 * are refused deterministically with execution_mismatch: the browser
 * trace walker is a browser-behavior oracle this SDK does not carry,
 * and an armed record must never pass without it.
 */
public final class Verifier {
    /** The explicit request-binding enforcement policy. */
    public static final class RequestBindingExpectation {
        /** Whether enforcement runs at all. */
        public final boolean enforced;
        /** The authoritative expected binding. */
        public final String expected;
        /** Whether an explicitly unbound record must fail a set expectation. */
        public final boolean requireBindingPresence;

        private RequestBindingExpectation(boolean enforced, String expected, boolean requireBindingPresence) {
            this.enforced = enforced;
            this.expected = expected;
            this.requireBindingPresence = requireBindingPresence;
        }

        /** Skips the request-binding check. */
        public static RequestBindingExpectation unenforced() {
            return new RequestBindingExpectation(false, "", false);
        }

        /** Requires Option-equality with the expected binding. */
        public static RequestBindingExpectation exact(String expected) {
            return new RequestBindingExpectation(true, expected == null ? "" : expected, true);
        }

        /** The explicitly named compatibility mode. */
        public static RequestBindingExpectation legacy(String expected) {
            return new RequestBindingExpectation(expected != null && !expected.isEmpty(),
                    expected == null ? "" : expected, false);
        }
    }

    /** The execution digest and trace one solution token carries. */
    public static final class ExecutionEvidence {
        public final String digest;
        public final String trace;

        ExecutionEvidence(String digest, String trace) {
            this.digest = digest;
            this.trace = trace;
        }

        /** Reports the unarmed evidence shape. */
        public boolean isEmpty() {
            return digest.isEmpty() && trace.isEmpty();
        }
    }

    /** Extracts the evidence of one token. */
    public static ExecutionEvidence evidenceFromToken(SolutionToken token) {
        return new ExecutionEvidence(token.executionDigest, token.executionTrace);
    }

    /** The admission-gate seam, mirroring the php VerificationAdmissionGate. */
    public interface AdmissionGate {
        /** Returns a lease when a slot was granted, null on exhaustion, or throws on backend failure. */
        Object acquire();

        /** Returns the lease; a failing release must never break the verification. */
        void release(Object lease);
    }

    /** The default admission gate that always grants. */
    public static final class PassThroughGate implements AdmissionGate {
        @Override
        public Object acquire() {
            return new Object();
        }

        @Override
        public void release(Object lease) {
            // Nothing to return.
        }
    }

    /** Models a full admission pool: acquire always refuses. */
    public static final class ExhaustionGate implements AdmissionGate {
        @Override
        public Object acquire() {
            return null;
        }

        @Override
        public void release(Object lease) {
            // Nothing to return.
        }
    }

    /** One trapdoor entry of the rotation keyring. */
    public static final class RswKeyPair {
        public final String modulusN;
        public final String lambda;

        public RswKeyPair(String modulusN, String lambda) {
            this.modulusN = modulusN;
            this.lambda = lambda;
        }
    }

    /** Reports an invalid construction. */
    public static final class VerifierBuildException extends RuntimeException {
        public VerifierBuildException(String reason) {
            super("kiwicaptcha: invalid verifier config: " + reason);
        }
    }

    /**
     * The verifier construction options, mirroring the php
     * constructor. nowSecs supplies the wall clock in unix seconds and
     * stands in for it in tests. secretsByKid maps positive kid values
     * to secrets of at least 32 bytes; an empty map keeps the legacy
     * single-secret path.
     */
    public static final class Config {
        public Store.StoreAdapter storage;
        public AdmissionGate argonGate;
        public LongSupplier nowSecs;
        public boolean acceptLegacyV1;
        public String region = "";
        public int expectedPolicyVersion;
        public int policyVersionFloor;
        public String expectedIssuer = "";
        public Map<Integer, String> secretsByKid = Map.of();
        public Map<Integer, Boolean> revokedKids = Map.of();
        public String rswModulusN = "";
        public String rswLambda = "";
        public String tenantId = "";
        public Map<String, RswKeyPair> rswVerificationKeys = Map.of();
        public boolean allowLegacyRswIdentity;

        // The trapdoors resolved once at build time.
        Rsw activeRsw;
        Map<String, Rsw> rswByHash;
        Map<String, String> rswModulusByHash;
    }

    /**
     * Validates the construction options and resolves the rsw
     * trapdoors once at build time, mirroring the php memo.
     */
    public static Config validateConfig(Config config) {
        for (Map.Entry<Integer, String> entry : config.secretsByKid.entrySet()) {
            if (entry.getKey() == null || entry.getKey() < 1
                    || entry.getValue() == null
                    || entry.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8).length < Kiwi.MIN_SECRET_BYTES) {
                throw new VerifierBuildException(
                        "secrets by kid must map positive integer kids to secrets of at least 32 bytes");
            }
        }
        for (Map.Entry<Integer, Boolean> entry : config.revokedKids.entrySet()) {
            if (entry.getKey() == null || entry.getKey() < 1) {
                throw new VerifierBuildException("revoked kids must be positive integers 1..N");
            }
        }
        boolean modulusSet = !config.rswModulusN.isEmpty();
        boolean lambdaSet = !config.rswLambda.isEmpty();
        if (modulusSet != lambdaSet) {
            throw new VerifierBuildException(
                    "rsw modulus and lambda must be configured together (the rsw trapdoor pair)");
        }
        if (!config.tenantId.isEmpty() && !ChallengeRecord.isValidIdentifier(config.tenantId, 64)) {
            throw new VerifierBuildException("tenant id must be 1..64 bytes of [A-Za-z0-9._:-] when set");
        }
        if (config.nowSecs == null) {
            config.nowSecs = () -> System.currentTimeMillis() / 1000;
        }
        if (config.argonGate == null) {
            config.argonGate = new PassThroughGate();
        }
        if (config.expectedPolicyVersion < 0 || config.policyVersionFloor < 0) {
            throw new VerifierBuildException("policy versions are non negative");
        }
        config.activeRsw = modulusSet ? Rsw.of(config.rswModulusN, config.rswLambda) : null;
        config.rswByHash = new java.util.HashMap<>();
        config.rswModulusByHash = new java.util.HashMap<>();
        for (Map.Entry<String, RswKeyPair> entry : config.rswVerificationKeys.entrySet()) {
            String hash = entry.getKey();
            RswKeyPair pair = entry.getValue();
            if (!SolutionToken.isHexN(hash, 64)) {
                throw new VerifierBuildException(
                        "rsw verification keys must map a 64 hex modulus sha256 to a pair");
            }
            if (pair == null || pair.modulusN.isEmpty() || pair.lambda.isEmpty()) {
                throw new VerifierBuildException(
                        "rsw verification key values must be a non-empty {modulus_n, lambda} pair");
            }
            if (!Rsw.identityMatches(hash, pair.modulusN, config.allowLegacyRswIdentity)) {
                throw new VerifierBuildException(
                        "rsw verification key hashes must be the canonical sha256 of the decoded modulus "
                                + "(or its legacy base64-text alias while the migration mode is enabled)");
            }
            Rsw trapdoor = Rsw.of(pair.modulusN, pair.lambda);
            config.rswByHash.put(hash, trapdoor);
            config.rswModulusByHash.put(hash, pair.modulusN);
            String fingerprint = Rsw.fingerprint(pair.modulusN);
            if (!fingerprint.isEmpty()) {
                config.rswByHash.put(fingerprint, trapdoor);
                config.rswModulusByHash.put(fingerprint, pair.modulusN);
            }
            if (config.allowLegacyRswIdentity) {
                String legacy = Rsw.legacyIdentity(pair.modulusN);
                config.rswByHash.put(legacy, trapdoor);
                config.rswModulusByHash.put(legacy, pair.modulusN);
            }
        }
        return config;
    }

    private final Store.StoreAdapter storage;
    private final Config config;

    /** Builds a verifier over a validated config. */
    public Verifier(Store.StoreAdapter storage, Config config) {
        validateConfig(config);
        this.storage = storage;
        this.config = config;
    }

    private long nowSecs() {
        return config.nowSecs.getAsLong();
    }

    /** The store adapter this verifier consumes, for tests and doctor. */
    public Store.StoreAdapter storage() {
        return storage;
    }

    /** One verify call's parameters. */
    public static final class Options {
        public String secretKey = "";
        public String expectedScope = "";
        public String clientIp = "";
        public long nowNs;
        public boolean nowNsSet;
        public boolean enforceTelemetry;
        public String operationIdentity = "";
        public String expectedRequestBinding = "";
        public RequestBindingExpectation bindingExpectation;
        /**
         * The execution-armed dimension policy: null (the default)
         * fails every armed record closed; the sidecar policy
         * delegates that single verification to a co-located
         * kiwicaptcha-verifier sidecar.
         */
        public ExecutionPolicy executionPolicy;
    }

    /**
     * The structural validation of a stored record before any crypto
     * or timing work: the protocol grammar, the scope shape, the nonce
     * and salt sizes, the ttl ceiling, the prefix binding, the
     * per-algorithm difficulty range, the decoy alphabet and the
     * execution commitment equivalence. A record failing any check is
     * malformed; it cannot have come from a KiwiCaptcha issuer.
     */
    public boolean validateRecord(ChallengeRecord record) {
        if (record.protocolVersion < 1 || record.protocolVersion > Kiwi.MAX_PROTOCOL_VERSION) {
            return false;
        }
        boolean executionPresent = !record.executionProgram.isEmpty();
        if (!ChallengeRecord.protocolExtensionGrammarOk(record.protocolVersion,
                !record.decoyField.isEmpty(), executionPresent, !record.rswModulusSha256.isEmpty())) {
            return false;
        }
        if (!ChallengeRecord.isValidIdentifier(record.scope, 128)) {
            return false;
        }
        if (!record.decoyField.isEmpty() && !ChallengeRecord.isValidDecoyFieldName(record.decoyField)) {
            return false;
        }
        if (executionPresent) {
            if (record.executionVersion < 1 || record.executionVersion > Kiwi.MAX_EXECUTION_VERSION
                    || record.executionCommitment.isEmpty()) {
                return false;
            }
            if (!SolutionToken.isHexN(record.executionCommitment, 64)) {
                return false;
            }
            if (!Canonical.constantTimeEquals(ExecutionProgram.commitment(record.executionProgram),
                    record.executionCommitment)) {
                return false;
            }
        } else if (record.executionVersion != 0 || !record.executionCommitment.isEmpty()) {
            return false;
        }
        if (!record.rswModulusSha256.isEmpty()) {
            if (!record.algorithm.equals("rsw") || !SolutionToken.isHexN(record.rswModulusSha256, 64)) {
                return false;
            }
        }
        byte[] nonceBytes = Canonical.b64CanonicalDecode(record.nonce);
        if (nonceBytes == null || nonceBytes.length != Kiwi.NONCE_B64_BYTES) {
            return false;
        }
        byte[] saltBytes = Canonical.b64CanonicalDecode(record.salt);
        if (saltBytes == null || saltBytes.length != Kiwi.SALT_B64_BYTES) {
            return false;
        }
        if (record.expiresAt <= record.issuedAt || record.expiresAt - record.issuedAt > Kiwi.MAX_TTL_SECS) {
            return false;
        }
        if (!Canonical.constantTimeEquals(record.challenge + "|" + record.salt + "|", record.prefix)) {
            return false;
        }
        if (record.targetBits < Kiwi.MIN_DIFFICULTY || record.targetBits > Kiwi.MAX_DIFFICULTY) {
            return false;
        }
        return !executionPresent || ExecutionProgram.isValidExecutionProgram(record.executionProgram);
    }

    private boolean isRevokedKid(int kid) {
        return config.revokedKids.getOrDefault(kid, false);
    }

    /**
     * Selects the signature secret for a record. With an empty secrets
     * set the legacy single-secret path stays. An unknown kid, or one
     * beyond the newest configured kid, yields null: the rollback and
     * forward guard keeps a future-keyed challenge from verifying on
     * an older node.
     */
    String secretForKey(ChallengeRecord record, String legacySecret) {
        if (config.secretsByKid.isEmpty()) {
            return legacySecret;
        }
        int newest = 0;
        for (Integer kid : config.secretsByKid.keySet()) {
            if (kid != null && kid > newest) {
                newest = kid;
            }
        }
        int kid = record.kidOrOne();
        if (kid > newest || !config.secretsByKid.containsKey(kid)) {
            return null;
        }
        return config.secretsByKid.get(kid);
    }

    /** Applies the absolute process ceilings to the signed parameters before any allocation. */
    private boolean argon2CeilingsOk(ChallengeRecord record) {
        if (!record.algorithm.equals("argon2id")) {
            return true;
        }
        return record.mKib >= Kiwi.MIN_ARGON_MEMORY_KIB && record.mKib <= Kiwi.MAX_ARGON_MEMORY_KIB
                && record.t >= Kiwi.MIN_ARGON_TIME && record.t <= Kiwi.MAX_ARGON_TIME
                && record.p >= Kiwi.MIN_PARALLELISM && record.p <= Kiwi.MAX_PARALLELISM;
    }

    /** Bounds the signed sequential cost to the issuance range. */
    private boolean rswParamsOk(ChallengeRecord record) {
        if (!record.algorithm.equals("rsw")) {
            return true;
        }
        return record.t >= Kiwi.MIN_RSW_T && record.t <= Kiwi.MAX_RSW_T;
    }

    /**
     * The authenticated hard core of the cheap phase: structural
     * validation, the protocol version gate, kid revocation and
     * resolution, the hmac signature re-check, and the process
     * ceilings. Shared by the cheap phase and the compositional replay
     * gate. Returns the resolved signing secret through outSecret.
     */
    private VerifyError checkAuthenticatedShape(ChallengeRecord record, String legacySecret,
                                                String[] outSecret) {
        if (!validateRecord(record)) {
            return VerifyError.MALFORMED_RECORD;
        }
        if (record.protocolVersion == 1 && !config.acceptLegacyV1) {
            return VerifyError.MALFORMED_RECORD;
        }
        if (isRevokedKid(record.kidOrOne())) {
            return VerifyError.UNKNOWN_KID;
        }
        String signingSecret = secretForKey(record, legacySecret);
        if (signingSecret == null) {
            return VerifyError.UNKNOWN_KID;
        }
        if (!Canonical.verifyRecordSignature(record, signingSecret, config.tenantId)) {
            return VerifyError.BAD_SIGNATURE;
        }
        outSecret[0] = signingSecret;
        if (!argon2CeilingsOk(record)) {
            return VerifyError.UNSUPPORTED_ARGON2;
        }
        if (!rswParamsOk(record)) {
            return VerifyError.UNSUPPORTED_RSW_PARAMS;
        }
        return null;
    }

    /**
     * The ttl window on the verifier's clock: expired, or an issuance
     * more than the future-skew bound ahead. The exempt expiry
     * circumstance, deliberately excluded from the compositional
     * replay gate.
     */
    private VerifyError checkTtl(ChallengeRecord record) {
        long now = nowSecs();
        if (now >= record.expiresAt) {
            return VerifyError.EXPIRED;
        }
        if (record.issuedAt > now + Kiwi.MAX_CLOCK_SKEW) {
            return VerifyError.EXPIRED;
        }
        return null;
    }

    /**
     * The single request-binding check: exact Option-equality between
     * the record's signed request binding and the expectation's
     * authoritative binding, compared in constant time when both
     * sides carry a string.
     */
    private VerifyError checkRequestBinding(ChallengeRecord record, RequestBindingExpectation expectation) {
        if (!expectation.enforced) {
            return null;
        }
        if (record.requestBinding.isEmpty() || expectation.expected.isEmpty()) {
            if (record.requestBinding.isEmpty() && !expectation.requireBindingPresence) {
                return null;
            }
            if (record.requestBinding.equals(expectation.expected)) {
                return null;
            }
            return VerifyError.REQUEST_BINDING;
        }
        if (Canonical.constantTimeEquals(record.requestBinding, expectation.expected)) {
            return null;
        }
        return VerifyError.REQUEST_BINDING;
    }

    /**
     * The scope validation and the expected request binding, in
     * cheap-phase order. The expected scope is REQUIRED: an empty
     * scope option answers the typed required_scope failure instead of
     * silently accepting a token minted for any scope.
     */
    private VerifyError checkScopeAndBinding(ChallengeRecord record, String expectedScope,
                                             RequestBindingExpectation expectation) {
        if (expectedScope.isEmpty()) {
            return VerifyError.REQUIRED_SCOPE;
        }
        if (!record.scope.equals(expectedScope)) {
            return VerifyError.WRONG_SCOPE;
        }
        return checkRequestBinding(record, expectation);
    }

    /**
     * The ip binding check. The stored record is authoritative. An
     * empty binding tag means binding is disabled. A nonempty tag
     * means the challenge is bound, so a missing client ip fails
     * closed instead of silently skipping the check. A client ip that
     * cannot be canonicalized at all resolves to the typed mismatch
     * instead of an escaped error.
     */
    private VerifyError checkIpBinding(ChallengeRecord record, String clientIp, String signingSecret) {
        if (record.bindingTag.isEmpty()) {
            return null;
        }
        if (clientIp == null || clientIp.isEmpty()) {
            return VerifyError.MISSING_CLIENT_IP;
        }
        String expectedTag;
        if (record.protocolVersion == 1) {
            expectedTag = Canonical.hashIpV1(clientIp, signingSecret);
        } else {
            String computed;
            try {
                computed = Canonical.bindingTag(record.nonce, clientIp, signingSecret, config.tenantId);
            } catch (Canonical.InvalidIpException e) {
                return VerifyError.IP_MISMATCH;
            }
            expectedTag = computed;
        }
        if (!Canonical.constantTimeEquals(expectedTag, record.bindingTag)) {
            return VerifyError.IP_MISMATCH;
        }
        return null;
    }

    /**
     * Whether the record's security-policy epoch satisfies the
     * configured expectations: no expected epoch disables the check
     * entirely; no declared floor keeps the strict equality contract;
     * a declared rollout window accepts floor <= epoch <= expected. A
     * floor above the expected epoch accepts nothing, so the window is
     * fail-closed, never a licence to verify below the newest declared
     * epoch.
     */
    boolean policyVersionAccepted(int recordVersion) {
        if (config.expectedPolicyVersion == 0) {
            return true;
        }
        if (config.policyVersionFloor == 0) {
            return recordVersion == config.expectedPolicyVersion;
        }
        return config.policyVersionFloor <= recordVersion && recordVersion <= config.expectedPolicyVersion;
    }

    /** Region, policy epoch and issuer, hard invariants in cheap-phase order. */
    private VerifyError checkDeploymentExpectations(ChallengeRecord record) {
        if (!config.region.isEmpty() && !record.region.equals(config.region)) {
            return VerifyError.WRONG_REGION;
        }
        if (!policyVersionAccepted(record.policyVersionOrOne())) {
            return VerifyError.WRONG_POLICY_VERSION;
        }
        if (!config.expectedIssuer.isEmpty() && !record.issuer.equals(config.expectedIssuer)) {
            return VerifyError.WRONG_ISSUER;
        }
        return null;
    }

    /**
     * The execution binding check. An unarmed record demands no
     * digest: a presented digest is stray execution evidence and is
     * rejected deterministically, never silently ignored. An armed
     * record demands the browser-trace walker, a browser-behavior
     * oracle this SDK does not carry. The armed dimension fails
     * closed: the record's own authenticated program and commitment
     * still verify, but no submission can satisfy the armed binding,
     * matching the mandate that a missing capability must never widen
     * acceptance.
     */
    private VerifyError checkExecutionBinding(ChallengeRecord record, ExecutionEvidence evidence) {
        if (record.executionProgram.isEmpty()) {
            if (evidence.isEmpty()) {
                return null;
            }
            return VerifyError.EXECUTION_MISMATCH;
        }
        return VerifyError.EXECUTION_MISMATCH;
    }

    /**
     * The server-measured minimum duration. Elapsed time is the gap
     * between the record's high-resolution issuance timestamp and the
     * verification receipt time. The client-reported duration is
     * forgeable, so it never drives the check; a record without an
     * authenticated issuance clock cannot be timed and fails closed.
     */
    private VerifyError checkMinDuration(ChallengeRecord record, long nowNs, boolean nowNsSet) {
        if (record.issuedAtNs <= 0) {
            return VerifyError.MALFORMED_RECORD;
        }
        int floor = Math.max(record.minDurationMs, 0);
        if (floor == 0) {
            return null;
        }
        if (record.serverMac.isEmpty()) {
            // The issuance clock is unauthenticated: a storage writer
            // could have backdated it, so the floor cannot be evaluated
            // and fails closed. The mac itself was verified with the
            // signature before this check.
            return VerifyError.MALFORMED_RECORD;
        }
        long receiptNs = nowNsSet ? nowNs : java.time.Instant.now().toEpochMilli() * 1000;
        if (receiptNs >= record.issuedAtNs) {
            if (receiptNs - record.issuedAtNs < (long) floor * 1_000) {
                return VerifyError.TOO_FAST;
            }
        } else if (record.issuedAtNs - receiptNs > Kiwi.SKEW_TOLERANCE_US) {
            // Receipt before issuance by more than the skew bound is
            // physically impossible. Within the bound the two hosts'
            // clocks are unsynced, so the elapsed time cannot be
            // measured reliably, the floor check is skipped and the
            // proof-of-work check still applies.
            return VerifyError.TOO_FAST;
        }
        return null;
    }

    /**
     * The server-measured solve duration of a verified record in
     * milliseconds. Exposed only on the valid outcome of a fresh
     * derivation. A stored-success replay carries no value: the
     * retry's receipt is not the solve's endpoint, so the value
     * remains unforgeable behavioral evidence.
     */
    private long measurableSolveDurationMs(ChallengeRecord record, long receiptNs, boolean receiptSet) {
        if (record.serverMac.isEmpty() || record.issuedAtNs <= 0 || !receiptSet || receiptNs < record.issuedAtNs) {
            return -1;
        }
        return (receiptNs - record.issuedAtNs) / 1_000;
    }

    /**
     * Runs the shared security checks in the order of the ordinary
     * path; the first failing check decides the outcome.
     */
    private VerifyError cheapPhaseCheck(ChallengeRecord record, String tokenNonce, String secretKey,
                                        String expectedScope, String clientIp, boolean checkTiming,
                                        long nowNs, boolean nowNsSet,
                                        RequestBindingExpectation expectation, ExecutionEvidence evidence, boolean delegateExecution) {
        if (!record.nonce.equals(tokenNonce)) {
            return VerifyError.MALFORMED_RECORD;
        }
        String[] outSecret = {""};
        VerifyError err = checkAuthenticatedShape(record, secretKey, outSecret);
        if (err != null) {
            return err;
        }
        if (checkTiming) {
            err = checkTtl(record);
            if (err != null) {
                return err;
            }
        }
        err = checkScopeAndBinding(record, expectedScope, expectation);
        if (err != null) {
            return err;
        }
        err = checkIpBinding(record, clientIp, outSecret[0]);
        if (err != null) {
            return err;
        }
        err = checkDeploymentExpectations(record);
        if (err != null) {
            return err;
        }
        if (!delegateExecution) {
            // The delegation path leaves the execution gate to the
            // sidecar's full-core pass; every other gate stays local.
            err = checkExecutionBinding(record, evidence);
            if (err != null) {
                return err;
            }
        }
        if (checkTiming) {
            err = checkMinDuration(record, nowNs, nowNsSet);
            if (err != null) {
                return err;
            }
        }
        return null;
    }

    /**
     * The compositional replay gate: every non-exempt hard invariant,
     * evaluated with the exempt circumstances left out. Those
     * circumstances may have caused the cheap phase's first failure on
     * a consumed record, and an exempt failure that sits early in the
     * cheap-phase order would otherwise shadow every later hard
     * verdict. When the cheap phase fails with a replay-exempt error
     * on a consumed record, this check re-evaluates the full hard set
     * on the same record; any failure wins outright with the consumed
     * evidence preserved.
     */
    private VerifyError replaySecurityCheck(ChallengeRecord record, String secretKey, String expectedScope,
                                            RequestBindingExpectation expectation, ExecutionEvidence evidence,
                                            long receiptNs, boolean receiptSet) {
        String[] outSecret = {""};
        VerifyError err = checkAuthenticatedShape(record, secretKey, outSecret);
        if (err != null) {
            return err;
        }
        err = checkScopeAndBinding(record, expectedScope, expectation);
        if (err != null) {
            return err;
        }
        err = checkDeploymentExpectations(record);
        if (err != null) {
            return err;
        }
        err = checkExecutionBinding(record, evidence);
        if (err != null) {
            return err;
        }
        return checkMinDuration(record, receiptNs, receiptSet);
    }

    /** The retained consumed-state tri-state, best-effort read. */
    private String retainedConsumedState(String nonce) {
        if (!(storage instanceof Store.ConsumedStateReader reader)) {
            return "unknown";
        }
        Store.ConsumedRecord consumed;
        try {
            consumed = reader.consumedState(nonce);
        } catch (RuntimeException e) {
            return "unreadable";
        }
        return consumed != null ? "consumed" : "pending";
    }

    private void bestEffortDelete(String nonce) {
        try {
            storage.delete(nonce);
        } catch (RuntimeException ignored) {
            // Best-effort: the cleanup never overrides the verdict.
        }
    }

    /** The deterministic derivation of one counter's proof-of-work hash. */
    private byte[] deriveHash(ChallengeRecord record, long counter) {
        byte[] saltBytes = Canonical.b64CanonicalDecode(record.salt);
        if (saltBytes == null) {
            return null;
        }
        String password = record.prefix + counter;
        return switch (record.algorithm) {
            case "sha256" -> Canonical.sha256((password + new String(saltBytes, java.nio.charset.StandardCharsets.ISO_8859_1))
                    .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            case "argon2id" -> argon2idDerive(password, saltBytes, record);
            default -> null;
        };
    }

    /**
     * Applies the protocol profile split: p must be 1 and t at least
     * 3. Parameters outside the profile are authentic but unsupported,
     * so the derivation fails closed with a null instead of silently
     * verifying wrong bytes.
     */
    private byte[] argon2idDerive(String password, byte[] saltBytes, ChallengeRecord record) {
        if (record.p != 1 || record.t < 3) {
            return null;
        }
        if ((long) record.mKib * 1024 < 8192) {
            return null;
        }
        return Argon2id.derive(password.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1),
                saltBytes, record.t, record.mKib, 1, 32, new byte[0], new byte[0]);
    }

    /** Picks the trapdoor for a record: the keyring first, then the active pair. */
    private Rsw resolveRsw(ChallengeRecord record) {
        if (!record.rswModulusSha256.isEmpty()) {
            boolean allowAlias = config.allowLegacyRswIdentity && record.protocolVersion <= 4;
            String identity = record.rswModulusSha256;
            String modulus = config.rswModulusByHash.get(identity);
            if (modulus != null && Rsw.identityMatches(identity, modulus, allowAlias)) {
                return config.rswByHash.get(identity);
            }
            if (config.activeRsw != null && Rsw.identityMatches(identity, config.rswModulusN, allowAlias)) {
                return config.activeRsw;
            }
            return null;
        }
        return config.activeRsw;
    }

    /**
     * The deterministic proof verdict of a presented token against a
     * record, per algorithm. Returns the verdict, or null with
     * outUnsupported set when the derivation cannot be computed.
     */
    private Boolean recomputeValidProof(ChallengeRecord record, SolutionToken token) {
        if (record.algorithm.equals("rsw")) {
            Rsw rsw = resolveRsw(record);
            if (rsw == null) {
                throw new UnsupportedDerivationException(record.algorithm);
            }
            if (token.counter != 0 || token.rswProof.isEmpty()) {
                return false;
            }
            String expected = rsw.expectedProofHex(record.prefix, record.nonce, record.t);
            return Canonical.constantTimeEquals(expected, token.rswProof);
        }
        if (!token.rswProof.isEmpty()) {
            // An rsw final value is rsw evidence only, so a sha256 or
            // argon2id record presented with one is rejected outright:
            // the hash is never derived for it.
            return false;
        }
        byte[] digest = deriveHash(record, token.counter);
        if (digest == null) {
            throw new UnsupportedDerivationException(record.algorithm);
        }
        return Canonical.leadingZeroBits(digest) >= record.targetBits;
    }

    private static final class UnsupportedDerivationException extends RuntimeException {
        final String algorithm;

        UnsupportedDerivationException(String algorithm) {
            this.algorithm = algorithm;
        }
    }

    private boolean commitConsumedResult(ChallengeRecord record, boolean valid, String operationIdentity,
                                        String secret) {
        String binding = record.requestBinding;
        if (storage instanceof Store.AuthenticatedResultCommit committer) {
            byte[] macKey = Canonical.serverStateMacKey(secret, config.tenantId);
            String mac = Canonical.serverStateMacConsumedResult(macKey, record.challenge, valid,
                    binding, operationIdentity);
            try {
                return committer.commitAuthenticatedResult(record.nonce,
                        new Store.ConsumedResult(valid, binding, mac));
            } catch (RuntimeException e) {
                return false;
            }
        }
        try {
            return storage.commitResult(record.nonce, valid, binding);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private void bestEffortCommit(ChallengeRecord record, boolean valid, String operationIdentity,
                                  String secret) {
        commitConsumedResult(record, valid, operationIdentity, secret);
    }

    /**
     * Whether a consumed record's committed success is authentic
     * enough to replay. A storage writer without the master secret
     * cannot produce the server-state mac, so a forged stored success
     * is refused.
     */
    private boolean storedSuccessAuthentic(Store.ConsumedRecord consumed, String secretKey) {
        Store.ConsumedResult result = consumed.consumedResult;
        if (result == null || !result.valid) {
            return false;
        }
        if (result.mac.isEmpty()) {
            return !(storage instanceof Store.AuthenticatedResultCommit);
        }
        String secret = secretForKey(consumed.record, secretKey);
        if (secret == null) {
            return false;
        }
        byte[] key = Canonical.serverStateMacKey(secret, config.tenantId);
        String expected = Canonical.serverStateMacConsumedResult(key, consumed.record.challenge,
                result.valid, result.binding, consumed.operationIdentity);
        return Canonical.constantTimeEquals(expected, result.mac);
    }

    /**
     * Resolves an already-consumed record's retained state into the
     * deterministic verification outcome, shared by the
     * consume-returned envelope and the pre-admission terminal-state
     * check, so the two paths can never diverge. A stored invalid
     * outcome is deterministic and replays to any caller. A stored
     * success is an authorization grant: it replays only when the
     * caller proves the exact logical operation. A retry with any
     * other identity is refused as already consumed. A consumed
     * record without a committed result is ambiguous and reported as
     * indeterminate.
     */
    VerifyOutcome resolveConsumedRecord(Store.ConsumedRecord consumed, String tokenNonce,
                                        String operationIdentity, String secretKey) {
        if (!consumed.record.nonce.equals(tokenNonce)) {
            return VerifyOutcome.invalid(VerifyError.MALFORMED_RECORD);
        }
        if (consumed.consumedResult == null) {
            return VerifyOutcome.invalid(VerifyError.CONSUME_INDETERMINATE);
        }
        if (!consumed.consumedResult.valid) {
            return VerifyOutcome.invalid(VerifyError.INSUFFICIENT_WORK);
        }
        if (!operationIdentity.isEmpty() && !consumed.operationIdentity.isEmpty()
                && Canonical.constantTimeEquals(consumed.operationIdentity, operationIdentity)) {
            if (!storedSuccessAuthentic(consumed, secretKey)) {
                return VerifyOutcome.invalid(VerifyError.MALFORMED_RECORD);
            }
            return VerifyOutcome.valid(consumed.record.nonce, consumed.consumedResult.binding,
                    true, 0, false, consumed.record.decoyField);
        }
        return VerifyOutcome.invalid(VerifyError.ALREADY_CONSUMED);
    }

    /**
     * Runs the one-shot verification of one solution token against
     * this verifier's store. The full cheap-gate order, the
     * replay-exempt split, the consumed resolution, the proof phase
     * and the post-derive final revalidation mirror the php Verifier
     * exactly.
     */
    public VerifyOutcome verify(String rawToken, Options options) {
        RequestBindingExpectation expectation = options.bindingExpectation != null
                ? options.bindingExpectation
                : RequestBindingExpectation.exact(options.expectedRequestBinding);
        String secretKey = options.secretKey;
        SolutionToken token;
        try {
            token = SolutionToken.decode(rawToken);
        } catch (SolutionToken.DecodeException e) {
            return VerifyOutcome.malformedToken(e.code);
        }

        long receiptNs = options.nowNsSet ? options.nowNs : java.time.Instant.now().toEpochMilli() * 1000;
        boolean receiptSet = true;
        ExecutionEvidence evidence = evidenceFromToken(token);

        Store.ChallengeRuntimeState runtimeState = null;
        boolean hasRuntime = false;
        ChallengeRecord peek = null;
        if (storage instanceof Store.RuntimeStateReader reader) {
            try {
                runtimeState = reader.runtimeState(token.nonce);
            } catch (RuntimeException e) {
                return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE);
            }
            hasRuntime = true;
            if (runtimeState.kind == Store.RuntimeStateKind.MISSING) {
                return VerifyOutcome.invalid(VerifyError.RECORD_NOT_FOUND);
            }
            peek = runtimeState.record;
        }
        if (peek == null) {
            try {
                peek = storage.find(token.nonce);
            } catch (RuntimeException e) {
                return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE);
            }
            if (peek == null) {
                return VerifyOutcome.invalid(VerifyError.RECORD_NOT_FOUND);
            }
        }

        // The execution delegation plane: an armed record under a
        // sidecar policy delegates the execution dimension after the
        // cheap phase proved everything the SDK checks locally.
        boolean delegateExecution = !peek.executionProgram.isEmpty()
                && options.executionPolicy != null && options.executionPolicy.enabled();
        VerifyError failure = cheapPhaseCheck(peek, token.nonce, secretKey, options.expectedScope,
                options.clientIp, true, receiptNs, receiptSet, expectation, evidence, delegateExecution);
        if (failure == null && delegateExecution) {
            String[] delegated = options.executionPolicy.delegate(rawToken, options.expectedScope,
                    options.clientIp);
            if ("ok".equals(delegated[0])) {
                return VerifyOutcome.valid(peek.nonce, peek.requestBinding, true, 0L, false,
                        peek.decoyField);
            }
            VerifyError mapped = VerifyError.fromCodeOrNull(delegated[1]);
            // A code outside the vocabulary stays the deterministic
            // deny, never widened into an acceptance.
            return VerifyOutcome.invalid(mapped != null ? mapped : VerifyError.EXECUTION_MISMATCH);
        }
        if (failure != null) {
            if (storage instanceof Store.AtomicDeleteIfPending cleanup && failure != VerifyError.MISSING_CLIENT_IP) {
                Store.DeleteIfPendingResult cleanupResult;
                try {
                    cleanupResult = cleanup.deleteIfPending(token.nonce);
                } catch (RuntimeException e) {
                    return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE);
                }
                if (!cleanupResult.wasConsumed()) {
                    return VerifyOutcome.invalid(failure);
                }
                if (!failure.isReplayExempt()) {
                    return VerifyOutcome.invalid(failure);
                }
                VerifyError hard = replaySecurityCheck(peek, secretKey, options.expectedScope,
                        expectation, evidence, receiptNs, receiptSet);
                if (hard != null) {
                    return VerifyOutcome.invalid(hard);
                }
            } else {
                String retained;
                if (hasRuntime) {
                    retained = runtimeState.kind == Store.RuntimeStateKind.CONSUMED ? "consumed" : "pending";
                } else {
                    retained = retainedConsumedState(token.nonce);
                    if ("unreadable".equals(retained)) {
                        return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE);
                    }
                }
                if ("consumed".equals(retained) && !failure.isReplayExempt()) {
                    return VerifyOutcome.invalid(failure);
                }
                if ("consumed".equals(retained)) {
                    VerifyError hard = replaySecurityCheck(peek, secretKey, options.expectedScope,
                            expectation, evidence, receiptNs, receiptSet);
                    if (hard != null) {
                        return VerifyOutcome.invalid(hard);
                    }
                } else {
                    if (failure != VerifyError.MISSING_CLIENT_IP) {
                        bestEffortDelete(token.nonce);
                    }
                    return VerifyOutcome.invalid(failure);
                }
            }
        }

        // The opt-in telemetry gate. The telemetry is client-controlled,
        // so this is a defense-in-depth signal, not a hard gate. An
        // empty telemetry payload is itself a bot signal and must not
        // bypass strict mode. The gate is replay-exempt: it is
        // client-side evidence about the original solve.
        boolean telemetryEmpty = token.telemetry == null || token.telemetry.size() == 0;
        if (options.enforceTelemetry
                && (telemetryEmpty || Telemetry.scoreTelemetry(token.telemetry, token.durationMs))
                && !(hasRuntime && runtimeState.kind == Store.RuntimeStateKind.CONSUMED)) {
            if (storage instanceof Store.AtomicDeleteIfPending cleanup) {
                Store.DeleteIfPendingResult cleanupResult;
                try {
                    cleanupResult = cleanup.deleteIfPending(token.nonce);
                } catch (RuntimeException e) {
                    return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE);
                }
                if (!cleanupResult.wasConsumed()) {
                    return VerifyOutcome.invalid(VerifyError.TELEMETRY_REJECTED);
                }
            } else {
                String retained;
                if (hasRuntime) {
                    retained = runtimeState.kind == Store.RuntimeStateKind.CONSUMED ? "consumed" : "pending";
                } else {
                    retained = retainedConsumedState(token.nonce);
                    if ("unreadable".equals(retained)) {
                        return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE);
                    }
                }
                if (!"consumed".equals(retained)) {
                    bestEffortDelete(token.nonce);
                    return VerifyOutcome.invalid(VerifyError.TELEMETRY_REJECTED);
                }
            }
        }

        // Terminal-state resolution before the admission gate: a
        // cancelled or already-consumed record must never acquire a
        // scarce admission slot, and a terminal record's outcome is
        // fully determined.
        if (hasRuntime) {
            if (runtimeState.kind == Store.RuntimeStateKind.CANCELLED) {
                return VerifyOutcome.invalid(VerifyError.RECORD_NOT_FOUND);
            }
            if (runtimeState.kind == Store.RuntimeStateKind.CONSUMED) {
                if (runtimeState.consumed != null) {
                    return resolveConsumedRecord(runtimeState.consumed, token.nonce,
                            options.operationIdentity, secretKey);
                }
                if (storage instanceof Store.ConsumedStateReader reader) {
                    Store.ConsumedRecord retained;
                    try {
                        retained = reader.consumedState(token.nonce);
                    } catch (RuntimeException e) {
                        return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE);
                    }
                    if (retained != null) {
                        return resolveConsumedRecord(retained, token.nonce,
                                options.operationIdentity, secretKey);
                    }
                }
            }
        }

        // Argon2id admission: the memory-hard hash is expensive, so an
        // optional gate bounds concurrency. Exhaustion rejects without
        // consuming or deleting the record; the client can retry.
        Object lease = null;
        boolean leaseHeld = false;
        if (peek.algorithm.equals("argon2id")) {
            Object acquired;
            try {
                acquired = config.argonGate.acquire();
            } catch (RuntimeException e) {
                // A broken admission backend is a typed, non-consuming
                // result: the challenge stays intact and can be retried
                // once the backend recovers.
                return VerifyOutcome.invalid(VerifyError.ADMISSION_UNAVAILABLE);
            }
            if (acquired == null) {
                return VerifyOutcome.invalid(VerifyError.CAPACITY_EXCEEDED);
            }
            lease = acquired;
            leaseHeld = true;
        }

        try {
            Store.ConsumedRecord consumed;
            try {
                consumed = consumeRecord(token.nonce, options.operationIdentity);
            } catch (ConsumeIndeterminateSignal e) {
                // A lost transition response, including an identity the
                // storage boundary refused, is ambiguous: the challenge
                // may or may not have been consumed.
                return VerifyOutcome.invalid(VerifyError.CONSUME_INDETERMINATE);
            }
            if (consumed == null) {
                return VerifyOutcome.invalid(VerifyError.RECORD_NOT_FOUND);
            }
            if (consumed.consumedBefore) {
                return resolveConsumedRecord(consumed, token.nonce, options.operationIdentity, secretKey);
            }
            ChallengeRecord record = consumed.record;
            // The consumed instance must be the same challenge that was
            // validated and mac-checked via the peek. The v2 signature
            // covers every immutable parameter, so full revalidation
            // and signature re-verification on the consumed instance is
            // the check that holds: a swapped or racing record fails
            // closed instead of verifying against bytes that were never
            // validated.
            String consumedSecret = secretForKey(record, secretKey);
            if (!Canonical.constantTimeEquals(peek.challenge, record.challenge)
                    || isRevokedKid(record.kidOrOne())
                    || consumedSecret == null
                    || !validateRecord(record)
                    || !Canonical.verifyRecordSignature(record, consumedSecret, config.tenantId)) {
                return VerifyOutcome.invalid(VerifyError.MALFORMED_RECORD);
            }
            if (!argon2CeilingsOk(record)) {
                return VerifyOutcome.invalid(VerifyError.UNSUPPORTED_ARGON2);
            }
            if (!rswParamsOk(record)) {
                return VerifyOutcome.invalid(VerifyError.UNSUPPORTED_RSW_PARAMS);
            }
            if (!policyVersionAccepted(record.policyVersionOrOne())) {
                return VerifyOutcome.invalid(VerifyError.WRONG_POLICY_VERSION);
            }
            if (!config.expectedIssuer.isEmpty() && !record.issuer.equals(config.expectedIssuer)) {
                return VerifyOutcome.invalid(VerifyError.WRONG_ISSUER);
            }

            boolean valid;
            try {
                valid = recomputeValidProof(record, token);
            } catch (UnsupportedDerivationException e) {
                return switch (e.algorithm) {
                    case "rsw" -> VerifyOutcome.invalid(VerifyError.UNSUPPORTED_RSW_PARAMS);
                    case "argon2id" -> VerifyOutcome.invalid(VerifyError.UNSUPPORTED_ARGON2);
                    default -> VerifyOutcome.invalid(VerifyError.MALFORMED_RECORD);
                };
            }

            // Post-derive final revalidation: re-check against the
            // current server clock and the current expectations before
            // the verdict, for both a valid and an invalid derivation.
            // A record that expired during the derivation commits
            // expired, never a stale insufficient-work.
            long now = nowSecs();
            if (now >= record.expiresAt) {
                return VerifyOutcome.invalid(VerifyError.EXPIRED);
            }
            if (!policyVersionAccepted(record.policyVersionOrOne())) {
                return VerifyOutcome.invalid(VerifyError.WRONG_POLICY_VERSION);
            }
            if (!config.region.isEmpty() && !record.region.equals(config.region)) {
                return VerifyOutcome.invalid(VerifyError.WRONG_REGION);
            }
            if (!config.expectedIssuer.isEmpty() && !record.issuer.equals(config.expectedIssuer)) {
                return VerifyOutcome.invalid(VerifyError.WRONG_ISSUER);
            }

            if (!valid) {
                bestEffortCommit(record, false, consumed.operationIdentity, consumedSecret);
                return VerifyOutcome.invalid(VerifyError.INSUFFICIENT_WORK);
            }
            bestEffortCommit(record, true, consumed.operationIdentity, consumedSecret);
            long durationMs = measurableSolveDurationMs(record, receiptNs, receiptSet);
            boolean measured = durationMs >= 0;
            return VerifyOutcome.valid(record.nonce, record.requestBinding, false,
                    Math.max(durationMs, 0), measured, record.decoyField);
        } finally {
            if (leaseHeld) {
                try {
                    config.argonGate.release(lease);
                } catch (RuntimeException ignored) {
                    // Best-effort: a failed release must not override
                    // the verification result (the challenge is already
                    // consumed). A leaked lease is recovered by its TTL.
                }
            }
        }
    }

    /** Marks a lost transition response: the challenge may or may not have been consumed. */
    private static final class ConsumeIndeterminateSignal extends RuntimeException {
    }

    private Store.ConsumedRecord consumeRecord(String nonce, String operationIdentity) {
        String identity = operationIdentity == null ? "" : operationIdentity;
        if (!identity.isEmpty() && storage instanceof Store.OperationIdentityAware aware) {
            try {
                Store.validateOperationIdentity(identity);
            } catch (Store.OperationIdentityException e) {
                // An identity the storage boundary refused is
                // ambiguous: the challenge may or may not have been
                // consumed.
                throw new ConsumeIndeterminateSignal();
            }
            try {
                return aware.consumeWithOperationIdentity(nonce, identity);
            } catch (Store.OperationIdentityException e) {
                throw new ConsumeIndeterminateSignal();
            } catch (RuntimeException e) {
                throw new ConsumeIndeterminateSignal();
            }
        }
        try {
            return storage.consume(nonce);
        } catch (RuntimeException e) {
            throw new ConsumeIndeterminateSignal();
        }
    }
}
