using System.Text;

namespace KiwiCaptcha;

/// <summary>
/// The solution verifier: the exact cheap-gate order and the consumed
/// resolution of the php Verifier, over the storage seam.
///
/// The gate order is normative: nonce match, structure, protocol
/// gate, kid revocation, kid resolution, signature, argon2id
/// ceilings, rsw bounds, ttl, scope, request binding, ip binding,
/// region, policy epoch, issuer, execution binding and minimum
/// duration. The policy epoch carries the rollout-floor window. Then
/// comes the opt-in telemetry gate, the terminal-state resolution,
/// the admission gate, consume, proof, the post-derive final
/// revalidation and the result commit.
///
/// Verify is pure-local: it never calls out to any network service.
/// The only side effects are the storage transitions the one-shot
/// model requires. Execution-armed records (the signed e= commitment)
/// are refused deterministically with execution_mismatch: the browser
/// trace walker is a browser-behavior oracle this SDK does not carry,
/// and an armed record must never pass without it.
/// </summary>
public sealed class Verifier
{
    /// <summary>The explicit request-binding enforcement policy.</summary>
    public sealed record RequestBindingExpectation(
        bool Enforced,
        string Expected,
        bool RequireBindingPresence)
    {
        /// <summary>Skips the request-binding check.</summary>
        public static RequestBindingExpectation Unenforced() => new(false, "", false);

        /// <summary>Requires Option-equality with the expected binding.</summary>
        public static RequestBindingExpectation Exact(string expected) =>
            new(true, expected ?? "", true);

        /// <summary>The explicitly named compatibility mode.</summary>
        public static RequestBindingExpectation Legacy(string expected) =>
            new(!string.IsNullOrEmpty(expected), expected ?? "", false);
    }

    /// <summary>The execution digest and trace one solution token carries.</summary>
    public sealed record ExecutionEvidence(string Digest, string Trace)
    {
        /// <summary>Reports the unarmed evidence shape.</summary>
        public bool IsEmpty() => Digest.Length == 0 && Trace.Length == 0;
    }

    /// <summary>Extracts the evidence of one token.</summary>
    public static ExecutionEvidence EvidenceFromToken(SolutionToken token) =>
        new(token.ExecutionDigest, token.ExecutionTrace);

    /// <summary>The admission-gate seam, mirroring the php VerificationAdmissionGate.</summary>
    public interface IAdmissionGate
    {
        /// <summary>Returns a lease when granted, null on exhaustion, or throws on backend failure.</summary>
        object? Acquire();

        /// <summary>Returns the lease; a failing release must never break the verification.</summary>
        void Release(object? lease);
    }

    /// <summary>The default admission gate that always grants.</summary>
    public sealed class PassThroughGate : IAdmissionGate
    {
        public object? Acquire() => new object();

        public void Release(object? lease)
        {
            // Nothing to return.
        }
    }

    /// <summary>Models a full admission pool: acquire always refuses.</summary>
    public sealed class ExhaustionGate : IAdmissionGate
    {
        public object? Acquire() => null;

        public void Release(object? lease)
        {
            // Nothing to return.
        }
    }

    /// <summary>One trapdoor entry of the rotation keyring.</summary>
    public sealed record RswKeyPair(string ModulusN, string Lambda);

    /// <summary>Reports an invalid construction.</summary>
    public sealed class VerifierBuildException : Exception
    {
        public VerifierBuildException(string reason)
            : base("kiwicaptcha: invalid verifier config: " + reason)
        {
        }
    }

    /// <summary>
    /// The verifier construction options, mirroring the php
    /// constructor. NowSecs supplies the wall clock in unix seconds.
    /// SecretsByKid maps positive kid values to secrets of at least
    /// 32 bytes; an empty map keeps the legacy single-secret path.
    /// </summary>
    public sealed class Config
    {
        public IAdmissionGate? ArgonGate { get; set; }
        public Func<long>? NowSecs { get; set; }
        public bool AcceptLegacyV1 { get; set; }
        public string Region { get; set; } = "";
        public int ExpectedPolicyVersion { get; set; }
        public int PolicyVersionFloor { get; set; }
        public string ExpectedIssuer { get; set; } = "";
        public IReadOnlyDictionary<int, string> SecretsByKid { get; set; } =
            new Dictionary<int, string>();
        public IReadOnlyDictionary<int, bool> RevokedKids { get; set; } =
            new Dictionary<int, bool>();
        public string RswModulusN { get; set; } = "";
        public string RswLambda { get; set; } = "";
        public string TenantId { get; set; } = "";
        public IReadOnlyDictionary<string, RswKeyPair> RswVerificationKeys { get; set; } =
            new Dictionary<string, RswKeyPair>();
        public bool AllowLegacyRswIdentity { get; set; }

        // The trapdoors resolved once at build time.
        internal Rsw? ActiveRsw;
        internal Dictionary<string, Rsw> RswByHash = new();
        internal Dictionary<string, string> RswModulusByHash = new();
    }

    /// <summary>
    /// Validates the construction options and resolves the rsw
    /// trapdoors once at build time, mirroring the php memo.
    /// </summary>
    public static Config ValidateConfig(Config config)
    {
        foreach (var entry in config.SecretsByKid)
        {
            if (entry.Key < 1
                || Encoding.UTF8.GetByteCount(entry.Value) < Kiwi.MinSecretBytes)
            {
                throw new VerifierBuildException(
                    "secrets by kid must map positive integer kids to secrets of at least 32 bytes");
            }
        }
        foreach (var entry in config.RevokedKids)
        {
            if (entry.Key < 1)
            {
                throw new VerifierBuildException("revoked kids must be positive integers 1..N");
            }
        }
        var modulusSet = config.RswModulusN.Length > 0;
        var lambdaSet = config.RswLambda.Length > 0;
        if (modulusSet != lambdaSet)
        {
            throw new VerifierBuildException(
                "rsw modulus and lambda must be configured together (the rsw trapdoor pair)");
        }
        if (config.TenantId.Length > 0 && !ChallengeRecord.IsValidIdentifier(config.TenantId, 64))
        {
            throw new VerifierBuildException("tenant id must be 1..64 bytes of [A-Za-z0-9._:-] when set");
        }
        config.NowSecs ??= () => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        config.ArgonGate ??= new PassThroughGate();
        if (config.ExpectedPolicyVersion < 0 || config.PolicyVersionFloor < 0)
        {
            throw new VerifierBuildException("policy versions are non negative");
        }
        config.ActiveRsw = modulusSet ? Rsw.Of(config.RswModulusN, config.RswLambda) : null;
        config.RswByHash = new Dictionary<string, Rsw>();
        config.RswModulusByHash = new Dictionary<string, string>();
        foreach (var entry in config.RswVerificationKeys)
        {
            var hash = entry.Key;
            var pair = entry.Value;
            if (!SolutionToken.IsHexN(hash, 64))
            {
                throw new VerifierBuildException(
                    "rsw verification keys must map a 64 hex modulus sha256 to a pair");
            }
            if (pair.ModulusN.Length == 0 || pair.Lambda.Length == 0)
            {
                throw new VerifierBuildException(
                    "rsw verification key values must be a non-empty {modulus_n, lambda} pair");
            }
            if (!Rsw.IdentityMatches(hash, pair.ModulusN, config.AllowLegacyRswIdentity))
            {
                throw new VerifierBuildException(
                    "rsw verification key hashes must be the canonical sha256 of the decoded modulus " +
                    "(or its legacy base64-text alias while the migration mode is enabled)");
            }
            var trapdoor = Rsw.Of(pair.ModulusN, pair.Lambda);
            config.RswByHash[hash] = trapdoor;
            config.RswModulusByHash[hash] = pair.ModulusN;
            var fingerprint = Rsw.Fingerprint(pair.ModulusN);
            if (fingerprint.Length > 0)
            {
                config.RswByHash[fingerprint] = trapdoor;
                config.RswModulusByHash[fingerprint] = pair.ModulusN;
            }
            if (config.AllowLegacyRswIdentity)
            {
                var legacy = Rsw.LegacyIdentity(pair.ModulusN);
                config.RswByHash[legacy] = trapdoor;
                config.RswModulusByHash[legacy] = pair.ModulusN;
            }
        }
        return config;
    }

    private readonly Store.IStoreAdapter _storage;
    private readonly Config _config;

    /// <summary>Builds a verifier over a validated config.</summary>
    public Verifier(Store.IStoreAdapter storage, Config config)
    {
        ValidateConfig(config);
        _storage = storage;
        _config = config;
    }

    /// <summary>The store adapter this verifier consumes, for tests and doctor.</summary>
    public Store.IStoreAdapter Storage() => _storage;

    private long NowSecs() => _config.NowSecs!();

    /// <summary>One verify call's parameters.</summary>
    public sealed class Options
    {
        public string SecretKey { get; set; } = "";
        public string ExpectedScope { get; set; } = "";
        public string ClientIp { get; set; } = "";
        public long NowNs { get; set; }
        public bool NowNsSet { get; set; }
        public bool EnforceTelemetry { get; set; }
        public string OperationIdentity { get; set; } = "";
        public string ExpectedRequestBinding { get; set; } = "";
        public RequestBindingExpectation? BindingExpectation { get; set; }
    }

    /// <summary>
    /// The structural validation of a stored record before any crypto
    /// or timing work: the protocol grammar, the scope shape, the
    /// nonce and salt sizes, the ttl ceiling, the prefix binding, the
    /// per-algorithm difficulty range, the decoy alphabet and the
    /// execution commitment equivalence. A record failing any check
    /// is malformed; it cannot have come from a KiwiCaptcha issuer.
    /// </summary>
    public bool ValidateRecord(ChallengeRecord record)
    {
        if (record.ProtocolVersion < 1 || record.ProtocolVersion > Kiwi.MaxProtocolVersion)
        {
            return false;
        }
        var executionPresent = record.ExecutionProgram.Length > 0;
        if (!ChallengeRecord.ProtocolExtensionGrammarOk(record.ProtocolVersion,
                record.DecoyField.Length > 0, executionPresent, record.RswModulusSha256.Length > 0))
        {
            return false;
        }
        if (!ChallengeRecord.IsValidIdentifier(record.Scope, 128))
        {
            return false;
        }
        if (record.DecoyField.Length > 0 && !ChallengeRecord.IsValidDecoyFieldName(record.DecoyField))
        {
            return false;
        }
        if (executionPresent)
        {
            if (record.ExecutionVersion < 1 || record.ExecutionVersion > Kiwi.MaxExecutionVersion
                || record.ExecutionCommitment.Length == 0)
            {
                return false;
            }
            if (!SolutionToken.IsHexN(record.ExecutionCommitment, 64))
            {
                return false;
            }
            if (!Canonical.ConstantTimeEquals(ExecutionProgram.Commitment(record.ExecutionProgram),
                    record.ExecutionCommitment))
            {
                return false;
            }
        }
        else if (record.ExecutionVersion != 0 || record.ExecutionCommitment.Length > 0)
        {
            return false;
        }
        if (record.RswModulusSha256.Length > 0)
        {
            if (record.Algorithm != "rsw" || !SolutionToken.IsHexN(record.RswModulusSha256, 64))
            {
                return false;
            }
        }
        var nonceBytes = Canonical.B64CanonicalDecode(record.Nonce);
        if (nonceBytes == null || nonceBytes.Length != Kiwi.NonceB64Bytes)
        {
            return false;
        }
        var saltBytes = Canonical.B64CanonicalDecode(record.Salt);
        if (saltBytes == null || saltBytes.Length != Kiwi.SaltB64Bytes)
        {
            return false;
        }
        if (record.ExpiresAt <= record.IssuedAt || record.ExpiresAt - record.IssuedAt > Kiwi.MaxTtlSecs)
        {
            return false;
        }
        if (!Canonical.ConstantTimeEquals(record.Challenge + "|" + record.Salt + "|", record.Prefix))
        {
            return false;
        }
        if (record.TargetBits < Kiwi.MinDifficulty || record.TargetBits > Kiwi.MaxDifficulty)
        {
            return false;
        }
        return !executionPresent || ExecutionProgram.IsValidExecutionProgram(record.ExecutionProgram);
    }

    private bool IsRevokedKid(int kid) =>
        _config.RevokedKids.TryGetValue(kid, out var revoked) && revoked;

    /// <summary>
    /// Selects the signature secret for a record. With an empty
    /// secrets set the legacy single-secret path stays. An unknown
    /// kid, or one beyond the newest configured kid, yields null: the
    /// rollback and forward guard keeps a future-keyed challenge from
    /// verifying on an older node.
    /// </summary>
    internal string? SecretForKey(ChallengeRecord record, string legacySecret)
    {
        if (_config.SecretsByKid.Count == 0)
        {
            return legacySecret;
        }
        var newest = 0;
        foreach (var kid in _config.SecretsByKid.Keys)
        {
            if (kid > newest)
            {
                newest = kid;
            }
        }
        var recordKid = record.KidOrOne();
        if (recordKid > newest || !_config.SecretsByKid.TryGetValue(recordKid, out var secret))
        {
            return null;
        }
        return secret;
    }

    /// <summary>Applies the absolute process ceilings to the signed parameters.</summary>
    private bool Argon2CeilingsOk(ChallengeRecord record)
    {
        if (record.Algorithm != "argon2id")
        {
            return true;
        }
        return record.MKib >= Kiwi.MinArgonMemoryKib && record.MKib <= Kiwi.MaxArgonMemoryKib
            && record.T >= Kiwi.MinArgonTime && record.T <= Kiwi.MaxArgonTime
            && record.P >= Kiwi.MinParallelism && record.P <= Kiwi.MaxParallelism;
    }

    /// <summary>Bounds the signed sequential cost to the issuance range.</summary>
    private bool RswParamsOk(ChallengeRecord record)
    {
        if (record.Algorithm != "rsw")
        {
            return true;
        }
        return record.T >= Kiwi.MinRswT && record.T <= Kiwi.MaxRswT;
    }

    /// <summary>
    /// The authenticated hard core of the cheap phase. Shared by the
    /// cheap phase and the compositional replay gate. Returns the
    /// resolved signing secret through outSecret.
    /// </summary>
    private VerifyError? CheckAuthenticatedShape(ChallengeRecord record, string legacySecret,
        out string signingSecret)
    {
        signingSecret = "";
        if (!ValidateRecord(record))
        {
            return VerifyError.MalformedRecord;
        }
        if (record.ProtocolVersion == 1 && !_config.AcceptLegacyV1)
        {
            return VerifyError.MalformedRecord;
        }
        if (IsRevokedKid(record.KidOrOne()))
        {
            return VerifyError.UnknownKid;
        }
        var secret = SecretForKey(record, legacySecret);
        if (secret == null)
        {
            return VerifyError.UnknownKid;
        }
        if (!Canonical.VerifyRecordSignature(record, secret, _config.TenantId))
        {
            return VerifyError.BadSignature;
        }
        signingSecret = secret;
        if (!Argon2CeilingsOk(record))
        {
            return VerifyError.UnsupportedArgon2;
        }
        if (!RswParamsOk(record))
        {
            return VerifyError.UnsupportedRswParams;
        }
        return null;
    }

    /// <summary>
    /// The ttl window on the verifier's clock: expired, or an issuance
    /// more than the future-skew bound ahead.
    /// </summary>
    private VerifyError? CheckTtl(ChallengeRecord record)
    {
        var now = NowSecs();
        if (now >= record.ExpiresAt)
        {
            return VerifyError.Expired;
        }
        if (record.IssuedAt > now + Kiwi.MaxClockSkew)
        {
            return VerifyError.Expired;
        }
        return null;
    }

    /// <summary>
    /// The single request-binding check: exact Option-equality between
    /// the record's signed request binding and the expectation's
    /// authoritative binding.
    /// </summary>
    private VerifyError? CheckRequestBinding(ChallengeRecord record, RequestBindingExpectation expectation)
    {
        if (!expectation.Enforced)
        {
            return null;
        }
        if (record.RequestBinding.Length == 0 || expectation.Expected.Length == 0)
        {
            if (record.RequestBinding.Length == 0 && !expectation.RequireBindingPresence)
            {
                return null;
            }
            if (record.RequestBinding == expectation.Expected)
            {
                return null;
            }
            return VerifyError.RequestBinding;
        }
        if (Canonical.ConstantTimeEquals(record.RequestBinding, expectation.Expected))
        {
            return null;
        }
        return VerifyError.RequestBinding;
    }

    /// <summary>The scope validation and the expected request binding.</summary>
    private VerifyError? CheckScopeAndBinding(ChallengeRecord record, string expectedScope,
        RequestBindingExpectation expectation)
    {
        if (expectedScope.Length > 0 && record.Scope != expectedScope)
        {
            return VerifyError.WrongScope;
        }
        return CheckRequestBinding(record, expectation);
    }

    /// <summary>
    /// The ip binding check. The stored record is authoritative. An
    /// empty binding tag means binding is disabled. A nonempty tag
    /// means the challenge is bound, so a missing client ip fails
    /// closed instead of silently skipping the check.
    /// </summary>
    private VerifyError? CheckIpBinding(ChallengeRecord record, string? clientIp, string signingSecret)
    {
        if (record.BindingTag.Length == 0)
        {
            return null;
        }
        if (string.IsNullOrEmpty(clientIp))
        {
            return VerifyError.MissingClientIp;
        }
        string expectedTag;
        if (record.ProtocolVersion == 1)
        {
            expectedTag = Canonical.HashIpV1(clientIp, signingSecret);
        }
        else
        {
            string computed;
            try
            {
                computed = Canonical.BindingTag(record.Nonce, clientIp, signingSecret, _config.TenantId);
            }
            catch (Canonical.InvalidIpException)
            {
                return VerifyError.IpMismatch;
            }
            expectedTag = computed;
        }
        if (!Canonical.ConstantTimeEquals(expectedTag, record.BindingTag))
        {
            return VerifyError.IpMismatch;
        }
        return null;
    }

    /// <summary>
    /// Whether the record's security-policy epoch satisfies the
    /// configured expectations. A declared rollout window accepts
    /// floor <= epoch <= expected; a floor above the expected epoch
    /// accepts nothing, so the window is fail-closed, never a licence
    /// to verify below the newest declared epoch.
    /// </summary>
    internal bool PolicyVersionAccepted(int recordVersion)
    {
        if (_config.ExpectedPolicyVersion == 0)
        {
            return true;
        }
        if (_config.PolicyVersionFloor == 0)
        {
            return recordVersion == _config.ExpectedPolicyVersion;
        }
        return _config.PolicyVersionFloor <= recordVersion && recordVersion <= _config.ExpectedPolicyVersion;
    }

    /// <summary>Region, policy epoch and issuer, hard invariants in cheap-phase order.</summary>
    private VerifyError? CheckDeploymentExpectations(ChallengeRecord record)
    {
        if (_config.Region.Length > 0 && record.Region != _config.Region)
        {
            return VerifyError.WrongRegion;
        }
        if (!PolicyVersionAccepted(record.PolicyVersionOrOne()))
        {
            return VerifyError.WrongPolicyVersion;
        }
        if (_config.ExpectedIssuer.Length > 0 && record.Issuer != _config.ExpectedIssuer)
        {
            return VerifyError.WrongIssuer;
        }
        return null;
    }

    /// <summary>
    /// The execution binding check. An unarmed record demands no
    /// digest: a presented digest is stray execution evidence and is
    /// rejected deterministically, never silently ignored. An armed
    /// record demands the browser-trace walker, a browser-behavior
    /// oracle this SDK does not carry, so the armed dimension fails
    /// closed.
    /// </summary>
    private VerifyError? CheckExecutionBinding(ChallengeRecord record, ExecutionEvidence evidence)
    {
        if (record.ExecutionProgram.Length == 0)
        {
            if (evidence.IsEmpty())
            {
                return null;
            }
            return VerifyError.ExecutionMismatch;
        }
        return VerifyError.ExecutionMismatch;
    }

    /// <summary>
    /// The server-measured minimum duration. Elapsed time is the gap
    /// between the record's high-resolution issuance timestamp and the
    /// verification receipt time. The client-reported duration is
    /// forgeable, so it never drives the check; a record without an
    /// authenticated issuance clock cannot be timed and fails closed.
    /// </summary>
    private VerifyError? CheckMinDuration(ChallengeRecord record, long nowNs, bool nowNsSet)
    {
        if (record.IssuedAtNs <= 0)
        {
            return VerifyError.MalformedRecord;
        }
        var floor = Math.Max(record.MinDurationMs, 0);
        if (floor == 0)
        {
            return null;
        }
        if (record.ServerMac.Length == 0)
        {
            // The issuance clock is unauthenticated: a storage writer
            // could have backdated it, so the floor cannot be evaluated
            // and fails closed.
            return VerifyError.MalformedRecord;
        }
        var receiptNs = nowNsSet ? nowNs : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
        if (receiptNs >= record.IssuedAtNs)
        {
            if (receiptNs - record.IssuedAtNs < (long)floor * 1_000)
            {
                return VerifyError.TooFast;
            }
        }
        else if (record.IssuedAtNs - receiptNs > Kiwi.SkewToleranceUs)
        {
            // Receipt before issuance by more than the skew bound is
            // physically impossible. Within the bound the two hosts'
            // clocks are unsynced, so the elapsed time cannot be
            // measured reliably, the floor check is skipped and the
            // proof-of-work check still applies.
            return VerifyError.TooFast;
        }
        return null;
    }

    /// <summary>
    /// The server-measured solve duration of a verified record in
    /// milliseconds, or -1 when unmeasurable.
    /// </summary>
    private long MeasurableSolveDurationMs(ChallengeRecord record, long receiptNs, bool receiptSet)
    {
        if (record.ServerMac.Length == 0 || record.IssuedAtNs <= 0 || !receiptSet
            || receiptNs < record.IssuedAtNs)
        {
            return -1;
        }
        return (receiptNs - record.IssuedAtNs) / 1_000;
    }

    /// <summary>
    /// Runs the shared security checks in the order of the ordinary
    /// path; the first failing check decides the outcome.
    /// </summary>
    private VerifyError? CheapPhaseCheck(ChallengeRecord record, string tokenNonce, string secretKey,
        string expectedScope, string? clientIp, bool checkTiming, long nowNs, bool nowNsSet,
        RequestBindingExpectation expectation, ExecutionEvidence evidence)
    {
        if (record.Nonce != tokenNonce)
        {
            return VerifyError.MalformedRecord;
        }
        var err = CheckAuthenticatedShape(record, secretKey, out var signingSecret);
        if (err != null)
        {
            return err;
        }
        if (checkTiming)
        {
            err = CheckTtl(record);
            if (err != null)
            {
                return err;
            }
        }
        err = CheckScopeAndBinding(record, expectedScope, expectation);
        if (err != null)
        {
            return err;
        }
        err = CheckIpBinding(record, clientIp, signingSecret);
        if (err != null)
        {
            return err;
        }
        err = CheckDeploymentExpectations(record);
        if (err != null)
        {
            return err;
        }
        err = CheckExecutionBinding(record, evidence);
        if (err != null)
        {
            return err;
        }
        if (checkTiming)
        {
            err = CheckMinDuration(record, nowNs, nowNsSet);
            if (err != null)
            {
                return err;
            }
        }
        return null;
    }

    /// <summary>
    /// The compositional replay gate: every non-exempt hard
    /// invariant, evaluated with the exempt circumstances left out.
    /// When the cheap phase fails with a replay-exempt error on a
    /// consumed record, this check re-evaluates the full hard set on
    /// the same record; any failure wins outright with the consumed
    /// evidence preserved.
    /// </summary>
    private VerifyError? ReplaySecurityCheck(ChallengeRecord record, string secretKey, string expectedScope,
        RequestBindingExpectation expectation, ExecutionEvidence evidence, long receiptNs, bool receiptSet)
    {
        var err = CheckAuthenticatedShape(record, secretKey, out _);
        if (err != null)
        {
            return err;
        }
        err = CheckScopeAndBinding(record, expectedScope, expectation);
        if (err != null)
        {
            return err;
        }
        err = CheckDeploymentExpectations(record);
        if (err != null)
        {
            return err;
        }
        err = CheckExecutionBinding(record, evidence);
        if (err != null)
        {
            return err;
        }
        return CheckMinDuration(record, receiptNs, receiptSet);
    }

    /// <summary>The retained consumed-state tri-state, best-effort read.</summary>
    private string RetainedConsumedState(string nonce)
    {
        if (_storage is not Store.IConsumedStateReader reader)
        {
            return "unknown";
        }
        Store.ConsumedRecord? consumed;
        try
        {
            consumed = reader.ConsumedState(nonce);
        }
        catch (Exception)
        {
            return "unreadable";
        }
        return consumed != null ? "consumed" : "pending";
    }

    private void BestEffortDelete(string nonce)
    {
        try
        {
            _storage.Delete(nonce);
        }
        catch (Exception)
        {
            // Best-effort: the cleanup never overrides the verdict.
        }
    }

    /// <summary>The deterministic derivation of one counter's proof-of-work hash.</summary>
    private byte[]? DeriveHash(ChallengeRecord record, long counter)
    {
        var saltBytes = Canonical.B64CanonicalDecode(record.Salt);
        if (saltBytes == null)
        {
            return null;
        }
        var password = record.Prefix + counter;
        switch (record.Algorithm)
        {
            case "sha256":
            {
                var passwordBytes = Encoding.UTF8.GetBytes(password);
                var input = new byte[passwordBytes.Length + saltBytes.Length];
                Array.Copy(passwordBytes, input, passwordBytes.Length);
                Array.Copy(saltBytes, 0, input, passwordBytes.Length, saltBytes.Length);
                return Canonical.Sha256(input);
            }
            case "argon2id":
                return Argon2IdDerive(password, saltBytes, record);
            default:
                return null;
        }
    }

    /// <summary>
    /// Applies the protocol profile split: p must be 1 and t at least
    /// 3. Parameters outside the profile are authentic but
    /// unsupported, so the derivation fails closed with a null.
    /// </summary>
    private byte[]? Argon2IdDerive(string password, byte[] saltBytes, ChallengeRecord record)
    {
        if (record.P != 1 || record.T < 3)
        {
            return null;
        }
        if ((long)record.MKib * 1024 < 8192)
        {
            return null;
        }
        return Argon2Id.Derive(Encoding.UTF8.GetBytes(password), saltBytes, record.T, record.MKib,
            1, 32, Array.Empty<byte>(), Array.Empty<byte>());
    }

    /// <summary>Picks the trapdoor for a record: the keyring first, then the active pair.</summary>
    private Rsw? ResolveRsw(ChallengeRecord record)
    {
        if (record.RswModulusSha256.Length > 0)
        {
            var allowAlias = _config.AllowLegacyRswIdentity && record.ProtocolVersion <= 4;
            var identity = record.RswModulusSha256;
            if (_config.RswModulusByHash.TryGetValue(identity, out var modulus)
                && Rsw.IdentityMatches(identity, modulus, allowAlias))
            {
                return _config.RswByHash[identity];
            }
            if (_config.ActiveRsw != null && Rsw.IdentityMatches(identity, _config.RswModulusN, allowAlias))
            {
                return _config.ActiveRsw;
            }
            return null;
        }
        return _config.ActiveRsw;
    }

    /// <summary>Marks a derivation this verifier cannot compute.</summary>
    private sealed class UnsupportedDerivationException : Exception
    {
        internal string Algorithm { get; }

        internal UnsupportedDerivationException(string algorithm) => Algorithm = algorithm;
    }

    /// <summary>
    /// The deterministic proof verdict of a presented token against a
    /// record, per algorithm. Returns the verdict, or throws the
    /// unsupported marker when the derivation cannot be computed.
    /// </summary>
    private bool RecomputeValidProof(ChallengeRecord record, SolutionToken token)
    {
        if (record.Algorithm == "rsw")
        {
            var rsw = ResolveRsw(record);
            if (rsw == null)
            {
                throw new UnsupportedDerivationException("rsw");
            }
            if (token.Counter != 0 || token.RswProof.Length == 0)
            {
                return false;
            }
            var expected = rsw.ExpectedProofHex(record.Prefix, record.Nonce, record.T);
            return Canonical.ConstantTimeEquals(expected, token.RswProof);
        }
        if (token.RswProof.Length > 0)
        {
            // An rsw final value is rsw evidence only, so a sha256 or
            // argon2id record presented with one is rejected outright:
            // the hash is never derived for it.
            return false;
        }
        var digest = DeriveHash(record, token.Counter);
        if (digest == null)
        {
            throw new UnsupportedDerivationException(record.Algorithm);
        }
        return Canonical.LeadingZeroBits(digest) >= record.TargetBits;
    }

    private bool CommitConsumedResult(ChallengeRecord record, bool valid, string operationIdentity,
        string secret)
    {
        var binding = record.RequestBinding;
        if (_storage is Store.IAuthenticatedResultCommit committer)
        {
            var macKey = Canonical.ServerStateMacKey(secret, _config.TenantId);
            var mac = Canonical.ServerStateMacConsumedResult(macKey, record.Challenge, valid,
                binding, operationIdentity);
            try
            {
                return committer.CommitAuthenticatedResult(record.Nonce,
                    new Store.ConsumedResult(valid, binding, mac));
            }
            catch (Exception)
            {
                return false;
            }
        }
        try
        {
            return _storage.CommitResult(record.Nonce, valid, binding);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private void BestEffortCommit(ChallengeRecord record, bool valid, string operationIdentity,
        string secret) => CommitConsumedResult(record, valid, operationIdentity, secret);

    /// <summary>
    /// Whether a consumed record's committed success is authentic
    /// enough to replay. A storage writer without the master secret
    /// cannot produce the server-state mac, so a forged stored success
    /// is refused.
    /// </summary>
    private bool StoredSuccessAuthentic(Store.ConsumedRecord consumed, string secretKey)
    {
        var result = consumed.ConsumedResult;
        if (result == null || !result.Valid)
        {
            return false;
        }
        if (result.Mac.Length == 0)
        {
            return _storage is not Store.IAuthenticatedResultCommit;
        }
        var secret = SecretForKey(consumed.Record, secretKey);
        if (secret == null)
        {
            return false;
        }
        var key = Canonical.ServerStateMacKey(secret, _config.TenantId);
        var expected = Canonical.ServerStateMacConsumedResult(key, consumed.Record.Challenge,
            result.Valid, result.Binding, consumed.OperationIdentity);
        return Canonical.ConstantTimeEquals(expected, result.Mac);
    }

    /// <summary>
    /// Resolves an already-consumed record's retained state into the
    /// deterministic verification outcome, shared by the
    /// consume-returned envelope and the pre-admission terminal-state
    /// check, so the two paths can never diverge.
    /// </summary>
    internal VerifyOutcome ResolveConsumedRecord(Store.ConsumedRecord consumed, string tokenNonce,
        string operationIdentity, string secretKey)
    {
        if (consumed.Record.Nonce != tokenNonce)
        {
            return VerifyOutcome.InvalidOutcome(VerifyError.MalformedRecord);
        }
        if (consumed.ConsumedResult == null)
        {
            return VerifyOutcome.InvalidOutcome(VerifyError.ConsumeIndeterminate);
        }
        if (!consumed.ConsumedResult.Valid)
        {
            return VerifyOutcome.InvalidOutcome(VerifyError.InsufficientWork);
        }
        if (operationIdentity.Length > 0 && consumed.OperationIdentity.Length > 0
            && Canonical.ConstantTimeEquals(consumed.OperationIdentity, operationIdentity))
        {
            if (!StoredSuccessAuthentic(consumed, secretKey))
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.MalformedRecord);
            }
            return VerifyOutcome.ValidOutcome(consumed.Record.Nonce, consumed.ConsumedResult.Binding,
                true, 0, false, consumed.Record.DecoyField);
        }
        return VerifyOutcome.InvalidOutcome(VerifyError.AlreadyConsumed);
    }

    /// <summary>Marks a lost transition response: the challenge may or may not have been consumed.</summary>
    private sealed class ConsumeIndeterminateSignal : Exception
    {
    }

    private Store.ConsumedRecord? ConsumeRecord(string nonce, string? operationIdentity)
    {
        var identity = operationIdentity ?? "";
        if (identity.Length > 0 && _storage is Store.IOperationIdentityAware aware)
        {
            try
            {
                Store.ValidateOperationIdentity(identity);
            }
            catch (Store.OperationIdentityException)
            {
                // An identity the storage boundary refused is
                // ambiguous: the challenge may or may not have been
                // consumed.
                throw new ConsumeIndeterminateSignal();
            }
            try
            {
                return aware.ConsumeWithOperationIdentity(nonce, identity);
            }
            catch (Store.OperationIdentityException)
            {
                throw new ConsumeIndeterminateSignal();
            }
            catch (Exception)
            {
                throw new ConsumeIndeterminateSignal();
            }
        }
        try
        {
            return _storage.Consume(nonce);
        }
        catch (Exception)
        {
            throw new ConsumeIndeterminateSignal();
        }
    }

    /// <summary>
    /// Runs the one-shot verification of one solution token against
    /// this verifier's store. The full cheap-gate order, the
    /// replay-exempt split, the consumed resolution, the proof phase
    /// and the post-derive final revalidation mirror the php Verifier
    /// exactly.
    /// </summary>
    public VerifyOutcome Verify(string rawToken, Options options)
    {
        var expectation = options.BindingExpectation
            ?? RequestBindingExpectation.Exact(options.ExpectedRequestBinding);
        var secretKey = options.SecretKey;
        SolutionToken token;
        try
        {
            token = SolutionToken.Decode(rawToken);
        }
        catch (SolutionToken.DecodeException e)
        {
            return VerifyOutcome.MalformedTokenOutcome(e.Code);
        }

        var receiptNs = options.NowNsSet
            ? options.NowNs
            : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
        var receiptSet = true;
        var evidence = EvidenceFromToken(token);

        Store.ChallengeRuntimeState? runtimeState = null;
        var hasRuntime = false;
        ChallengeRecord? peek = null;
        if (_storage is Store.IRuntimeStateReader reader)
        {
            try
            {
                runtimeState = reader.RuntimeState(token.Nonce);
            }
            catch (Exception)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.StorageUnavailable);
            }
            hasRuntime = true;
            if (runtimeState.Kind == Store.RuntimeStateKind.Missing)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.RecordNotFound);
            }
            peek = runtimeState.Record;
        }
        if (peek == null)
        {
            try
            {
                peek = _storage.Find(token.Nonce);
            }
            catch (Exception)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.StorageUnavailable);
            }
            if (peek == null)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.RecordNotFound);
            }
        }

        var failure = CheapPhaseCheck(peek, token.Nonce, secretKey, options.ExpectedScope,
            options.ClientIp, true, receiptNs, receiptSet, expectation, evidence);
        if (failure != null)
        {
            if (_storage is Store.IAtomicDeleteIfPending cleanup && failure != VerifyError.MissingClientIp)
            {
                Store.DeleteIfPendingResult cleanupResult;
                try
                {
                    cleanupResult = cleanup.DeleteIfPending(token.Nonce);
                }
                catch (Exception)
                {
                    return VerifyOutcome.InvalidOutcome(VerifyError.StorageUnavailable);
                }
                if (!cleanupResult.WasConsumed())
                {
                    return VerifyOutcome.InvalidOutcome(failure!.Value);
                }
                if (!failure.Value.IsReplayExempt())
                {
                    return VerifyOutcome.InvalidOutcome(failure.Value);
                }
                var hard = ReplaySecurityCheck(peek, secretKey, options.ExpectedScope,
                    expectation, evidence, receiptNs, receiptSet);
                if (hard != null)
                {
                    return VerifyOutcome.InvalidOutcome(hard.Value);
                }
            }
            else
            {
                string retained;
                if (hasRuntime)
                {
                    retained = runtimeState!.Kind == Store.RuntimeStateKind.Consumed ? "consumed" : "pending";
                }
                else
                {
                    retained = RetainedConsumedState(token.Nonce);
                    if (retained == "unreadable")
                    {
                        return VerifyOutcome.InvalidOutcome(VerifyError.StorageUnavailable);
                    }
                }
                if (retained == "consumed" && !failure.Value.IsReplayExempt())
                {
                    return VerifyOutcome.InvalidOutcome(failure.Value);
                }
                if (retained == "consumed")
                {
                    var hard = ReplaySecurityCheck(peek, secretKey, options.ExpectedScope,
                        expectation, evidence, receiptNs, receiptSet);
                    if (hard != null)
                    {
                        return VerifyOutcome.InvalidOutcome(hard.Value);
                    }
                }
                else
                {
                    if (failure.Value != VerifyError.MissingClientIp)
                    {
                        BestEffortDelete(token.Nonce);
                    }
                    return VerifyOutcome.InvalidOutcome(failure.Value);
                }
            }
        }

        // The opt-in telemetry gate. The telemetry is client-controlled,
        // so this is a defense-in-depth signal, not a hard gate. An
        // empty telemetry payload is itself a bot signal and must not
        // bypass strict mode. The gate is replay-exempt: it is
        // client-side evidence about the original solve.
        var telemetryEmpty = token.Telemetry.Size == 0;
        if (options.EnforceTelemetry
            && (telemetryEmpty || Telemetry.ScoreTelemetry(token.Telemetry, token.DurationMs))
            && !(hasRuntime && runtimeState!.Kind == Store.RuntimeStateKind.Consumed))
        {
            if (_storage is Store.IAtomicDeleteIfPending telemetryCleanup)
            {
                Store.DeleteIfPendingResult cleanupResult;
                try
                {
                    cleanupResult = telemetryCleanup.DeleteIfPending(token.Nonce);
                }
                catch (Exception)
                {
                    return VerifyOutcome.InvalidOutcome(VerifyError.StorageUnavailable);
                }
                if (!cleanupResult.WasConsumed())
                {
                    return VerifyOutcome.InvalidOutcome(VerifyError.TelemetryRejected);
                }
            }
            else
            {
                string retained;
                if (hasRuntime)
                {
                    retained = runtimeState!.Kind == Store.RuntimeStateKind.Consumed ? "consumed" : "pending";
                }
                else
                {
                    retained = RetainedConsumedState(token.Nonce);
                    if (retained == "unreadable")
                    {
                        return VerifyOutcome.InvalidOutcome(VerifyError.StorageUnavailable);
                    }
                }
                if (retained != "consumed")
                {
                    BestEffortDelete(token.Nonce);
                    return VerifyOutcome.InvalidOutcome(VerifyError.TelemetryRejected);
                }
            }
        }

        // Terminal-state resolution before the admission gate: a
        // cancelled or already-consumed record must never acquire a
        // scarce admission slot, and a terminal record's outcome is
        // fully determined.
        if (hasRuntime)
        {
            if (runtimeState!.Kind == Store.RuntimeStateKind.Cancelled)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.RecordNotFound);
            }
            if (runtimeState.Kind == Store.RuntimeStateKind.Consumed)
            {
                if (runtimeState.Consumed != null)
                {
                    return ResolveConsumedRecord(runtimeState.Consumed, token.Nonce,
                        options.OperationIdentity, secretKey);
                }
                if (_storage is Store.IConsumedStateReader consumedReader)
                {
                    Store.ConsumedRecord? retained;
                    try
                    {
                        retained = consumedReader.ConsumedState(token.Nonce);
                    }
                    catch (Exception)
                    {
                        return VerifyOutcome.InvalidOutcome(VerifyError.StorageUnavailable);
                    }
                    if (retained != null)
                    {
                        return ResolveConsumedRecord(retained, token.Nonce,
                            options.OperationIdentity, secretKey);
                    }
                }
            }
        }

        // Argon2id admission: the memory-hard hash is expensive, so an
        // optional gate bounds concurrency. Exhaustion rejects without
        // consuming or deleting the record; the client can retry.
        object? lease = null;
        var leaseHeld = false;
        if (peek.Algorithm == "argon2id")
        {
            object? acquired;
            try
            {
                acquired = _config.ArgonGate!.Acquire();
            }
            catch (Exception)
            {
                // A broken admission backend is a typed, non-consuming
                // result: the challenge stays intact and can be retried
                // once the backend recovers.
                return VerifyOutcome.InvalidOutcome(VerifyError.AdmissionUnavailable);
            }
            if (acquired == null)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.CapacityExceeded);
            }
            lease = acquired;
            leaseHeld = true;
        }

        try
        {
            Store.ConsumedRecord? consumed;
            try
            {
                consumed = ConsumeRecord(token.Nonce, options.OperationIdentity);
            }
            catch (ConsumeIndeterminateSignal)
            {
                // A lost transition response, including an identity the
                // storage boundary refused, is ambiguous: the challenge
                // may or may not have been consumed.
                return VerifyOutcome.InvalidOutcome(VerifyError.ConsumeIndeterminate);
            }
            if (consumed == null)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.RecordNotFound);
            }
            if (consumed.ConsumedBefore)
            {
                return ResolveConsumedRecord(consumed, token.Nonce, options.OperationIdentity, secretKey);
            }
            var record = consumed.Record;

            // The consumed instance must be the same challenge that was
            // validated and mac-checked via the peek. The v2 signature
            // covers every immutable parameter, so full revalidation
            // and signature re-verification on the consumed instance
            // is the check that holds: a swapped or racing record
            // fails closed instead of verifying against bytes that
            // were never validated.
            var consumedSecret = SecretForKey(record, secretKey);
            if (!Canonical.ConstantTimeEquals(peek.Challenge, record.Challenge)
                || IsRevokedKid(record.KidOrOne())
                || consumedSecret == null
                || !ValidateRecord(record)
                || !Canonical.VerifyRecordSignature(record, consumedSecret, _config.TenantId))
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.MalformedRecord);
            }
            if (!Argon2CeilingsOk(record))
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.UnsupportedArgon2);
            }
            if (!RswParamsOk(record))
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.UnsupportedRswParams);
            }
            if (!PolicyVersionAccepted(record.PolicyVersionOrOne()))
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.WrongPolicyVersion);
            }
            if (_config.ExpectedIssuer.Length > 0 && record.Issuer != _config.ExpectedIssuer)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.WrongIssuer);
            }

            bool valid;
            try
            {
                valid = RecomputeValidProof(record, token);
            }
            catch (UnsupportedDerivationException e)
            {
                return e.Algorithm switch
                {
                    "rsw" => VerifyOutcome.InvalidOutcome(VerifyError.UnsupportedRswParams),
                    "argon2id" => VerifyOutcome.InvalidOutcome(VerifyError.UnsupportedArgon2),
                    _ => VerifyOutcome.InvalidOutcome(VerifyError.MalformedRecord),
                };
            }

            // Post-derive final revalidation: re-check against the
            // current server clock and the current expectations before
            // the verdict, for both a valid and an invalid derivation.
            // A record that expired during the derivation commits
            // expired, never a stale insufficient-work.
            var now = NowSecs();
            if (now >= record.ExpiresAt)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.Expired);
            }
            if (!PolicyVersionAccepted(record.PolicyVersionOrOne()))
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.WrongPolicyVersion);
            }
            if (_config.Region.Length > 0 && record.Region != _config.Region)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.WrongRegion);
            }
            if (_config.ExpectedIssuer.Length > 0 && record.Issuer != _config.ExpectedIssuer)
            {
                return VerifyOutcome.InvalidOutcome(VerifyError.WrongIssuer);
            }

            if (!valid)
            {
                BestEffortCommit(record, false, consumed.OperationIdentity, consumedSecret);
                return VerifyOutcome.InvalidOutcome(VerifyError.InsufficientWork);
            }
            BestEffortCommit(record, true, consumed.OperationIdentity, consumedSecret);
            var durationMs = MeasurableSolveDurationMs(record, receiptNs, receiptSet);
            var measured = durationMs >= 0;
            return VerifyOutcome.ValidOutcome(record.Nonce, record.RequestBinding, false,
                Math.Max(durationMs, 0), measured, record.DecoyField);
        }
        finally
        {
            if (leaseHeld)
            {
                try
                {
                    _config.ArgonGate!.Release(lease);
                }
                catch (Exception)
                {
                    // Best-effort: a failed release must not override
                    // the verification result (the challenge is already
                    // consumed). A leaked lease is recovered by its TTL.
                }
            }
        }
    }
}

/// <summary>
/// The contract level answer of verify: the shared server SDK shape
/// {ok, disposition, decision_handle, price}. Disposition is allow
/// when the proof verified, deny for a definitive rejection, and
/// retry for a transient condition.
/// </summary>
public sealed record Decision
{
    public const string DispositionAllow = "allow";
    public const string DispositionDeny = "deny";
    public const string DispositionRetry = "retry";

    /// <summary>Whether the proof verified.</summary>
    public bool Ok { get; init; }

    /// <summary>allow, deny or retry.</summary>
    public string Disposition { get; init; } = DispositionDeny;

    /// <summary>The verified nonce, empty on a failure.</summary>
    public string DecisionHandle { get; init; } = "";

    /// <summary>The work ladder rung of the challenge, empty on a failure.</summary>
    public string Price { get; init; } = "";

    /// <summary>The machine readable failure code, empty when ok.</summary>
    public string Error { get; init; } = "";

    /// <summary>The full underlying outcome.</summary>
    public VerifyOutcome Outcome { get; init; } = VerifyOutcome.InvalidOutcome(default);

    private static readonly IReadOnlyDictionary<VerifyError, bool> RetryCodes =
        new Dictionary<VerifyError, bool>
        {
            [VerifyError.StorageUnavailable] = true,
            [VerifyError.CapacityExceeded] = true,
            [VerifyError.AdmissionUnavailable] = true,
            [VerifyError.ConsumeIndeterminate] = true,
        };

    /// <summary>Maps a verify outcome onto the decision plane.</summary>
    public static Decision FromOutcome(VerifyOutcome outcome, string price)
    {
        if (outcome.Valid)
        {
            return new Decision
            {
                Ok = true,
                Disposition = DispositionAllow,
                DecisionHandle = outcome.Nonce,
                Price = price,
                Outcome = outcome,
            };
        }
        var disposition = outcome.Error != null && RetryCodes.ContainsKey(outcome.Error.Value)
            ? DispositionRetry
            : DispositionDeny;
        return new Decision
        {
            Ok = false,
            Disposition = disposition,
            Error = outcome.Code,
            Outcome = outcome,
        };
    }

    /// <summary>
    /// Names the work ladder rung of one record's authenticated
    /// parameters. The sha rungs carry their difficulty, the argon
    /// rungs their memory, and the sequential time-lock rung is rsw.
    /// </summary>
    public static string PriceRung(string algorithm, int targetBits, int mKib) => algorithm switch
    {
        "sha256" => "sha" + targetBits,
        "argon2id" => "argon" + mKib,
        _ => "rsw",
    };
}
