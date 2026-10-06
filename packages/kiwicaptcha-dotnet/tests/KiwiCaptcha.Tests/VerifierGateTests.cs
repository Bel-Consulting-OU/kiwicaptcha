using System.Text;
using Xunit;

namespace KiwiCaptcha.Tests;

/// <summary>The drivable error codes, the gate order and the one-shot model.</summary>
public class VerifierGateTests
{
    private const long GoldenIssuedAt = 1_900_000_000L;

    private static string TokenForRecord(ChallengeRecord record) =>
        SolutionToken.Create(record.Nonce,
            Support.SolveSha(record.Prefix, record.Salt, record.TargetBits), 5000,
            JsonObject.Of(("me", new JsonNumber("1")))).Encode();

    private static Verifier.Options Options(string? scope, string? clientIp) => new()
    {
        SecretKey = Support.TestSecret,
        ExpectedScope = scope ?? "",
        ClientIp = clientIp ?? "",
    };

    private static string Repeat(string s, int count) => string.Concat(Enumerable.Repeat(s, count));

    [Fact]
    public void GoldenSha256EndToEnd()
    {
        var golden = Support.StrictJson(Support.TestdataPath("golden/golden_sha256_v2.json"));
        var record = Support.GoldenRecord(golden);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), GoldenIssuedAt);
        Support.StoreRecord(verifier.Storage(), record);
        var token = SolutionToken.Create(record.Nonce,
            Support.SolveSha(record.Prefix, record.Salt, record.TargetBits), 5000,
            new JsonObject()).Encode();
        var outcome = verifier.Verify(token, Options("login", "198.51.100.7"));
        Support.RequireValid(outcome);
        Assert.Equal(record.Nonce, outcome.Nonce);
        Assert.Equal("sha8", Decision.PriceRung(record.Algorithm, record.TargetBits, record.MKib));
    }

    [Fact]
    public void MalformedToken()
    {
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        var outcome = verifier.Verify("not-a-token", Options(null, null));
        Support.RequireCode(outcome, VerifyError.MalformedToken);
        Assert.Equal(SolutionToken.DecodeErrInvalidBase64, outcome.Detail);
    }

    [Fact]
    public void RecordNotFound()
    {
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        var token = SolutionToken.Create(Support.ShaVector.Nonce, 1, 1, new JsonObject()).Encode();
        Support.RequireCode(verifier.Verify(token, Options(null, null)), VerifyError.RecordNotFound);
    }

    [Fact]
    public void BadSignature()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        // The scope is signed, so rewriting it breaks the hmac while
        // every structural check still passes.
        record.Scope = "logi";
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("", Support.TestClientIp)),
            VerifyError.BadSignature);
    }

    [Fact]
    public void Expired()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestIssuedAt + 121);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.Expired);
    }

    [Fact]
    public void FutureIssuance()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(),
            Support.TestIssuedAt - Kiwi.MaxClockSkew - 1);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.Expired);
    }

    [Fact]
    public void WrongScope()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("comment", Support.TestClientIp)),
            VerifyError.WrongScope);
    }

    [Fact]
    public void MissingScopeOptionIsTheTypedRequiredScopeRefusal()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        // The empty scope option accepts nothing: the typed refusal
        // replaces the lax any-scope acceptance.
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("", Support.TestClientIp)),
            VerifyError.RequiredScope);
    }

    [Fact]
    public void MissingClientIp()
    {
        var mint = new Support.MintOptions { BindingIp = Support.TestClientIp };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(verifier.Verify(TokenForRecord(record), Options("login", null)),
            VerifyError.MissingClientIp);
        // The retry path keeps the record so the caller can retry with the ip.
        Assert.NotNull(verifier.Storage().Find(record.Nonce));
    }

    [Fact]
    public void IpMismatch()
    {
        var mint = new Support.MintOptions { BindingIp = Support.TestClientIp };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", "192.0.2.9")),
            VerifyError.IpMismatch);
    }

    [Fact]
    public void WrongRegion()
    {
        var mint = new Support.MintOptions { Region = "eu" };
        var record = Support.MintRecord(mint);
        var config = new Verifier.Config { Region = "us" };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.WrongRegion);
    }

    [Fact]
    public void WrongIssuer()
    {
        var mint = new Support.MintOptions { Issuer = "staging" };
        var record = Support.MintRecord(mint);
        var config = new Verifier.Config { ExpectedIssuer = "prod" };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.WrongIssuer);
    }

    [Fact]
    public void UnboundRecordFailsARegionBoundVerifier()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var config = new Verifier.Config { Region = "eu" };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.WrongRegion);
    }

    [Fact]
    public void WrongPolicyVersion()
    {
        var mint = new Support.MintOptions { PolicyVersion = 2 };
        var record = Support.MintRecord(mint);
        var config = new Verifier.Config { ExpectedPolicyVersion = 3 };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.WrongPolicyVersion);
    }

    [Fact]
    public void PolicyRolloutWindowAcceptsAndRejects()
    {
        var mint = new Support.MintOptions { PolicyVersion = 2 };
        var record = Support.MintRecord(mint);
        var floored = Support.NewTestVerifier(new Verifier.Config
        {
            ExpectedPolicyVersion = 3,
            PolicyVersionFloor = 2,
        }, Support.TestNow);
        Support.StoreRecord(floored.Storage(), record);
        Support.RequireValid(
            floored.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)));

        var strict = Support.NewTestVerifier(new Verifier.Config { ExpectedPolicyVersion = 3 },
            Support.TestNow);
        Support.StoreRecord(strict.Storage(), record);
        Support.RequireCode(
            strict.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.WrongPolicyVersion);

        // A floor above the expected epoch accepts nothing.
        var inverted = Support.NewTestVerifier(new Verifier.Config
        {
            ExpectedPolicyVersion = 2,
            PolicyVersionFloor = 3,
        }, Support.TestNow);
        Support.StoreRecord(inverted.Storage(), record);
        Support.RequireCode(
            inverted.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.WrongPolicyVersion);
    }

    [Fact]
    public void RevokedKid()
    {
        var mint = new Support.MintOptions { Kid = 2 };
        var record = Support.MintRecord(mint);
        var config = new Verifier.Config
        {
            SecretsByKid = new Dictionary<int, string> { [1] = Support.TestSecret, [2] = Support.TestSecret },
            RevokedKids = new Dictionary<int, bool> { [2] = true },
        };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.UnknownKid);
    }

    [Fact]
    public void ForwardKidGuard()
    {
        var mint = new Support.MintOptions { Kid = 3 };
        var record = Support.MintRecord(mint);
        var config = new Verifier.Config
        {
            SecretsByKid = new Dictionary<int, string> { [1] = Support.TestSecret },
        };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.UnknownKid);
    }

    [Fact]
    public void KidRotationSelectsTheSecret()
    {
        var mint = new Support.MintOptions { Kid = 2 };
        var record = Support.MintRecord(mint);
        var config = new Verifier.Config
        {
            SecretsByKid = new Dictionary<int, string>
            {
                [1] = "other-secret-other-secret-other-32",
                [2] = Support.TestSecret,
            },
        };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        var opts = Options("login", Support.TestClientIp);
        opts.SecretKey = "unused";
        Support.RequireValid(verifier.Verify(TokenForRecord(record), opts));
    }

    [Fact]
    public void UnsupportedArgon2Params()
    {
        var mint = new Support.MintOptions { Algorithm = "argon2id", MKib = 131072, T = 3, TargetBits = 4 };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.UnsupportedArgon2);
    }

    [Fact]
    public void UnsupportedRswParams()
    {
        var mint = new Support.MintOptions
        {
            Algorithm = "rsw",
            T = Kiwi.MinRswT - 1,
            TargetBits = Kiwi.RswTargetBitsPin,
        };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.UnsupportedRswParams);
    }

    [Fact]
    public void TooFast()
    {
        var mint = new Support.MintOptions { MinDurationMs = 5000, MintMetaMac = true };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestIssuedAt);
        Support.StoreRecord(verifier.Storage(), record);
        var fast = Options("login", Support.TestClientIp);
        fast.NowNs = record.IssuedAtNs + 1_000_000;
        fast.NowNsSet = true;
        Support.RequireCode(verifier.Verify(TokenForRecord(record), fast), VerifyError.TooFast);
        // Past the floor the same token verifies.
        var fresh = Support.MintRecord(mint);
        Support.StoreRecord(verifier.Storage(), fresh);
        var slow = Options("login", Support.TestClientIp);
        slow.NowNs = fresh.IssuedAtNs + 6_000_000;
        slow.NowNsSet = true;
        Support.RequireValid(verifier.Verify(TokenForRecord(fresh), slow));
    }

    [Fact]
    public void UnmeasuredFloorFailsClosed()
    {
        var mint = new Support.MintOptions { MinDurationMs = 5000 };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestIssuedAt);
        Support.StoreRecord(verifier.Storage(), record);
        var opts = Options("login", Support.TestClientIp);
        opts.NowNs = record.IssuedAtNs + 6_000_000;
        opts.NowNsSet = true;
        Support.RequireCode(verifier.Verify(TokenForRecord(record), opts), VerifyError.MalformedRecord);
    }

    [Fact]
    public void InsufficientWork()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        var token = SolutionToken.Create(record.Nonce, 0, 5000, new JsonObject()).Encode();
        Support.RequireCode(verifier.Verify(token, Options("login", Support.TestClientIp)),
            VerifyError.InsufficientWork);
        // The deterministic invalid outcome replays without re-deriving.
        var replay = verifier.Storage().Consume(record.Nonce);
        Assert.NotNull(replay);
        Support.RequireCode(verifier.Verify(token, Options("login", Support.TestClientIp)),
            VerifyError.InsufficientWork);
    }

    [Fact]
    public void RequestBindingMismatch()
    {
        var mint = new Support.MintOptions { RequestBinding = "tx-123" };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        var wrong = Options("login", Support.TestClientIp);
        wrong.BindingExpectation = Verifier.RequestBindingExpectation.Exact("tx-999");
        Support.RequireCode(verifier.Verify(TokenForRecord(record), wrong), VerifyError.RequestBinding);
        // The record burned on the first attempt: mint a fresh one.
        var fresh = Support.MintRecord(mint);
        Support.StoreRecord(verifier.Storage(), fresh);
        var right = Options("login", Support.TestClientIp);
        right.BindingExpectation = Verifier.RequestBindingExpectation.Exact("tx-123");
        Support.RequireValid(verifier.Verify(TokenForRecord(fresh), right));
    }

    [Fact]
    public void UnboundRecordUnderAPresentedBinding()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        var expecting = Options("login", Support.TestClientIp);
        expecting.BindingExpectation = Verifier.RequestBindingExpectation.Exact("tx-123");
        Support.RequireCode(verifier.Verify(TokenForRecord(record), expecting),
            VerifyError.RequestBinding);
        // The legacy mode passes the unbound record.
        var fresh = Support.MintRecord(new Support.MintOptions());
        Support.StoreRecord(verifier.Storage(), fresh);
        var legacy = Options("login", Support.TestClientIp);
        legacy.BindingExpectation = Verifier.RequestBindingExpectation.Legacy("tx-123");
        Support.RequireValid(verifier.Verify(TokenForRecord(fresh), legacy));
    }

    [Fact]
    public void ExecutionArmedFailsClosed()
    {
        var golden = Support.StrictJson(Support.TestdataPath("golden/golden_execution_v4.json"));
        var record = Support.GoldenRecord(golden);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), GoldenIssuedAt);
        Support.StoreRecord(verifier.Storage(), record);
        var token = SolutionToken.Create(record.Nonce,
            Support.SolveSha(record.Prefix, record.Salt, record.TargetBits), 5000,
            new JsonObject(), executionDigest: Repeat("ab", 32)).Encode();
        Support.RequireCode(verifier.Verify(token, Options("login", "198.51.100.7")),
            VerifyError.ExecutionMismatch);
    }

    [Fact]
    public void StrayExecutionEvidence()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        var token = SolutionToken.Create(record.Nonce,
            Support.SolveSha(record.Prefix, record.Salt, record.TargetBits), 5000,
            new JsonObject(), executionDigest: Repeat("ab", 32)).Encode();
        Support.RequireCode(verifier.Verify(token, Options("login", Support.TestClientIp)),
            VerifyError.ExecutionMismatch);
    }

    [Fact]
    public void TelemetryRejectedAndEmptyPayload()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        // An empty telemetry payload is itself a bot signal.
        var token = SolutionToken.Create(record.Nonce,
            Support.SolveSha(record.Prefix, record.Salt, record.TargetBits), 5000,
            new JsonObject()).Encode();
        var strict = Options("login", Support.TestClientIp);
        strict.EnforceTelemetry = true;
        Support.RequireCode(verifier.Verify(token, strict), VerifyError.TelemetryRejected);
        // Perfectly uniform event intervals trip the timing signal.
        var events = new List<object?>();
        for (var i = 0; i < 30; i++)
        {
            events.Add(new JsonNumber(Convert.ToString(i * 10)));
        }
        var fresh = Support.MintRecord(new Support.MintOptions());
        Support.StoreRecord(verifier.Storage(), fresh);
        var tokenUniform = SolutionToken.Create(fresh.Nonce,
            Support.SolveSha(fresh.Prefix, fresh.Salt, fresh.TargetBits), 5000,
            JsonObject.Of(("et", events))).Encode();
        Support.RequireCode(verifier.Verify(tokenUniform, strict), VerifyError.TelemetryRejected);
        // Organic timings pass.
        var organic = new List<object?>();
        for (var i = 0; i < 30; i++)
        {
            organic.Add(new JsonNumber(Convert.ToString(i * i + 3)));
        }
        var third = Support.MintRecord(new Support.MintOptions());
        Support.StoreRecord(verifier.Storage(), third);
        var tokenOrganic = SolutionToken.Create(third.Nonce,
            Support.SolveSha(third.Prefix, third.Salt, third.TargetBits), 5000,
            JsonObject.Of(("et", organic))).Encode();
        Support.RequireValid(verifier.Verify(tokenOrganic, strict));
    }

    [Fact]
    public void CapacityExceeded()
    {
        var mint = new Support.MintOptions { Algorithm = "argon2id", MKib = 8, T = 3, TargetBits = 1 };
        var record = Support.MintRecord(mint);
        var config = new Verifier.Config { ArgonGate = new Verifier.ExhaustionGate() };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.CapacityExceeded);
        // Exhaustion never consumes: the client can retry.
        Assert.NotNull(verifier.Storage().Find(record.Nonce));
    }

    [Fact]
    public void AdmissionBackendFailure()
    {
        var mint = new Support.MintOptions { Algorithm = "argon2id", MKib = 8, T = 3, TargetBits = 1 };
        var record = Support.MintRecord(mint);
        var config = new Verifier.Config
        {
            ArgonGate = new BrokenGate(),
        };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.AdmissionUnavailable);
    }

    private sealed class BrokenGate : Verifier.IAdmissionGate
    {
        public object? Acquire() => throw new InvalidOperationException("backend down");

        public void Release(object? lease)
        {
            // Never reached.
        }
    }

    private sealed class FailingStore : Store.IStoreAdapter
    {
        public ChallengeRecord? Find(string nonce) => throw new Store.StorageUnavailableException("down");

        public bool Delete(string nonce) => throw new Store.StorageUnavailableException("down");

        public Store.ConsumedRecord? Consume(string nonce) =>
            throw new Store.StorageUnavailableException("down");

        public bool CommitResult(string nonce, bool valid, string binding) =>
            throw new Store.StorageUnavailableException("down");
    }

    [Fact]
    public void StorageUnavailable()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = new Verifier(new FailingStore(), new Verifier.Config());
        Support.RequireCode(verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.StorageUnavailable);
    }

    [Fact]
    public void CancelledRecordAnswersNotFound()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        ((Store.ICancellable)verifier.Storage()).Cancel(record.Nonce);
        Support.RequireCode(verifier.Verify(TokenForRecord(record), Options("login", Support.TestClientIp)),
            VerifyError.RecordNotFound);
    }

    [Fact]
    public void ConsumedIdentityGate()
    {
        var mint = new Support.MintOptions { BindingIp = Support.TestClientIp };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        var token = TokenForRecord(record);
        var first = Options("login", Support.TestClientIp);
        first.OperationIdentity = "op-1";
        Support.RequireValid(verifier.Verify(token, first));
        // The stored success replays only to the exact logical operation.
        var replay = Options("login", Support.TestClientIp);
        replay.OperationIdentity = "op-1";
        var replayOutcome = verifier.Verify(token, replay);
        Support.RequireValid(replayOutcome);
        Assert.True(replayOutcome.FromStoredResult);
        Assert.False(replayOutcome.SolveDurationSet);
        Support.RequireCode(verifier.Verify(token, Options("login", Support.TestClientIp)),
            VerifyError.AlreadyConsumed);
        var other = Options("login", Support.TestClientIp);
        other.OperationIdentity = "op-2";
        Support.RequireCode(verifier.Verify(token, other), VerifyError.AlreadyConsumed);
        // The ip binding is a replay-exempt circumstance: on a consumed
        // record it routes into the identity-gated consumed branch, so
        // the proven operation replays even from another network path.
        var elsewhere = Options("login", "192.0.2.9");
        elsewhere.OperationIdentity = "op-1";
        Support.RequireValid(verifier.Verify(token, elsewhere));
        // A hard verdict is different: the stored success never replays
        // around a security failure. Scope is a hard invariant.
        var hardScope = Options("comment", Support.TestClientIp);
        hardScope.OperationIdentity = "op-1";
        Support.RequireCode(verifier.Verify(token, hardScope), VerifyError.WrongScope);
    }

    [Fact]
    public void Argon2VectorEndToEnd()
    {
        var record = Support.VectorRecord(Support.Argon2Vector);
        var config = new Verifier.Config { AcceptLegacyV1 = true };
        var verifier = Support.NewTestVerifier(config, Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireValid(verifier.Verify(Support.VectorToken(Support.Argon2Vector, -1, -1),
            Options("login", Support.TestClientIp)));
    }

    [Fact]
    public void SolveDurationMeasured()
    {
        var mint = new Support.MintOptions { MintMetaMac = true };
        var record = Support.MintRecord(mint);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestIssuedAt);
        Support.StoreRecord(verifier.Storage(), record);
        var opts = Options("login", Support.TestClientIp);
        opts.NowNs = record.IssuedAtNs + 12_500_000;
        opts.NowNsSet = true;
        var outcome = verifier.Verify(TokenForRecord(record), opts);
        Support.RequireValid(outcome);
        Assert.True(outcome.SolveDurationSet);
        Assert.Equal(12_500, outcome.SolveDurationMs);
        // Without the metadata mac the measured duration is withheld.
        var unmacced = Support.MintRecord(new Support.MintOptions());
        var second = Support.NewTestVerifier(new Verifier.Config(), Support.TestIssuedAt);
        Support.StoreRecord(second.Storage(), unmacced);
        var opts2 = Options("login", Support.TestClientIp);
        opts2.NowNs = unmacced.IssuedAtNs + 12_500_000;
        opts2.NowNsSet = true;
        var outcome2 = second.Verify(TokenForRecord(unmacced), opts2);
        Support.RequireValid(outcome2);
        Assert.False(outcome2.SolveDurationSet);
    }

    [Fact]
    public void LegacyV1Gate()
    {
        var record = Support.VectorRecord(Support.ShaVector);
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        Support.RequireCode(
            verifier.Verify(Support.VectorToken(Support.ShaVector, -1, -1),
                Options("login", Support.TestClientIp)),
            VerifyError.MalformedRecord);
        var accepting = Support.NewTestVerifier(new Verifier.Config { AcceptLegacyV1 = true },
            Support.TestNow);
        Support.StoreRecord(accepting.Storage(), record);
        Support.RequireValid(accepting.Verify(Support.VectorToken(Support.ShaVector, -1, -1),
            Options("login", Support.TestClientIp)));
    }

    [Fact]
    public void ExactlyOnceUnderConcurrency()
    {
        var record = Support.MintRecord(new Support.MintOptions());
        var verifier = Support.NewTestVerifier(new Verifier.Config(), Support.TestNow);
        Support.StoreRecord(verifier.Storage(), record);
        var token = TokenForRecord(record);
        const int threads = 8;
        using var start = new ManualResetEventSlim(false);
        var winners = 0;
        var lockObject = new object();
        var workers = new List<Thread>();
        for (var i = 0; i < threads; i++)
        {
            var worker = new Thread(() =>
            {
                start.Wait();
                var outcome = verifier.Verify(token, Options("login", Support.TestClientIp));
                if (outcome.Valid)
                {
                    lock (lockObject)
                    {
                        winners++;
                    }
                }
            });
            workers.Add(worker);
            worker.Start();
        }
        start.Set();
        foreach (var worker in workers)
        {
            worker.Join();
        }
        Assert.Equal(1, winners);
    }

    [Fact]
    public void DecisionPlane()
    {
        var valid = VerifyOutcome.ValidOutcome("nonce", "binding", false, 0, false, "");
        var decision = Decision.FromOutcome(valid, "sha8");
        Assert.True(decision.Ok);
        Assert.Equal(Decision.DispositionAllow, decision.Disposition);
        Assert.Equal("nonce", decision.DecisionHandle);
        Assert.Equal("sha8", decision.Price);
        var denied = Decision.FromOutcome(VerifyOutcome.InvalidOutcome(VerifyError.WrongScope), "");
        Assert.False(denied.Ok);
        Assert.Equal(Decision.DispositionDeny, denied.Disposition);
        Assert.Equal("wrong_scope", denied.Error);
        var retry = Decision.FromOutcome(VerifyOutcome.InvalidOutcome(VerifyError.StorageUnavailable), "");
        Assert.Equal(Decision.DispositionRetry, retry.Disposition);
        Assert.Null(valid.Error);
    }
}
