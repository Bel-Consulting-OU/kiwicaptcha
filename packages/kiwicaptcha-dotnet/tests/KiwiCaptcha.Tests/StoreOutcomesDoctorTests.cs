using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Http;
using Xunit;



namespace KiwiCaptcha.Tests;

/// <summary>The memory store: one-shot transitions, retention and cancellation.</summary>
public class StoreTests
{
    private static ChallengeRecord MintRecord(long issuedAt, long ttl)
    {
        var options = new Support.MintOptions { IssuedAt = issuedAt, Ttl = ttl };
        return Support.MintRecord(options);
    }

    [Fact]
    public void StoreFindConsumeCommitDeleteRoundtrip()
    {
        var store = new MemoryStore();
        var record = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(record);
        Assert.Equal(record.Nonce, store.Find(record.Nonce)!.Nonce);
        var consumed = store.Consume(record.Nonce);
        Assert.NotNull(consumed);
        Assert.True(consumed!.ConsumedNow);
        Assert.True(store.CommitResult(record.Nonce, true, "binding"));
        Assert.False(store.CommitResult(record.Nonce, true, "binding"));
        Assert.True(store.Delete(record.Nonce));
        Assert.False(store.Delete(record.Nonce));
        Assert.Null(store.Find(record.Nonce));
    }

    [Fact]
    public void ExpiredRecordsVanish()
    {
        var clock = Support.TestIssuedAt;
        var store = new MemoryStore(() => clock);
        var record = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(record);
        Assert.NotNull(store.Find(record.Nonce));
        clock = Support.TestIssuedAt + 121;
        Assert.Null(store.Find(record.Nonce));
        Assert.Null(store.Consume(record.Nonce));
        Assert.Equal(0, store.Len());
    }

    [Fact]
    public void ConsumedRecordRetainsUntilExpiry()
    {
        var clock = Support.TestIssuedAt;
        var store = new MemoryStore(() => clock);
        var record = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(record);
        Assert.NotNull(store.Consume(record.Nonce));
        var before = store.Consume(record.Nonce);
        Assert.NotNull(before);
        Assert.True(before!.ConsumedBefore);
        Assert.NotNull(store.ConsumedState(record.Nonce));
        clock = Support.TestIssuedAt + 121;
        Assert.Null(store.ConsumedState(record.Nonce));
    }

    [Fact]
    public void CommitOnlyFirstWins()
    {
        var store = new MemoryStore();
        var record = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(record);
        store.Consume(record.Nonce);
        Assert.True(store.CommitAuthenticatedResult(record.Nonce,
            new Store.ConsumedResult(true, "b", new string('a', 64))));
        Assert.False(store.CommitAuthenticatedResult(record.Nonce,
            new Store.ConsumedResult(false, "", "")));
        Assert.Equal(new string('a', 64), store.ConsumedState(record.Nonce)!.ConsumedResult!.Mac);
    }

    [Fact]
    public void DeleteIfPendingClassifies()
    {
        var store = new MemoryStore();
        var pending = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(pending);
        Assert.Equal(Store.DeleteStatusDeletedPending, store.DeleteIfPending(pending.Nonce).Status);
        Assert.Null(store.Find(pending.Nonce));
        Assert.Equal(Store.DeleteStatusMissing, store.DeleteIfPending(pending.Nonce).Status);

        var consumedRecord = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(consumedRecord);
        store.Consume(consumedRecord.Nonce);
        var consumed = store.DeleteIfPending(consumedRecord.Nonce);
        Assert.True(consumed.WasConsumed());
        Assert.NotNull(consumed.Consumed);
        Assert.NotNull(store.Find(consumedRecord.Nonce));

        var cancelledRecord = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(cancelledRecord);
        store.Cancel(cancelledRecord.Nonce);
        Assert.Equal(Store.DeleteStatusCancelled, store.DeleteIfPending(cancelledRecord.Nonce).Status);
    }

    [Fact]
    public void CancelStates()
    {
        var store = new MemoryStore();
        Assert.Null(store.Cancel("missing"));
        var record = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(record);
        Assert.Equal(Store.CancelStatusCancelledNow, store.Cancel(record.Nonce)!.Status);
        Assert.Equal(Store.CancelStatusCancelled, store.Cancel(record.Nonce)!.Status);
        Assert.Equal(Store.RuntimeStateKind.Cancelled, store.RuntimeState(record.Nonce).Kind);
    }

    [Fact]
    public void RuntimeStateKinds()
    {
        var store = new MemoryStore();
        Assert.Equal(Store.RuntimeStateKind.Missing, store.RuntimeState("gone").Kind);
        var record = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(record);
        Assert.Equal(Store.RuntimeStateKind.Pending, store.RuntimeState(record.Nonce).Kind);
        store.Consume(record.Nonce);
        var consumed = store.RuntimeState(record.Nonce);
        Assert.Equal(Store.RuntimeStateKind.Consumed, consumed.Kind);
        Assert.NotNull(consumed.Consumed);
        // A consumed record is terminal, never cancellable; a fresh
        // record cancels.
        Assert.Equal(Store.CancelStatusConsumed, store.Cancel(record.Nonce)!.Status);
        var fresh = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(fresh);
        Assert.Equal(Store.CancelStatusCancelledNow, store.Cancel(fresh.Nonce)!.Status);
        Assert.Equal(Store.RuntimeStateKind.Cancelled, store.RuntimeState(fresh.Nonce).Kind);
    }

    [Fact]
    public void ConsumeRacesHaveOneWinner()
    {
        var store = new MemoryStore();
        var record = MintRecord(Support.TestIssuedAt, 120);
        store.StoreRecord(record);
        const int threads = 16;
        using var start = new ManualResetEventSlim(false);
        var winners = 0;
        var lockObject = new object();
        var workers = new List<Thread>();
        for (var i = 0; i < threads; i++)
        {
            var worker = new Thread(() =>
            {
                start.Wait();
                var consumed = store.Consume(record.Nonce);
                if (consumed != null && consumed.ConsumedNow)
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
    public void EnvelopeRoundTripThroughTheWireSchema()
    {
        var store = new MemoryStore();
        var mint = new Support.MintOptions { MintMetaMac = true };
        var record = Support.MintRecord(mint);
        var parsed = ChallengeRecord.Parse(Encoding.UTF8.GetBytes(record.MarshalJson()));
        Assert.Equal(record.Nonce, parsed.Nonce);
        store.StoreRecord(parsed);
        Assert.Equal(record.Nonce, store.Find(record.Nonce)!.Nonce);
        Assert.Equal(record.ServerMac, store.Find(record.Nonce)!.ServerMac);
    }

    [Fact]
    public void GoldenEnvelopeShapeStaysCompatible()
    {
        // The php-issued golden record round-trips the envelope writer
        // and refuses the runtime markers as record keys.
        var golden = Support.GoldenVectors();
        var first = (Dictionary<string, object?>)((List<object?>)golden["records"])[0]!;
        var recordMap = (Dictionary<string, object?>)first["record"]!;
        var record = ChallengeRecord.FromMap(recordMap);
        var envelope = record.ToWireMap();
        envelope["state"] = "pending";
        envelope["consumed_result"] = null;
        envelope["operation_identity"] = null;
        var encoded = WireJson.EncodeEnvelope(envelope);
        Assert.StartsWith("{\"nonce\":", encoded);
        Assert.Contains("\"state\":\"pending\"", encoded);
        Assert.Throws<ChallengeRecord.MalformedRecordException>(
            () => ChallengeRecord.Parse(Encoding.UTF8.GetBytes(encoded)));
    }

    [Fact]
    public void ReplayProtocolsOfTheDecisionPlane()
    {
        // Deny vs retry dispositions across the retryable codes.
        foreach (VerifyError code in Enum.GetValues<VerifyError>())
        {
            var decision = Decision.FromOutcome(VerifyOutcome.InvalidOutcome(code), "");
            var retryExpected = code is VerifyError.StorageUnavailable or VerifyError.CapacityExceeded
                or VerifyError.AdmissionUnavailable or VerifyError.ConsumeIndeterminate;
            XAssert.Equal(retryExpected ? Decision.DispositionRetry : Decision.DispositionDeny,
                decision.Disposition, code.Code());
        }
    }
}

/// <summary>The versioned outcomes mapping and the reporting client.</summary>
public class OutcomesTests
{
    private static Dictionary<string, object?> OutcomeVectors() =>
        Support.StrictJson(Support.ProtocolPathOrSkip("risk-v1/outcomes-vectors.json"));

    private static Outcomes.Outcome OutcomeByWire(string wire)
    {
        foreach (Outcomes.Outcome outcome in Enum.GetValues<Outcomes.Outcome>())
        {
            if (outcome.Wire() == wire)
            {
                return outcome;
            }
        }
        throw new Xunit.Sdk.XunitException("unknown outcome " + wire);
    }

    private static Outcomes.HandleDimension DimensionByWire(string wire)
    {
        foreach (Outcomes.HandleDimension dimension in Enum.GetValues<Outcomes.HandleDimension>())
        {
            if (dimension.Wire() == wire)
            {
                return dimension;
            }
        }
        throw new Xunit.Sdk.XunitException("unknown dimension " + wire);
    }

    private static string NullableString(object? value) =>
        value == null ? "null" : Convert.ToString(value) ?? "";

    private static bool ThrowsArg(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private static string LedgerAction(Outcomes.OutcomeMapping mapping)
    {
        if (mapping.LedgerLegitimate == null)
        {
            return "null";
        }
        return mapping.LedgerLegitimate.Value ? "L" : "A";
    }

    [Fact]
    public void TableVersionPinsTheFixture()
    {
        var document = OutcomeVectors();
        Assert.Equal(Outcomes.OutcomesVersion, ((JsonNumber)document["version"]!).IntValue());
    }

    [Fact]
    public void TrustPolarityIsDisjoint()
    {
        var map = new Outcomes.OutcomeMap();
        var rows = map.All();
        Assert.Equal(3, rows.Count(r => r.MaySubtractRisk));
        Assert.Equal(4, rows.Count(r => r.WritesAbuseMark));
        foreach (var row in rows)
        {
            if (row.MaySubtractRisk)
            {
                Assert.True(row.ServerConfirmed, row.Outcome.Wire());
                Assert.False(row.WritesAbuseMark, row.Outcome.Wire());
            }
            if (row.WritesAbuseMark)
            {
                Assert.False(row.MaySubtractRisk, row.Outcome.Wire());
                Assert.True(row.ServerConfirmed, row.Outcome.Wire());
            }
        }
    }

    [Fact]
    public void FixtureVectorsHold()
    {
        var document = OutcomeVectors();
        var map = new Outcomes.OutcomeMap();
        var vectors = (List<object?>)document["vectors"];
        foreach (var item in vectors)
        {
            var vector = (Dictionary<string, object?>)item!;
            var outcome = OutcomeByWire(Convert.ToString(vector["outcome"])!);
            var handle = (Dictionary<string, object?>)vector["handle"]!;
            var dimensionWire = Convert.ToString(handle["dimension"])!;
            var identifier = Convert.ToString(handle["id"])!;
            var reject = vector.TryGetValue("reject", out var rejectValue)
                ? Convert.ToString(rejectValue)
                : null;
            if (reject == "identifier")
            {
                // The raw identifier dies at handle construction on a
                // pseudonym-only dimension, before any mapping lookup.
                var failedDimension = dimensionWire;
                var failedId = identifier;
                XAssert.True(ThrowsArg(() => Outcomes.OutcomeHandle.Of(
                    DimensionByWire(failedDimension), failedId)),
                outcome.Wire() + " with a raw identifier");
                continue;
            }
            var dimension = DimensionByWire(dimensionWire);
            var mapping = map.ForOutcome(outcome);
            var accepted = mapping.Accepts(dimension);
            XAssert.Equal(Convert.ToString(vector["accepted"])!.ToLowerInvariant() == "true" ? "true" : "false",
                accepted ? "true" : "false", outcome.Wire() + " on " + dimension.Wire());
            if (accepted)
            {
                XAssert.Equal(((JsonNumber)vector["channel_value"]!).IntValue(), mapping.Channel,
                    outcome.Wire());
                XAssert.Equal(NullableString(vector["ledger_action"]), LedgerAction(mapping),
                    outcome.Wire() + " ledger");
                XAssert.Equal(NullableString(vector["mark_kind"]),
                    mapping.MarkKind().Length == 0 ? "null" : mapping.MarkKind(),
                    outcome.Wire() + " mark");
            }
        }
    }

    [Fact]
    public void HandleValidation()
    {
        Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.Principal, "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18");
        Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.Agent, "backfill-bot");
        Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.DecisionId, "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18");
        Assert.Throws<ArgumentException>(() => Outcomes.OutcomeHandle.Of(
            Outcomes.HandleDimension.Principal, "user@example.com"));
        Assert.Throws<ArgumentException>(() => Outcomes.OutcomeHandle.Of(
            Outcomes.HandleDimension.Agent, ""));
        Assert.Throws<ArgumentException>(() => Outcomes.OutcomeHandle.Of(
            Outcomes.HandleDimension.Agent, "bad:colon"));
        Assert.Throws<ArgumentException>(() => Outcomes.OutcomeHandle.Of(
            Outcomes.HandleDimension.Agent, "bad}brace"));
    }

    [Fact]
    public void ReportBooksLedgerMarksAndChannels()
    {
        var sink = new Outcomes.MemoryOutcomeSink("deployments/test");
        var client = new Outcomes.OutcomesClient(sink, () => 1_700_000_000_000L);
        const string decisionId = "d4e5f60718293a4b5c6d7e8f90a1b2c3";
        // No ledger entry yet: a legitimate confirm reports status 0.
        var first = client.Report(Outcomes.Outcome.ConfirmedLegitimate,
            Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.DecisionId, decisionId), "evt-1", 0);
        Assert.Equal(0, first.Status);
        Assert.False(first.ChannelBooked);
        // Register the decision, then confirm it legitimate.
        sink.RegisterOutcome(decisionId, 1_700_000_000_000L);
        var second = client.Report(Outcomes.Outcome.ConfirmedLegitimate,
            Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.DecisionId, decisionId), "evt-2", 0);
        Assert.Equal(1, second.Status);
        Assert.True(second.ChannelBooked);
        // An abuse outcome writes the identity mark.
        var abuse = client.Report(Outcomes.Outcome.FraudConfirmed,
            Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.Principal,
                "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18"), "evt-3", 0);
        Assert.Equal(1, abuse.MarksWritten);
        Assert.Equal(1, abuse.MarkCount);
        Assert.Equal(new[] { "fraudConfirmed" },
            sink.MarksOf("principal", "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18"));
        Assert.Equal(1, client.Forget(Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.Principal,
            "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18")));
        Assert.Empty(sink.MarksOf("principal", "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18"));
    }

    [Fact]
    public void DimensionRejections()
    {
        var client = new Outcomes.OutcomesClient(new Outcomes.MemoryOutcomeSink("d"));
        // The identity-only outcomes refuse every ledger handle.
        XAssert.True(ThrowsArg(() => client.Report(Outcomes.Outcome.StepUpCompleted,
            Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.Nonce,
                "0f1e2d3c4b5a69788796a5b4c3d2e1f0"), "evt", 0)), "stepUp on nonce");
        XAssert.True(ThrowsArg(() => client.Report(Outcomes.Outcome.SpamReported,
            Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.DecisionId,
                "d4e5f60718293a4b5c6d7e8f90a1b2c3"), "evt", 0)), "spam on decisionId");
    }
}

/// <summary>The doctor checks and the settings factory.</summary>
public class DoctorTests
{
    [Fact]
    public void SettingsCheck()
    {
        Assert.False(Doctor.CheckSettings("short", "standard").Ok);
        Assert.False(Doctor.CheckSettings(Support.TestSecret, "scrypt").Ok);
        Assert.True(Doctor.CheckSettings(Support.TestSecret, "standard").Ok);
        Assert.True(Doctor.CheckSettings(Support.TestSecret, "argon64").Ok);
    }

    [Fact]
    public void StoreCheckMemory()
    {
        var check = Doctor.CheckStore("memory://");
        Assert.True(check.Ok, check.Detail);
    }

    [Fact]
    public void StoreCheckBadUrl()
    {
        Assert.False(Doctor.CheckStore("bogus://").Ok);
    }

    [Fact]
    public void StoreCheckSqlite()
    {
        // The file-backed adapter is wired: the doctor roundtrip passes
        // on a real database file, which the check itself creates.
        var path = Path.Combine(Path.GetTempPath(), "kiwicaptcha-doctor-" + Guid.NewGuid().ToString("N") + ".sqlite3");
        try
        {
            var check = Doctor.CheckStore("sqlite://" + path);
            Assert.True(check.Ok, check.Detail);
            Assert.True(File.Exists(path), "the store url created the database file");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ScopesCheck()
    {
        Assert.True(Doctor.CheckScopes(Array.Empty<string>()).Ok);
        Assert.True(Doctor.CheckScopes(new[] { "login", "comment" }).Ok);
        Assert.False(Doctor.CheckScopes(new[] { "bad scope" }).Ok);
    }

    [Fact]
    public void ProofBudgetChecks()
    {
        Assert.True(Doctor.CheckProofBudget("standard").Ok);
        Assert.True(Doctor.CheckProofBudget("argon16").Ok);
        Assert.False(Doctor.CheckProofBudget("scrypt").Ok);
    }

    [Fact]
    public void DoctorRunOrder()
    {
        var results = Doctor.Run(Support.TestSecret, "memory://", new[] { "login" }, "standard");
        Assert.Equal(4, results.Count);
        Assert.Equal("settings", results[0].Name);
        Assert.Equal("store", results[1].Name);
        Assert.Equal("scopes", results[2].Name);
        Assert.Equal("proof_budget", results[3].Name);
    }

    [Fact]
    public void SelfCheckRecordVerifies()
    {
        var record = Doctor.DoctorSelfCheckRecord();
        Assert.True(Canonical.VerifyRecordSignature(record, "kiwicaptcha-doctor-self-check-secret-0000", ""));
    }

    [Fact]
    public void SettingsBuildVerifierMemory()
    {
        var settings = new Settings { Secret = Support.TestSecret, StoreUrl = "memory://" };
        var verifier = settings.BuildVerifier();
        Assert.NotNull(verifier.Storage());
    }

    [Fact]
    public void SettingsBuildVerifierRejectsBadInputs()
    {
        Assert.Throws<ArgumentException>(() => new Settings
        {
            Secret = Support.TestSecret,
            Profile = "scrypt",
        }.BuildVerifier());
        Assert.Throws<Canonical.SecretTooShortException>(() => new Settings
        {
            Secret = "short",
        }.BuildVerifier());
    }
}

/// <summary>
/// The Redis suite runs against a scratch redis-server on a test
/// port, started and skipped like the repo's other redis-gated
/// tests: a run without the binary stays green everywhere.
/// </summary>
public class RedisStoreTests : IDisposable
{
    private static readonly bool RedisAvailable = FindRedisServer();
    private Process? _redis;
    private RespClient? _client;
    private readonly int _port = 6399 + (int)(Environment.ProcessId % 100);

    private static bool FindRedisServer()
    {
        try
        {
            var probe = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "which",
                    Arguments = "redis-server",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                },
            };
            probe.Start();
            var output = probe.StandardOutput.ReadToEnd().Trim();
            probe.WaitForExit(5000);
            return probe.HasExited && probe.ExitCode == 0 && output.Length > 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private RespClient Client()
    {
        if (_client != null)
        {
            return _client;
        }
        Assert.True(RedisAvailable, "redis-server binary not available");
        var tmpdir = Path.Combine(Path.GetTempPath(), "kiwi-redis-test-" + Environment.ProcessId);
        Directory.CreateDirectory(tmpdir);
        _redis = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "redis-server",
                Arguments = $"--port {_port} --save \"\" --appendonly no --dir {tmpdir}",
                UseShellExecute = false,
            },
        };
        Assert.True(_redis.Start(), "the scratch redis-server never started");
        var deadline = DateTime.UtcNow.AddSeconds(10);
        Exception? last = null;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var attempted = RespClient.Dial($"redis://127.0.0.1:{_port}");
                attempted.Ping();
                _client = attempted;
                attempted.Command("FLUSHALL");
                return attempted;
            }
            catch (Exception e)
            {
                last = e;
                Thread.Sleep(100);
            }
        }
        throw new Xunit.Sdk.XunitException("the scratch redis-server never came up", last);
    }

    public void Dispose()
    {
        _client?.Close();
        try
        {
            if (_redis != null && !_redis.HasExited)
            {
                _redis.Kill(entireProcessTree: true);
            }
            _redis?.Dispose();
        }
        catch (Exception)
        {
            // Cleanup is best-effort.
        }
    }

    private RedisStore NewStore() => new(Client(), Kiwi.EnvelopeDefaultPrefix);

    private static ChallengeRecord MintRecord()
    {
        var options = new Support.MintOptions { MintMetaMac = true };
        return Support.MintRecord(options);
    }

    [Fact]
    public void RespClientRoundTrips()
    {
        if (!RedisAvailable)
        {
            return; // redis-server binary not available: the suite stays green.
        }
        var client = Client();
        Assert.Equal("PONG", client.Command("PING"));
        client.Command("SET", "kiwi-test:resp", "value");
        Assert.Equal("value", client.Get("kiwi-test:resp"));
        Assert.Null(client.Get("kiwi-test:absent"));
        Assert.True(client.Del("kiwi-test:resp"));
    }

    [Fact]
    public void FullOneShotRoundtrip()
    {
        if (!RedisAvailable)
        {
            return;
        }
        var store = NewStore();
        var record = MintRecord();
        store.StoreRecord(record);
        Assert.Equal(record.Nonce, store.Find(record.Nonce)!.Nonce);
        Assert.Equal(Store.RuntimeStateKind.Pending, store.RuntimeState(record.Nonce).Kind);
        var consumed = store.Consume(record.Nonce);
        Assert.NotNull(consumed);
        Assert.True(consumed!.ConsumedNow);
        Assert.True(store.CommitResult(record.Nonce, true, ""));
        Assert.True(store.Delete(record.Nonce));
        Assert.Null(store.Find(record.Nonce));
    }

    [Fact]
    public void EnvelopeIsByteCompatibleWithTheSharedWriters()
    {
        if (!RedisAvailable)
        {
            return;
        }
        var store = NewStore();
        var record = MintRecord();
        store.StoreRecord(record);
        var envelope = Client().Get(Kiwi.EnvelopeDefaultPrefix + record.Nonce);
        Assert.NotNull(envelope);
        Assert.StartsWith("{\"nonce\":\"" + record.Nonce + "\",\"scope\":\"login\"", envelope);
        Assert.Contains("\"state\":\"pending\"", envelope);
        Assert.Contains("\"consumed_result\":null", envelope);
        // The stored envelope carries runtime markers the record
        // parser refuses; the envelope decoder strips them first.
        Assert.Throws<ChallengeRecord.MalformedRecordException>(
            () => ChallengeRecord.Parse(Encoding.UTF8.GetBytes(envelope)));
    }

    [Fact]
    public void ConsumeIsOneShotAndReplayable()
    {
        if (!RedisAvailable)
        {
            return;
        }
        var store = NewStore();
        var record = MintRecord();
        store.StoreRecord(record);
        Assert.NotNull(store.Consume(record.Nonce));
        var replay = store.Consume(record.Nonce);
        Assert.NotNull(replay);
        Assert.True(replay!.ConsumedBefore);
        // The committed result replays through the runtime snapshot.
        store.CommitAuthenticatedResult(record.Nonce,
            new Store.ConsumedResult(true, "b", new string('a', 64)));
        var retained = store.ConsumedState(record.Nonce);
        Assert.NotNull(retained);
        Assert.NotNull(retained!.ConsumedResult);
        Assert.Equal(new string('a', 64), retained.ConsumedResult!.Mac);
    }

    [Fact]
    public void DeleteIfPendingClassifies()
    {
        if (!RedisAvailable)
        {
            return;
        }
        var store = NewStore();
        var pending = MintRecord();
        store.StoreRecord(pending);
        Assert.Equal(Store.DeleteStatusDeletedPending, store.DeleteIfPending(pending.Nonce).Status);
        Assert.Null(store.Find(pending.Nonce));
        Assert.Equal(Store.DeleteStatusMissing, store.DeleteIfPending(pending.Nonce).Status);

        var consumed = MintRecord();
        store.StoreRecord(consumed);
        store.Consume(consumed.Nonce);
        var kept = store.DeleteIfPending(consumed.Nonce);
        Assert.True(kept.WasConsumed());
        Assert.NotNull(store.Find(consumed.Nonce));

        var cancelled = MintRecord();
        store.StoreRecord(cancelled);
        store.Cancel(cancelled.Nonce);
        Assert.Equal(Store.DeleteStatusCancelled, store.DeleteIfPending(cancelled.Nonce).Status);
    }

    [Fact]
    public void IdentityBearingConsume()
    {
        if (!RedisAvailable)
        {
            return;
        }
        var store = NewStore();
        var record = MintRecord();
        store.StoreRecord(record);
        var consumed = store.ConsumeWithOperationIdentity(record.Nonce, "op-1");
        Assert.NotNull(consumed);
        Assert.True(consumed!.ConsumedNow);
        Assert.Equal("op-1", consumed.OperationIdentity);
        var replay = store.ConsumeWithOperationIdentity(record.Nonce, "op-1");
        Assert.Equal("op-1", replay!.OperationIdentity);
        Assert.Throws<Store.OperationIdentityException>(
            () => store.ConsumeWithOperationIdentity(record.Nonce, "bad identity"));
    }

    [Fact]
    public void CancelledRecordsNeverConsume()
    {
        if (!RedisAvailable)
        {
            return;
        }
        var store = NewStore();
        var record = MintRecord();
        store.StoreRecord(record);
        Assert.Equal(Store.CancelStatusCancelledNow, store.Cancel(record.Nonce)!.Status);
        Assert.Equal(Store.CancelStatusCancelled, store.Cancel(record.Nonce)!.Status);
        Assert.Null(store.Consume(record.Nonce));
        Assert.Equal(Store.RuntimeStateKind.Cancelled, store.RuntimeState(record.Nonce).Kind);
    }

    [Fact]
    public void VerifierRunsOverTheRedisStore()
    {
        if (!RedisAvailable)
        {
            return;
        }
        var storage = NewStore();
        var config = new Verifier.Config { NowSecs = () => Support.TestIssuedAt };
        var verifier = new Verifier(storage, config);
        var record = MintRecord();
        storage.StoreRecord(record);
        var token = SolutionToken.Create(record.Nonce,
            Support.SolveSha(record.Prefix, record.Salt, record.TargetBits), 5000,
            JsonObject.Of(("v", new JsonNumber("1")))).Encode();
        var options = new Verifier.Options
        {
            SecretKey = Support.TestSecret,
            ExpectedScope = "login",
            ClientIp = Support.TestClientIp,
        };
        Support.RequireValid(verifier.Verify(token, options));
        Support.RequireCode(verifier.Verify(token, options), VerifyError.AlreadyConsumed);
    }

    [Fact]
    public void ForgedPendingEnvelopeIsRefused()
    {
        if (!RedisAvailable)
        {
            return;
        }
        var record = MintRecord();
        var recordJson = record.MarshalJson();
        // A forged pending envelope that already carries a committed
        // result, hand-spliced like a hostile storage writer would.
        var encoded = recordJson[..^1]
            + ",\"state\":\"pending\",\"consumed_result\":{\"valid\":true,\"binding\":\"b\"},"
            + "\"operation_identity\":null}";
        var key = Kiwi.EnvelopeDefaultPrefix + "forged";
        Client().SetWithTtl(key, encoded, 60_000);
        // The pending-envelope guard refuses a pending record that
        // already carries a committed result.
        Assert.Null(NewStore().Consume("forged"));
        Client().Del(key);
    }
}

/// <summary>
/// The committed PHP-issued golden vectors, driven end to end: every
/// record is minted by the real php Issuer with its sealed
/// record-metadata mac, so the verdicts here pin this SDK against the
/// canonical core, not against this SDK's own minting.
/// </summary>
public class GoldenTests
{
    private static Dictionary<string, object?> GoldenEntry(string name)
    {
        var golden = Support.GoldenVectors();
        var records = (List<object?>)golden["records"];
        foreach (var item in records)
        {
            var entry = (Dictionary<string, object?>)item!;
            if (name == Convert.ToString(entry["name"]))
            {
                return entry;
            }
        }
        throw new Xunit.Sdk.XunitException("missing golden entry " + name);
    }

    private static (Verifier.Config Config, Verifier.Options Options) VerifyCall(Dictionary<string, object?> entry)
    {
        var rawOpts = entry.TryGetValue("verify_opts", out var opts) ? opts : null;
        // The php writer emits a php empty array as a json list, so an
        // empty opts row carries [] rather than {}.
        var verifyOpts = rawOpts is Dictionary<string, object?> map
            ? map
            : new Dictionary<string, object?>();
        var config = new Verifier.Config();
        var options = new Verifier.Options
        {
            SecretKey = Support.TestSecret,
            ExpectedScope = verifyOpts.TryGetValue("expected_scope", out var scope)
                ? Convert.ToString(scope)
                : "",
            ClientIp = verifyOpts.TryGetValue("client_ip", out var ip) ? Convert.ToString(ip) : "",
        };
        config.ExpectedIssuer = verifyOpts.TryGetValue("expected_issuer", out var issuer)
            ? Convert.ToString(issuer) ?? ""
            : "";
        if (verifyOpts.TryGetValue("expected_policy_version", out var policyValue))
        {
            config.ExpectedPolicyVersion = ((JsonNumber)policyValue).IntValue();
        }
        if (verifyOpts.TryGetValue("expected_request_binding", out var bindingValue))
        {
            options.BindingExpectation = Verifier.RequestBindingExpectation.Exact(
                Convert.ToString(bindingValue) ?? "");
        }
        if (verifyOpts.TryGetValue("now_ns", out var nowValue))
        {
            options.NowNs = ((JsonNumber)nowValue).LongValue();
            options.NowNsSet = true;
        }
        if (verifyOpts.TryGetValue("region", out var regionValue))
        {
            config.Region = Convert.ToString(regionValue) ?? "";
        }
        if (verifyOpts.TryGetValue("secrets_by_kid", out var secretsValue))
        {
            var byKid = new Dictionary<int, string>();
            foreach (var kid in (Dictionary<string, object?>)secretsValue)
            {
                byKid[int.Parse(kid.Key)] = Convert.ToString(kid.Value) ?? "";
            }
            config.SecretsByKid = byKid;
        }
        if (verifyOpts.TryGetValue("rsw", out var rswValue))
        {
            var rsw = (Dictionary<string, object?>)rswValue;
            config.RswModulusN = Convert.ToString(rsw["modulus_n"]) ?? "";
            config.RswLambda = Convert.ToString(rsw["lambda"]) ?? "";
        }
        return (config, options);
    }

    [Fact]
    public void EveryGoldenVectorResolvesToItsPinnedVerdict()
    {
        var golden = Support.GoldenVectors();
        var records = (List<object?>)golden["records"];
        foreach (var item in records)
        {
            var entry = (Dictionary<string, object?>)item!;
            var name = Convert.ToString(entry["name"]);
            var record = Support.GoldenRecord(entry);
            var (config, options) = VerifyCall(entry);
            // The php issuance ran live, so the verdict clock pins to
            // the record's own issuance second: deterministic replay.
            config.NowSecs = () => record.IssuedAt;
            var verifier = new Verifier(new MemoryStore(() => record.IssuedAt), config);
            Support.StoreRecord(verifier.Storage(), record);
            var outcome = verifier.Verify(Convert.ToString(entry["token_b64"])!, options);
            var expected = (Dictionary<string, object?>)entry["expected"]!;
            var expectedOk = Convert.ToString(expected["ok"])!.ToLowerInvariant() == "true";
            if (expectedOk)
            {
                Assert.True(outcome.Valid, $"{name}: expected ok, got {outcome.Code}");
                if (expected.TryGetValue("decoyField", out var decoyValue))
                {
                    XAssert.Equal(Convert.ToString(decoyValue) ?? "", outcome.DecoyField, name!);
                }
            }
            else
            {
                XAssert.Equal(Convert.ToString(expected["code"]) ?? "", outcome.Code, name!);
            }
        }
    }

    [Fact]
    public void ProvenanceNamesThePhpIssuer()
    {
        var golden = Support.GoldenVectors();
        var provenance = (Dictionary<string, object?>)golden["provenance"];
        Assert.Contains("php Issuer", Convert.ToString(provenance["issuer"]));
        Assert.True(provenance.ContainsKey("generator"));
        Assert.Equal(Support.TestSecret, Convert.ToString(provenance["secret"]));
    }

    [Fact]
    public void ShaPlainGoldenReplaysAsAlreadyConsumed()
    {
        var entry = GoldenEntry("sha_plain");
        var record = Support.GoldenRecord(entry);
        var config = new Verifier.Config { NowSecs = () => record.IssuedAt };
        var verifier = new Verifier(new MemoryStore(() => record.IssuedAt), config);
        Support.StoreRecord(verifier.Storage(), record);
        var token = Convert.ToString(entry["token_b64"])!;
        var options = new Verifier.Options
        {
            SecretKey = Support.TestSecret,
            ExpectedScope = "login",
            NowNs = record.IssuedAtNs + 3_000_000,
            NowNsSet = true,
        };
        Support.RequireValid(verifier.Verify(token, options));
        Support.RequireCode(verifier.Verify(token, options), VerifyError.AlreadyConsumed);
    }

    [Fact]
    public void Argon2IdGoldenCarriesAVerifyingProof()
    {
        var entry = GoldenEntry("argon2id");
        var record = Support.GoldenRecord(entry);
        var token = SolutionToken.Decode(Convert.ToString(entry["token_b64"])!);
        // The committed token solves the record: the SDK's own
        // argon2id recompute accepts it inside the verifier.
        var config = new Verifier.Config { NowSecs = () => record.IssuedAt };
        var verifier = new Verifier(new MemoryStore(() => record.IssuedAt), config);
        Support.StoreRecord(verifier.Storage(), record);
        var options = new Verifier.Options
        {
            SecretKey = Support.TestSecret,
            ExpectedScope = "login",
        };
        Support.RequireValid(verifier.Verify(token.Encode(), options));
    }

    [Fact]
    public void GoldenDirectoryIsSelfContained()
    {
        var golden = Support.TestdataPath(Path.Combine("golden", "golden-php-vectors.json"));
        Assert.True(new FileInfo(golden).Length > 1000,
            "the golden vectors must be committed beside the suites");
    }
}
