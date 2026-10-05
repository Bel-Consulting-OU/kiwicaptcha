using Xunit;

namespace KiwiCaptcha.Tests;

/// <summary>
/// The file-backed sqlite store: the exactly-once consume contract, the
/// replay identity, the retained consumed state and the PHP interop —
/// the fixture database was written by the php SqliteStorage, and every
/// read and transition here must agree with it.
/// </summary>
public sealed class SqliteStoreTests
{
    private const long IssuedAt = 1_800_000_000;

    private static string TempDb()
    {
        var path = Path.Combine(Path.GetTempPath(), "kiwicaptcha-store-" + Guid.NewGuid().ToString("N") + ".db");
        return path;
    }

    private static ChallengeRecord Record(string nonce, string algorithm = "sha256", int mKib = 0) => new()
    {
        Nonce = nonce,
        Scope = "login",
        BindingTag = "tag-1",
        IssuedAt = IssuedAt,
        ExpiresAt = IssuedAt + 120,
        ProtocolVersion = 2,
        Algorithm = algorithm,
        MKib = mKib,
        T = algorithm == "argon2id" ? 3 : 1,
        P = 1,
        TargetBits = algorithm == "argon2id" ? 4 : 8,
        Salt = "c2FsdA==",
        Prefix = "pre-",
        Challenge = "challenge",
        MinDurationMs = 0,
        IssuedAtNs = IssuedAt * 1_000_000,
    };

    [Fact]
    public void ConsumeIsExactlyOnceUnderRacingCallers()
    {
        var path = TempDb();
        try
        {
            var clock = IssuedAt + 10;
            var store = new SqliteStore(path, 5000, 60, () => clock);
            store.StoreRecord(Record("race-nonce"));

            var won = 0;
            var consumedBefore = 0;
            var missing = 0;
            Parallel.For(0, 8, _ =>
            {
                using var racer = new SqliteStore(path, 5000, 60, () => clock);
                var consumed = racer.Consume("race-nonce");
                if (consumed == null)
                {
                    Interlocked.Increment(ref missing);
                }
                else if (consumed.ConsumedNow)
                {
                    Interlocked.Increment(ref won);
                }
                else if (consumed.ConsumedBefore)
                {
                    Interlocked.Increment(ref consumedBefore);
                }
            });
            Assert.Equal(1, won);
            Assert.Equal(7, consumedBefore);
            Assert.Equal(0, missing);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void TheRetainedEnvelopeAnswersTheReplayIdentically()
    {
        var path = TempDb();
        try
        {
            var clock = IssuedAt + 10;
            var store = new SqliteStore(path, 5000, 60, () => clock);
            store.StoreRecord(Record("replay-nonce", "argon2id", 64));
            Assert.True(store.Consume("replay-nonce")!.ConsumedNow);
            Assert.True(store.CommitAuthenticatedResult("replay-nonce", new Store.ConsumedResult(true, "tag-1", "aabb")));

            var replay = store.Consume("replay-nonce");
            Assert.NotNull(replay);
            Assert.False(replay!.ConsumedNow);
            Assert.True(replay.ConsumedBefore);
            Assert.NotNull(replay.ConsumedResult);
            Assert.True(replay.ConsumedResult!.Valid);
            Assert.Equal("tag-1", replay.ConsumedResult.Binding);
            Assert.Equal("aabb", replay.ConsumedResult.Mac);

            var state = store.ConsumedState("replay-nonce");
            Assert.NotNull(state);
            Assert.Equal(replay.ConsumedResult!.Mac, state!.ConsumedResult!.Mac);
            Assert.Equal(Store.RuntimeStateKind.Consumed, store.RuntimeState("replay-nonce").Kind);

            // Only the first commit wins.
            Assert.False(store.CommitResult("replay-nonce", false, "other"));
            Assert.True(store.ConsumedState("replay-nonce")!.ConsumedResult!.Valid);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CleanupCancellationAndExpiryFollowTheStateMachines()
    {
        var path = TempDb();
        try
        {
            var clock = IssuedAt + 10;
            var store = new SqliteStore(path, 5000, 60, () => clock);
            store.StoreRecord(Record("cleanup-nonce"));
            Assert.Equal(Store.DeleteStatusDeletedPending, store.DeleteIfPending("cleanup-nonce").Status);
            Assert.Equal(Store.DeleteStatusMissing, store.DeleteIfPending("cleanup-nonce").Status);

            store.StoreRecord(Record("cancel-nonce"));
            Assert.Equal(Store.CancelStatusCancelledNow, store.Cancel("cancel-nonce")!.Status);
            Assert.Equal(Store.CancelStatusCancelled, store.Cancel("cancel-nonce")!.Status);
            Assert.Equal(Store.RuntimeStateKind.Cancelled, store.RuntimeState("cancel-nonce").Kind);

            // Past the retained_until the row is absent to every read.
            clock = IssuedAt + 120 + 61;
            Assert.Null(store.Find("cancel-nonce"));
            Assert.Null(store.Consume("cancel-nonce"));
            Assert.Equal(Store.RuntimeStateKind.Missing, store.RuntimeState("cancel-nonce").Kind);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// The PHP interop: the fixture database was written by the php
    /// core's SqliteStorage (one pending row, one consumed row with its
    /// committed result and operation identity). Every read and
    /// transition here answers what the php writer stored.
    /// </summary>
    [Fact]
    public void ThePhpWrittenFixtureInterops()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "testdata", "php_interop.db");
        Assert.True(File.Exists(path), "the php-written fixture must ship with the tests");
        var work = Path.Combine(Path.GetTempPath(), "kiwicaptcha-interop-" + Guid.NewGuid().ToString("N") + ".db");
        File.Copy(path, work, true);
        try
        {
            var clock = IssuedAt + 10;
            var store = new SqliteStore(work, 5000, 60, () => clock);

            // The pending row: minted by php, decoded here, consumed
            // exactly once, then the deterministic outcome lands in the
            // php-written schema.
            var pending = store.Find("interop-pending-nonce-0000000001");
            Assert.NotNull(pending);
            Assert.Equal("login", pending!.Scope);
            Assert.Equal("sha256", pending.Algorithm);
            Assert.Equal(8, pending.TargetBits);
            Assert.Equal("pre-", pending.Prefix);
            Assert.True(pending.ServerMac.Length >= 0);

            var consumed = store.ConsumeWithOperationIdentity("interop-pending-nonce-0000000001", "op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            Assert.NotNull(consumed);
            Assert.True(consumed!.ConsumedNow);
            Assert.True(store.CommitResult("interop-pending-nonce-0000000001", valid: true, binding: "tag-1"));
            var after = store.ConsumedState("interop-pending-nonce-0000000001");
            Assert.NotNull(after);
            Assert.Equal("op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", after!.OperationIdentity);
            Assert.True(after.ConsumedResult!.Valid);

            // The consumed row: php wrote the verdict, the binding and
            // the identity; the read returns them verbatim, and a
            // consume-before replay answers the retained envelope.
            var retained = store.Consume("interop-consumed-nonce-000000001");
            Assert.NotNull(retained);
            Assert.False(retained!.ConsumedNow);
            Assert.True(retained.ConsumedBefore);
            Assert.Equal("op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", retained.OperationIdentity);
            Assert.NotNull(retained.ConsumedResult);
            Assert.True(retained.ConsumedResult!.Valid);
            Assert.Equal("tag-2", retained.ConsumedResult.Binding);
            Assert.Equal(Store.RuntimeStateKind.Consumed, store.RuntimeState("interop-consumed-nonce-000000001").Kind);

            // The schema stays the php one: the version stamp the php
            // writer left is the version this adapter understands.
            using (var pragma = store.Connection.CreateCommand())
            {
                pragma.CommandText = "PRAGMA user_version";
                Assert.Equal(1L, Convert.ToInt64(pragma.ExecuteScalar()));
            }
        }
        finally
        {
            File.Delete(work);
        }
    }
}
