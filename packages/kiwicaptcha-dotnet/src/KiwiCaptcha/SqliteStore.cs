using Microsoft.Data.Sqlite;
using System.Text;

namespace KiwiCaptcha;

/// <summary>
/// SQLite-backed storage: the zero-infrastructure single-node adapter,
/// over Microsoft.Data.Sqlite (the canonical ADO.NET driver; adding it
/// to the library is the deliberate, idiomatic choice). The schema,
/// the state machine and the wire shapes are the ones the php
/// SqliteStorage writes: one table keyed by nonce, the canonical
/// record JSON beside the runtime columns, WAL journaling, and every
/// durable transition inside one begin-immediate transaction, so two
/// racing consumers of one nonce can never both observe the pending
/// row. Expiry mirrors the Redis TTLs: a row past its retained_until
/// is absent to every read and transition.
/// </summary>
public sealed class SqliteStore : Store.IStoreAdapter, Store.IConsumedStateReader,
    Store.IRuntimeStateReader, Store.IAtomicDeleteIfPending, Store.IOperationIdentityAware,
    Store.IAuthenticatedResultCommit, Store.ICancellable, Store.IStorer, IDisposable
{
    /// <summary>The schema version this adapter writes and understands.</summary>
    public const int SchemaVersion = 1;

    private const long DefaultTtlMarginSecs = 60;

    private readonly SqliteConnection _connection;
    private readonly Func<long> _clock;
    private readonly long _ttlMarginSecs;
    private readonly object _lock = new();

    /// <summary>Opens (or creates) the database file with the shared schema.</summary>
    public SqliteStore(string path, int busyTimeoutMs = 5000, long ttlMarginSecs = DefaultTtlMarginSecs)
        : this(path, busyTimeoutMs, ttlMarginSecs, static () => DateTimeOffset.UtcNow.ToUnixTimeSeconds())
    {
    }

    /// <summary>Opens the store over an injectable unix-second clock.</summary>
    public SqliteStore(string path, int busyTimeoutMs, long ttlMarginSecs, Func<long> clock)
    {
        if (busyTimeoutMs < 0)
        {
            throw new ArgumentException("kiwicaptcha: the sqlite busy timeout must be >= 0", nameof(busyTimeoutMs));
        }
        if (ttlMarginSecs < 0)
        {
            throw new ArgumentException("kiwicaptcha: the sqlite ttl margin must be >= 0", nameof(ttlMarginSecs));
        }
        _clock = clock;
        _ttlMarginSecs = ttlMarginSecs;
        _connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Pooling = false,
        }.ToString());
        _connection.Open();
        Exec($"PRAGMA busy_timeout = {busyTimeoutMs}");
        if (path != ":memory:")
        {
            Exec("PRAGMA journal_mode = WAL");
        }
        InitializeSchema();
    }

    /// <summary>The live connection, for operator and test inspection.</summary>
    public SqliteConnection Connection => _connection;

    /// <summary>Persists one pending record, sweeping expired rows in the same transaction.</summary>
    public void StoreRecord(ChallengeRecord record)
    {
        Write("challenge issuance", () =>
        {
            Exec("DELETE FROM kiwicaptcha_challenge_records WHERE retained_until <= $now", ("$now", NowSecs()));
            Exec(
                "INSERT INTO kiwicaptcha_challenge_records " +
                "(nonce, record_json, state, consumed_result_json, operation_identity, resume_owner, resume_until, retained_until) " +
                "VALUES ($nonce, $record_json, 'pending', NULL, NULL, NULL, NULL, $retained_until) " +
                "ON CONFLICT(nonce) DO UPDATE SET record_json = excluded.record_json, state = excluded.state, " +
                "consumed_result_json = excluded.consumed_result_json, operation_identity = excluded.operation_identity, " +
                "resume_owner = excluded.resume_owner, resume_until = excluded.resume_until, retained_until = excluded.retained_until",
                ("$nonce", record.Nonce),
                ("$record_json", record.MarshalJson()),
                ("$retained_until", record.ExpiresAt + _ttlMarginSecs));
            return true;
        });
    }

    /// <summary>Returns the pending or retained record, absent once expired.</summary>
    public ChallengeRecord? Find(string nonce)
    {
        lock (_lock)
        {
            var row = LiveRow(nonce);
            return row == null ? null : DecodeRecord(row);
        }
    }

    public bool Delete(string nonce)
    {
        return Write("the record deletion", () =>
            Exec("DELETE FROM kiwicaptcha_challenge_records WHERE nonce = $nonce", ("$nonce", nonce)) > 0);
    }

    /// <summary>Runs the one-shot transition.</summary>
    public Store.ConsumedRecord? Consume(string nonce) => ConsumeWithOperationIdentity(nonce, "");

    /// <summary>Runs the one-shot transition, recording the identity with the flip.</summary>
    public Store.ConsumedRecord? ConsumeWithOperationIdentity(string nonce, string? operationIdentity)
    {
        var identity = Store.ValidateOperationIdentity(operationIdentity);
        return Write("the pending-to-consumed transition", () =>
        {
            var row = LiveRow(nonce);
            if (row == null)
            {
                return null;
            }
            var record = DecodeRecord(row);
            if (record == null)
            {
                return null;
            }
            var state = StateOf(row);
            if (state == "consumed")
            {
                return ConsumedEnvelope(row, record);
            }
            if (state != "pending")
            {
                return null;
            }
            if (row.ConsumedResultJson is not null || row.OperationIdentity is not null || row.ResumeOwner is not null)
            {
                return null;
            }
            Exec("UPDATE kiwicaptcha_challenge_records SET state = 'consumed', operation_identity = $identity WHERE nonce = $nonce",
                ("$identity", identity.Length == 0 ? null : identity), ("$nonce", nonce));
            return new Store.ConsumedRecord(record, true, false, null, identity);
        });
    }

    /// <summary>Reads the retained consumed envelope.</summary>
    public Store.ConsumedRecord? ConsumedState(string nonce)
    {
        lock (_lock)
        {
            var row = LiveRow(nonce);
            if (row == null || StateOf(row) != "consumed")
            {
                return null;
            }
            var record = DecodeRecord(row);
            return record == null ? null : ConsumedEnvelope(row, record);
        }
    }

    /// <summary>Commits the deterministic outcome of a consumed record.</summary>
    public bool CommitResult(string nonce, bool valid, string binding) =>
        CommitAuthenticatedResult(nonce, new Store.ConsumedResult(valid, binding, ""));

    /// <summary>Commits the outcome with its server-state mac; only the first commit wins.</summary>
    public bool CommitAuthenticatedResult(string nonce, Store.ConsumedResult result)
    {
        return Write("the result commit", () =>
        {
            var row = LiveRow(nonce);
            if (row == null || DecodeRecord(row) == null || StateOf(row) != "consumed" || row.ConsumedResultJson is not null)
            {
                return false;
            }
            Exec("UPDATE kiwicaptcha_challenge_records SET consumed_result_json = $result WHERE nonce = $nonce",
                ("$result", MarshalConsumedResult(result)), ("$nonce", nonce));
            return true;
        });
    }

    /// <summary>Runs the fused cleanup transition.</summary>
    public Store.DeleteIfPendingResult DeleteIfPending(string nonce)
    {
        return Write("the delete-if-pending transition", () =>
        {
            var row = LiveRow(nonce);
            if (row == null)
            {
                return new Store.DeleteIfPendingResult(Store.DeleteStatusMissing, null);
            }
            var record = DecodeRecord(row);
            if (record == null)
            {
                return new Store.DeleteIfPendingResult(Store.DeleteStatusCorrupt, null);
            }
            var state = StateOf(row);
            if (state == "consumed")
            {
                return new Store.DeleteIfPendingResult(Store.DeleteStatusConsumed, ConsumedEnvelope(row, record));
            }
            if (state == "cancelled")
            {
                return new Store.DeleteIfPendingResult(Store.DeleteStatusCancelled, null);
            }
            if (state != "pending")
            {
                return new Store.DeleteIfPendingResult(Store.DeleteStatusCorrupt, null);
            }
            Exec("DELETE FROM kiwicaptcha_challenge_records WHERE nonce = $nonce", ("$nonce", nonce));
            return new Store.DeleteIfPendingResult(Store.DeleteStatusDeletedPending, null);
        });
    }

    /// <summary>Reads the terminal-aware snapshot.</summary>
    public Store.ChallengeRuntimeState RuntimeState(string nonce)
    {
        lock (_lock)
        {
            var row = LiveRow(nonce);
            if (row == null)
            {
                return Store.ChallengeRuntimeState.Missing();
            }
            var record = DecodeRecord(row);
            if (record == null)
            {
                return Store.ChallengeRuntimeState.Missing();
            }
            var state = StateOf(row);
            if (state == "cancelled")
            {
                return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.Cancelled, record, null);
            }
            if (state == "consumed")
            {
                return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.Consumed, record, ConsumedEnvelope(row, record));
            }
            if (state == "pending")
            {
                return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.Pending, record, null);
            }
            return Store.ChallengeRuntimeState.Missing();
        }
    }

    /// <summary>Flips the terminal cancellation marker.</summary>
    public Store.CancellationResult? Cancel(string nonce)
    {
        return Write("the pending-to-cancelled transition", () =>
        {
            var row = LiveRow(nonce);
            if (row == null || DecodeRecord(row) == null)
            {
                return null;
            }
            var state = StateOf(row);
            if (state == "consumed")
            {
                return new Store.CancellationResult(Store.CancelStatusConsumed);
            }
            if (state == "cancelled")
            {
                return new Store.CancellationResult(Store.CancelStatusCancelled);
            }
            if (state != "pending")
            {
                return null;
            }
            Exec("UPDATE kiwicaptcha_challenge_records SET state = 'cancelled' WHERE nonce = $nonce", ("$nonce", nonce));
            return new Store.CancellationResult(Store.CancelStatusCancelledNow);
        });
    }

    private Store.ConsumedRecord ConsumedEnvelope(Row row, ChallengeRecord record)
    {
        var result = row.ConsumedResultJson is null ? null : ParseConsumedResult(row.ConsumedResultJson);
        return new Store.ConsumedRecord(record, false, true, result, row.OperationIdentity ?? "");
    }

    private Row? LiveRow(string nonce)
    {
        var row = RawRow(nonce);
        if (row == null)
        {
            return null;
        }
        if (NowSecs() >= row.RetainedUntil)
        {
            return null;
        }
        return row;
    }

    private Row? RawRow(string nonce)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT record_json, state, consumed_result_json, operation_identity, resume_owner, resume_until, retained_until " +
            "FROM kiwicaptcha_challenge_records WHERE nonce = $nonce";
        command.Parameters.AddWithValue("$nonce", nonce);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }
        return new Row(
            reader.IsDBNull(0) ? null : reader.GetString(0),
            reader.IsDBNull(1) ? "" : reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3),
            reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetInt64(5),
            reader.GetInt64(6));
    }

    private ChallengeRecord? DecodeRecord(Row row)
    {
        try
        {
            return ChallengeRecord.Parse(Encoding.UTF8.GetBytes(row.RecordJson!));
        }
        catch (ChallengeRecord.MalformedRecordException)
        {
            return null;
        }
    }

    private static string StateOf(Row row) => row.State ?? "";

    private static string MarshalConsumedResult(Store.ConsumedResult result)
    {
        var sb = new StringBuilder();
        sb.Append("{\"valid\":").Append(result.Valid ? "true" : "false");
        sb.Append(",\"binding\":");
        if (result.Binding.Length == 0)
        {
            sb.Append("null");
        }
        else
        {
            JsonObject.WriteJsonString(sb, result.Binding);
        }
        if (result.Mac.Length > 0)
        {
            sb.Append(",\"mac\":");
            JsonObject.WriteJsonString(sb, result.Mac);
        }
        sb.Append('}');
        return sb.ToString();
    }

    private static Store.ConsumedResult ParseConsumedResult(string json)
    {
        var data = JsonObject.ParseObject(json);
        var valid = data.BoolOrNull("valid") ?? false;
        var binding = data.TryGet("binding", out var b) && b is string bs && bs.Length > 0 ? bs : "";
        var mac = data.TryGet("mac", out var m) && m is string ms && ms.Length > 0 ? ms : "";
        return new Store.ConsumedResult(valid, binding, mac);
    }

    private void InitializeSchema()
    {
        Write("schema initialization", () =>
        {
            var version = Scalar("PRAGMA user_version");
            if (version > SchemaVersion)
            {
                throw new Store.StorageUnavailableException(
                    $"the database carries schema version {version}, newer than the {SchemaVersion} this adapter supports; upgrade the KiwiCaptcha package");
            }
            if (version == SchemaVersion)
            {
                var present = Scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'kiwicaptcha_challenge_records'");
                if (present != 1)
                {
                    throw new Store.StorageUnavailableException(
                        "the database is stamped with the kiwicaptcha schema version but the challenge table is missing; the file is damaged");
                }
                return true;
            }
            Exec("CREATE TABLE IF NOT EXISTS kiwicaptcha_challenge_records (" +
                "nonce TEXT PRIMARY KEY, " +
                "record_json TEXT NOT NULL, " +
                "state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')), " +
                "consumed_result_json TEXT, " +
                "operation_identity TEXT, " +
                "resume_owner TEXT, " +
                "resume_until INTEGER, " +
                "retained_until INTEGER NOT NULL)");
            Exec("CREATE INDEX IF NOT EXISTS kiwicaptcha_challenge_records_retained_until_idx " +
                "ON kiwicaptcha_challenge_records (retained_until)");
            Exec($"PRAGMA user_version = {SchemaVersion}");
            return true;
        });
    }

    private T Write<T>(string what, Func<T> body)
    {
        lock (_lock)
        {
            try
            {
                Exec("BEGIN IMMEDIATE");
            }
            catch (SqliteException e)
            {
                throw new Store.StorageUnavailableException($"sqlite storage failure during {what}: {e.Message}", e);
            }
            try
            {
                var result = body();
                Exec("COMMIT");
                return result;
            }
            catch (Store.OperationIdentityException)
            {
                SafeRollback();
                throw;
            }
            catch (SqliteException e)
            {
                SafeRollback();
                throw new Store.StorageUnavailableException($"sqlite storage failure during {what}: {e.Message}", e);
            }
            catch (ChallengeRecord.MalformedRecordException e)
            {
                SafeRollback();
                throw new Store.StorageUnavailableException($"sqlite storage failure during {what}: {e.Message}", e);
            }
        }
    }

    private void SafeRollback()
    {
        try
        {
            Exec("ROLLBACK");
        }
        catch (SqliteException)
        {
            // The rollback of a broken connection is best-effort.
        }
    }

    private int Exec(string sql, params (string, object?)[] parameters)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? System.DBNull.Value);
        }
        return command.ExecuteNonQuery();
    }

    private long Scalar(string sql)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = sql;
        var result = command.ExecuteScalar();
        return Convert.ToInt64(result ?? 0);
    }

    private long NowSecs() => _clock();

    /// <summary>Closes the database connection.</summary>
    public void Dispose()
    {
        _connection.Dispose();
    }

    /// <summary>The one row shape every transition reads, column-named.</summary>
    private sealed record Row(
        string? RecordJson,
        string? State,
        string? ConsumedResultJson,
        string? OperationIdentity,
        string? ResumeOwner,
        long? ResumeUntil,
        long RetainedUntil);
}
