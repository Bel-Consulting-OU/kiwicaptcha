using System.Collections.Concurrent;

namespace KiwiCaptcha;

/// <summary>
/// The store adapter seam: record envelopes, runtime states and the
/// capability interfaces the verifier composes. Every backend
/// implements IStoreAdapter. The narrower capabilities are optional:
/// the verifier probes them with an instanceof check and follows the
/// same fallbacks as the php verifier.
/// </summary>
public static class Store
{
    /// <summary>The typed fail-closed storage failure.</summary>
    public sealed class StorageUnavailableException : Exception
    {
        public StorageUnavailableException(string message)
            : base("kiwicaptcha: storage backend unavailable" +
                  (string.IsNullOrEmpty(message) ? "" : ": " + message))
        {
        }

        public StorageUnavailableException(string message, Exception cause)
            : base("kiwicaptcha: storage backend unavailable" +
                  (string.IsNullOrEmpty(message) ? "" : ": " + message), cause)
        {
        }

        public StorageUnavailableException(Exception cause)
            : base("kiwicaptcha: storage backend unavailable", cause)
        {
        }
    }

    /// <summary>Reports an invalid logical-operation identity before any transition runs.</summary>
    public sealed class OperationIdentityException : Exception
    {
        public OperationIdentityException()
            : base("kiwicaptcha: operation identity must be 1..128 bytes of [A-Za-z0-9_-]")
        {
        }
    }

    /// <summary>Validates one logical-operation identity, returning the empty string for none.</summary>
    public static string ValidateOperationIdentity(string? operationIdentity)
    {
        if (string.IsNullOrEmpty(operationIdentity))
        {
            return "";
        }
        if (operationIdentity.Length > 128)
        {
            throw new OperationIdentityException();
        }
        foreach (var c in operationIdentity)
        {
            var ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
                or '_' or '-';
            if (!ok)
            {
                throw new OperationIdentityException();
            }
        }
        return operationIdentity;
    }

    /// <summary>The runtime states of a stored record.</summary>
    public enum RuntimeStateKind
    {
        Missing,
        Pending,
        Consumed,
        Cancelled,
    }

    /// <summary>
    /// One runtime-state snapshot: the kind plus the decoded
    /// payloads. Record is set for every non-missing kind. Consumed
    /// carries the retained consumed envelope exactly when the kind
    /// is Consumed.
    /// </summary>
    public sealed record ChallengeRuntimeState(
        RuntimeStateKind Kind,
        ChallengeRecord? Record,
        ConsumedRecord? Consumed)
    {
        public static ChallengeRuntimeState Missing() => new(RuntimeStateKind.Missing, null, null);
    }

    /// <summary>
    /// The committed deterministic outcome of one consumed challenge.
    /// Mac is the server-state mac over the record's challenge, the
    /// verdict, the binding and the operation identity, or empty on a
    /// legacy commit from a backend that cannot carry one.
    /// </summary>
    public sealed record ConsumedResult(bool Valid, string Binding, string Mac);

    /// <summary>
    /// The consume transition's return: the record plus its new
    /// state. ConsumedNow marks the call that won the pending to
    /// consumed flip; ConsumedBefore marks a retry against an already
    /// consumed record.
    /// </summary>
    public sealed record ConsumedRecord(
        ChallengeRecord Record,
        bool ConsumedNow,
        bool ConsumedBefore,
        ConsumedResult? ConsumedResult,
        string OperationIdentity);

    /// <summary>Status values of the fused cleanup transition.</summary>
    public const string DeleteStatusMissing = "missing";
    public const string DeleteStatusDeletedPending = "deleted-pending";
    public const string DeleteStatusConsumed = "consumed";
    public const string DeleteStatusCancelled = "cancelled";
    public const string DeleteStatusCorrupt = "corrupt";

    /// <summary>The fused cheap-failure cleanup outcome.</summary>
    public sealed record DeleteIfPendingResult(string Status, ConsumedRecord? Consumed)
    {
        /// <summary>Whether the fused transition observed the consumed retention.</summary>
        public bool WasConsumed() => DeleteStatusConsumed == Status;
    }

    /// <summary>Status values of the cancel transition.</summary>
    public const string CancelStatusCancelledNow = "cancelled-now";
    public const string CancelStatusCancelled = "cancelled";
    public const string CancelStatusConsumed = "consumed";

    /// <summary>The cancel transition's outcome.</summary>
    public sealed record CancellationResult(string Status);

    /// <summary>The mandatory store adapter surface.</summary>
    public interface IStoreAdapter
    {
        /// <summary>Returns null without error for an absent or expired record.</summary>
        ChallengeRecord? Find(string nonce);

        /// <summary>Removes one record and reports whether it existed.</summary>
        bool Delete(string nonce);

        /// <summary>Runs the one-shot pending to consumed transition.</summary>
        ConsumedRecord? Consume(string nonce);

        /// <summary>Commits the deterministic outcome; only the first commit wins.</summary>
        bool CommitResult(string nonce, bool valid, string binding);
    }

    /// <summary>The retained consumed-envelope read.</summary>
    public interface IConsumedStateReader
    {
        ConsumedRecord? ConsumedState(string nonce);
    }

    /// <summary>The single get runtime-state snapshot read.</summary>
    public interface IRuntimeStateReader
    {
        ChallengeRuntimeState RuntimeState(string nonce);
    }

    /// <summary>The fused read-and-delete-on-pending transition.</summary>
    public interface IAtomicDeleteIfPending
    {
        DeleteIfPendingResult DeleteIfPending(string nonce);
    }

    /// <summary>The identity-bearing consume transition.</summary>
    public interface IOperationIdentityAware
    {
        ConsumedRecord? ConsumeWithOperationIdentity(string nonce, string operationIdentity);
    }

    /// <summary>The server-state-mac commit for a consumed result.</summary>
    public interface IAuthenticatedResultCommit
    {
        bool CommitAuthenticatedResult(string nonce, ConsumedResult result);
    }

    /// <summary>The terminal cancellation marker transition.</summary>
    public interface ICancellable
    {
        CancellationResult? Cancel(string nonce);
    }

    /// <summary>The write side every shipped backend carries.</summary>
    public interface IStorer
    {
        void StoreRecord(ChallengeRecord record);
    }
}

/// <summary>
/// In-memory storage: single process, non-persistent, a port of the
/// php ArrayStorage. The lock serializes the read-modify-write
/// transitions, so consume stays one-shot under concurrency. Consume
/// marks the record consumed and keeps it until deletion, so replay
/// protection is the consumed marker, never absence. Expiry follows
/// the Redis ttl semantics: an entry whose expires_at has passed is
/// absent from every read and transition and is evicted lazily on
/// first observation.
/// </summary>
public sealed class MemoryStore : Store.IStoreAdapter, Store.IConsumedStateReader,
    Store.IRuntimeStateReader, Store.IAtomicDeleteIfPending, Store.IOperationIdentityAware,
    Store.IAuthenticatedResultCommit, Store.ICancellable, Store.IStorer
{
    /// <summary>The store's entry cap.</summary>
    public const int DefaultMaxEntries = 10_000;

    private sealed class Entry
    {
        internal readonly ChallengeRecord Record;
        internal bool Consumed;
        internal bool Cancelled;
        internal Store.ConsumedResult? Result;
        internal string Identity = "";

        internal Entry(ChallengeRecord record) => Record = record;
    }

    private readonly Func<long> _clock;
    private readonly int _maxEntries;
    private readonly Dictionary<string, Entry> _records = new();
    private readonly object _lock = new();

    /// <summary>Builds the in-process store over the wall clock in unix seconds.</summary>
    public MemoryStore() : this(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds())
    {
    }

    /// <summary>Builds the store over an injectable unix-second clock.</summary>
    public MemoryStore(Func<long> clock)
    {
        _clock = clock;
        _maxEntries = DefaultMaxEntries;
    }

    private long NowSecs() => _clock();

    private Entry? Entry_(string nonce)
    {
        if (!_records.TryGetValue(nonce, out var entry))
        {
            return null;
        }
        if (NowSecs() >= entry.Record.ExpiresAt)
        {
            _records.Remove(nonce);
            return null;
        }
        return entry;
    }

    private void PruneExpired()
    {
        var now = NowSecs();
        var expired = new List<string>();
        foreach (var (nonce, entry) in _records)
        {
            if (now >= entry.Record.ExpiresAt)
            {
                expired.Add(nonce);
            }
        }
        foreach (var nonce in expired)
        {
            _records.Remove(nonce);
        }
    }

    private Store.ConsumedRecord ConsumedEnvelope(Entry entry) =>
        new(entry.Record, false, true, entry.Result, entry.Identity);

    /// <summary>Persists one pending record with bounded retention.</summary>
    public void StoreRecord(ChallengeRecord record)
    {
        lock (_lock)
        {
            PruneExpired();
            if (!_records.ContainsKey(record.Nonce))
            {
                var needed = _records.Count + 1 - _maxEntries;
                if (needed > 0)
                {
                    var nonces = new List<string>(_records.Keys);
                    nonces.Sort((a, b) => _records[a].Record.ExpiresAt.CompareTo(_records[b].Record.ExpiresAt));
                    for (var i = 0; i < needed; i++)
                    {
                        _records.Remove(nonces[i]);
                    }
                }
            }
            _records[record.Nonce] = new Entry(record);
        }
    }

    /// <summary>Returns the pending or retained record, absent once expired.</summary>
    public ChallengeRecord? Find(string nonce)
    {
        lock (_lock)
        {
            var entry = Entry_(nonce);
            return entry?.Record;
        }
    }

    public bool Delete(string nonce)
    {
        lock (_lock)
        {
            return _records.Remove(nonce);
        }
    }

    /// <summary>Runs the one-shot transition.</summary>
    public Store.ConsumedRecord? Consume(string nonce) => ConsumeWithOperationIdentity(nonce, "");

    /// <summary>
    /// Runs the one-shot transition and records the logical-operation
    /// identity atomically with the flip.
    /// </summary>
    public Store.ConsumedRecord? ConsumeWithOperationIdentity(string nonce, string? operationIdentity)
    {
        var identity = Store.ValidateOperationIdentity(operationIdentity);
        lock (_lock)
        {
            var entry = Entry_(nonce);
            if (entry == null || entry.Cancelled)
            {
                return null;
            }
            if (entry.Consumed)
            {
                return ConsumedEnvelope(entry);
            }
            if (entry.Result != null || entry.Identity.Length > 0)
            {
                return null;
            }
            entry.Consumed = true;
            if (identity.Length > 0)
            {
                entry.Identity = identity;
            }
            return new Store.ConsumedRecord(entry.Record, true, false, null, entry.Identity);
        }
    }

    /// <summary>Reads the retained consumed envelope.</summary>
    public Store.ConsumedRecord? ConsumedState(string nonce)
    {
        lock (_lock)
        {
            var entry = Entry_(nonce);
            if (entry == null || !entry.Consumed)
            {
                return null;
            }
            return ConsumedEnvelope(entry);
        }
    }

    /// <summary>Commits the deterministic outcome of a consumed record.</summary>
    public bool CommitResult(string nonce, bool valid, string binding) =>
        CommitAuthenticatedResult(nonce, new Store.ConsumedResult(valid, binding, ""));

    /// <summary>Commits the outcome with its server-state mac; only the first commit wins.</summary>
    public bool CommitAuthenticatedResult(string nonce, Store.ConsumedResult result)
    {
        lock (_lock)
        {
            var entry = Entry_(nonce);
            if (entry == null || !entry.Consumed || entry.Result != null)
            {
                return false;
            }
            entry.Result = result;
            return true;
        }
    }

    /// <summary>
    /// Runs the fused cleanup transition. A consumed or cancelled
    /// record is returned verbatim and kept; only the exact pending
    /// state is deleted.
    /// </summary>
    public Store.DeleteIfPendingResult DeleteIfPending(string nonce)
    {
        lock (_lock)
        {
            var entry = Entry_(nonce);
            if (entry == null)
            {
                return new Store.DeleteIfPendingResult(Store.DeleteStatusMissing, null);
            }
            if (entry.Consumed)
            {
                return new Store.DeleteIfPendingResult(Store.DeleteStatusConsumed, ConsumedEnvelope(entry));
            }
            if (entry.Cancelled)
            {
                return new Store.DeleteIfPendingResult(Store.DeleteStatusCancelled, null);
            }
            _records.Remove(nonce);
            return new Store.DeleteIfPendingResult(Store.DeleteStatusDeletedPending, null);
        }
    }

    /// <summary>Reads the terminal-aware snapshot.</summary>
    public Store.ChallengeRuntimeState RuntimeState(string nonce)
    {
        lock (_lock)
        {
            var entry = Entry_(nonce);
            if (entry == null)
            {
                return Store.ChallengeRuntimeState.Missing();
            }
            if (entry.Cancelled)
            {
                return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.Cancelled, entry.Record, null);
            }
            if (entry.Consumed)
            {
                return new Store.ChallengeRuntimeState(
                    Store.RuntimeStateKind.Consumed, entry.Record, ConsumedEnvelope(entry));
            }
            return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.Pending, entry.Record, null);
        }
    }

    /// <summary>
    /// Flips the terminal cancellation marker. A consumed record is
    /// terminal and never cancellable; a cancelled record is
    /// idempotent.
    /// </summary>
    public Store.CancellationResult? Cancel(string nonce)
    {
        lock (_lock)
        {
            var entry = Entry_(nonce);
            if (entry == null)
            {
                return null;
            }
            if (entry.Consumed)
            {
                return new Store.CancellationResult(Store.CancelStatusConsumed);
            }
            if (entry.Cancelled)
            {
                return new Store.CancellationResult(Store.CancelStatusCancelled);
            }
            entry.Cancelled = true;
            return new Store.CancellationResult(Store.CancelStatusCancelledNow);
        }
    }

    /// <summary>Reports the live entry count.</summary>
    public int Len()
    {
        lock (_lock)
        {
            PruneExpired();
            return _records.Count;
        }
    }
}
