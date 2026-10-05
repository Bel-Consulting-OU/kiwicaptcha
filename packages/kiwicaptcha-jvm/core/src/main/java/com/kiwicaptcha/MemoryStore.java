package com.kiwicaptcha;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * In-memory storage: single process, non-persistent, a port of the
 * php ArrayStorage. The monitor serializes the read-modify-write
 * transitions, so consume stays one-shot under concurrency. Consume
 * marks the record consumed and keeps it until deletion, so replay
 * protection is the consumed marker, never absence. Expiry follows
 * the Redis ttl semantics: an entry whose expires_at has passed is
 * absent from every read and transition and is evicted lazily on
 * first observation. storeRecord prunes expired entries and evicts
 * the earliest-expiring entries at the hard cap, so a long-lived
 * process never accumulates unbounded state.
 */
public final class MemoryStore implements Store.StoreAdapter, Store.ConsumedStateReader,
        Store.RuntimeStateReader, Store.AtomicDeleteIfPending, Store.OperationIdentityAware,
        Store.AuthenticatedResultCommit, Store.Cancellable, Store.Storer {

    /** The store's entry cap. */
    public static final int DEFAULT_MAX_ENTRIES = 10_000;

    private static final class Entry {
        final ChallengeRecord record;
        boolean consumed;
        boolean cancelled;
        Store.ConsumedResult result;
        String identity = "";

        Entry(ChallengeRecord record) {
            this.record = record;
        }
    }

    private final LongSupplierClock clock;
    private final int maxEntries;
    private final Map<String, Entry> records = new HashMap<>();

    /** A long supplier in unix seconds, the injectable test clock. */
    public interface LongSupplierClock {
        long now();
    }

    /** Builds the in-process store over the wall clock. */
    public MemoryStore() {
        this(() -> System.currentTimeMillis() / 1000);
    }

    /** Builds the store over a test clock in unix seconds. */
    public MemoryStore(LongSupplierClock clock) {
        this.clock = clock;
        this.maxEntries = DEFAULT_MAX_ENTRIES;
    }

    private long nowSecs() {
        return clock.now();
    }

    private Entry entry(String nonce) {
        Entry entry = records.get(nonce);
        if (entry == null) {
            return null;
        }
        if (nowSecs() >= entry.record.expiresAt) {
            records.remove(nonce);
            return null;
        }
        return entry;
    }

    private void pruneExpired() {
        long now = nowSecs();
        records.values().removeIf(e -> now >= e.record.expiresAt);
    }

    private Store.ConsumedRecord consumedEnvelope(Entry entry) {
        return new Store.ConsumedRecord(entry.record, false, true, entry.result, entry.identity);
    }

    /** Persists one pending record with bounded retention. */
    @Override
    public void storeRecord(ChallengeRecord record) {
        synchronized (this) {
            pruneExpired();
            if (!records.containsKey(record.nonce)) {
                int needed = records.size() + 1 - maxEntries;
                if (needed > 0) {
                    List<String> nonces = new ArrayList<>(records.keySet());
                    nonces.sort(Comparator.comparingLong(n -> records.get(n).record.expiresAt));
                    for (int i = 0; i < needed; i++) {
                        records.remove(nonces.get(i));
                    }
                }
            }
            records.put(record.nonce, new Entry(record));
        }
    }

    /** Returns the pending or retained record, absent once expired. */
    @Override
    public ChallengeRecord find(String nonce) {
        synchronized (this) {
            Entry entry = entry(nonce);
            return entry == null ? null : entry.record;
        }
    }

    @Override
    public boolean delete(String nonce) {
        synchronized (this) {
            return records.remove(nonce) != null;
        }
    }

    /** Runs the one-shot transition. */
    @Override
    public Store.ConsumedRecord consume(String nonce) {
        return consumeWithOperationIdentity(nonce, "");
    }

    /**
     * Runs the one-shot transition and records the logical-operation
     * identity atomically with the flip.
     */
    @Override
    public Store.ConsumedRecord consumeWithOperationIdentity(String nonce, String operationIdentity) {
        String identity = Store.validateOperationIdentity(operationIdentity);
        synchronized (this) {
            Entry entry = entry(nonce);
            if (entry == null || entry.cancelled) {
                return null;
            }
            if (entry.consumed) {
                return consumedEnvelope(entry);
            }
            if (entry.result != null || !entry.identity.isEmpty()) {
                return null;
            }
            entry.consumed = true;
            if (!identity.isEmpty()) {
                entry.identity = identity;
            }
            return new Store.ConsumedRecord(entry.record, true, false, null, entry.identity);
        }
    }

    /** Reads the retained consumed envelope. */
    @Override
    public Store.ConsumedRecord consumedState(String nonce) {
        synchronized (this) {
            Entry entry = entry(nonce);
            if (entry == null || !entry.consumed) {
                return null;
            }
            return consumedEnvelope(entry);
        }
    }

    /** Commits the deterministic outcome of a consumed record. */
    @Override
    public boolean commitResult(String nonce, boolean valid, String binding) {
        return commitAuthenticatedResult(nonce, new Store.ConsumedResult(valid, binding, ""));
    }

    /** Commits the outcome with its server-state mac. Only the first commit wins. */
    @Override
    public boolean commitAuthenticatedResult(String nonce, Store.ConsumedResult result) {
        synchronized (this) {
            Entry entry = entry(nonce);
            if (entry == null || !entry.consumed || entry.result != null) {
                return false;
            }
            entry.result = result;
            return true;
        }
    }

    /**
     * Runs the fused cleanup transition. A consumed or cancelled
     * record is returned verbatim and kept; only the exact pending
     * state is deleted.
     */
    @Override
    public Store.DeleteIfPendingResult deleteIfPending(String nonce) {
        synchronized (this) {
            Entry entry = entry(nonce);
            if (entry == null) {
                return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_MISSING, null);
            }
            if (entry.consumed) {
                return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_CONSUMED, consumedEnvelope(entry));
            }
            if (entry.cancelled) {
                return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_CANCELLED, null);
            }
            records.remove(nonce);
            return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_DELETED_PENDING, null);
        }
    }

    /** Reads the terminal-aware snapshot. */
    @Override
    public Store.ChallengeRuntimeState runtimeState(String nonce) {
        synchronized (this) {
            Entry entry = entry(nonce);
            if (entry == null) {
                return Store.ChallengeRuntimeState.missing();
            }
            if (entry.cancelled) {
                return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.CANCELLED, entry.record, null);
            }
            if (entry.consumed) {
                return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.CONSUMED, entry.record,
                        consumedEnvelope(entry));
            }
            return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.PENDING, entry.record, null);
        }
    }

    /**
     * Flips the terminal cancellation marker. A consumed record is
     * terminal and never cancellable; a cancelled record is idempotent.
     */
    @Override
    public Store.CancellationResult cancel(String nonce) {
        synchronized (this) {
            Entry entry = entry(nonce);
            if (entry == null) {
                return null;
            }
            if (entry.consumed) {
                return new Store.CancellationResult(Store.CANCEL_STATUS_CONSUMED);
            }
            if (entry.cancelled) {
                return new Store.CancellationResult(Store.CANCEL_STATUS_CANCELLED);
            }
            entry.cancelled = true;
            return new Store.CancellationResult(Store.CANCEL_STATUS_CANCELLED_NOW);
        }
    }

    /** Reports the live entry count. */
    public int len() {
        synchronized (this) {
            pruneExpired();
            return records.size();
        }
    }
}
