package com.kiwicaptcha.stores.sqlite;

import com.kiwicaptcha.ChallengeRecord;
import com.kiwicaptcha.Store;
import com.kiwicaptcha.StrictJson;
import org.sqlite.SQLiteConfig;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Locale;
import java.util.function.LongSupplier;

/**
 * The file-backed single-node SQLite store adapter, over sqlite-jdbc.
 * The schema, the state machine and the wire shapes are the ones the
 * php SqliteStorage writes: one table keyed by nonce, the canonical
 * record JSON beside the runtime columns, WAL journaling, and every
 * durable transition inside one BEGIN IMMEDIATE transaction, so two
 * racing consumers of one nonce can never both observe the pending
 * row. Expiry mirrors the Redis TTLs: a row past its retained_until is
 * absent to every read and transition.
 *
 * This module is the optional home of the adapter: the core artifact
 * stays dependency-free, and enabling the store is exactly one
 * dependency on kiwicaptcha-stores-sqlite.
 */
public final class SqliteStore implements Store.StoreAdapter, Store.ConsumedStateReader,
        Store.RuntimeStateReader, Store.AtomicDeleteIfPending, Store.OperationIdentityAware,
        Store.AuthenticatedResultCommit, Store.Cancellable, Store.Storer, AutoCloseable {

    /** The schema version this adapter writes and understands. */
    public static final int SCHEMA_VERSION = 1;

    private static final long DEFAULT_TTL_MARGIN_SECS = 60;

    private final Connection connection;
    private final LongSupplier clock;
    private final long ttlMarginSecs;
    private final Object lock = new Object();

    /** Opens (or creates) the database file with the shared schema. */
    public static SqliteStore open(String path, int busyTimeoutMs, long ttlMarginSecs) {
        return new SqliteStore(path, busyTimeoutMs, ttlMarginSecs, () -> System.currentTimeMillis() / 1000);
    }

    /** Opens the store over an injectable unix-second clock. */
    public static SqliteStore open(String path, int busyTimeoutMs, long ttlMarginSecs, LongSupplier clock) {
        return new SqliteStore(path, busyTimeoutMs, ttlMarginSecs, clock);
    }

    private SqliteStore(String path, int busyTimeoutMs, long ttlMarginSecs, LongSupplier clock) {
        if (busyTimeoutMs < 0 || ttlMarginSecs < 0) {
            throw new Store.StorageUnavailableException(
                    "kiwicaptcha: the sqlite busy timeout and ttl margin must be >= 0");
        }
        this.clock = clock;
        this.ttlMarginSecs = ttlMarginSecs;
        try {
            SQLiteConfig config = new SQLiteConfig();
            config.setBusyTimeout(busyTimeoutMs);
            config.setJournalMode(path.equals(":memory:")
                    ? SQLiteConfig.JournalMode.MEMORY
                    : SQLiteConfig.JournalMode.WAL);
            this.connection = DriverManager.getConnection("jdbc:sqlite:" + Path.of(path).toAbsolutePath(), config.toProperties());
        } catch (SQLException e) {
            throw new Store.StorageUnavailableException("kiwicaptcha: sqlite storage failure during opening the database file: " + e.getMessage(), e);
        }
        initializeSchema();
    }

    /** Closes the database connection. */
    @Override
    public void close() throws SQLException {
        connection.close();
    }

    /** The live connection, for operator and test inspection. */
    public Connection connection() {
        return connection;
    }

    /** Persists one pending record, sweeping expired rows in the same transaction. */
    @Override
    public void storeRecord(ChallengeRecord record) {
        write("challenge issuance", () -> {
            exec("DELETE FROM kiwicaptcha_challenge_records WHERE retained_until <= ?", nowSecs());
            exec("INSERT INTO kiwicaptcha_challenge_records " +
                    "(nonce, record_json, state, consumed_result_json, operation_identity, resume_owner, resume_until, retained_until) " +
                    "VALUES (?, ?, 'pending', NULL, NULL, NULL, NULL, ?) " +
                    "ON CONFLICT(nonce) DO UPDATE SET record_json = excluded.record_json, state = excluded.state, " +
                    "consumed_result_json = excluded.consumed_result_json, operation_identity = excluded.operation_identity, " +
                    "resume_owner = excluded.resume_owner, resume_until = excluded.resume_until, " +
                    "retained_until = excluded.retained_until",
                    record.nonce, record.marshalJson(), record.expiresAt + ttlMarginSecs);
        });
    }

    /** Returns the pending or retained record, absent once expired. */
    @Override
    public ChallengeRecord find(String nonce) {
        Row row = liveRow(nonce);
        return row == null ? null : decodeRecord(row.recordJson);
    }

    @Override
    public boolean delete(String nonce) {
        int[] existed = {0};
        write("the record deletion", () ->
                existed[0] = exec("DELETE FROM kiwicaptcha_challenge_records WHERE nonce = ?", nonce));
        return existed[0] > 0;
    }

    /** Runs the one-shot transition. */
    @Override
    public Store.ConsumedRecord consume(String nonce) {
        return consumeWithOperationIdentity(nonce, "");
    }

    /** Runs the one-shot transition, recording the identity with the flip. */
    @Override
    public Store.ConsumedRecord consumeWithOperationIdentity(String nonce, String operationIdentity) {
        String identity = Store.validateOperationIdentity(operationIdentity);
        return write("the pending-to-consumed transition", () -> {
            Row row = liveRow(nonce);
            if (row == null) {
                return null;
            }
            ChallengeRecord record = decodeRecord(row.recordJson);
            if (record == null) {
                return null;
            }
            if (row.state.equals("consumed")) {
                return consumedEnvelope(row, record);
            }
            if (!row.state.equals("pending")) {
                return null;
            }
            if (row.consumedResultJson != null || row.operationIdentity != null || row.resumeOwner != null) {
                return null;
            }
            if (identity.isEmpty()) {
                exec("UPDATE kiwicaptcha_challenge_records SET state = 'consumed' WHERE nonce = ?", nonce);
            } else {
                exec("UPDATE kiwicaptcha_challenge_records SET state = 'consumed', operation_identity = ? WHERE nonce = ?",
                        identity, nonce);
            }
            return new Store.ConsumedRecord(record, true, false, null, identity);
        });
    }

    /** Reads the retained consumed envelope. */
    @Override
    public Store.ConsumedRecord consumedState(String nonce) {
        Row row = liveRow(nonce);
        if (row == null || !row.state.equals("consumed")) {
            return null;
        }
        ChallengeRecord record = decodeRecord(row.recordJson);
        return record == null ? null : consumedEnvelope(row, record);
    }

    /** Commits the deterministic outcome of a consumed record. */
    @Override
    public boolean commitResult(String nonce, boolean valid, String binding) {
        return commitAuthenticatedResult(nonce, new Store.ConsumedResult(valid, binding, ""));
    }

    /** Commits the outcome with its server-state mac; only the first commit wins. */
    @Override
    public boolean commitAuthenticatedResult(String nonce, Store.ConsumedResult result) {
        return write("the result commit", () -> {
            Row row = liveRow(nonce);
            if (row == null || row.state.isEmpty() || !row.state.equals("consumed") || row.consumedResultJson != null) {
                return false;
            }
            if (decodeRecord(row.recordJson) == null) {
                return false;
            }
            exec("UPDATE kiwicaptcha_challenge_records SET consumed_result_json = ? WHERE nonce = ?",
                    marshalConsumedResult(result), nonce);
            return true;
        });
    }

    /** Runs the fused read-and-delete-on-pending transition. */
    @Override
    public Store.DeleteIfPendingResult deleteIfPending(String nonce) {
        return write("the delete-if-pending transition", () -> {
            Row row = liveRow(nonce);
            if (row == null) {
                return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_MISSING, null);
            }
            ChallengeRecord record = decodeRecord(row.recordJson);
            if (record == null) {
                return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_CORRUPT, null);
            }
            if (row.state.equals("consumed")) {
                return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_CONSUMED, consumedEnvelope(row, record));
            }
            if (row.state.equals("cancelled")) {
                return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_CANCELLED, null);
            }
            if (!row.state.equals("pending")) {
                return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_CORRUPT, null);
            }
            exec("DELETE FROM kiwicaptcha_challenge_records WHERE nonce = ?", nonce);
            return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_DELETED_PENDING, null);
        });
    }

    /** Reads the terminal-aware snapshot. */
    @Override
    public Store.ChallengeRuntimeState runtimeState(String nonce) {
        Row row = liveRow(nonce);
        if (row == null) {
            return Store.ChallengeRuntimeState.missing();
        }
        ChallengeRecord record = decodeRecord(row.recordJson);
        if (record == null) {
            // A corrupt row fails closed as missing, never pending.
            return Store.ChallengeRuntimeState.missing();
        }
        if (row.state.equals("cancelled")) {
            return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.CANCELLED, record, null);
        }
        if (row.state.equals("consumed")) {
            return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.CONSUMED, record, consumedEnvelope(row, record));
        }
        if (row.state.equals("pending")) {
            return new Store.ChallengeRuntimeState(Store.RuntimeStateKind.PENDING, record, null);
        }
        return Store.ChallengeRuntimeState.missing();
    }

    /** Flips the terminal cancellation marker. */
    @Override
    public Store.CancellationResult cancel(String nonce) {
        return write("the pending-to-cancelled transition", () -> {
            Row row = liveRow(nonce);
            if (row == null || decodeRecord(row.recordJson) == null) {
                return null;
            }
            if (row.state.equals("consumed")) {
                return new Store.CancellationResult(Store.CANCEL_STATUS_CONSUMED);
            }
            if (row.state.equals("cancelled")) {
                return new Store.CancellationResult(Store.CANCEL_STATUS_CANCELLED);
            }
            if (!row.state.equals("pending")) {
                return null;
            }
            exec("UPDATE kiwicaptcha_challenge_records SET state = 'cancelled' WHERE nonce = ?", nonce);
            return new Store.CancellationResult(Store.CANCEL_STATUS_CANCELLED_NOW);
        });
    }

    private Store.ConsumedRecord consumedEnvelope(Row row, ChallengeRecord record) {
        Store.ConsumedResult result = null;
        if (row.consumedResultJson != null) {
            result = parseConsumedResult(row.consumedResultJson);
        }
        String identity = row.operationIdentity == null ? "" : row.operationIdentity;
        return new Store.ConsumedRecord(record, false, true, result, identity);
    }

    private Row liveRow(String nonce) {
        Row row = rawRow(nonce);
        if (row == null) {
            return null;
        }
        if (nowSecs() >= row.retainedUntil) {
            return null;
        }
        return row;
    }

    private Row rawRow(String nonce) {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT record_json, state, consumed_result_json, operation_identity, resume_owner, resume_until, retained_until " +
                        "FROM kiwicaptcha_challenge_records WHERE nonce = ?")) {
            statement.setString(1, nonce);
            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                Row row = new Row();
                row.recordJson = rs.getString(1);
                row.state = rs.getString(2) == null ? "" : rs.getString(2);
                row.consumedResultJson = rs.getString(3);
                row.operationIdentity = rs.getString(4);
                row.resumeOwner = rs.getString(5);
                row.resumeUntil = rs.getObject(6) == null ? null : rs.getLong(6);
                row.retainedUntil = rs.getLong(7);
                return row;
            }
        } catch (SQLException e) {
            throw unavailable("reading the row", e);
        }
    }

    private ChallengeRecord decodeRecord(String recordJson) {
        try {
            return ChallengeRecord.parse(recordJson.getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            // An unusable row is null, never a partially trusted record.
            return null;
        }
    }

    private static Store.ConsumedResult parseConsumedResult(String json) {
        Object decoded = StrictJson.decode(json.getBytes(StandardCharsets.UTF_8));
        if (!(decoded instanceof java.util.Map<?, ?> data)) {
            return new Store.ConsumedResult(false, "", "");
        }
        boolean valid = Boolean.TRUE.equals(data.get("valid"));
        Object rawBinding = data.get("binding");
        String binding = rawBinding instanceof String s && !s.isEmpty() ? s : "";
        Object rawMac = data.get("mac");
        String mac = rawMac instanceof String s && !s.isEmpty() ? s : "";
        return new Store.ConsumedResult(valid, binding, mac);
    }

    private static String marshalConsumedResult(Store.ConsumedResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"valid\":").append(result.valid);
        sb.append(",\"binding\":");
        if (result.binding.isEmpty()) {
            sb.append("null");
        } else {
            sb.append('"').append(result.binding.replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
        }
        if (!result.mac.isEmpty()) {
            sb.append(",\"mac\":");
            sb.append('"').append(result.mac.replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    private void initializeSchema() {
        write("schema initialization", () -> {
            long version = scalar("PRAGMA user_version");
            if (version > SCHEMA_VERSION) {
                throw new Store.StorageUnavailableException(String.format(Locale.ROOT,
                        "kiwicaptcha: the database carries schema version %d, newer than the %d this adapter supports; upgrade the kiwicaptcha-stores-sqlite artifact",
                        version, SCHEMA_VERSION));
            }
            if (version == SCHEMA_VERSION) {
                long present = scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'kiwicaptcha_challenge_records'");
                if (present != 1) {
                    throw new Store.StorageUnavailableException(
                            "kiwicaptcha: the database is stamped with the kiwicaptcha schema version but the challenge table is missing; the file is damaged");
                }
                return;
            }
            exec("CREATE TABLE IF NOT EXISTS kiwicaptcha_challenge_records (" +
                    "nonce TEXT PRIMARY KEY, " +
                    "record_json TEXT NOT NULL, " +
                    "state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')), " +
                    "consumed_result_json TEXT, " +
                    "operation_identity TEXT, " +
                    "resume_owner TEXT, " +
                    "resume_until INTEGER, " +
                    "retained_until INTEGER NOT NULL)");
            exec("CREATE INDEX IF NOT EXISTS kiwicaptcha_challenge_records_retained_until_idx " +
                    "ON kiwicaptcha_challenge_records (retained_until)");
            exec("PRAGMA user_version = " + SCHEMA_VERSION);
        });
    }

    private <T> T write(String what, java.util.function.Supplier<T> body) {
        synchronized (lock) {
            try (Statement begin = connection.createStatement()) {
                begin.execute("BEGIN IMMEDIATE");
            } catch (SQLException e) {
                throw unavailable(what, e);
            }
            try {
                T result = body.get();
                try (Statement commit = connection.createStatement()) {
                    commit.execute("COMMIT");
                }
                return result;
            } catch (RuntimeException e) {
                rollbackQuietly();
                if (isContention(e)) {
                    throw unavailable(what + "; the write lock stayed held past the busy timeout, so raise the busy timeout or serialize writers", e);
                }
                throw e;
            } catch (SQLException e) {
                rollbackQuietly();
                throw unavailable(what, e);
            }
        }
    }

    private void write(String what, Runnable body) {
        write(what, () -> {
            body.run();
            return null;
        });
    }

    private void rollbackQuietly() {
        try (Statement rollback = connection.createStatement()) {
            rollback.execute("ROLLBACK");
        } catch (SQLException e) {
            // The rollback of a broken connection is best-effort.
        }
    }

    private static boolean isContention(Exception e) {
        String message = String.valueOf(e.getMessage()).toLowerCase(Locale.ROOT);
        return message.contains("locked") || message.contains("busy");
    }

    private Store.StorageUnavailableException unavailable(String what, Exception e) {
        return new Store.StorageUnavailableException(
                "kiwicaptcha: sqlite storage failure during " + what + ": " + e.getMessage(), e);
    }

    private int exec(String sql, Object... parameters) {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                if (parameters[i] == null) {
                    statement.setObject(i + 1, null);
                } else {
                    statement.setObject(i + 1, parameters[i]);
                }
            }
            return statement.executeUpdate();
        } catch (SQLException e) {
            throw unavailable("executing a statement", e);
        }
    }

    private long scalar(String sql) {
        try (Statement statement = connection.createStatement(); ResultSet rs = statement.executeQuery(sql)) {
            return rs.next() ? rs.getLong(1) : 0;
        } catch (SQLException e) {
            throw unavailable("reading a scalar", e);
        }
    }

    private long nowSecs() {
        return clock.getAsLong();
    }

    /** The one row shape every transition reads, column-named. */
    private static final class Row {
        String recordJson;
        String state;
        String consumedResultJson;
        String operationIdentity;
        String resumeOwner;
        Long resumeUntil;
        long retainedUntil;
    }
}
