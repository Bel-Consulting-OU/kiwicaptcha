package com.kiwicaptcha.stores.sqlite;

import com.kiwicaptcha.ChallengeRecord;
import com.kiwicaptcha.Store;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The file-backed sqlite store: the exactly-once consume contract, the
 * replay identity, the state machines, and the PHP interop — the
 * fixture database was written by the php SqliteStorage, and every
 * read and transition here must agree with it.
 */
final class SqliteStoreTest {

    private static final long ISSUED_AT = 1_800_000_000L;

    private static ChallengeRecord record(String nonce, String algorithm, int mKib, int t, int targetBits) {
        ChallengeRecord r = new ChallengeRecord();
        r.nonce = nonce;
        r.scope = "login";
        r.bindingTag = "tag-1";
        r.issuedAt = ISSUED_AT;
        r.expiresAt = ISSUED_AT + 120;
        r.protocolVersion = 2;
        r.algorithm = algorithm;
        r.mKib = mKib;
        r.t = t;
        r.p = 1;
        r.targetBits = targetBits;
        r.salt = "c2FsdA==";
        r.prefix = "pre-";
        r.challenge = "challenge";
        r.minDurationMs = 0;
        r.issuedAtNs = ISSUED_AT * 1_000_000L;
        return r;
    }

    @SuppressWarnings("resource")
    private SqliteStore newStore(Path path) {
        AtomicLong clock = new AtomicLong(ISSUED_AT + 10);
        return SqliteStore.open(path.toString(), 5000, 60, clock::get);
    }

    @Test
    void consumeIsExactlyOnceUnderRacingStores(@TempDir Path dir) throws Exception {
        Path path = dir.resolve("race.db");
        SqliteStore store = newStore(path);
        store.storeRecord(record("race-nonce", "sha256", 0, 1, 8));

        int racers = 8;
        ExecutorService pool = Executors.newFixedThreadPool(racers);
        CountDownLatch ready = new CountDownLatch(racers);
        CountDownLatch start = new CountDownLatch(1);
        AtomicLong won = new AtomicLong();
        AtomicLong before = new AtomicLong();
        AtomicLong missing = new AtomicLong();
        List<Future<?>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < racers; i++) {
            futures.add(pool.submit(() -> {
                try (SqliteStore racer = SqliteStore.open(path.toString(), 5000, 60)) {
                    ready.countDown();
                    start.await();
                    Store.ConsumedRecord consumed = racer.consume("race-nonce");
                    if (consumed == null) {
                        missing.incrementAndGet();
                    } else if (consumed.consumedNow) {
                        won.incrementAndGet();
                    } else if (consumed.consumedBefore) {
                        before.incrementAndGet();
                    }
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }));
        }
        ready.await();
        start.countDown();
        for (Future<?> future : futures) {
            future.get();
        }
        pool.shutdown();
        assertEquals(1, won.get(), () -> "exactly one racer wins the flip: before=" + before.get() + " missing=" + missing.get());
        assertEquals(racers - 1, before.get(), "the losers answer the retained envelope");
        assertEquals(0, missing.get());
    }

    @Test
    void theRetainedEnvelopeAnswersTheReplayIdentically(@TempDir Path dir) {
        SqliteStore store = newStore(dir.resolve("replay.db"));
        store.storeRecord(record("replay-nonce", "argon2id", 64, 3, 4));
        assertTrue(store.consume("replay-nonce").consumedNow);
        assertTrue(store.commitAuthenticatedResult("replay-nonce", new Store.ConsumedResult(true, "tag-1", "aabb")));
        assertFalse(store.commitResult("replay-nonce", false, "other"), "only the first commit wins");

        Store.ConsumedRecord replay = store.consume("replay-nonce");
        assertNotNull(replay);
        assertFalse(replay.consumedNow);
        assertTrue(replay.consumedBefore);
        assertNotNull(replay.consumedResult);
        assertTrue(replay.consumedResult.valid);
        assertEquals("tag-1", replay.consumedResult.binding);
        assertEquals("aabb", replay.consumedResult.mac);

        Store.ConsumedRecord state = store.consumedState("replay-nonce");
        assertNotNull(state);
        assertEquals("aabb", state.consumedResult.mac);
        assertEquals(Store.RuntimeStateKind.CONSUMED, store.runtimeState("replay-nonce").kind);
    }

    @Test
    void cleanupCancellationAndExpiryFollowTheStateMachines(@TempDir Path dir) throws Exception {
        SqliteStore store = newStore(dir.resolve("states.db"));
        store.storeRecord(record("cleanup-nonce", "sha256", 0, 1, 8));
        assertEquals(Store.DELETE_STATUS_DELETED_PENDING, store.deleteIfPending("cleanup-nonce").status);
        assertEquals(Store.DELETE_STATUS_MISSING, store.deleteIfPending("cleanup-nonce").status);

        store.storeRecord(record("cancel-nonce", "sha256", 0, 1, 8));
        assertEquals(Store.CANCEL_STATUS_CANCELLED_NOW, store.cancel("cancel-nonce").status);
        assertEquals(Store.CANCEL_STATUS_CANCELLED, store.cancel("cancel-nonce").status);
        assertEquals(Store.RuntimeStateKind.CANCELLED, store.runtimeState("cancel-nonce").kind);

        // Past the retention margin the row is absent to every read.
        store.close();
        AtomicLong late = new AtomicLong(ISSUED_AT + 120 + 61);
        SqliteStore expired = SqliteStore.open(dir.resolve("states.db").toString(), 5000, 60, late::get);
        assertNull(expired.find("cancel-nonce"));
        assertNull(expired.consume("cancel-nonce"));
        assertEquals(Store.RuntimeStateKind.MISSING, expired.runtimeState("cancel-nonce").kind);
    }

    /**
     * The PHP interop: the fixture database was written by the php
     * core's SqliteStorage (one pending row, one consumed row with its
     * committed result and operation identity). Every read and
     * transition here answers what the php writer stored.
     */
    @Test
    void thePhpWrittenFixtureInterops(@TempDir Path dir) throws Exception {
        Path fixture = Path.of("src", "test", "resources", "php_interop.db");
        assertTrue(Files.exists(fixture), "the php-written fixture must ship with the tests");
        Path work = dir.resolve("interop.db");
        Files.copy(fixture, work);

        SqliteStore store = newStore(work);

        ChallengeRecord pending = store.find("interop-pending-nonce-0000000001");
        assertNotNull(pending, "the php-written pending row reads");
        assertEquals("login", pending.scope);
        assertEquals("sha256", pending.algorithm);
        assertEquals(8, pending.targetBits);
        assertEquals("pre-", pending.prefix);

        Store.ConsumedRecord consumed = store.consumeWithOperationIdentity("interop-pending-nonce-0000000001",
                "op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assertNotNull(consumed);
        assertTrue(consumed.consumedNow);
        assertTrue(store.commitResult("interop-pending-nonce-0000000001", true, "tag-1"));
        Store.ConsumedRecord after = store.consumedState("interop-pending-nonce-0000000001");
        assertNotNull(after);
        assertEquals("op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", after.operationIdentity);
        assertTrue(after.consumedResult.valid);

        Store.ConsumedRecord retained = store.consume("interop-consumed-nonce-000000001");
        assertNotNull(retained);
        assertFalse(retained.consumedNow);
        assertTrue(retained.consumedBefore);
        assertEquals("op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", retained.operationIdentity);
        assertNotNull(retained.consumedResult);
        assertTrue(retained.consumedResult.valid);
        assertEquals("tag-2", retained.consumedResult.binding);
        assertEquals(Store.RuntimeStateKind.CONSUMED, store.runtimeState("interop-consumed-nonce-000000001").kind);
    }

    @Test
    void aCorruptRowFailsClosed(@TempDir Path dir) throws Exception {
        Path path = dir.resolve("corrupt.db");
        SqliteStore store = newStore(path);
        store.storeRecord(record("corrupt-nonce", "sha256", 0, 1, 8));
        try (var statement = store.connection().createStatement()) {
            statement.execute("UPDATE kiwicaptcha_challenge_records SET record_json = '{not json' WHERE nonce = 'corrupt-nonce'");
        }
        assertNull(store.find("corrupt-nonce"), "a corrupt row is absent, never partial");
        assertEquals(Store.RuntimeStateKind.MISSING, store.runtimeState("corrupt-nonce").kind);
        assertEquals(Store.DELETE_STATUS_CORRUPT, store.deleteIfPending("corrupt-nonce").status);
    }
}
