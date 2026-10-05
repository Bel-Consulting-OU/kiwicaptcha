package com.kiwicaptcha;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Redis suite runs against a scratch redis-server on a test port,
 * started and skipped like the repo's other redis-gated tests: a run
 * without the binary stays green everywhere.
 */
@EnabledIf("com.kiwicaptcha.RedisStoreTest#redisServerAvailable")
class RedisStoreTest {

    private static Process redis;
    private static Path tmpdir;
    private static RespClient client;
    private static int port;

    static boolean redisServerAvailable() {
        try {
            Process probe = new ProcessBuilder("which", "redis-server").start();
            boolean found = probe.waitFor(5, TimeUnit.SECONDS) && probe.exitValue() == 0;
            probe.destroyForcibly();
            return found;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    @BeforeAll
    static void startRedis() throws Exception {
        tmpdir = Files.createTempDirectory("kiwi-redis-test-");
        port = 6399 + (int) (ProcessHandle.current().pid() % 100);
        redis = new ProcessBuilder("redis-server",
                "--port", String.valueOf(port),
                "--save", "",
                "--appendonly", "no",
                "--dir", tmpdir.toString())
                .start();
        client = dialWithRetry();
        client.command("FLUSHALL");
    }

    @AfterAll
    static void stopRedis() {
        if (client != null) {
            client.close();
        }
        if (redis != null) {
            redis.destroyForcibly();
        }
        if (tmpdir != null) {
            try {
                Files.walk(tmpdir).sorted(java.util.Comparator.reverseOrder())
                        .forEach(path -> path.toFile().delete());
            } catch (IOException ignored) {
                // Cleanup is best-effort.
            }
        }
    }

    private static RespClient dialWithRetry() throws InterruptedException {
        java.time.Instant deadline = java.time.Instant.now().plusSeconds(10);
        RuntimeException last = null;
        while (java.time.Instant.now().isBefore(deadline)) {
            try {
                RespClient attempted = RespClient.dial("redis://127.0.0.1:" + port);
                attempted.ping();
                return attempted;
            } catch (RuntimeException e) {
                last = e;
                Thread.sleep(100);
            }
        }
        throw last;
    }

    private RedisStore store() {
        return new RedisStore(client, Kiwi.ENVELOPE_DEFAULT_PREFIX);
    }

    private static ChallengeRecord mintRecord() {
        Support.MintOptions options = new Support.MintOptions();
        options.mintMetaMac = true;
        return Support.mintRecord(options);
    }

    @Test
    void respClientRoundTrips() {
        assertEquals("PONG", client.command("PING"));
        client.command("SET", "kiwi-test:resp", "value");
        String[] got = client.get("kiwi-test:resp");
        assertNotNull(got);
        assertEquals("value", got[0]);
        assertNull(client.get("kiwi-test:absent"));
        assertTrue(client.del("kiwi-test:resp"));
    }

    @Test
    void fullOneShotRoundtrip() {
        RedisStore store = store();
        ChallengeRecord record = mintRecord();
        store.storeRecord(record);
        assertEquals(record.nonce, store.find(record.nonce).nonce);
        assertEquals(Store.RuntimeStateKind.PENDING, store.runtimeState(record.nonce).kind);
        Store.ConsumedRecord consumed = store.consume(record.nonce);
        assertNotNull(consumed);
        assertTrue(consumed.consumedNow);
        assertTrue(store.commitResult(record.nonce, true, ""));
        assertTrue(store.delete(record.nonce));
        assertNull(store.find(record.nonce));
    }

    @Test
    void envelopeIsByteCompatibleWithTheSharedWriters() {
        RedisStore store = store();
        ChallengeRecord record = mintRecord();
        store.storeRecord(record);
        String[] envelope = client.get(Kiwi.ENVELOPE_DEFAULT_PREFIX + record.nonce);
        assertNotNull(envelope);
        assertTrue(envelope[0].startsWith("{\"nonce\":\"" + record.nonce + "\",\"scope\":\"login\""));
        assertTrue(envelope[0].contains("\"state\":\"pending\""));
        assertTrue(envelope[0].contains("\"consumed_result\":null"));
        // A stored envelope rides runtime markers the record parser
        // refuses; the envelope decoder strips them before parsing.
        String[] envelope2 = client.get(Kiwi.ENVELOPE_DEFAULT_PREFIX + record.nonce);
        assertThrows(ChallengeRecord.MalformedRecordException.class,
                () -> ChallengeRecord.parse(envelope2[0].getBytes()));
    }

    @Test
    void consumeIsOneShotAndReplayable() {
        RedisStore store = store();
        ChallengeRecord record = mintRecord();
        store.storeRecord(record);
        assertNotNull(store.consume(record.nonce));
        Store.ConsumedRecord replay = store.consume(record.nonce);
        assertNotNull(replay);
        assertTrue(replay.consumedBefore);
        // The committed result replays through the runtime snapshot.
        store.commitAuthenticatedResult(record.nonce,
                new Store.ConsumedResult(true, "b", "ab".repeat(32)));
        Store.ConsumedRecord retained = store.consumedState(record.nonce);
        assertNotNull(retained);
        assertNotNull(retained.consumedResult);
        assertEquals("ab".repeat(32), retained.consumedResult.mac);
    }

    @Test
    void deleteIfPendingClassifies() {
        RedisStore store = store();
        ChallengeRecord pending = mintRecord();
        store.storeRecord(pending);
        assertEquals(Store.DELETE_STATUS_DELETED_PENDING, store.deleteIfPending(pending.nonce).status);
        assertNull(store.find(pending.nonce));
        assertEquals(Store.DELETE_STATUS_MISSING, store.deleteIfPending(pending.nonce).status);

        ChallengeRecord consumed = mintRecord();
        store.storeRecord(consumed);
        store.consume(consumed.nonce);
        Store.DeleteIfPendingResult kept = store.deleteIfPending(consumed.nonce);
        assertTrue(kept.wasConsumed());
        assertNotNull(store.find(consumed.nonce));

        ChallengeRecord cancelled = mintRecord();
        store.storeRecord(cancelled);
        store.cancel(cancelled.nonce);
        assertEquals(Store.DELETE_STATUS_CANCELLED, store.deleteIfPending(cancelled.nonce).status);
    }

    @Test
    void identityBearingConsume() {
        RedisStore store = store();
        ChallengeRecord record = mintRecord();
        store.storeRecord(record);
        Store.ConsumedRecord consumed = store.consumeWithOperationIdentity(record.nonce, "op-1");
        assertNotNull(consumed);
        assertTrue(consumed.consumedNow);
        assertEquals("op-1", consumed.operationIdentity);
        Store.ConsumedRecord replay = store.consumeWithOperationIdentity(record.nonce, "op-1");
        assertEquals("op-1", replay.operationIdentity);
        try {
            store.consumeWithOperationIdentity(record.nonce, "bad identity");
            throw new AssertionError("the identity gate must refuse");
        } catch (Store.OperationIdentityException expected) {
            // The shared validate gate fired before any transition.
        }
    }

    @Test
    void cancelledRecordsNeverConsume() {
        RedisStore store = store();
        ChallengeRecord record = mintRecord();
        store.storeRecord(record);
        assertEquals(Store.CANCEL_STATUS_CANCELLED_NOW, store.cancel(record.nonce).status);
        assertEquals(Store.CANCEL_STATUS_CANCELLED, store.cancel(record.nonce).status);
        assertNull(store.consume(record.nonce));
        assertEquals(Store.RuntimeStateKind.CANCELLED, store.runtimeState(record.nonce).kind);
    }

    @Test
    void verifierRunsOverTheRedisStore() {
        RedisStore storage = store();
        Verifier.Config config = new Verifier.Config();
        config.nowSecs = () -> Support.TEST_ISSUED_AT;
        Verifier verifier = new Verifier(storage, config);
        ChallengeRecord record = mintRecord();
        storage.storeRecord(record);
        String token = SolutionToken.create(record.nonce,
                Support.solveSha(record.prefix, record.salt, record.targetBits), 5000,
                JsonObject.of("v", new JsonNumber("1")), "", "", "").encode();
        Verifier.Options options = new Verifier.Options();
        options.secretKey = Support.TEST_SECRET;
        options.expectedScope = "login";
        options.clientIp = Support.TEST_CLIENT_IP;
        Support.requireValid(verifier.verify(token, options));
        Support.requireCode(verifier.verify(token, options), VerifyError.ALREADY_CONSUMED);
    }

    @Test
    void crossSdkEnvelopeFixtureShape() {
        // A pending envelope carries only null markers; the consume
        // transition refuses one that carries terminal state early.
        ChallengeRecord record = mintRecord();
        String recordJson = record.marshalJson();
        // A forged pending envelope that already carries a committed
        // result, hand-spliced like a hostile storage writer would.
        String encoded = recordJson.substring(0, recordJson.length() - 1)
                + ",\"state\":\"pending\",\"consumed_result\":{\"valid\":true,\"binding\":\"b\"},"
                + "\"operation_identity\":null}";
        String key = Kiwi.ENVELOPE_DEFAULT_PREFIX + "forged";
        client.setWithTtl(key, encoded, 60_000);
        // The pending-envelope guard refuses a pending record that
        // already carries a committed result: the transition answers
        // missing instead of installing the carried result.
        assertNull(store().consume("forged"));
        client.del(key);
    }
}
