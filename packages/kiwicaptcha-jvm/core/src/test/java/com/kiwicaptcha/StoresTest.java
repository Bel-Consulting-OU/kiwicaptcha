package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The memory store: one-shot transitions, retention and cancellation. */
class StoresTest {

    private static ChallengeRecord mintRecord(long issuedAt, long ttl) {
        Support.MintOptions options = new Support.MintOptions();
        options.issuedAt = issuedAt;
        options.ttl = ttl;
        return Support.mintRecord(options);
    }

    @Test
    void storeFindConsumeCommitDeleteRoundtrip() {
        MemoryStore store = new MemoryStore();
        ChallengeRecord record = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(record);
        assertEquals(record.nonce, store.find(record.nonce).nonce);
        Store.ConsumedRecord consumed = store.consume(record.nonce);
        assertNotNull(consumed);
        assertTrue(consumed.consumedNow);
        assertTrue(store.commitResult(record.nonce, true, "binding"));
        assertFalse(store.commitResult(record.nonce, true, "binding"));
        assertTrue(store.delete(record.nonce));
        assertFalse(store.delete(record.nonce));
        assertNull(store.find(record.nonce));
    }

    @Test
    void expiredRecordsVanish() {
        long[] clock = {Support.TEST_ISSUED_AT};
        MemoryStore store = new MemoryStore(() -> clock[0]);
        ChallengeRecord record = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(record);
        assertNotNull(store.find(record.nonce));
        clock[0] = Support.TEST_ISSUED_AT + 121;
        assertNull(store.find(record.nonce));
        assertNull(store.consume(record.nonce));
        assertEquals(0, store.len());
    }

    @Test
    void consumedRecordRetainsUntilExpiry() {
        long[] clock = {Support.TEST_ISSUED_AT};
        MemoryStore store = new MemoryStore(() -> clock[0]);
        ChallengeRecord record = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(record);
        assertNotNull(store.consume(record.nonce));
        Store.ConsumedRecord before = store.consume(record.nonce);
        assertNotNull(before);
        assertTrue(before.consumedBefore);
        assertNotNull(store.consumedState(record.nonce));
        clock[0] = Support.TEST_ISSUED_AT + 121;
        assertNull(store.consumedState(record.nonce));
    }

    @Test
    void commitOnlyFirstWins() {
        MemoryStore store = new MemoryStore();
        ChallengeRecord record = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(record);
        store.consume(record.nonce);
        assertTrue(store.commitAuthenticatedResult(record.nonce,
                new Store.ConsumedResult(true, "b", "ab".repeat(32))));
        assertFalse(store.commitAuthenticatedResult(record.nonce,
                new Store.ConsumedResult(false, "", "")));
        assertEquals("ab".repeat(32), store.consumedState(record.nonce).consumedResult.mac);
    }

    @Test
    void deleteIfPendingClassifies() {
        MemoryStore store = new MemoryStore();
        ChallengeRecord pending = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(pending);
        assertEquals(Store.DELETE_STATUS_DELETED_PENDING,
                store.deleteIfPending(pending.nonce).status);
        assertNull(store.find(pending.nonce));

        ChallengeRecord consumedRecord = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(consumedRecord);
        store.consume(consumedRecord.nonce);
        Store.DeleteIfPendingResult consumed = store.deleteIfPending(consumedRecord.nonce);
        assertTrue(consumed.wasConsumed());
        assertNotNull(consumed.consumed);
        assertNotNull(store.find(consumedRecord.nonce));

        ChallengeRecord cancelledRecord = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(cancelledRecord);
        store.cancel(cancelledRecord.nonce);
        assertEquals(Store.DELETE_STATUS_CANCELLED, store.deleteIfPending(cancelledRecord.nonce).status);
        assertNotNull(store.find(cancelledRecord.nonce));

        assertEquals(Store.DELETE_STATUS_MISSING, store.deleteIfPending("missing").status);
    }

    @Test
    void cancelStates() {
        MemoryStore store = new MemoryStore();
        assertNull(store.cancel("missing"));
        ChallengeRecord record = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(record);
        assertEquals(Store.CANCEL_STATUS_CANCELLED_NOW, store.cancel(record.nonce).status);
        assertEquals(Store.CANCEL_STATUS_CANCELLED, store.cancel(record.nonce).status);
        assertEquals(Store.RuntimeStateKind.CANCELLED, store.runtimeState(record.nonce).kind);

        ChallengeRecord consumed = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(consumed);
        store.consume(consumed.nonce);
        assertEquals(Store.CANCEL_STATUS_CONSUMED, store.cancel(consumed.nonce).status);
    }

    @Test
    void runtimeStateKinds() {
        MemoryStore store = new MemoryStore();
        assertEquals(Store.RuntimeStateKind.MISSING, store.runtimeState("gone").kind);
        ChallengeRecord record = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(record);
        assertEquals(Store.RuntimeStateKind.PENDING, store.runtimeState(record.nonce).kind);
        store.consume(record.nonce);
        Store.ChallengeRuntimeState consumed = store.runtimeState(record.nonce);
        assertEquals(Store.RuntimeStateKind.CONSUMED, consumed.kind);
        assertNotNull(consumed.consumed);
        // A consumed record is terminal, never cancellable; a fresh
        // record cancels.
        assertEquals(Store.CANCEL_STATUS_CONSUMED, store.cancel(record.nonce).status);
        ChallengeRecord fresh = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(fresh);
        assertEquals(Store.CANCEL_STATUS_CANCELLED_NOW, store.cancel(fresh.nonce).status);
        assertEquals(Store.RuntimeStateKind.CANCELLED, store.runtimeState(fresh.nonce).kind);
    }

    @Test
    void capacityEviction() {
        long[] clock = {Support.TEST_ISSUED_AT};
        MemoryStore store = new MemoryStore(() -> clock[0]);
        // The shipped cap is 10000; the prune path runs over a loop of
        // short-lived records so a long-lived process stays bounded.
        for (int i = 0; i < 250; i++) {
            ChallengeRecord record = mintRecord(Support.TEST_ISSUED_AT + i, 10);
            store.storeRecord(record);
            clock[0] = Support.TEST_ISSUED_AT + i;
        }
        assertTrue(store.len() <= 1);
    }

    @Test
    void consumeRacesHaveOneWinner() throws Exception {
        MemoryStore store = new MemoryStore();
        ChallengeRecord record = mintRecord(Support.TEST_ISSUED_AT, 120);
        store.storeRecord(record);
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger winners = new AtomicInteger();
        Thread[] workers = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            workers[i] = new Thread(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    return;
                }
                Store.ConsumedRecord consumed = store.consume(record.nonce);
                if (consumed != null && consumed.consumedNow) {
                    winners.incrementAndGet();
                }
            });
            workers[i].start();
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }
        assertEquals(1, winners.get());
    }

    @Test
    void envelopeRoundTripThroughTheWireSchema() {
        MemoryStore store = new MemoryStore();
        Support.MintOptions options = new Support.MintOptions();
        options.mintMetaMac = true;
        options.decoyField = "";
        ChallengeRecord record = Support.mintRecord(options);
        String envelopeBytes = record.marshalJson();
        ChallengeRecord parsed = ChallengeRecord.parse(envelopeBytes.getBytes());
        assertEquals(record.nonce, parsed.nonce);
        store.storeRecord(parsed);
        assertEquals(record.nonce, store.find(record.nonce).nonce);
        assertEquals(record.serverMac, store.find(record.nonce).serverMac);
    }

    @Test
    void goldenEnvelopeShapeStaysCompatible() {
        // The committed envelope sample pins the exact runtime marker
        // shape the php and Python writers emit.
        Map<String, Object> golden = Support.goldenVectors();
        assertNotNull(golden.get("records"));
        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) ((java.util.List<?>) golden.get("records")).get(0);
        @SuppressWarnings("unchecked")
        Map<String, Object> recordMap = (Map<String, Object>) first.get("record");
        ChallengeRecord record = ChallengeRecord.fromMap(recordMap);
        var envelope = record.toWireMap();
        envelope.put("state", "pending");
        envelope.put("consumed_result", null);
        envelope.put("operation_identity", null);
        String encoded = WireJson.encodeEnvelope(envelope);
        assertTrue(encoded.startsWith("{\"nonce\":"));
        assertTrue(encoded.contains("\"state\":\"pending\""));
        // The envelope decoder strips the runtime markers first; the
        // direct record parser refuses them as unknown keys.
        assertThrows(ChallengeRecord.MalformedRecordException.class,
                () -> ChallengeRecord.parse(encoded.getBytes()));
    }

    @Test
    void replayProtocolsOfTheDecisionPlane() {
        // Deny vs retry dispositions across the retryable codes.
        for (VerifyError code : VerifyError.values()) {
            Decision decision = Decision.fromOutcome(VerifyOutcome.invalid(code), "");
            boolean retryExpected = code == VerifyError.STORAGE_UNAVAILABLE
                    || code == VerifyError.CAPACITY_EXCEEDED
                    || code == VerifyError.ADMISSION_UNAVAILABLE
                    || code == VerifyError.CONSUME_INDETERMINATE;
            assertEquals(retryExpected ? Decision.DISPOSITION_RETRY : Decision.DISPOSITION_DENY,
                    decision.disposition, code.code());
        }
    }
}
