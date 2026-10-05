package com.kiwicaptcha;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Redis storage: the shared-backend store adapter, a port of the php
 * RedisStorage. The stored envelope is one json document per nonce
 * key: the flattened record fields plus the state, consumed_result
 * and operation_identity runtime markers. The consume, delete-if-
 * pending, cancel and commit transitions run the exact Lua scripts of
 * the php adapter, so envelopes written by either SDK are
 * interchangeable, byte for byte.
 */
public final class RedisStore implements Store.StoreAdapter, Store.ConsumedStateReader,
        Store.RuntimeStateReader, Store.AtomicDeleteIfPending, Store.OperationIdentityAware,
        Store.AuthenticatedResultCommit, Store.Cancellable, Store.Storer {

    private final RedisClient client;
    private final String prefix;
    private final long ttlMarginMillis;
    private final ConcurrentHashMap<String, String> shaCache = new ConcurrentHashMap<>();

    /** Binds the adapter to a client. */
    public RedisStore(RedisClient client, String prefix) {
        this.client = client;
        this.prefix = prefix == null || prefix.isEmpty() ? Kiwi.ENVELOPE_DEFAULT_PREFIX : prefix;
        this.ttlMarginMillis = Kiwi.REDIS_STORAGE_TTL * 1000L;
    }

    private RuntimeException unavailable(Exception e) {
        return new Store.StorageUnavailableException(e.getMessage() == null ? e.toString() : e.getMessage());
    }

    /**
     * Runs one script through the sha cache with the noscript
     * fallback to a plain eval. The cache is concurrent, so concurrent
     * verifications share one adapter safely.
     */
    private Object eval(String script, List<String> keys, List<String> args) {
        String sha = shaCache.get(script);
        if (sha != null) {
            try {
                return client.evalSha(sha, keys, args);
            } catch (RespClient.RedisException e) {
                if (!e.isNoScript()) {
                    throw unavailable(e);
                }
            } catch (RuntimeException e) {
                throw unavailable(e);
            }
        }
        String loaded;
        try {
            loaded = client.scriptLoad(script);
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        if (loaded != null && !loaded.isEmpty()) {
            shaCache.put(script, loaded);
        }
        try {
            return client.eval(script, keys, args);
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
    }

    /** One decoded stored envelope: the record plus its runtime markers. */
    private static final class EnvelopeDoc {
        ChallengeRecord record;
        String state = "";
        String identity = "";
        Store.ConsumedResult result;
    }

    /**
     * Decodes one stored envelope. A nil record means the value is
     * absent or unusable; an unusable document is also an absent
     * record, never a partially trusted one, mirroring the php strict
     * json gate.
     */
    private static EnvelopeDoc decodeEnvelope(String raw) {
        EnvelopeDoc doc = new EnvelopeDoc();
        if (raw == null || raw.isEmpty() || raw.length() > Kiwi.ENVELOPE_MAX_BYTES) {
            return doc;
        }
        Object value;
        try {
            value = StrictJson.decode(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return doc;
        }
        if (!(value instanceof Map<?, ?> data)) {
            return doc;
        }
        Object state = data.get("state");
        if (state instanceof String s) {
            doc.state = s;
        }
        Object identity = data.get("operation_identity");
        if (identity instanceof String s) {
            doc.identity = s;
        }
        if (data.containsKey("consumed_result")) {
            Object rawResult = data.get("consumed_result");
            if (rawResult instanceof Map<?, ?> resultMap) {
                try {
                    doc.result = consumedResultFromMap(resultMap);
                } catch (RuntimeException ignored) {
                    // An unusable result payload is not a record failure.
                }
            }
        }
        Map<String, Object> recordData = new HashMap<>();
        for (Map.Entry<?, ?> entry : data.entrySet()) {
            String key = String.valueOf(entry.getKey());
            if (key.equals("state") || key.equals("consumed_result") || key.equals("operation_identity")
                    || key.equals("resume_owner") || key.equals("resume_until")) {
                continue;
            }
            recordData.put(key, entry.getValue());
        }
        try {
            doc.record = ChallengeRecord.fromMap(recordData);
        } catch (RuntimeException e) {
            return doc;
        }
        return doc;
    }

    private static Store.ConsumedResult consumedResultFromMap(Map<?, ?> data) {
        for (Object key : data.keySet()) {
            String name = String.valueOf(key);
            if (!name.equals("valid") && !name.equals("binding") && !name.equals("mac")) {
                throw new IllegalArgumentException("consumed_result carries unsupported keys");
            }
        }
        boolean valid;
        Object rawValid = data.get("valid");
        if (rawValid instanceof Boolean b) {
            valid = b;
        } else if (rawValid instanceof JsonNumber n) {
            // The production Lua accepts the legacy 1 or 0 form.
            valid = n.raw.equals("1");
        } else {
            throw new IllegalArgumentException("consumed_result.valid must be a boolean");
        }
        String binding = "";
        Object rawBinding = data.get("binding");
        if (rawBinding instanceof String s) {
            binding = s;
        } else if (rawBinding != null) {
            throw new IllegalArgumentException("consumed_result.binding must be a string or null");
        }
        String mac = "";
        Object rawMac = data.get("mac");
        if (rawMac == null) {
            // Absent.
        } else if (rawMac instanceof String s) {
            if (!SolutionToken.isHexN(s, 64)) {
                throw new IllegalArgumentException("consumed_result.mac must be 64 lowercase hex characters");
            }
            mac = s;
        } else {
            throw new IllegalArgumentException("consumed_result.mac must be a string or null");
        }
        return new Store.ConsumedResult(valid, binding, mac);
    }

    /** Persists one pending record with a lifetime of the signed remainder plus the margin. */
    @Override
    public void storeRecord(ChallengeRecord record) {
        Map<String, Object> envelope = record.toWireMap();
        envelope.put("state", "pending");
        envelope.put("consumed_result", null);
        envelope.put("operation_identity", null);
        String encoded = WireJson.encodeEnvelope(envelope);
        long ttlSeconds = record.expiresAt - System.currentTimeMillis() / 1000;
        long ttlMillis = ttlSeconds * 1000 + ttlMarginMillis;
        if (ttlMillis < 1000) {
            ttlMillis = 1000;
        }
        try {
            client.setWithTtl(prefix + record.nonce, encoded, ttlMillis);
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
    }

    /** Reads the record from the envelope. */
    @Override
    public ChallengeRecord find(String nonce) {
        String[] raw;
        try {
            raw = client.get(prefix + nonce);
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        if (raw == null) {
            return null;
        }
        return decodeEnvelope(raw[0]).record;
    }

    private Store.ConsumedRecord consume(String nonce, String identityJson) {
        List<String> keys = List.of(prefix + nonce);
        Object reply;
        try {
            reply = eval(LuaScripts.CONSUME_SCRIPT, keys, List.of(identityJson == null ? "" : identityJson));
        } catch (Store.StorageUnavailableException e) {
            throw e;
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        if (!(reply instanceof List<?> items) || items.size() < 3 || items.get(0) == null) {
            return null;
        }
        if (!(items.get(0) instanceof String payload)) {
            return null;
        }
        EnvelopeDoc doc = decodeEnvelope(payload);
        if (doc.record == null) {
            return null;
        }
        return new Store.ConsumedRecord(doc.record,
                replyInt(items.get(1)) == 1,
                replyInt(items.get(2)) == 1,
                doc.result, doc.identity);
    }

    /** Runs the fused one-shot transition. */
    @Override
    public Store.ConsumedRecord consume(String nonce) {
        return consume(nonce, "");
    }

    /**
     * Runs the fused transition and records the validated identity
     * atomically with the flip.
     */
    @Override
    public Store.ConsumedRecord consumeWithOperationIdentity(String nonce, String operationIdentity) {
        String identity = Store.validateOperationIdentity(operationIdentity);
        String identityJson = identity.isEmpty() ? "" : WireJson.encodeJsonString(identity);
        return consume(nonce, identityJson);
    }

    /** Reads the retained consumed envelope. */
    @Override
    public Store.ConsumedRecord consumedState(String nonce) {
        String[] raw;
        try {
            raw = client.get(prefix + nonce);
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        if (raw == null) {
            return null;
        }
        EnvelopeDoc doc = decodeEnvelope(raw[0]);
        if (doc.record == null || !"consumed".equals(doc.state)) {
            return null;
        }
        return new Store.ConsumedRecord(doc.record, false, true, doc.result, doc.identity);
    }

    /** Runs the fused atomic cleanup. */
    @Override
    public Store.DeleteIfPendingResult deleteIfPending(String nonce) {
        Object reply;
        try {
            reply = eval(LuaScripts.DELETE_IF_PENDING_SCRIPT, List.of(prefix + nonce), List.of());
        } catch (Store.StorageUnavailableException e) {
            throw e;
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        if (!(reply instanceof List<?> items) || items.isEmpty()) {
            throw new Store.StorageUnavailableException("delete-if-pending returned an unexpected reply");
        }
        String status = items.get(0) instanceof String s ? s : "";
        if (Store.DELETE_STATUS_CONSUMED.equals(status)) {
            if (items.size() < 2) {
                throw new Store.StorageUnavailableException("delete-if-pending lost the consumed envelope");
            }
            String payload = items.get(1) instanceof String s ? s : "";
            EnvelopeDoc doc = decodeEnvelope(payload);
            if (doc.record == null) {
                throw new Store.StorageUnavailableException("delete-if-pending returned an undecodable envelope");
            }
            return new Store.DeleteIfPendingResult(Store.DELETE_STATUS_CONSUMED,
                    new Store.ConsumedRecord(doc.record, false, true, doc.result, doc.identity));
        }
        if (status.isEmpty()) {
            status = Store.DELETE_STATUS_CORRUPT;
        }
        return new Store.DeleteIfPendingResult(status, null);
    }

    /** Reads the terminal-aware snapshot. */
    @Override
    public Store.ChallengeRuntimeState runtimeState(String nonce) {
        String[] raw;
        try {
            raw = client.get(prefix + nonce);
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        if (raw == null) {
            return Store.ChallengeRuntimeState.missing();
        }
        EnvelopeDoc doc = decodeEnvelope(raw[0]);
        if (doc.record == null) {
            return Store.ChallengeRuntimeState.missing();
        }
        return switch (doc.state) {
            case "cancelled" -> new Store.ChallengeRuntimeState(Store.RuntimeStateKind.CANCELLED,
                    doc.record, null);
            case "consumed" -> new Store.ChallengeRuntimeState(Store.RuntimeStateKind.CONSUMED,
                    doc.record,
                    new Store.ConsumedRecord(doc.record, false, true, doc.result, doc.identity));
            case "pending" -> new Store.ChallengeRuntimeState(Store.RuntimeStateKind.PENDING,
                    doc.record, null);
            default -> Store.ChallengeRuntimeState.missing();
        };
    }

    /** Flips the terminal cancellation marker through the fused script. */
    @Override
    public Store.CancellationResult cancel(String nonce) {
        Object reply;
        try {
            reply = eval(LuaScripts.CANCEL_SCRIPT, List.of(prefix + nonce), List.of());
        } catch (Store.StorageUnavailableException e) {
            throw e;
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        if (!(reply instanceof List<?> items) || items.isEmpty()) {
            return null;
        }
        String status = items.get(0) instanceof String s ? s : "";
        if (status.isEmpty()) {
            return null;
        }
        return new Store.CancellationResult(status);
    }

    /** Removes one key. */
    @Override
    public boolean delete(String nonce) {
        boolean removed;
        try {
            removed = client.del(prefix + nonce);
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        return removed;
    }

    /** Commits the deterministic outcome without a mac. */
    @Override
    public boolean commitResult(String nonce, boolean valid, String binding) {
        return commitAuthenticatedResult(nonce, new Store.ConsumedResult(valid, binding, ""));
    }

    /**
     * Commits the outcome with its server-state mac through the fused
     * script. The write preserves the key's remaining lifetime and
     * refuses a key without one.
     */
    @Override
    public boolean commitAuthenticatedResult(String nonce, Store.ConsumedResult result) {
        List<String> args = new ArrayList<>(List.of(
                boolArg(result.valid),
                result.binding,
                boolArg(!result.binding.isEmpty()),
                "",
                result.mac));
        Object reply;
        try {
            reply = eval(LuaScripts.COMMIT_SCRIPT, List.of(prefix + nonce), args);
        } catch (Store.StorageUnavailableException e) {
            throw e;
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        return replyInt(reply) == 1;
    }

    private static long replyInt(Object reply) {
        return reply instanceof Long value ? value : 0;
    }

    private static String boolArg(boolean value) {
        return value ? "1" : "0";
    }
}
