package com.kiwicaptcha;

/**
 * The store adapter seam: record envelopes, runtime states and the
 * capability interfaces the verifier composes.
 *
 * Every backend implements Store. The narrower capabilities are
 * optional: the verifier probes them with an instanceof check and
 * follows the same fallbacks as the php verifier. The fallbacks cover
 * the plain consume without an identity, the one-shot delete on a
 * cheap failure, and the legacy commit without a server-state mac.
 * The shipped memory and Redis backends implement every capability.
 */
public final class Store {
    private Store() {}

    /** The typed fail-closed storage failure the verifier resolves as an unavailable store. */
    public static final class StorageUnavailableException extends RuntimeException {
        public StorageUnavailableException(String message, Throwable cause) {
            super("kiwicaptcha: storage backend unavailable", cause);
        }

        public StorageUnavailableException(String message) {
            super("kiwicaptcha: storage backend unavailable" + (message == null || message.isEmpty() ? "" : ": " + message));
        }

        public StorageUnavailableException(Throwable cause) {
            super("kiwicaptcha: storage backend unavailable", cause);
        }
    }

    /** Reports an invalid logical-operation identity before any transition runs. */
    public static final class OperationIdentityException extends RuntimeException {
        public OperationIdentityException() {
            super("kiwicaptcha: operation identity must be 1..128 bytes of [A-Za-z0-9_-]");
        }
    }

    /** Validates one logical-operation identity, returning the empty string for none. */
    public static String validateOperationIdentity(String operationIdentity) {
        if (operationIdentity == null || operationIdentity.isEmpty()) {
            return "";
        }
        if (operationIdentity.length() > 128) {
            throw new OperationIdentityException();
        }
        for (int i = 0; i < operationIdentity.length(); i++) {
            char c = operationIdentity.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '_' || c == '-';
            if (!ok) {
                throw new OperationIdentityException();
            }
        }
        return operationIdentity;
    }

    /** The runtime states of a stored record. */
    public enum RuntimeStateKind {
        MISSING, PENDING, CONSUMED, CANCELLED
    }

    /**
     * One runtime-state snapshot: the kind plus the decoded payloads.
     * record is set for every non-missing kind. consumed carries the
     * retained consumed envelope exactly when the kind is CONSUMED.
     */
    public static final class ChallengeRuntimeState {
        public final RuntimeStateKind kind;
        public final ChallengeRecord record;
        public final ConsumedRecord consumed;

        public ChallengeRuntimeState(RuntimeStateKind kind, ChallengeRecord record, ConsumedRecord consumed) {
            this.kind = kind;
            this.record = record;
            this.consumed = consumed;
        }

        public static ChallengeRuntimeState missing() {
            return new ChallengeRuntimeState(RuntimeStateKind.MISSING, null, null);
        }
    }

    /**
     * The committed deterministic outcome of one consumed challenge.
     * mac is the server-state mac over the record's challenge, the
     * verdict, the binding and the operation identity, or empty on a
     * legacy commit from a backend that cannot carry one.
     */
    public static final class ConsumedResult {
        public final boolean valid;
        public final String binding;
        public final String mac;

        public ConsumedResult(boolean valid, String binding, String mac) {
            this.valid = valid;
            this.binding = binding;
            this.mac = mac == null ? "" : mac;
        }
    }

    /**
     * The consume transition's return: the record plus its new state.
     * consumedNow marks the call that won the pending to consumed
     * flip; consumedBefore marks a retry against an already consumed
     * record.
     */
    public static final class ConsumedRecord {
        public final ChallengeRecord record;
        public final boolean consumedNow;
        public final boolean consumedBefore;
        public final ConsumedResult consumedResult;
        public final String operationIdentity;

        public ConsumedRecord(ChallengeRecord record, boolean consumedNow, boolean consumedBefore,
                              ConsumedResult consumedResult, String operationIdentity) {
            this.record = record;
            this.consumedNow = consumedNow;
            this.consumedBefore = consumedBefore;
            this.consumedResult = consumedResult;
            this.operationIdentity = operationIdentity == null ? "" : operationIdentity;
        }
    }

    /** Status values of the fused cleanup transition. */
    public static final String DELETE_STATUS_MISSING = "missing";
    public static final String DELETE_STATUS_DELETED_PENDING = "deleted-pending";
    public static final String DELETE_STATUS_CONSUMED = "consumed";
    public static final String DELETE_STATUS_CANCELLED = "cancelled";
    public static final String DELETE_STATUS_CORRUPT = "corrupt";

    /** The fused cheap-failure cleanup outcome. */
    public static final class DeleteIfPendingResult {
        public final String status;
        public final ConsumedRecord consumed;

        public DeleteIfPendingResult(String status, ConsumedRecord consumed) {
            this.status = status;
            this.consumed = consumed;
        }

        /** Whether the fused transition observed the consumed retention. */
        public boolean wasConsumed() {
            return DELETE_STATUS_CONSUMED.equals(status);
        }
    }

    /** Status values of the cancel transition. */
    public static final String CANCEL_STATUS_CANCELLED_NOW = "cancelled-now";
    public static final String CANCEL_STATUS_CANCELLED = "cancelled";
    public static final String CANCEL_STATUS_CONSUMED = "consumed";

    /** The cancel transition's outcome: a fresh flip, an idempotent repeat, or a refusal. */
    public static final class CancellationResult {
        public final String status;

        public CancellationResult(String status) {
            this.status = status;
        }
    }

    /** The mandatory store adapter surface. */
    public interface StoreAdapter {
        /** Returns null without error for an absent or expired record. */
        ChallengeRecord find(String nonce);

        /** Removes one record and reports whether it existed. */
        boolean delete(String nonce);

        /** Runs the one-shot pending to consumed transition. */
        ConsumedRecord consume(String nonce);

        /** Commits the deterministic outcome of a consumed record; only the first commit wins. */
        boolean commitResult(String nonce, boolean valid, String binding);
    }

    /** The retained consumed-envelope read. */
    public interface ConsumedStateReader {
        ConsumedRecord consumedState(String nonce);
    }

    /** The single get runtime-state snapshot read. */
    public interface RuntimeStateReader {
        ChallengeRuntimeState runtimeState(String nonce);
    }

    /** The fused read-and-delete-on-pending transition. */
    public interface AtomicDeleteIfPending {
        DeleteIfPendingResult deleteIfPending(String nonce);
    }

    /** The identity-bearing consume transition. */
    public interface OperationIdentityAware {
        ConsumedRecord consumeWithOperationIdentity(String nonce, String operationIdentity);
    }

    /** The server-state-mac commit for a consumed result. */
    public interface AuthenticatedResultCommit {
        boolean commitAuthenticatedResult(String nonce, ConsumedResult result);
    }

    /** The terminal cancellation marker transition. */
    public interface Cancellable {
        CancellationResult cancel(String nonce);
    }

    /** The write side every shipped backend carries. */
    public interface Storer {
        void storeRecord(ChallengeRecord record);
    }
}
