package com.kiwicaptcha;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The versioned outcomes mapping and its reporting client, a port of
 * packages/kiwicaptcha-risk-php/src/Outcomes. One mapping table
 * resolves each of the eight typed outcomes onto the risk-v1 event
 * channels, the always-on outcome ledger and the long-memory marks.
 * The trust polarity is a table property: exactly the three
 * server-confirmed trust outcomes may subtract risk, and exactly the
 * four abuse outcomes write marks; the two classes are disjoint. The
 * vectors at protocol/risk-v1/outcomes-vectors.json pin the table
 * contents across the languages.
 */
public final class Outcomes {
    private Outcomes() {}

    /** The mapping table version. */
    public static final int OUTCOMES_VERSION = 1;

    /** The typed outcome vocabulary, in table order. */
    public enum Outcome {
        CONFIRMED_LEGITIMATE("confirmedLegitimate"),
        STEP_UP_COMPLETED("stepUpCompleted"),
        AUTHENTICATION_SUCCESS("authenticationSuccess"),
        AUTHENTICATION_FAILURE("authenticationFailure"),
        SPAM_REPORTED("spamReported"),
        CHARGEBACK("chargeback"),
        ACCOUNT_BANNED("accountBanned"),
        FRAUD_CONFIRMED("fraudConfirmed");

        /** The typed outcome wire name. */
        public final String wire;

        Outcome(String wire) {
            this.wire = wire;
        }

        /** The typed outcome wire name. */
        public String wire() {
            return wire;
        }
    }

    /** The risk-v1 event channel values. */
    public static final int CHANNEL_CONFIRMED_LEGITIMATE = 12;
    public static final int CHANNEL_PROTECTED_ACTION_SUCCESS = 8;
    public static final int CHANNEL_AUTHENTICATION_SUCCESS = 10;
    public static final int CHANNEL_AUTHENTICATION_FAILURE = 11;
    public static final int CHANNEL_PROTECTED_ACTION_FAILURE = 9;
    public static final int CHANNEL_CONFIRMED_ABUSE = 13;

    /** The subject-address dimensions. */
    public enum HandleDimension {
        NONCE("nonce"),
        DECISION_ID("decisionId"),
        PRINCIPAL("principal"),
        TARGET("target"),
        SESSION("session"),
        AGENT("agent");

        /** The dimension wire name. */
        public final String wire;

        HandleDimension(String wire) {
            this.wire = wire;
        }

        /** Reports the two ledger dimensions, whose entries confirm decisions. */
        public boolean isLedger() {
            return this == NONCE || this == DECISION_ID;
        }

        /** Reports the four identity dimensions, which carry pseudonyms only. */
        public boolean isIdentity() {
            return !isLedger();
        }

        /** The mark bucket of an identity dimension, null for the ledger ones. */
        public String markDimension() {
            return isLedger() ? null : wire;
        }
    }

    /** The vocabulary order of the dimensions. */
    public static final List<HandleDimension> HANDLE_DIMENSION_ORDER = List.of(
            HandleDimension.NONCE, HandleDimension.DECISION_ID, HandleDimension.PRINCIPAL,
            HandleDimension.TARGET, HandleDimension.SESSION, HandleDimension.AGENT);

    /** The four identity dimensions. */
    public static final List<HandleDimension> IDENTITY_DIMENSIONS = List.of(
            HandleDimension.PRINCIPAL, HandleDimension.TARGET,
            HandleDimension.SESSION, HandleDimension.AGENT);

    /** The two ledger dimensions. */
    public static final List<HandleDimension> LEDGER_DIMENSIONS = List.of(
            HandleDimension.NONCE, HandleDimension.DECISION_ID);

    private static boolean isPseudonym(String value) {
        if (value == null || value.length() != 32) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
                return false;
            }
        }
        return true;
    }

    /**
     * The shared key-safety rule for caller-supplied identifiers. A
     * 32-char lowercase hex id always passes; otherwise the value must
     * be non-empty and free of control characters, ':' and '}', the
     * key separator and the hash-tag closing byte.
     */
    public static void assertKeySafeIdentifier(String value) {
        if (isPseudonym(value)) {
            return;
        }
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(
                    "kiwicaptcha: identifiers must be a 32-char lowercase hex id or a non-empty value free of control characters, ':' and '}'");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= 0x1f || c == 0x7f || c == ':' || c == '}') {
                throw new IllegalArgumentException(
                        "kiwicaptcha: identifiers must be free of control characters, ':' and '}'");
            }
        }
        // The utf-8 continuation bytes of the reference control set.
        for (int i = 0; i < value.length() - 1; i++) {
            if (value.charAt(i) == 0xc2) {
                char next = value.charAt(i + 1);
                if (next >= 0x80 && next <= 0x9f) {
                    throw new IllegalArgumentException(
                            "kiwicaptcha: identifiers must be free of control characters, ':' and '}'");
                }
            }
        }
    }

    /**
     * One subject address of a typed outcome report. The principal,
     * target and session dimensions carry pseudonyms, never raw
     * identifiers, so a raw-looking value is rejected at construction,
     * fail-closed. The agent and the ledger dimensions accept the
     * shared key-safety rule instead.
     */
    public static final class OutcomeHandle {
        public final HandleDimension dimension;
        public final String id;

        private OutcomeHandle(HandleDimension dimension, String id) {
            this.dimension = dimension;
            this.id = id;
        }

        /** Validates one handle. */
        public static OutcomeHandle of(HandleDimension dimension, String identifier) {
            boolean pseudonymOnly = dimension == HandleDimension.PRINCIPAL
                    || dimension == HandleDimension.TARGET || dimension == HandleDimension.SESSION;
            if (pseudonymOnly && !isPseudonym(identifier)) {
                throw new IllegalArgumentException(
                        "kiwicaptcha: identity handles must carry the 32-char lowercase hex pseudonym, never a raw identifier");
            }
            if (!pseudonymOnly) {
                assertKeySafeIdentifier(identifier);
            }
            return new OutcomeHandle(dimension, identifier);
        }
    }

    /** One immutable table row: channel, ledger and mark behavior. */
    public static final class OutcomeMapping {
        public final Outcome outcome;
        public final int channel;
        public final Boolean ledgerLegitimate;
        public final boolean writesAbuseMark;
        public final boolean serverConfirmed;
        public final boolean maySubtractRisk;
        public final List<HandleDimension> acceptedHandles;

        OutcomeMapping(Outcome outcome, int channel, Boolean ledgerLegitimate, boolean writesAbuseMark,
                       boolean serverConfirmed, boolean maySubtractRisk, List<HandleDimension> acceptedHandles) {
            this.outcome = outcome;
            this.channel = channel;
            this.ledgerLegitimate = ledgerLegitimate;
            this.writesAbuseMark = writesAbuseMark;
            this.serverConfirmed = serverConfirmed;
            this.maySubtractRisk = maySubtractRisk;
            this.acceptedHandles = acceptedHandles;
        }

        /** Whether the dimension is reportable for the row. */
        public boolean accepts(HandleDimension dimension) {
            return acceptedHandles.contains(dimension);
        }

        /** The abuse mark the row writes, empty when none. */
        public String markKind() {
            return writesAbuseMark ? outcome.wire : "";
        }

        /** Whether the row books a ledger entry. */
        public boolean hasLedgerAction() {
            return ledgerLegitimate != null;
        }
    }

    private static final Map<Outcome, OutcomeMapping> OUTCOME_TABLE = Map.of(
            Outcome.CONFIRMED_LEGITIMATE, new OutcomeMapping(Outcome.CONFIRMED_LEGITIMATE,
                    CHANNEL_CONFIRMED_LEGITIMATE, true, false, true, true, HANDLE_DIMENSION_ORDER),
            Outcome.STEP_UP_COMPLETED, new OutcomeMapping(Outcome.STEP_UP_COMPLETED,
                    CHANNEL_PROTECTED_ACTION_SUCCESS, null, false, true, true, IDENTITY_DIMENSIONS),
            Outcome.AUTHENTICATION_SUCCESS, new OutcomeMapping(Outcome.AUTHENTICATION_SUCCESS,
                    CHANNEL_AUTHENTICATION_SUCCESS, null, false, true, true, IDENTITY_DIMENSIONS),
            Outcome.AUTHENTICATION_FAILURE, new OutcomeMapping(Outcome.AUTHENTICATION_FAILURE,
                    CHANNEL_AUTHENTICATION_FAILURE, null, false, false, false, IDENTITY_DIMENSIONS),
            Outcome.SPAM_REPORTED, new OutcomeMapping(Outcome.SPAM_REPORTED,
                    CHANNEL_PROTECTED_ACTION_FAILURE, null, true, true, false, IDENTITY_DIMENSIONS),
            Outcome.CHARGEBACK, new OutcomeMapping(Outcome.CHARGEBACK,
                    CHANNEL_CONFIRMED_ABUSE, false, true, true, false, HANDLE_DIMENSION_ORDER),
            Outcome.ACCOUNT_BANNED, new OutcomeMapping(Outcome.ACCOUNT_BANNED,
                    CHANNEL_CONFIRMED_ABUSE, false, true, true, false, HANDLE_DIMENSION_ORDER),
            Outcome.FRAUD_CONFIRMED, new OutcomeMapping(Outcome.FRAUD_CONFIRMED,
                    CHANNEL_CONFIRMED_ABUSE, false, true, true, false, HANDLE_DIMENSION_ORDER));

    /** The one versioned mapping table, total over the vocabulary. */
    public static final class OutcomeMap {
        /** Resolves the row of one outcome. */
        public OutcomeMapping forOutcome(Outcome outcome) {
            OutcomeMapping row = OUTCOME_TABLE.get(outcome);
            if (row == null) {
                throw new IllegalArgumentException("kiwicaptcha: no outcome mapping row for " + outcome.wire);
            }
            return row;
        }

        /** Returns the rows in vocabulary order. */
        public List<OutcomeMapping> all() {
            List<OutcomeMapping> rows = new ArrayList<>();
            for (Outcome outcome : Outcome.values()) {
                rows.add(OUTCOME_TABLE.get(outcome));
            }
            return rows;
        }
    }

    /** The outcome of one report: what was booked where. */
    public static final class OutcomeReceipt {
        public final Outcome outcome;
        public final HandleDimension handleDimension;
        public final int status;
        public final boolean channelBooked;
        public final int marksWritten;
        public final int markCount;
        public final String eventId;

        OutcomeReceipt(Outcome outcome, HandleDimension handleDimension, int status, boolean channelBooked,
                       int marksWritten, int markCount, String eventId) {
            this.outcome = outcome;
            this.handleDimension = handleDimension;
            this.status = status;
            this.channelBooked = channelBooked;
            this.marksWritten = marksWritten;
            this.markCount = markCount;
            this.eventId = eventId;
        }
    }

    /**
     * The injectable dispatch surface of the reporting client. The
     * shipped memory sink keeps marks and ledger actions in-process;
     * binding the sink to a shared deployment is a deployment
     * composition, not a protocol concern.
     */
    public interface OutcomeSink {
        int confirmOutcome(String decisionId, boolean legitimate);

        void registerOutcome(String decisionId, long atMs);

        int writeMark(String dimension, String identifier, String kind, long atMs);

        int forgetMarks(String dimension, String identifier);

        String recordOutcomeFeedback(int channel, String idempotencyKey);
    }

    private static final class LedgerEntry {
        final boolean legitimate;
        final long atMs;

        LedgerEntry(boolean legitimate, long atMs) {
            this.legitimate = legitimate;
            this.atMs = atMs;
        }
    }

    private static final class MarkEntry {
        final String kind;
        final long atMs;

        MarkEntry(String kind, long atMs) {
            this.kind = kind;
            this.atMs = atMs;
        }
    }

    /**
     * The in-process sink. Status follows the ledger confirm contract:
     * 1 confirmed as legitimate, minus 1 confirmed as abusive, 0 when
     * no ledger entry existed. Marks accumulate per key.
     */
    public static final class MemoryOutcomeSink implements OutcomeSink {
        /** The deployment namespace of the sink keys. */
        public final String namespace;

        private final Map<String, List<LedgerEntry>> ledger = new ConcurrentHashMap<>();
        private final Map<String, List<MarkEntry>> marks = new ConcurrentHashMap<>();

        /** Builds the sink under one namespace. */
        public MemoryOutcomeSink(String namespace) {
            this.namespace = namespace;
        }

        /** Renders the mark bucket key of one subject. */
        public String markKey(String dimension, String identifier) {
            return "mark:{kiwi:" + namespace + "}:" + dimension + ":" + identifier;
        }

        @Override
        public int confirmOutcome(String decisionId, boolean legitimate) {
            synchronized (ledger) {
                List<LedgerEntry> entries = ledger.get(decisionId);
                if (entries == null || entries.isEmpty()) {
                    return 0;
                }
                long last = entries.get(entries.size() - 1).atMs;
                List<LedgerEntry> grown = new ArrayList<>(entries);
                grown.add(new LedgerEntry(legitimate, last));
                ledger.put(decisionId, grown);
                return legitimate ? 1 : -1;
            }
        }

        @Override
        public void registerOutcome(String decisionId, long atMs) {
            synchronized (ledger) {
                List<LedgerEntry> grown = new ArrayList<>(ledger.getOrDefault(decisionId, List.of()));
                grown.add(new LedgerEntry(false, atMs));
                ledger.put(decisionId, grown);
            }
        }

        @Override
        public int writeMark(String dimension, String identifier, String kind, long atMs) {
            String key = markKey(dimension, identifier);
            synchronized (marks) {
                List<MarkEntry> grown = new ArrayList<>(marks.getOrDefault(key, List.of()));
                grown.add(new MarkEntry(kind, atMs));
                marks.put(key, grown);
            }
            return 1;
        }

        @Override
        public int forgetMarks(String dimension, String identifier) {
            String key = markKey(dimension, identifier);
            synchronized (marks) {
                List<MarkEntry> removed = marks.remove(key);
                return removed == null ? 0 : removed.size();
            }
        }

        @Override
        public String recordOutcomeFeedback(int channel, String idempotencyKey) {
            return idempotencyKey;
        }

        /** Lists the live marks of one subject, for tests. */
        public List<String> marksOf(String dimension, String identifier) {
            List<MarkEntry> entries = marks.get(markKey(dimension, identifier));
            List<String> out = new ArrayList<>();
            if (entries != null) {
                for (MarkEntry entry : entries) {
                    out.add(entry.kind);
                }
            }
            return out;
        }
    }

    /** The typed outcome reporter, mirroring the php KiwiOutcomes. */
    public static final class OutcomesClient {
        private final OutcomeSink sink;
        private final TimeSource time;

        /** The injectable millisecond clock. */
        public interface TimeSource {
            long nowMs();
        }

        /** Binds the reporter to a sink. */
        public OutcomesClient(OutcomeSink sink) {
            this(sink, System::currentTimeMillis);
        }

        /** Binds the reporter to a sink and a clock. */
        public OutcomesClient(OutcomeSink sink, TimeSource time) {
            this.sink = sink;
            this.time = time;
        }

        /**
         * Books one typed outcome onto one handle. The mapping decides
         * acceptance, the ledger action and the abuse mark, so a
         * report can never bypass the table's trust polarity. atMs 0
         * means now.
         */
        public OutcomeReceipt report(Outcome outcome, OutcomeHandle handle, String idempotencyKey, long atMs) {
            OutcomeMapping mapping = new OutcomeMap().forOutcome(outcome);
            if (!mapping.accepts(handle.dimension)) {
                throw new IllegalArgumentException("kiwicaptcha: outcome " + outcome.wire
                        + " cannot be reported on a " + handle.dimension.wire + " handle");
            }
            long at = atMs != 0 ? atMs : time.nowMs();
            OutcomeReceipt receipt;
            if (handle.dimension.isLedger()) {
                int status = 0;
                if (mapping.hasLedgerAction()) {
                    status = sink.confirmOutcome(handle.id, mapping.ledgerLegitimate);
                }
                boolean channelBooked = status != 0;
                String eventId = channelBooked ? sink.recordOutcomeFeedback(mapping.channel, idempotencyKey) : "";
                receipt = new OutcomeReceipt(outcome, handle.dimension, status, channelBooked,
                        0, 0, eventId);
            } else {
                int markCount = 0;
                int marksWritten = 0;
                if (mapping.writesAbuseMark) {
                    markCount = sink.writeMark(handle.dimension.markDimension(), handle.id,
                            mapping.markKind(), at);
                    marksWritten = 1;
                }
                String eventId = sink.recordOutcomeFeedback(mapping.channel, idempotencyKey);
                receipt = new OutcomeReceipt(outcome, handle.dimension, 0, true, marksWritten, markCount, eventId);
            }
            return receipt;
        }

        /** Clears the marks of one handle's subject. */
        public int forget(OutcomeHandle handle) {
            String dimension = handle.dimension.markDimension();
            if (dimension == null) {
                return 0;
            }
            return sink.forgetMarks(dimension, handle.id);
        }
    }
}
