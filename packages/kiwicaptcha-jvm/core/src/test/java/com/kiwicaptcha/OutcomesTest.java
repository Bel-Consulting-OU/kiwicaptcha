package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The versioned outcomes mapping and the reporting client. */
class OutcomesTest {

    @Test
    void tableVersionPinsTheFixture() {
        var document = outcomeVectors();
        assertEquals(Outcomes.OUTCOMES_VERSION, ((JsonNumber) document.get("version")).intValue());
    }

    @Test
    void trustPolarityIsDisjoint() {
        Outcomes.OutcomeMap map = new Outcomes.OutcomeMap();
        for (Outcomes.OutcomeMapping row : map.all()) {
            if (row.maySubtractRisk) {
                assertTrue(row.serverConfirmed, row.outcome.wire());
                assertFalse(row.writesAbuseMark, row.outcome.wire());
                assertEquals(3, countSubtractRisk(map.all()));
            }
            if (row.writesAbuseMark) {
                assertFalse(row.maySubtractRisk, row.outcome.wire());
                assertTrue(row.serverConfirmed, row.outcome.wire());
            }
        }
    }

    private static int countSubtractRisk(List<Outcomes.OutcomeMapping> rows) {
        int count = 0;
        for (Outcomes.OutcomeMapping row : rows) {
            if (row.maySubtractRisk) {
                count++;
            }
        }
        return count;
    }

    @Test
    void fixtureVectorsHold() {
        var document = outcomeVectors();
        Outcomes.OutcomeMap map = new Outcomes.OutcomeMap();
        @SuppressWarnings("unchecked")
        List<Object> vectors = (List<Object>) document.get("vectors");
        for (Object item : vectors) {
            @SuppressWarnings("unchecked")
            Map<String, Object> vector = (Map<String, Object>) item;
            Outcomes.Outcome outcome = outcomeByWire(String.valueOf(vector.get("outcome")));
            @SuppressWarnings("unchecked")
            Map<String, Object> handle = (Map<String, Object>) vector.get("handle");
            String dimensionWire = String.valueOf(handle.get("dimension"));
            String identifier = String.valueOf(handle.get("id"));
            String reject = stringOrNull(vector.get("reject"));
            if ("identifier".equals(reject)) {
                // The raw identifier dies at handle construction on a
                // pseudonym-only dimension, before any mapping lookup.
                final Outcomes.Outcome failedOutcome = outcome;
                final String failedDimension = dimensionWire;
                final String failedId = identifier;
                assertThrows(IllegalArgumentException.class, () -> Outcomes.OutcomeHandle.of(
                        dimensionByWire(failedDimension), failedId),
                        failedOutcome.wire() + " with a raw identifier");
                continue;
            }
            Outcomes.HandleDimension dimension = dimensionByWire(dimensionWire);
            Outcomes.OutcomeMapping mapping = map.forOutcome(outcome);
            boolean accepted = mapping.accepts(dimension);
            assertEquals(Boolean.TRUE.equals(vector.get("accepted")), accepted,
                    outcome.wire() + " on " + dimension.wire);
            if (accepted) {
                assertEquals(((JsonNumber) vector.get("channel_value")).intValue(), mapping.channel,
                        outcome.wire());
                assertEquals(String.valueOf(vector.get("ledger_action")),
                        ledgerAction(mapping), outcome.wire() + " ledger");
                assertEquals(String.valueOf(vector.get("mark_kind")), mapping.markKind().isEmpty()
                        ? "null" : mapping.markKind(), outcome.wire() + " mark");
            }
        }
    }

    private static String stringOrNull(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static String ledgerAction(Outcomes.OutcomeMapping mapping) {
        if (mapping.ledgerLegitimate == null) {
            return "null";
        }
        return mapping.ledgerLegitimate ? "L" : "A";
    }

    private static Outcomes.Outcome outcomeByWire(String wire) {
        for (Outcomes.Outcome outcome : Outcomes.Outcome.values()) {
            if (outcome.wire.equals(wire)) {
                return outcome;
            }
        }
        throw new AssertionError("unknown outcome " + wire);
    }

    private static Outcomes.HandleDimension dimensionByWire(String wire) {
        for (Outcomes.HandleDimension dimension : Outcomes.HandleDimension.values()) {
            if (dimension.wire.equals(wire)) {
                return dimension;
            }
        }
        throw new AssertionError("unknown dimension " + wire);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> outcomeVectors() {
        java.nio.file.Path path = Support.protocolPathOrSkip("risk-v1/outcomes-vectors.json");
        try {
            return (Map<String, Object>) StrictJson.decode(java.nio.file.Files.readAllBytes(path));
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void handleValidation() {
        Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.PRINCIPAL, "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18");
        Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.AGENT, "backfill-bot");
        Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.DECISION_ID, "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18");
        assertThrows(IllegalArgumentException.class,
                () -> Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.PRINCIPAL, "user@example.com"));
        assertThrows(IllegalArgumentException.class,
                () -> Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.AGENT, ""));
        assertThrows(IllegalArgumentException.class,
                () -> Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.AGENT, "bad:colon"));
        assertThrows(IllegalArgumentException.class,
                () -> Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.AGENT, "bad}brace"));
    }

    @Test
    void reportBooksLedgerMarksAndChannels() {
        Outcomes.MemoryOutcomeSink sink = new Outcomes.MemoryOutcomeSink("deployments/test");
        Outcomes.OutcomesClient client = new Outcomes.OutcomesClient(sink, () -> 1_700_000_000_000L);
        String decisionId = "d4e5f60718293a4b5c6d7e8f90a1b2c3";
        // No ledger entry yet: a legitimate confirm reports status 0.
        Outcomes.OutcomeReceipt first = client.report(Outcomes.Outcome.CONFIRMED_LEGITIMATE,
                Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.DECISION_ID, decisionId), "evt-1", 0);
        assertEquals(0, first.status);
        assertFalse(first.channelBooked);
        // Register the decision, then confirm it legitimate.
        sink.registerOutcome(decisionId, 1_700_000_000_000L);
        Outcomes.OutcomeReceipt second = client.report(Outcomes.Outcome.CONFIRMED_LEGITIMATE,
                Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.DECISION_ID, decisionId), "evt-2", 0);
        assertEquals(1, second.status);
        assertTrue(second.channelBooked);
        assertEquals(12, Outcomes.CHANNEL_CONFIRMED_LEGITIMATE);
        // An abuse outcome writes the identity mark.
        Outcomes.OutcomeReceipt abuse = client.report(Outcomes.Outcome.FRAUD_CONFIRMED,
                Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.PRINCIPAL,
                        "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18"), "evt-3", 0);
        assertEquals(1, abuse.marksWritten);
        assertEquals(1, abuse.markCount);
        assertEquals(List.of("fraudConfirmed"),
                sink.marksOf("principal", "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18"));
        assertEquals(1, client.forget(Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.PRINCIPAL,
                "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18")));
        assertEquals(List.of(), sink.marksOf("principal", "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18"));
    }

    @Test
    void dimensionRejections() {
        Outcomes.OutcomesClient client = new Outcomes.OutcomesClient(new Outcomes.MemoryOutcomeSink("d"));
        // The identity-only outcomes refuse every ledger handle.
        assertThrows(IllegalArgumentException.class, () -> client.report(Outcomes.Outcome.STEP_UP_COMPLETED,
                Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.NONCE,
                        "0f1e2d3c4b5a69788796a5b4c3d2e1f0"), "evt", 0));
        assertThrows(IllegalArgumentException.class, () -> client.report(Outcomes.Outcome.SPAM_REPORTED,
                Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.DECISION_ID,
                        "d4e5f60718293a4b5c6d7e8f90a1b2c3"), "evt", 0));
    }
}
