package kiwicaptcha

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type outcomesVectors struct {
	Version   int               `json:"version"`
	Namespace string            `json:"namespace"`
	Handles   map[string]string `json:"handles"`
	Vectors   []struct {
		Outcome string `json:"outcome"`
		Handle  struct {
			Dimension string `json:"dimension"`
			ID        string `json:"id"`
		} `json:"handle"`
		Accepted        bool    `json:"accepted"`
		ChannelValue    int     `json:"channel_value"`
		LedgerAction    *string `json:"ledger_action"`
		MarkKind        *string `json:"mark_kind"`
		MarkKey         *string `json:"mark_key"`
		ServerConfirmed bool    `json:"server_confirmed"`
		MaySubtractRisk bool    `json:"may_subtract_risk"`
		WritesAbuseMark bool    `json:"writes_abuse_mark"`
	} `json:"vectors"`
}

func loadOutcomeVectors(t *testing.T) outcomesVectors {
	t.Helper()
	data, err := os.ReadFile(repoProtocolPath(t, filepath.Join("risk-v1", "outcomes-vectors.json")))
	if err != nil {
		t.Fatalf("outcome vectors: %v", err)
	}
	var document outcomesVectors
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("outcome vectors: %v", err)
	}
	return document
}

func TestOutcomesMappingConformance(t *testing.T) {
	document := loadOutcomeVectors(t)
	if document.Version != OutcomesVersion {
		t.Fatalf("the mapping version must match the vectors")
	}
	table := OutcomeMap{}
	for index, vector := range document.Vectors {
		outcome := Outcome(vector.Outcome)
		row, err := table.ForOutcome(outcome)
		if err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		dimension := HandleDimension(vector.Handle.Dimension)
		// Acceptance covers the dimension and the identifier rule: the
		// identity dimensions refuse raw identifiers at construction.
		accepts := row.Accepts(dimension)
		if accepts {
			if _, err := NewOutcomeHandle(dimension, vector.Handle.ID); err != nil {
				accepts = false
			}
		}
		if accepts != vector.Accepted {
			t.Fatalf("vector %d %s on %s (%q): accepted %v want %v", index, vector.Outcome, dimension, vector.Handle.ID, accepts, vector.Accepted)
		}
		// Rejection rows carry no booking fields.
		if !vector.Accepted {
			continue
		}
		if row.Channel != vector.ChannelValue {
			t.Fatalf("vector %d %s: channel %d want %d", index, vector.Outcome, row.Channel, vector.ChannelValue)
		}
		if row.ServerConfirmed != vector.ServerConfirmed {
			t.Fatalf("vector %d %s: server_confirmed drift", index, vector.Outcome)
		}
		if row.MaySubtractRisk != vector.MaySubtractRisk {
			t.Fatalf("vector %d %s: may_subtract_risk drift", index, vector.Outcome)
		}
		if row.WritesAbuseMark != vector.WritesAbuseMark {
			t.Fatalf("vector %d %s: writes_abuse_mark drift", index, vector.Outcome)
		}
		if got := row.MarkKind(); vector.MarkKind == nil != (got == "") || (vector.MarkKind != nil && got != *vector.MarkKind) {
			t.Fatalf("vector %d %s: mark_kind %q want %v", index, vector.Outcome, got, vector.MarkKind)
		}
		hasLedger := vector.LedgerAction != nil
		if row.HasLedgerAction() != hasLedger {
			t.Fatalf("vector %d %s: ledger action drift", index, vector.Outcome)
		}
		// The mark key layout matches the shared writers.
		if vector.MarkKey != nil {
			expected := "mark:{kiwi:" + document.Namespace + "}:" + dimension.MarkDimension() + ":" + vector.Handle.ID
			if expected != *vector.MarkKey {
				t.Fatalf("vector %d %s: mark key %s want %s", index, vector.Outcome, expected, *vector.MarkKey)
			}
		}
	}
	// The trust polarity: the classes are disjoint.
	for _, row := range table.All() {
		if row.MaySubtractRisk && row.WritesAbuseMark {
			t.Fatalf("%s may not subtract risk and write a mark", row.Outcome)
		}
		if row.MaySubtractRisk && !row.ServerConfirmed {
			t.Fatalf("%s subtracts risk without server confirmation", row.Outcome)
		}
	}
}

func TestOutcomeHandlesValidation(t *testing.T) {
	document := loadOutcomeVectors(t)
	for _, rawPseudonym := range []string{document.Handles["principal"], document.Handles["target"], document.Handles["session"]} {
		if _, err := NewOutcomeHandle(DimensionPrincipal, rawPseudonym); err != nil {
			t.Fatalf("the fixture pseudonym must validate: %v", err)
		}
	}
	if _, err := NewOutcomeHandle(DimensionPrincipal, "raw-user-42"); err == nil {
		t.Fatalf("a raw identifier must be rejected on an identity handle")
	}
	if _, err := NewOutcomeHandle(DimensionAgent, document.Handles["agent"]); err != nil {
		t.Fatalf("the agent id must validate: %v", err)
	}
	if _, err := NewOutcomeHandle(DimensionDecisionID, "bad:id"); err == nil {
		t.Fatalf("the key separator must be refused")
	}
}

func TestOutcomesClientReports(t *testing.T) {
	sink := NewMemoryOutcomeSink("d")
	client := NewOutcomesClient(sink)
	abusive := OutcomeHandle{Dimension: DimensionPrincipal, ID: loadOutcomeVectors(t).Handles["principal"]}
	receipt, err := client.Report(OutcomeFraudConfirmed, abusive, "evt-1", 1234)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	row, err := (OutcomeMap{}).ForOutcome(OutcomeFraudConfirmed)
	if err != nil {
		t.Fatalf("mapping: %v", err)
	}
	if !receipt.ChannelBooked || row.Channel != ChannelConfirmedAbuse || receipt.MarkCount != 1 {
		t.Fatalf("the abuse report must book the channel and the mark: %+v", receipt)
	}
	if marks := sink.MarksOf("principal", abusive.ID); len(marks) != 1 || marks[0] != "fraudConfirmed" {
		t.Fatalf("the mark drift: %v", marks)
	}
	// The ledger leg: a decision id without an entry answers 0.
	ledger := OutcomeHandle{Dimension: DimensionDecisionID, ID: "d4e5f60718293a4b5c6d7e8f90a1b2c3"}
	receipt, err = client.Report(OutcomeConfirmedLegitimate, ledger, "evt-2", 0)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if receipt.Status != 0 || receipt.ChannelBooked {
		t.Fatalf("a missing ledger entry books nothing: %+v", receipt)
	}
	sink.RegisterOutcome(ledger.ID, 42)
	receipt, err = client.Report(OutcomeConfirmedLegitimate, ledger, "evt-3", 0)
	if err != nil || receipt.Status != 1 || !receipt.ChannelBooked {
		t.Fatalf("the legitimate confirmation must book: %+v %v", receipt, err)
	}
	// An unaccepted dimension is refused.
	if _, err := client.Report(OutcomeStepUpCompleted, OutcomeHandle{Dimension: DimensionNonce, ID: "0f1e2d3c4b5a69788796a5b4c3d2e1f0"}, "", 0); err == nil {
		t.Fatalf("stepUpCompleted cannot ride a nonce handle")
	}
	// Forget clears the marks.
	if client.Forget(abusive) != 1 {
		t.Fatalf("forget must clear the mark")
	}
	if client.Forget(ledger) != 0 {
		t.Fatalf("forget on a ledger handle clears nothing")
	}
}
