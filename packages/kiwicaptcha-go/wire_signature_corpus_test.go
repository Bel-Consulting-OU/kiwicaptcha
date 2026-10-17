package kiwicaptcha

import (
	"encoding/json"
	"os"
	"testing"
)

// The shared challenge-signature corpus against the Go verifier. The
// fixture is expanded by the PHP generator and read byte-for-byte by
// every hosted SDK suite.

type wireSignatureRow struct {
	ID           string          `json:"id"`
	Record       json.RawMessage `json:"record"`
	Challenge    string          `json:"challenge"`
	VerifySecret string          `json:"verify_secret"`
	VerifyTenant *string         `json:"verify_tenant"`
	Expect       string          `json:"expect"`
}

func TestWireSignatureCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/wire-signature-corpus.json")
	if err != nil {
		t.Fatalf("the signature corpus fixture must exist: %v", err)
	}
	var document struct {
		Vectors []wireSignatureRow `json:"vectors"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("the signature corpus must be valid JSON: %v", err)
	}
	if len(document.Vectors) < 40 {
		t.Fatalf("the signature corpus must stay broad, got %d rows", len(document.Vectors))
	}

	for _, row := range document.Vectors {
		row := row
		t.Run(row.ID, func(t *testing.T) {
			record, err := ParseChallengeRecord(row.Record)
			if err != nil {
				t.Fatalf("the corpus record must parse: %v", err)
			}
			if record.Challenge != row.Challenge {
				t.Fatalf("record challenge = %q, want %q", record.Challenge, row.Challenge)
			}
			tenant := ""
			if row.VerifyTenant != nil {
				tenant = *row.VerifyTenant
			}
			verified := VerifyRecordSignature(record, row.VerifySecret, tenant)
			if verified != (row.Expect == "accept") {
				t.Fatalf("verified = %v, want %s", verified, row.Expect)
			}
		})
	}
}
