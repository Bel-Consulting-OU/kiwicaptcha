package kiwicaptcha

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// decisionCorpus is the shared decision and authority register:
// protocol/decision-v1/corpus.json. The Go side asserts every wire
// code and every token source matrix row against it.
type decisionCorpus struct {
	RetryCodes []string          `json:"retry_codes"`
	Codes      map[string]string `json:"codes"`
	HTTP       struct {
		AllowStatus int            `json:"allow_status"`
		RetryStatus int            `json:"retry_status"`
		DenyStatus  map[string]int `json:"deny_status"`
	} `json:"http"`
	Authority struct {
		ConflictCode string `json:"conflict_code"`
		MissingCode  string `json:"missing_code"`
		Matrix       []struct {
			Case    string   `json:"case"`
			Header  []string `json:"header"`
			Form    []string `json:"form"`
			Query   []string `json:"query"`
			Verdict string   `json:"verdict"`
			Token   string   `json:"token"`
		} `json:"matrix"`
	} `json:"authority"`
}

func loadDecisionCorpus(t *testing.T) decisionCorpus {
	t.Helper()
	raw, err := os.ReadFile("../../protocol/decision-v1/corpus.json")
	if err != nil {
		t.Fatalf("read the decision corpus: %v", err)
	}
	var corpus decisionCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("decode the decision corpus: %v", err)
	}
	return corpus
}

func TestDecisionCorpusDispositions(t *testing.T) {
	corpus := loadDecisionCorpus(t)
	if len(corpus.Codes) != len(verifyErrorDescriptions) {
		t.Fatalf("the corpus carries %d codes, the SDK carries %d", len(corpus.Codes), len(verifyErrorDescriptions))
	}
	for code, want := range corpus.Codes {
		decision := DecisionFromOutcome(InvalidOutcome(VerifyError(code)), "")
		if decision.Disposition != want {
			t.Fatalf("%s: disposition %s, want %s", code, decision.Disposition, want)
		}
		if decision.Error != code {
			t.Fatalf("%s: decision error %s", code, decision.Error)
		}
	}
	retry := make([]string, 0, len(retryCodes))
	for code := range retryCodes {
		retry = append(retry, string(code))
	}
	expected := append([]string(nil), corpus.RetryCodes...)
	sort.Strings(retry)
	sort.Strings(expected)
	if len(retry) != len(expected) {
		t.Fatalf("retry table %v, corpus %v", retry, expected)
	}
	for index := range retry {
		if retry[index] != expected[index] {
			t.Fatalf("retry table %v, corpus %v", retry, expected)
		}
	}
	if corpus.HTTP.AllowStatus != 200 || corpus.HTTP.RetryStatus != 503 {
		t.Fatalf("the status register drifted: %+v", corpus.HTTP)
	}
	if corpus.HTTP.DenyStatus["go"] != 403 {
		t.Fatalf("the go denial status drifted: %d", corpus.HTTP.DenyStatus["go"])
	}
}

func TestDecisionCorpusTokenAuthority(t *testing.T) {
	corpus := loadDecisionCorpus(t)
	if corpus.Authority.ConflictCode != string(ErrCodeTokenSourceConflict) {
		t.Fatalf("conflict code %s", corpus.Authority.ConflictCode)
	}
	if corpus.Authority.MissingCode != string(ErrCodeMalformedToken) {
		t.Fatalf("missing code %s", corpus.Authority.MissingCode)
	}
	for _, row := range corpus.Authority.Matrix {
		token, failure := ResolveTokenValues(row.Header, row.Form, row.Query)
		switch row.Verdict {
		case "verify":
			if failure != "" || token != row.Token {
				t.Fatalf("%s: token %q failure %q", row.Case, token, failure)
			}
		case "conflict":
			if failure != ErrCodeTokenSourceConflict || token != "" {
				t.Fatalf("%s: token %q failure %q", row.Case, token, failure)
			}
		case "missing":
			if failure != ErrCodeMalformedToken {
				t.Fatalf("%s: failure %q", row.Case, failure)
			}
		default:
			t.Fatalf("%s: unknown verdict %s", row.Case, row.Verdict)
		}
	}
}
