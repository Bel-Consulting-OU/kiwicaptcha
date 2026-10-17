package kiwicaptcha

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The shared hostile wire corpus against the Go decoder. The fixture is
// expanded by the PHP generator and read byte-for-byte by every hosted
// SDK suite; the expected verdicts are the reference decoder's.

type wireCorpusExpect struct {
	Verdict       string          `json:"verdict"`
	Class         string          `json:"class"`
	Counter       int             `json:"counter"`
	DurationMs    int             `json:"duration_ms"`
	Execution     *string         `json:"execution_digest"`
	Trace         *string         `json:"execution_trace"`
	Rsw            *string         `json:"rsw_proof"`
	TelemetryJSON  json.RawMessage `json:"telemetry"`
	TelemetryScore *bool           `json:"telemetry_score"`
}

type wireCorpusRow struct {
	ID     string           `json:"id"`
	Class  string           `json:"attack_class"`
	Raw    string           `json:"raw"`
	Expect wireCorpusExpect `json:"expect"`
}

type wireCorpusDoc struct {
	Counts struct {
		Total int `json:"total"`
	} `json:"counts"`
	Vectors []wireCorpusRow `json:"vectors"`
}

func decodeJSONValue(t *testing.T, raw []byte) interface{} {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value interface{}
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("fixture telemetry is not JSON: %v", err)
	}
	return value
}

func wireCorpusClass(code string) string {
	switch code {
	case DecodeErrInvalidBase64:
		return "base64"
	case DecodeErrInvalidUTF8:
		return "utf8"
	case DecodeErrInvalidCounter, DecodeErrInvalidCount:
		return "counter"
	case DecodeErrInvalidDur:
		return "duration"
	default:
		return "malformed"
	}
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func TestWireHostileCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/wire-hostile-corpus.json")
	if err != nil {
		t.Fatalf("the wire corpus fixture must exist: %v", err)
	}
	var document wireCorpusDoc
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("the wire corpus must be valid JSON: %v", err)
	}
	if document.Counts.Total < 100 {
		t.Fatalf("the corpus must stay broad, got %d rows", document.Counts.Total)
	}

	for _, row := range document.Vectors {
		row := row
		t.Run(row.ID, func(t *testing.T) {
			token, decodeErr := DecodeToken(row.Raw)
			if row.Expect.Verdict == "accept" {
				if decodeErr != nil {
					t.Fatalf("the Go decoder rejected an accepted row: %v", decodeErr)
				}
				if token.Counter != row.Expect.Counter {
					t.Fatalf("counter = %d, want %d", token.Counter, row.Expect.Counter)
				}
				if token.DurationMs != row.Expect.DurationMs {
					t.Fatalf("duration = %d, want %d", token.DurationMs, row.Expect.DurationMs)
				}
				if token.ExecutionDigest != optionalString(row.Expect.Execution) {
					t.Fatalf("digest = %q, want %q", token.ExecutionDigest, optionalString(row.Expect.Execution))
				}
				if token.ExecutionTrace != optionalString(row.Expect.Trace) {
					t.Fatalf("trace = %q, want %q", token.ExecutionTrace, optionalString(row.Expect.Trace))
				}
				if token.RswProof != optionalString(row.Expect.Rsw) {
					t.Fatalf("rsw proof = %q, want %q", token.RswProof, optionalString(row.Expect.Rsw))
				}
				if len(row.Expect.TelemetryJSON) > 0 {
					expected := decodeJSONValue(t, row.Expect.TelemetryJSON)
					actual := decodeJSONValue(t, []byte(token.Telemetry.Encode()))
					if !reflect.DeepEqual(expected, actual) {
						t.Fatalf("telemetry = %s, want %s", token.Telemetry.Encode(), string(row.Expect.TelemetryJSON))
					}
				}
				if row.Expect.TelemetryScore != nil {
					if got := ScoreTelemetry(token.Telemetry, token.DurationMs); got != *row.Expect.TelemetryScore {
						t.Fatalf("telemetry score = %v, want %v", got, *row.Expect.TelemetryScore)
					}
				}
				return
			}

			if decodeErr == nil {
				t.Fatalf("the Go decoder accepted a hostile row")
			}
			if row.Expect.Class == "any" {
				return
			}
			typed, ok := decodeErr.(*DecodeError)
			if !ok {
				t.Fatalf("a typed rejection is required, got %T", decodeErr)
			}
			if got := wireCorpusClass(typed.Code); got != row.Expect.Class {
				t.Fatalf("rejection class = %s, want %s (%s)", got, row.Expect.Class, typed.Code)
			}
		})
	}
}

// The ceiling rejection outranks a native integer overflow: a nine or
// more digit spelling is a solver-ceiling failure, never a syntax
// failure, exactly like the reference decoder.
func TestOversizedCounterSpellingIsACeilingRejection(t *testing.T) {
	nonce := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, counter := range []string{
		"9223372036854775808",
		"18446744073709551616",
		strings.Repeat("9", 100),
	} {
		raw := base64.StdEncoding.EncodeToString([]byte(nonce + "." + counter + ".2.{}"))
		_, err := DecodeToken(raw)
		typed, ok := err.(*DecodeError)
		if !ok || typed.Code != DecodeErrInvalidCount {
			t.Fatalf("counter %q: got %v, want %s", counter, err, DecodeErrInvalidCount)
		}
	}
}
