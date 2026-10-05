package kiwicaptcha

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadTokenFixtures(t *testing.T) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(repoProtocolPath(t, filepath.Join("solution-token-v1", "fixtures.json")))
	if err != nil {
		t.Fatalf("token fixtures: %v", err)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("token fixtures: %v", err)
	}
	return document
}

func fixtureString(t *testing.T, document map[string]interface{}, groups ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	cursor := document
	for index, key := range groups {
		value, ok := cursor[key]
		if !ok {
			t.Fatalf("fixture group %s missing", key)
		}
		if index == len(groups)-1 {
			typed, ok := value.(map[string]interface{})
			if !ok {
				t.Fatalf("fixture group %s is not an object", key)
			}
			for name, entry := range typed {
				text, ok := entry.(string)
				if !ok {
					t.Fatalf("fixture entry %s is not a string", name)
				}
				out[name] = text
			}
			return out
		}
		cursor, ok = value.(map[string]interface{})
		if !ok {
			t.Fatalf("fixture group %s is not an object", key)
		}
	}
	return out
}

func TestSolutionTokenFixtureAccepted(t *testing.T) {
	fixtures := loadTokenFixtures(t)
	accepted := fixtureString(t, fixtures, "accepted")
	for counter, encoded := range accepted {
		token, err := DecodeToken(encoded)
		if err != nil {
			t.Fatalf("accepted fixture %s: %v", counter, err)
		}
		if token.Encode() != encoded {
			t.Fatalf("accepted fixture %s round-trip drift", counter)
		}
	}
	cross, ok := fixtures["cross_language"].(map[string]interface{})
	if !ok {
		t.Fatalf("cross_language group missing")
	}
	encoded := cross["encoded"].(string)
	token, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("cross_language fixture: %v", err)
	}
	if token.Encode() != encoded {
		t.Fatalf("cross_language round-trip drift")
	}
	if token.Counter != 5_000_001 {
		t.Fatalf("cross_language counter: got %d", token.Counter)
	}
}

func TestSolutionTokenFixtureRejected(t *testing.T) {
	fixtures := loadTokenFixtures(t)
	rejected := fixtureString(t, fixtures, "rejected")
	for counter, encoded := range rejected {
		if _, err := DecodeToken(encoded); err == nil {
			t.Fatalf("rejected fixture %s must not decode", counter)
		}
	}
}

func TestTokenGrammarErrors(t *testing.T) {
	nonce := "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
	cases := []struct {
		name     string
		token    string
		expected string
	}{
		{"short segments", encodePlain(t, "a.b.c"), DecodeErrMalformed},
		{"bad base64", "!!!!", DecodeErrInvalidBase64},
		{"non canonical padding", paddedNonCanonical(t), DecodeErrInvalidBase64},
		{"bad nonce length", encodePlain(t, "short."+"1.1.{}"), DecodeErrMalformed},
		{"leading zero counter", encodePlain(t, nonce+".0042.1.{}"), DecodeErrInvalidCounter},
		{"counter over ceiling", encodePlain(t, nonce+".20000000.1.{}"), DecodeErrInvalidCount},
		{"leading zero duration", encodePlain(t, nonce+".1.007.{}"), DecodeErrInvalidDur},
		{"duration over ceiling", encodePlain(t, nonce+".1.3600001.{}"), DecodeErrInvalidDur},
		{"telemetry array", encodePlain(t, nonce+".1.1.[]"), DecodeErrMalformed},
		{"telemetry scalar", encodePlain(t, nonce+".1.1.7"), DecodeErrMalformed},
		{"execution digest shape", encodePlain(t, nonce+".1.1.{}.nothex"), DecodeErrMalformed},
		{"bad trace encoding", encodePlain(t, nonce+".1.1.{}.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:***"), DecodeErrMalformed},
	}
	for _, testCase := range cases {
		_, err := DecodeToken(testCase.token)
		if err == nil {
			t.Fatalf("%s: token must not decode", testCase.name)
		}
		if typed, ok := err.(*DecodeError); ok && typed.Code != testCase.expected && testCase.expected != "" {
			t.Fatalf("%s: got %s want %s", testCase.name, typed.Code, testCase.expected)
		}
	}
}

func TestTokenRswAndExecutionPeel(t *testing.T) {
	nonce := "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
	proof := stringsRepeat("ab", 256)
	digest := stringsRepeat("cd", 32)
	token := CreateToken(nonce, 0, 1234, NewJSONObject(JSONPair{Key: "me", Value: jsonNumber("1")}), digest, "AAEC", proof)
	decoded, err := DecodeToken(token.Encode())
	if err != nil {
		t.Fatalf("rsw and execution token: %v", err)
	}
	if decoded.RswProof != proof || decoded.ExecutionDigest != digest || decoded.ExecutionTrace != "AAEC" {
		t.Fatalf("peel drift: %+v", decoded)
	}
	if token.Encode() != decoded.Encode() {
		t.Fatalf("encode drift")
	}
	// A lone 512 hex tail with no execution segment peels as rsw only.
	lone := CreateToken(nonce, 0, 5, NewJSONObject(), "", "", proof)
	decodedLone, err := DecodeToken(lone.Encode())
	if err != nil {
		t.Fatalf("lone rsw token: %v", err)
	}
	if decodedLone.RswProof != proof || decodedLone.ExecutionDigest != "" {
		t.Fatalf("lone rsw peel drift")
	}
}

func TestTokenTelemetryOrderPreserved(t *testing.T) {
	nonce := "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
	telemetry := NewJSONObject(
		JSONPair{Key: "zebra", Value: jsonNumber("1")},
		JSONPair{Key: "alpha", Value: jsonNumber("2")},
	)
	encoded := CreateToken(nonce, 1, 1, telemetry, "", "", "").Encode()
	decoded, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("ordered telemetry: %v", err)
	}
	if got := decoded.Telemetry.Encode(); got != `{"zebra":1,"alpha":2}` {
		t.Fatalf("telemetry order drift: %s", got)
	}
}

func encodePlain(t *testing.T, plain string) string {
	t.Helper()
	return base64Std(plain)
}

func paddedNonCanonical(t *testing.T) string {
	t.Helper()
	return base64Std("aaaa.1.1.{}") + "="
}

func stringsRepeat(text string, count int) string {
	out := ""
	for i := 0; i < count; i++ {
		out += text
	}
	return out
}
