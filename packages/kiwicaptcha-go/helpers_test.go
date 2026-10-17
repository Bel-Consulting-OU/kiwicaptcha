package kiwicaptcha

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Direct coverage of the exported helper surface that the verify path
// composes: each helper carries a security decision, so the behavior
// is pinned here instead of only through the end-to-end suites.

func TestServerStateMacMarkerAndPurposeKeys(t *testing.T) {
	// The marker type names the server-state mac namespace.
	_ = ServerStateMac{}

	key, err := ServerStateMacKey(testSecret, "")
	if err != nil {
		t.Fatalf("server state key: %v", err)
	}
	if len(key) == 0 {
		t.Fatalf("the server state key must be non-empty")
	}
	meta := ServerStateMacRecordMeta(key, "challenge", 123, "")
	consumed := ServerStateMacConsumedResult(key, "challenge", true, "", "")
	if !isHex64(meta) || !isHex64(consumed) {
		t.Fatalf("the server state macs must be 64 lowercase hex")
	}
	if meta == consumed {
		t.Fatalf("the record-metadata and consumed-result domains must never collide")
	}
	tenantKey, err := ServerStateMacKey(testSecret, "tenant-a")
	if err != nil {
		t.Fatalf("tenant server state key: %v", err)
	}
	if string(tenantKey) == string(key) {
		t.Fatalf("the tenant must scope the server state key")
	}
	// Variable fields are length-prefixed and bound into the mac: a
	// hostname or issuance-clock change moves the value.
	if ServerStateMacRecordMeta(key, "challenge", 124, "") == meta {
		t.Fatalf("the issuance clock must bind the record metadata mac")
	}
	if ServerStateMacRecordMeta(key, "challenge", 123, "host") == meta {
		t.Fatalf("the hostname must bind the record metadata mac")
	}
}

func TestTokenFromRequestSourcesAndConflicts(t *testing.T) {
	t.Run("header", func(t *testing.T) {
		request := httptest.NewRequest("POST", "/submit", nil)
		request.Header.Set(TokenHeader, " header-token ")
		token, failure := TokenFromRequest(request)
		if failure != "" || token != "header-token" {
			t.Fatalf("header source: token=%q failure=%q", token, failure)
		}
	})
	t.Run("form", func(t *testing.T) {
		form := url.Values{TokenField: {"form-token"}}
		request := httptest.NewRequest("POST", "/submit", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		token, failure := TokenFromRequest(request)
		if failure != "" || token != "form-token" {
			t.Fatalf("form source: token=%q failure=%q", token, failure)
		}
	})
	t.Run("query", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/submit?kiwi_token=query-token", nil)
		token, failure := TokenFromRequest(request)
		if failure != "" || token != "query-token" {
			t.Fatalf("query source: token=%q failure=%q", token, failure)
		}
	})
	t.Run("same token every source", func(t *testing.T) {
		form := url.Values{TokenField: {"same-token"}}
		request := httptest.NewRequest("POST", "/submit?kiwi_token=same-token",
			strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set(TokenHeader, "same-token")
		token, failure := TokenFromRequest(request)
		if failure != "" || token != "same-token" {
			t.Fatalf("agreeing sources: token=%q failure=%q", token, failure)
		}
	})
	t.Run("conflict", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/submit?kiwi_token=query-token", nil)
		request.Header.Set(TokenHeader, "header-token")
		token, failure := TokenFromRequest(request)
		if failure != ErrCodeTokenSourceConflict || token != "" {
			t.Fatalf("conflicting sources: token=%q failure=%q", token, failure)
		}
	})
	t.Run("missing", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/submit", nil)
		token, failure := TokenFromRequest(request)
		if failure != ErrCodeMalformedToken || token != "" {
			t.Fatalf("missing token: token=%q failure=%q", token, failure)
		}
	})
}

func TestParseRecordJSONAcceptsTheWireShapeAndRefusesCorruption(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString(bytesOf(32, 1))
	salt := base64.StdEncoding.EncodeToString(bytesOf(16, 2))
	challenge := "payload.signature"
	data := map[string]interface{}{
		"nonce":            nonce,
		"scope":            "login",
		"binding_tag":      "",
		"issued_at":        json.Number("1800000000"),
		"expires_at":       json.Number("1800000120"),
		"algorithm":        "sha256",
		"m_kib":            json.Number("1"),
		"t":                json.Number("1"),
		"p":                json.Number("1"),
		"target_bits":      json.Number("4"),
		"salt":             salt,
		"prefix":           challenge + "|" + salt + "|",
		"challenge":        challenge,
		"min_duration_ms":  json.Number("0"),
		"protocol_version": json.Number("2"),
	}
	record, err := ParseRecordJSON(data)
	if err != nil {
		t.Fatalf("the canonical wire map must parse: %v", err)
	}
	if record.Nonce != nonce || record.Scope != "login" || record.TargetBits != 4 {
		t.Fatalf("record field drift: %+v", record)
	}

	corrupt := map[string]interface{}{}
	for key, value := range data {
		corrupt[key] = value
	}
	corrupt["unknown_key"] = "x"
	if _, err := ParseRecordJSON(corrupt); err == nil {
		t.Fatalf("an unknown record key must be refused")
	}
	delete(corrupt, "unknown_key")
	delete(corrupt, "nonce")
	if _, err := ParseRecordJSON(corrupt); err == nil {
		t.Fatalf("a missing required field must be refused")
	}
}

func TestChallengePayloadMatchesAuthenticatesTheEmbeddedCanonical(t *testing.T) {
	canonical := "nonce|scope|binding|1800000000"
	challenge := base64.StdEncoding.EncodeToString([]byte(canonical)) + "." + "deadbeef"
	if !ChallengePayloadMatches(challenge, canonical) {
		t.Fatalf("the canonical payload segment must match")
	}
	if ChallengePayloadMatches(challenge, canonical+"x") {
		t.Fatalf("a different canonical must not match")
	}
	if ChallengePayloadMatches("no-dot", canonical) {
		t.Fatalf("a challenge without a signature segment must not match")
	}
	if ChallengePayloadMatches("!!!."+"deadbeef", canonical) {
		t.Fatalf("a non-base64 payload segment must not match")
	}
}

func TestHashIPV1IsTheLegacySecretPlusIPDigest(t *testing.T) {
	sum := sha256.Sum256([]byte(testSecret + testClientIP))
	if got := HashIPV1(testClientIP, testSecret); got != strings.ToLower(hexOf(sum[:])) {
		t.Fatalf("HashIPV1 drift: %s", got)
	}
	if HashIPV1(testClientIP, testSecret) == HashIPV1(testClientIP, testSecret+"x") {
		t.Fatalf("the secret must bind the legacy binding tag")
	}
}

func TestDecodeExecutionProgramBoundsTheProgramLanguage(t *testing.T) {
	program := minimalProgramB64("login", "submit")
	if !DecodeExecutionProgram(program) {
		t.Fatalf("the minimal well-formed program must parse")
	}
	raw, err := base64.StdEncoding.DecodeString(program)
	if err != nil {
		t.Fatalf("decode program: %v", err)
	}
	trailing := base64.StdEncoding.EncodeToString(append(raw, 0))
	if DecodeExecutionProgram(trailing) {
		t.Fatalf("a program with trailing bytes must be refused")
	}
	if DecodeExecutionProgram("") || DecodeExecutionProgram("not base64!!!") {
		t.Fatalf("an empty or non-base64 program must be refused")
	}
}

func TestProtocolExtensionGrammarMatchesTheProtocolMatrix(t *testing.T) {
	cases := []struct {
		version   int
		decoy     bool
		execution bool
		rsw       bool
		want      bool
	}{
		{1, false, false, false, true},
		{2, false, false, false, true},
		{3, true, false, false, true},
		{3, false, false, false, false},
		{4, false, true, false, true},
		{4, true, true, false, true},
		{4, false, false, false, false},
		{5, false, false, true, true},
		{5, true, false, false, false},
		// The pre-v5 legacy shape: an identity-bearing record carries
		// the v5 rsw identity at versions 2 through 4. The grammar
		// admits it; the verifier's migration window decides whether
		// that identity is accepted.
		{2, false, false, true, true},
		{3, true, false, true, true},
		{4, false, true, true, true},
		{0, false, false, false, false},
		{6, true, true, true, false},
	}
	for _, test := range cases {
		got := ProtocolExtensionGrammarOk(test.version, test.decoy, test.execution, test.rsw)
		if got != test.want {
			t.Fatalf("version=%d decoy=%t execution=%t rsw=%t: got %t want %t",
				test.version, test.decoy, test.execution, test.rsw, got, test.want)
		}
	}
}

func TestIsValidIdentifierFollowsTheNarrowAlphabet(t *testing.T) {
	for _, valid := range []string{"login", "a.b_c:d-e", "A0", strings.Repeat("a", 64)} {
		if !IsValidIdentifier(valid, 64) {
			t.Fatalf("%q must be a valid identifier", valid)
		}
	}
	for _, invalid := range []string{"", "bad scope", "bad/scope", "bad|scope", strings.Repeat("a", 65)} {
		if IsValidIdentifier(invalid, 64) {
			t.Fatalf("%q must not be a valid identifier", invalid)
		}
	}
}

func TestIsValidDecoyFieldNameFollowsTheHoneypotAlphabet(t *testing.T) {
	for _, valid := range []string{"hp_field", "a-b", "A0", strings.Repeat("a", 64)} {
		if !IsValidDecoyFieldName(valid) {
			t.Fatalf("%q must be a valid decoy field name", valid)
		}
	}
	for _, invalid := range []string{"", "a.b", "a b", "a|b", strings.Repeat("a", 65)} {
		if IsValidDecoyFieldName(invalid) {
			t.Fatalf("%q must not be a valid decoy field name", invalid)
		}
	}
}

func TestDecodeRswModulusShape(t *testing.T) {
	raw := bytesOf(256, 3)
	raw[0] = 0x80
	raw[255] = 1
	encoded := base64.StdEncoding.EncodeToString(raw)
	modulus, err := DecodeRswModulus(encoded)
	if err != nil {
		t.Fatalf("the canonical modulus must decode: %v", err)
	}
	if modulus.BitLen() == 0 {
		t.Fatalf("the decoded modulus must be non-zero")
	}

	even := append([]byte(nil), raw...)
	even[255] = 2
	if _, err := DecodeRswModulus(base64.StdEncoding.EncodeToString(even)); err == nil {
		t.Fatalf("an even modulus must be refused")
	}
	lowTopBit := append([]byte(nil), raw...)
	lowTopBit[0] = 0x7f
	if _, err := DecodeRswModulus(base64.StdEncoding.EncodeToString(lowTopBit)); err == nil {
		t.Fatalf("a modulus without its top bit must be refused")
	}
	if _, err := DecodeRswModulus(base64.StdEncoding.EncodeToString(raw[:255])); err == nil {
		t.Fatalf("a short modulus must be refused")
	}
	if _, err := DecodeRswModulus("not base64!!!"); err == nil {
		t.Fatalf("a non-base64 modulus must be refused")
	}
}

func TestDecodeRswLambdaShape(t *testing.T) {
	raw := bytesOf(16, 4)
	raw[len(raw)-1] = 2
	lambda, err := DecodeRswLambda(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("the canonical lambda must decode: %v", err)
	}
	if lambda.Sign() <= 0 {
		t.Fatalf("the decoded lambda must be positive")
	}

	odd := append([]byte(nil), raw...)
	odd[len(odd)-1] = 3
	if _, err := DecodeRswLambda(base64.StdEncoding.EncodeToString(odd)); err == nil {
		t.Fatalf("an odd lambda must be refused")
	}
	if _, err := DecodeRswLambda(base64.StdEncoding.EncodeToString(nil)); err == nil {
		t.Fatalf("an empty lambda must be refused")
	}
	if _, err := DecodeRswLambda(base64.StdEncoding.EncodeToString(bytesOf(257, 4))); err == nil {
		t.Fatalf("an oversized lambda must be refused")
	}
	if _, err := DecodeRswLambda("not base64!!!"); err == nil {
		t.Fatalf("a non-base64 lambda must be refused")
	}
}

func TestRedisStorageTTLIsTheRetentionMargin(t *testing.T) {
	if RedisStorageTTL != 60 {
		t.Fatalf("the redis retention margin drift: %d", RedisStorageTTL)
	}
	storage := NewRedisStorage(nil, "")
	if storage.ttlMargin != RedisStorageTTL*time.Second {
		t.Fatalf("the adapter must add the documented margin: %v", storage.ttlMargin)
	}
}

func bytesOf(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed
	}
	return out
}

func hexOf(raw []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, by := range raw {
		out[i*2] = digits[by>>4]
		out[i*2+1] = digits[by&0x0f]
	}
	return string(out)
}
