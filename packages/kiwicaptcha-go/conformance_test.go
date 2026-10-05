package kiwicaptcha

import (
	"testing"
)

// TestProtocolCorpusConformance is the single conformance entry a CI
// run can point at: it walks the shared protocol corpora the SDK
// contract pins, the same corpus the php, Python and Rust suites
// replay, so behavior cannot drift.
func TestProtocolCorpusConformance(t *testing.T) {
	t.Run("canonical vectors end to end", func(t *testing.T) {
		for _, vector := range []protocolVector{shaVector, argon2Vector} {
			record := vectorRecord(vector)
			if !VerifyRecordSignature(record, testSecret, "") {
				t.Fatalf("%s: the canonical signature must verify", vector.Algorithm)
			}
			verifier := newTestVerifier(t, VerifierConfig{AcceptLegacyV1: true}, testNow)
			storeRecord(t, verifier.Storage, record)
			outcome := verifier.Verify(vectorToken(vector, -1, -1), VerifyOptions{
				SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP,
			})
			requireValid(t, outcome)
		}
	})
	t.Run("solution token boundary fixture", func(t *testing.T) {
		fixtures := loadTokenFixtures(t)
		for counter, encoded := range fixtureString(t, fixtures, "accepted") {
			token, err := DecodeToken(encoded)
			if err != nil {
				t.Fatalf("accepted %s: %v", counter, err)
			}
			if token.Encode() != encoded {
				t.Fatalf("accepted %s: round-trip drift", counter)
			}
		}
		for counter, encoded := range fixtureString(t, fixtures, "rejected") {
			if _, err := DecodeToken(encoded); err == nil {
				t.Fatalf("rejected %s: must not decode", counter)
			}
		}
		cross := fixtures["cross_language"].(map[string]interface{})
		token, err := DecodeToken(cross["encoded"].(string))
		if err != nil || token.Encode() != cross["encoded"].(string) {
			t.Fatalf("cross_language: round-trip drift (%v)", err)
		}
	})
	t.Run("ip hash vector", func(t *testing.T) {
		if got := sha256Hex(testSecret + testClientIP); got != testIPHash {
			t.Fatalf("ip hash drift: %s", got)
		}
	})
	t.Run("rsw identity fixture", func(t *testing.T) {
		fixture := loadRswFixture(t)
		if RswFingerprint(fixture.ModulusN) != fixture.Fingerprint {
			t.Fatalf("the rsw identity drift")
		}
	})
	t.Run("outcomes mapping fixture", func(t *testing.T) {
		document := loadOutcomeVectors(t)
		if document.Version != OutcomesVersion {
			t.Fatalf("the outcomes mapping version drift")
		}
	})
	t.Run("php issued golden records", func(t *testing.T) {
		for _, name := range []string{
			"golden_sha256_v2.json", "golden_argon2id_v2.json", "golden_decoy_v3.json",
			"golden_policy_epoch2_v2.json", "golden_region_issuer_v2.json",
			"golden_request_binding_v2.json", "golden_rsw_v5.json",
		} {
			record := goldenRecord(t, name)
			if !VerifyRecordSignature(record, testSecret, "") {
				t.Fatalf("%s: the php signature must verify", name)
			}
		}
	})
}
