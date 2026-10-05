package kiwicaptcha

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

type rswFixture struct {
	ModulusN            string `json:"modulus_n_b64"`
	Lambda              string `json:"lambda_b64"`
	Fingerprint         string `json:"rsw_modulus_n_sha256"`
	LegacyBase64TextSha string `json:"legacy_base64_text_sha256"`
	Secondary           struct {
		ModulusN    string `json:"modulus_n_b64"`
		Lambda      string `json:"lambda_b64"`
		Fingerprint string `json:"rsw_modulus_n_sha256"`
	} `json:"secondary"`
}

func loadRswFixture(t *testing.T) rswFixture {
	t.Helper()
	data, err := os.ReadFile(repoProtocolPath(t, filepath.Join("rsw-identity-v1", "fixtures.json")))
	if err != nil {
		t.Fatalf("rsw fixture: %v", err)
	}
	var fixture rswFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("rsw fixture: %v", err)
	}
	return fixture
}

func TestRswIdentityFixture(t *testing.T) {
	fixture := loadRswFixture(t)
	if got := RswFingerprint(fixture.ModulusN); got != fixture.Fingerprint {
		t.Fatalf("canonical fingerprint drift: got %s want %s", got, fixture.Fingerprint)
	}
	if got := RswLegacyIdentity(fixture.ModulusN); got != fixture.LegacyBase64TextSha {
		t.Fatalf("legacy alias drift: got %s want %s", got, fixture.LegacyBase64TextSha)
	}
	if !RswIdentityMatches(fixture.Fingerprint, fixture.ModulusN, false) {
		t.Fatalf("the canonical identity must always match")
	}
	if !RswIdentityMatches(fixture.LegacyBase64TextSha, fixture.ModulusN, true) {
		t.Fatalf("the legacy alias matches only with the migration mode")
	}
	if RswIdentityMatches(fixture.LegacyBase64TextSha, fixture.ModulusN, false) {
		t.Fatalf("the legacy alias must not match a drained deployment")
	}
	// The secondary pair is the negative-test modulus.
	if RswIdentityMatches(fixture.Secondary.Fingerprint, fixture.ModulusN, true) {
		t.Fatalf("the secondary identity must not match the primary modulus")
	}
	if RswFingerprint(fixture.Secondary.ModulusN) != fixture.Secondary.Fingerprint {
		t.Fatalf("the secondary fingerprint drift")
	}
}

func TestRswTrapdoorValidation(t *testing.T) {
	fixture := loadRswFixture(t)
	if _, err := NewRsw(fixture.ModulusN, fixture.Lambda); err != nil {
		t.Fatalf("the fixture pair must validate: %v", err)
	}
	// A mismatched lambda fails the trapdoor spot check.
	if _, err := NewRsw(fixture.ModulusN, fixture.Secondary.Lambda); err == nil {
		t.Fatalf("a foreign lambda must fail the spot check")
	}
	// A probable prime modulus is refused.
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 2040), big.NewInt(1))
	if !prime.ProbablyPrime(24) {
		t.Skipf("the prime probe did not produce a probable prime")
	}
	primeB64 := base64EncodeBytes(padTo256(t, prime))
	if _, err := NewRsw(primeB64, fixture.Lambda); err == nil {
		t.Fatalf("a probable prime modulus must be refused")
	}
	// A modulus with a small factor is refused: multiply the fixture
	// modulus down to a shape valid composite with a tiny factor.
	small := new(big.Int).Mul(big.NewInt(10007), new(big.Int).Lsh(big.NewInt(3), 2030))
	small = small.Add(small, big.NewInt(1))
	smallB64 := base64EncodeBytes(padTo256(t, small))
	if _, err := NewRsw(smallB64, fixture.Lambda); err == nil {
		t.Fatalf("a modulus with a small prime factor must be refused")
	}
}

// padTo256 renders one big integer as the 256 byte big-endian modulus
// shape, with the top bit set and odd.
func padTo256(t *testing.T, value *big.Int) []byte {
	t.Helper()
	raw := value.Bytes()
	padded := make([]byte, RswModulusBytes)
	copy(padded[RswModulusBytes-len(raw):], raw)
	padded[0] |= 0x80
	padded[RswModulusBytes-1] |= 1
	return padded
}

func TestRswGoldenProof(t *testing.T) {
	document := readGolden(t, "golden_rsw_v5.json")
	record := goldenRecord(t, "golden_rsw_v5.json")
	rswDocument := document["rsw"].(map[string]interface{})
	modulus := rswDocument["modulus_n"].(string)
	lambda := rswDocument["lambda"].(string)
	expected := rswDocument["expected_proof_hex"].(string)

	trapdoor, err := NewRsw(modulus, lambda)
	if err != nil {
		t.Fatalf("trapdoor: %v", err)
	}
	// The Go trapdoor must reproduce the php gmp expectation exactly.
	got := trapdoor.ExpectedProofHex(record.Prefix, record.Nonce, record.T)
	if got != expected {
		t.Fatalf("trapdoor drift: got %s... want %s...", got[:24], expected[:24])
	}
	if len(got) != RswProofHexLen {
		t.Fatalf("proof hex length drift: %d", len(got))
	}
	// The client solve, T sequential squarings, must land on the same
	// value and verify through the full gate.
	n := new(big.Int)
	n.SetBytes(mustDecodeB64(t, modulus))
	solved := solveRsw(record.Prefix, record.Nonce, n, record.T)
	if solved != expected {
		t.Fatalf("sequential squaring drift against the trapdoor")
	}
	verifier := newTestVerifier(t, VerifierConfig{RswModulusN: modulus, RswLambda: lambda}, goldenIssuedAt)
	storeRecord(t, verifier.Storage, record)
	token := CreateToken(record.Nonce, 0, 5000, NewJSONObject(), "", "", solved).Encode()
	outcome := verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"})
	requireValid(t, outcome)
	if PriceRung(record.Algorithm, record.TargetBits, record.MKib) != "rsw" {
		t.Fatalf("the rsw price rung drift")
	}
	// A wrong final value is insufficient work.
	wrongRecord := goldenRecord(t, "golden_rsw_v5.json")
	storeRecord(t, verifier.Storage, wrongRecord)
	wrongToken := CreateToken(record.Nonce, 0, 5000, NewJSONObject(), "", "", stringsRepeat("0", 512)).Encode()
	requireCode(t, verifier.Verify(wrongToken, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"}), ErrCodeInsufficientWork)
	// An rsw record carrying a search counter is rejected outright.
	counterRecord := goldenRecord(t, "golden_rsw_v5.json")
	storeRecord(t, verifier.Storage, counterRecord)
	counterToken := CreateToken(record.Nonce, 5, 5000, NewJSONObject(), "", "", solved).Encode()
	requireCode(t, verifier.Verify(counterToken, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"}), ErrCodeInsufficientWork)
}

func TestRswCrossTrapdoorFailsClosed(t *testing.T) {
	fixture := loadRswFixture(t)
	record := goldenRecord(t, "golden_rsw_v5.json")
	// The record is bound to the primary modulus; a verifier holding
	// only the secondary trapdoor is authentic but unsupported.
	verifier := newTestVerifier(t, VerifierConfig{
		RswModulusN: fixture.Secondary.ModulusN,
		RswLambda:   fixture.Secondary.Lambda,
	}, goldenIssuedAt)
	storeRecord(t, verifier.Storage, record)
	token := CreateToken(record.Nonce, 0, 5000, NewJSONObject(), "", "", stringsRepeat("1", 512)).Encode()
	requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"}), ErrCodeUnsupportedRswParams)
	// A verifier without any trapdoor refuses too.
	unconfigured := newTestVerifier(t, VerifierConfig{}, goldenIssuedAt)
	storeRecord(t, unconfigured.Storage, record)
	requireCode(t, unconfigured.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"}), ErrCodeUnsupportedRswParams)
	// The rotation keyring resolves the outstanding record.
	ring := newTestVerifier(t, VerifierConfig{
		RswModulusN: fixture.Secondary.ModulusN,
		RswLambda:   fixture.Secondary.Lambda,
		RswVerificationKeys: map[string]RswKeyPair{
			fixture.Fingerprint: {ModulusN: fixture.ModulusN, Lambda: fixture.Lambda},
		},
	}, goldenIssuedAt)
	storeRecord(t, ring.Storage, record)
	n := new(big.Int)
	n.SetBytes(mustDecodeB64(t, fixture.ModulusN))
	solved := solveRsw(record.Prefix, record.Nonce, n, record.T)
	ringToken := CreateToken(record.Nonce, 0, 5000, NewJSONObject(), "", "", solved).Encode()
	requireValid(t, ring.Verify(ringToken, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"}))
}

func mustDecodeB64(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64DecodeString(value)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return raw
}
