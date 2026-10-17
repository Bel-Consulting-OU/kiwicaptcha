package kiwicaptcha

import (
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"
)

// The replay and binding matrix against the golden PHP records: one
// solved token, every scope, tenant, transaction-binding and expiry
// pairing, plus a replayed redemption and a swapped nonce. The matrix
// is generated from the pairs, not hand written, so a binding
// regression fails on the exact pair that moved.

func goldenVerifier(t *testing.T, record *ChallengeRecord, config VerifierConfig, now int64) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(NewMemoryStorage(), mustConfig(t, config, now))
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	storeRecord(t, verifier.Storage, record)
	return verifier
}

func TestWireScopePairing(t *testing.T) {
	// The golden record was issued for "login". A null expectation
	// accepts it, the exact scope accepts it, and every other scope is
	// refused with wrong_scope.
	for expected, wantError := range map[string]VerifyError{
		"login":   "",
		"comment": ErrCodeWrongScope,
		"":        ErrCodeRequiredScope,
	} {
		options := goldenOptions
		options.ExpectedScope = expected
		outcome := goldenVerify(t, "golden_sha256_v2.json", VerifierConfig{}, options)
		if wantError == "" {
			if !outcome.Valid {
				t.Fatalf("verified as %q: rejected with %s", expected, outcome.Error.Code())
			}
			continue
		}
		if outcome.Valid || outcome.Error != wantError {
			t.Fatalf("verified as %q: valid=%v code=%s, want %s", expected, outcome.Valid, outcome.Error.Code(), wantError.Code())
		}
	}
}

func TestWireTenantPairing(t *testing.T) {
	for _, tenant := range []string{"", "tenant-a"} {
		config := VerifierConfig{}
		if tenant != "" {
			config.TenantID = tenant
		}
		outcome := goldenVerify(t, "golden_sha256_v2.json", config, goldenOptions)
		if outcome.Valid != (tenant == "") {
			t.Fatalf("an untenanted record verified under tenant %q: %v", tenant, outcome)
		}
	}
}

func TestWireRequestBindingPairing(t *testing.T) {
	for _, expected := range []string{"tx-123", "tx-456"} {
		options := goldenOptions
		expectation := ExactBinding(expected)
		options.BindingExpectation = &expectation
		outcome := goldenVerify(t, "golden_request_binding_v2.json", VerifierConfig{}, options)
		if outcome.Valid != (expected == "tx-123") {
			t.Fatalf("binding %q: valid=%v (%s)", expected, outcome.Valid, outcome.Error.Code())
		}
	}
}

func TestWireExpirySkewBoundary(t *testing.T) {
	record := goldenRecord(t, "golden_sha256_v2.json")
	ttl := record.ExpiresAt - record.IssuedAt
	for _, offset := range []int64{-61, -60, ttl - 1, ttl, ttl + 1} {
		verifier := goldenVerifier(t, record, VerifierConfig{}, goldenIssuedAt+offset)
		outcome := verifier.Verify(solvedToken(t, record), goldenOptions)
		wantValid := offset >= -MaxClockSkew && offset < ttl
		if outcome.Valid != wantValid {
			t.Fatalf("offset %d/%d: valid=%v (%s)", offset, ttl, outcome.Valid, outcome.Error.Code())
		}
	}
}

func TestWireReplayYieldsAtMostOneGrant(t *testing.T) {
	record := goldenRecord(t, "golden_sha256_v2.json")
	verifier := goldenVerifier(t, record, VerifierConfig{}, goldenIssuedAt)
	token := solvedToken(t, record)
	first := verifier.Verify(token, goldenOptions)
	if !first.Valid {
		t.Fatalf("the genuine first redemption must pass: %s", first.Error.Code())
	}
	secondOptions := goldenOptions
	secondOptions.OperationIdentity = "op-second"
	second := verifier.Verify(token, secondOptions)
	if second.Valid {
		t.Fatalf("a second redeemer received a fresh grant: %+v", second)
	}
}

func wireWorkBits(record *ChallengeRecord, counter uint64) int {
	salt, _ := base64.StdEncoding.DecodeString(record.Salt)
	sum := sha256.Sum256([]byte(record.Prefix + strconv.FormatUint(counter, 10) + string(salt)))
	return LeadingZeroBits(sum[:])
}

func TestWireNonceSwapIsRefused(t *testing.T) {
	first := goldenRecord(t, "golden_sha256_v2.json")
	second := goldenRecord(t, "golden_region_issuer_v2.json")
	verifier := goldenVerifier(t, second, VerifierConfig{}, goldenIssuedAt)
	storeRecord(t, verifier.Storage, first)

	// Find a counter that proves work for the first challenge and
	// provably does not for the second, so the swap cannot pass by
	// chance at equal difficulty.
	counter := uint64(solveSha(first.Prefix, first.Salt, first.TargetBits))
	for wireWorkBits(first, counter) < first.TargetBits || wireWorkBits(second, counter) >= second.TargetBits {
		counter++
	}
	swapped := CreateToken(second.Nonce, int(counter), 5000, NewJSONObject(), "", "", "").Encode()
	outcome := verifier.Verify(swapped, goldenOptions)
	if outcome.Valid {
		t.Fatalf("a counter solved for one challenge was accepted for another")
	}
}
