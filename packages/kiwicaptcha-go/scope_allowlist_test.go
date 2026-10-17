package kiwicaptcha

import (
	"strings"
	"testing"
	"time"
)

// The configured scope set is an allowlist: a non-empty set refuses a
// verify call whose expected scope is outside it with wrong_scope; an
// empty set keeps the historical any-scope acceptance.

func TestScopeAllowlistAllowsConfiguredScopes(t *testing.T) {
	options := defaultMintOptions()
	options.scope = "login"
	record := mintRecord(t, options)
	verifier := newTestVerifier(t, VerifierConfig{Scopes: []string{"login", "comment"}}, testNow)
	storeRecord(t, verifier.Storage, record)
	requireValid(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{
		SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP,
	}))
}

func TestScopeAllowlistRejectsAnExpectedScopeOutsideTheSet(t *testing.T) {
	options := defaultMintOptions()
	options.scope = "signup"
	record := mintRecord(t, options)
	if record.Scope != "signup" {
		t.Fatalf("mint scope drift: %s", record.Scope)
	}
	verifier := newTestVerifier(t, VerifierConfig{Scopes: []string{"login", "comment"}}, testNow)
	storeRecord(t, verifier.Storage, record)
	// The record and the expected scope agree; only the allowlist
	// refuses, and it must answer the existing wrong_scope code.
	requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{
		SecretKey: testSecret, ExpectedScope: "signup", ClientIP: testClientIP,
	}), ErrCodeWrongScope)
}

func TestEmptyScopeAllowlistAcceptsAnyScope(t *testing.T) {
	options := defaultMintOptions()
	options.scope = "signup"
	record := mintRecord(t, options)
	verifier := newTestVerifier(t, VerifierConfig{}, testNow)
	storeRecord(t, verifier.Storage, record)
	requireValid(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{
		SecretKey: testSecret, ExpectedScope: "signup", ClientIP: testClientIP,
	}))
}

func TestSettingsBuildVerifierCarriesTheScopeAllowlist(t *testing.T) {
	settings := Settings{
		Secret:  testSecret,
		Store:   "memory://",
		Scopes:  []string{"login"},
		Profile: "standard",
	}
	verifier, err := settings.BuildVerifier()
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	if closer, ok := verifier.Storage.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	options := defaultMintOptions()
	options.scope = "comment"
	// The settings-built verifier runs on the wall clock, so mint the
	// record inside its live window.
	options.issuedAt = time.Now().Unix() - 10
	record := mintRecord(t, options)
	storeRecord(t, verifier.Storage, record)
	requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{
		SecretKey: testSecret, ExpectedScope: "comment", ClientIP: testClientIP,
	}), ErrCodeWrongScope)
}

func TestSettingsBuildVerifierValidatesTheDeploymentSecret(t *testing.T) {
	for _, secret := range []string{"", "short", strings.Repeat("s", MinSecretBytes-1)} {
		settings := Settings{Secret: secret, Store: "memory://", Profile: "standard"}
		verifier, err := settings.BuildVerifier()
		if err == nil {
			if closer, ok := verifier.Storage.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
			t.Fatalf("a %d-byte secret must refuse to build", len(secret))
		}
	}
	settings := Settings{Secret: strings.Repeat("s", MinSecretBytes), Store: "memory://", Profile: "standard"}
	verifier, err := settings.BuildVerifier()
	if err != nil {
		t.Fatalf("a %d-byte secret must build: %v", MinSecretBytes, err)
	}
	if closer, ok := verifier.Storage.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func TestMaxShaTargetBitsIsEnforcedByValidateRecord(t *testing.T) {
	options := defaultMintOptions()
	options.targetBits = MaxShaTargetBits
	record := mintRecord(t, options)
	verifier := newTestVerifier(t, VerifierConfig{}, testNow)
	if !verifier.ValidateRecord(record) {
		t.Fatalf("a sha256 record at the %d-bit ceiling must validate", MaxShaTargetBits)
	}
	record.TargetBits = MaxShaTargetBits + 1
	if verifier.ValidateRecord(record) {
		t.Fatalf("a sha256 record above the %d-bit ceiling must be malformed", MaxShaTargetBits)
	}
}
