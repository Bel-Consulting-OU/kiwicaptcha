package kiwicaptcha

import (
	"math/big"
	"strings"
	"testing"
	"time"
)

// The golden end-to-end proof of life: every record below was issued
// by the php core (packages/kiwicaptcha-php Issuer, pinned issuance
// clock, provenance inside each file) and is verified here through
// the Go SDK: sha256 solve to ok, tampered to bad_signature, expired,
// wrong scope, and the rollout-window record to ok or rejected per
// the declared floor.

func goldenVerify(t *testing.T, name string, config VerifierConfig, options VerifyOptions) VerifyOutcome {
	t.Helper()
	record := goldenRecord(t, name)
	verifier, err := NewVerifier(NewMemoryStorage(), mustConfig(t, config, goldenIssuedAt))
	if err != nil {
		t.Fatalf("%s: verifier: %v", name, err)
	}
	storeRecord(t, verifier.Storage, record)
	token := solvedToken(t, record)
	return verifier.Verify(token, options)
}

func mustConfig(t *testing.T, config VerifierConfig, now int64) VerifierConfig {
	t.Helper()
	validated, err := NewVerifierConfig(config)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	validated.NowFunc = func() time.Time { return time.Unix(now, 0) }
	return validated
}

func solvedToken(t *testing.T, record *ChallengeRecord) string {
	t.Helper()
	if record.Algorithm == "rsw" {
		n := new(big.Int)
		n.SetBytes(mustDecodeB64(t, rswModulusOf(t, record)))
		return CreateToken(record.Nonce, 0, 5000, NewJSONObject(), "", "", solveRsw(record.Prefix, record.Nonce, n, record.T)).Encode()
	}
	if record.Algorithm == "argon2id" {
		return CreateToken(record.Nonce, solveArgon2(record.Prefix, record.Salt, record.TargetBits, record.T, record.MKib), 5000, NewJSONObject(), "", "", "").Encode()
	}
	return CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000, NewJSONObject(), "", "", "").Encode()
}

func rswModulusOf(t *testing.T, record *ChallengeRecord) string {
	t.Helper()
	document := readGolden(t, "golden_rsw_v5.json")
	rswDocument := document["rsw"].(map[string]interface{})
	if record.RswModulusSha256 != "" {
		fixture := loadRswFixture(t)
		if RswFingerprint(fixture.ModulusN) == record.RswModulusSha256 {
			return fixture.ModulusN
		}
	}
	return rswDocument["modulus_n"].(string)
}

var goldenOptions = VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"}

func TestGoldenSha256Ok(t *testing.T) {
	requireValid(t, goldenVerify(t, "golden_sha256_v2.json", VerifierConfig{}, goldenOptions))
}

func TestGoldenArgon2IdOk(t *testing.T) {
	requireValid(t, goldenVerify(t, "golden_argon2id_v2.json", VerifierConfig{}, goldenOptions))
}

func TestGoldenDecoyOk(t *testing.T) {
	// The decoy-armed v3 record verifies: the armed honeypot name rides
	// the signed canonical and demands nothing of the submission.
	requireValid(t, goldenVerify(t, "golden_decoy_v3.json", VerifierConfig{}, goldenOptions))
}

func TestGoldenRequestBindingOk(t *testing.T) {
	options := goldenOptions
	expectation := ExactBinding("tx-123")
	options.BindingExpectation = &expectation
	requireValid(t, goldenVerify(t, "golden_request_binding_v2.json", VerifierConfig{}, options))
}

func TestGoldenRegionIssuerOk(t *testing.T) {
	requireValid(t, goldenVerify(t, "golden_region_issuer_v2.json", VerifierConfig{
		Region:         "eu",
		ExpectedIssuer: "staging",
	}, goldenOptions))
}

func TestGoldenRswOk(t *testing.T) {
	document := readGolden(t, "golden_rsw_v5.json")
	rswDocument := document["rsw"].(map[string]interface{})
	requireValid(t, goldenVerify(t, "golden_rsw_v5.json", VerifierConfig{
		RswModulusN: rswDocument["modulus_n"].(string),
		RswLambda:   rswDocument["lambda"].(string),
	}, goldenOptions))
}

func TestGoldenTamperedChallengeFails(t *testing.T) {
	record := goldenRecord(t, "golden_sha256_v2.json")
	// A tampered challenge breaks the prefix binding and the signature.
	record.Challenge = strings.Repeat(record.Challenge[:len(record.Challenge)-1], 1) + "A"
	verifier, err := NewVerifier(NewMemoryStorage(), mustConfig(t, VerifierConfig{}, goldenIssuedAt))
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	storeRecord(t, verifier.Storage, record)
	token := CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000, NewJSONObject(), "", "", "").Encode()
	outcome := verifier.Verify(token, goldenOptions)
	if outcome.Valid {
		t.Fatalf("a tampered record must not verify")
	}
	// A scope rewrite is the clean bad_signature split: structurally
	// valid, wrongly signed.
	resigned := goldenRecord(t, "golden_sha256_v2.json")
	resigned.Scope = "logi"
	second, err := NewVerifier(NewMemoryStorage(), mustConfig(t, VerifierConfig{}, goldenIssuedAt))
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	storeRecord(t, second.Storage, resigned)
	token = CreateToken(resigned.Nonce, solveSha(resigned.Prefix, resigned.Salt, resigned.TargetBits), 5000, NewJSONObject(), "", "", "").Encode()
	scopeOptions := goldenOptions
	scopeOptions.ExpectedScope = ""
	requireCode(t, second.Verify(token, scopeOptions), ErrCodeBadSignature)
}

func TestGoldenExpired(t *testing.T) {
	// One second past the signed expiry the php record is dead.
	outcome := goldenVerify(t, "golden_sha256_v2.json", VerifierConfig{}, func() VerifyOptions {
		options := goldenOptions
		return options
	}())
	requireValid(t, outcome)
	verifier, err := NewVerifier(NewMemoryStorage(), mustConfig(t, VerifierConfig{}, goldenIssuedAt+121))
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	record := goldenRecord(t, "golden_sha256_v2.json")
	storeRecord(t, verifier.Storage, record)
	token := CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000, NewJSONObject(), "", "", "").Encode()
	requireCode(t, verifier.Verify(token, goldenOptions), ErrCodeExpired)
}

func TestGoldenWrongScope(t *testing.T) {
	options := goldenOptions
	options.ExpectedScope = "comment"
	requireCode(t, goldenVerify(t, "golden_sha256_v2.json", VerifierConfig{}, options), ErrCodeWrongScope)
}

func TestGoldenRolloutWindow(t *testing.T) {
	// The php record carries policy epoch 2.
	accepted := VerifierConfig{ExpectedPolicyVersion: 2}
	requireValid(t, goldenVerify(t, "golden_policy_epoch2_v2.json", accepted, goldenOptions))
	// The mixed fleet window: expected 3 with the floor 2 accepts the
	// draining epoch.
	floored := VerifierConfig{ExpectedPolicyVersion: 3, PolicyVersionFloor: 2}
	requireValid(t, goldenVerify(t, "golden_policy_epoch2_v2.json", floored, goldenOptions))
	// Strict equality refuses the draining epoch.
	strict := VerifierConfig{ExpectedPolicyVersion: 3}
	requireCode(t, goldenVerify(t, "golden_policy_epoch2_v2.json", strict, goldenOptions), ErrCodeWrongPolicyVersion)
	// An inverted window accepts nothing.
	inverted := VerifierConfig{ExpectedPolicyVersion: 2, PolicyVersionFloor: 3}
	requireCode(t, goldenVerify(t, "golden_policy_epoch2_v2.json", inverted, goldenOptions), ErrCodeWrongPolicyVersion)
}

func TestGoldenDecisionShape(t *testing.T) {
	record := goldenRecord(t, "golden_sha256_v2.json")
	verifier, err := NewVerifier(NewMemoryStorage(), mustConfig(t, VerifierConfig{}, goldenIssuedAt))
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	storeRecord(t, verifier.Storage, record)
	token := solvedToken(t, record)
	outcome := verifier.Verify(token, goldenOptions)
	decision := DecisionFromOutcome(outcome, PriceRung(record.Algorithm, record.TargetBits, record.MKib))
	if !decision.OK || decision.Disposition != DispositionAllow || decision.DecisionHandle != record.Nonce || decision.Price != "sha8" {
		t.Fatalf("the contract shape drift: %+v", decision)
	}
	// A denial carries the disposition verbs.
	denied := DecisionFromOutcome(InvalidOutcome(ErrCodeWrongScope), "")
	if denied.OK || denied.Disposition != DispositionDeny || denied.Error != "wrong_scope" {
		t.Fatalf("the denial shape drift: %+v", denied)
	}
	retry := DecisionFromOutcome(InvalidOutcome(ErrCodeStorageUnavailable), "")
	if retry.Disposition != DispositionRetry {
		t.Fatalf("a storage outage must answer retry")
	}
}
