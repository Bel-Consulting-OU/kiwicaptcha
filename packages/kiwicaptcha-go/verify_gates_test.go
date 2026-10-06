package kiwicaptcha

import (
	"testing"
)

func tokenForRecord(t *testing.T, record *ChallengeRecord) string {
	t.Helper()
	return CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000, NewJSONObject(JSONPair{Key: "me", Value: jsonNumber("1")}), "", "", "").Encode()
}

const goldenIssuedAt = 1_900_000_000

func TestVerifyGoldenSha256EndToEnd(t *testing.T) {
	record := goldenRecord(t, "golden_sha256_v2.json")
	verifier := newTestVerifier(t, VerifierConfig{}, goldenIssuedAt)
	storeRecord(t, verifier.Storage, record)
	token := CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000, NewJSONObject(), "", "", "").Encode()
	outcome := verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"})
	requireValid(t, outcome)
	if outcome.Nonce != record.Nonce {
		t.Fatalf("nonce drift")
	}
	if PriceRung(record.Algorithm, record.TargetBits, record.MKib) != "sha8" {
		t.Fatalf("price rung drift")
	}
}

func TestVerifyGateOrderAndCodes(t *testing.T) {
	t.Run("malformed token", func(t *testing.T) {
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		outcome := verifier.Verify("not-a-token", VerifyOptions{SecretKey: testSecret})
		requireCode(t, outcome, ErrCodeMalformedToken)
		if outcome.Detail != DecodeErrInvalidBase64 {
			t.Fatalf("detail drift: %s", outcome.Detail)
		}
	})
	t.Run("record not found", func(t *testing.T) {
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		token := CreateToken(shaVector.Nonce, 1, 1, NewJSONObject(), "", "", "").Encode()
		requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret}), ErrCodeRecordNotFound)
	})
	t.Run("bad signature", func(t *testing.T) {
		options := defaultMintOptions()
		record := mintRecord(t, options)
		// The scope is signed, so rewriting it breaks the hmac while
		// every structural check still passes.
		record.Scope = "logi"
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		token := CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000, NewJSONObject(), "", "", "").Encode()
		requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "", ClientIP: testClientIP}), ErrCodeBadSignature)
	})
	t.Run("expired", func(t *testing.T) {
		options := defaultMintOptions()
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testIssuedAt+121)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeExpired)
	})
	t.Run("future issuance", func(t *testing.T) {
		options := defaultMintOptions()
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testIssuedAt-MaxClockSkew-1)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeExpired)
	})
	t.Run("wrong scope", func(t *testing.T) {
		options := defaultMintOptions()
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "comment", ClientIP: testClientIP}), ErrCodeWrongScope)
	})
	t.Run("missing scope option is the typed required_scope refusal", func(t *testing.T) {
		options := defaultMintOptions()
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		// The empty scope option accepts nothing: the typed refusal
		// replaces the lax any-scope acceptance.
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ClientIP: testClientIP}), ErrCodeRequiredScope)
	})
	t.Run("missing client ip", func(t *testing.T) {
		options := defaultMintOptions()
		options.bindingIP = testClientIP
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login"}), ErrCodeMissingClientIP)
		// The retry path keeps the record so the caller can retry with
		// the ip.
		found, err := verifier.Storage.Find(record.Nonce)
		if err != nil || found == nil {
			t.Fatalf("the missing-ip failure must keep the record")
		}
	})
	t.Run("ip mismatch", func(t *testing.T) {
		options := defaultMintOptions()
		options.bindingIP = testClientIP
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "192.0.2.9"}), ErrCodeIPMismatch)
	})
	t.Run("wrong region", func(t *testing.T) {
		options := defaultMintOptions()
		options.region = "eu"
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{Region: "us"}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeWrongRegion)
	})
	t.Run("wrong issuer", func(t *testing.T) {
		options := defaultMintOptions()
		options.issuer = "staging"
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{ExpectedIssuer: "prod"}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeWrongIssuer)
	})
	t.Run("unbound record fails a region-bound verifier", func(t *testing.T) {
		record := mintRecord(t, defaultMintOptions())
		verifier := newTestVerifier(t, VerifierConfig{Region: "eu"}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeWrongRegion)
	})
	t.Run("wrong policy version", func(t *testing.T) {
		options := defaultMintOptions()
		options.policyVersion = 2
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{ExpectedPolicyVersion: 3}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeWrongPolicyVersion)
	})
	t.Run("policy rollout window accepts and rejects", func(t *testing.T) {
		options := defaultMintOptions()
		options.policyVersion = 2
		record := mintRecord(t, options)
		floored := newTestVerifier(t, VerifierConfig{ExpectedPolicyVersion: 3, PolicyVersionFloor: 2}, testNow)
		storeRecord(t, floored.Storage, record)
		requireValid(t, floored.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}))
		strict := newTestVerifier(t, VerifierConfig{ExpectedPolicyVersion: 3}, testNow)
		storeRecord(t, strict.Storage, record)
		requireCode(t, strict.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeWrongPolicyVersion)
		// A floor above the expected epoch accepts nothing.
		inverted := newTestVerifier(t, VerifierConfig{ExpectedPolicyVersion: 2, PolicyVersionFloor: 3}, testNow)
		storeRecord(t, inverted.Storage, record)
		requireCode(t, inverted.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeWrongPolicyVersion)
	})
	t.Run("revoked kid", func(t *testing.T) {
		options := defaultMintOptions()
		options.kid = 2
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{
			SecretsByKid: map[int]string{1: testSecret, 2: testSecret},
			RevokedKids:  map[int]bool{2: true},
		}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeUnknownKid)
	})
	t.Run("forward kid guard", func(t *testing.T) {
		options := defaultMintOptions()
		options.kid = 3
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{SecretsByKid: map[int]string{1: testSecret}}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeUnknownKid)
	})
	t.Run("kid rotation selects the secret", func(t *testing.T) {
		options := defaultMintOptions()
		options.kid = 2
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{SecretsByKid: map[int]string{1: "other-secret-other-secret-other-32", 2: testSecret}}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireValid(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: "unused", ExpectedScope: "login", ClientIP: testClientIP}))
	})
	t.Run("unsupported argon2 params", func(t *testing.T) {
		options := defaultMintOptions()
		options.algorithm = "argon2id"
		options.mKib = 131072
		options.t = 3
		options.targetBits = 4
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeUnsupportedArgon2)
	})
	t.Run("unsupported rsw params", func(t *testing.T) {
		options := defaultMintOptions()
		options.algorithm = "rsw"
		options.t = MinRswT - 1
		options.targetBits = RswTargetBitsPin
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeUnsupportedRswParams)
	})
	t.Run("too fast", func(t *testing.T) {
		options := defaultMintOptions()
		options.minDurationMs = 5000
		options.mintMetaMac = true
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testIssuedAt)
		storeRecord(t, verifier.Storage, record)
		outcome := verifier.Verify(tokenForRecord(t, record), VerifyOptions{
			SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP,
			NowNs: record.IssuedAtNs + 1_000_000, NowNsSet: true,
		})
		requireCode(t, outcome, ErrCodeTooFast)
		// Past the floor the same token verifies.
		fresh := mintRecord(t, options)
		storeRecord(t, verifier.Storage, fresh)
		outcome = verifier.Verify(tokenForRecord(t, fresh), VerifyOptions{
			SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP,
			NowNs: fresh.IssuedAtNs + 6_000_000, NowNsSet: true,
		})
		requireValid(t, outcome)
	})
	t.Run("unmeasured floor fails closed", func(t *testing.T) {
		options := defaultMintOptions()
		options.minDurationMs = 5000
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testIssuedAt)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{
			SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP,
			NowNs: record.IssuedAtNs + 6_000_000, NowNsSet: true,
		}), ErrCodeMalformedRecord)
	})
	t.Run("insufficient work", func(t *testing.T) {
		record := mintRecord(t, defaultMintOptions())
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		token := CreateToken(record.Nonce, 0, 5000, NewJSONObject(), "", "", "").Encode()
		requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeInsufficientWork)
		// The deterministic invalid outcome replays without re-deriving.
		replay, err := verifier.Storage.Consume(record.Nonce)
		if err != nil || replay == nil {
			t.Fatalf("the consumed record must be retained")
		}
		replayToken := CreateToken(record.Nonce, 0, 5000, NewJSONObject(), "", "", "").Encode()
		requireCode(t, verifier.Verify(replayToken, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeInsufficientWork)
	})
	t.Run("request binding mismatch", func(t *testing.T) {
		options := defaultMintOptions()
		options.requestBinding = "tx-123"
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		wrong := ExactBinding("tx-999")
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, BindingExpectation: &wrong}), ErrCodeRequestBinding)
		right := ExactBinding("tx-123")
		// The record burned on the first attempt: mint a fresh one.
		fresh := mintRecord(t, options)
		storeRecord(t, verifier.Storage, fresh)
		requireValid(t, verifier.Verify(tokenForRecord(t, fresh), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, BindingExpectation: &right}))
	})
	t.Run("unbound record under a presented binding", func(t *testing.T) {
		record := mintRecord(t, defaultMintOptions())
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		expectation := ExactBinding("tx-123")
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, BindingExpectation: &expectation}), ErrCodeRequestBinding)
		// The legacy mode passes the unbound record.
		fresh := mintRecord(t, defaultMintOptions())
		storeRecord(t, verifier.Storage, fresh)
		legacy := LegacyBinding("tx-123")
		requireValid(t, verifier.Verify(tokenForRecord(t, fresh), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, BindingExpectation: &legacy}))
	})
	t.Run("execution armed fails closed", func(t *testing.T) {
		record := goldenRecord(t, "golden_execution_v4.json")
		verifier := newTestVerifier(t, VerifierConfig{}, goldenIssuedAt)
		storeRecord(t, verifier.Storage, record)
		token := CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000,
			NewJSONObject(), stringsRepeat("ab", 32), "", "").Encode()
		requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"}), ErrCodeExecutionMismatch)
	})
	t.Run("stray execution evidence", func(t *testing.T) {
		record := mintRecord(t, defaultMintOptions())
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		token := CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000,
			NewJSONObject(), stringsRepeat("ab", 32), "", "").Encode()
		requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeExecutionMismatch)
	})
	t.Run("telemetry rejected and empty payload", func(t *testing.T) {
		options := defaultMintOptions()
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		// An empty telemetry payload is itself a bot signal.
		token := CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000, NewJSONObject(), "", "", "").Encode()
		requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, EnforceTelemetry: true}), ErrCodeTelemetryRejected)
		// Perfectly uniform event intervals trip the timing signal.
		events := make([]interface{}, 0, 30)
		for i := 0; i < 30; i++ {
			events = append(events, jsonNumber(itoaTest(i*10)))
		}
		fresh := mintRecord(t, options)
		storeRecord(t, verifier.Storage, fresh)
		uniform := NewJSONObject(JSONPair{Key: "et", Value: events})
		tokenUniform := CreateToken(fresh.Nonce, solveSha(fresh.Prefix, fresh.Salt, fresh.TargetBits), 5000, uniform, "", "", "").Encode()
		requireCode(t, verifier.Verify(tokenUniform, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, EnforceTelemetry: true}), ErrCodeTelemetryRejected)
		// Organic timings pass.
		organic := make([]interface{}, 0, 30)
		for i := 0; i < 30; i++ {
			organic = append(organic, jsonNumber(itoaTest(i*i+3)))
		}
		third := mintRecord(t, options)
		storeRecord(t, verifier.Storage, third)
		varied := NewJSONObject(JSONPair{Key: "et", Value: organic})
		tokenOrganic := CreateToken(third.Nonce, solveSha(third.Prefix, third.Salt, third.TargetBits), 5000, varied, "", "", "").Encode()
		requireValid(t, verifier.Verify(tokenOrganic, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, EnforceTelemetry: true}))
	})
	t.Run("capacity exceeded", func(t *testing.T) {
		options := defaultMintOptions()
		options.algorithm = "argon2id"
		options.mKib = 8
		options.t = 3
		options.targetBits = 1
		record := mintRecord(t, options)
		verifier := newTestVerifier(t, VerifierConfig{ArgonGate: ExhaustionGate{}}, testNow)
		storeRecord(t, verifier.Storage, record)
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeCapacityExceeded)
		// Exhaustion never consumes: the client can retry.
		found, err := verifier.Storage.Find(record.Nonce)
		if err != nil || found == nil {
			t.Fatalf("the exhaustion refusal must keep the record")
		}
	})
	t.Run("storage unavailable", func(t *testing.T) {
		record := mintRecord(t, defaultMintOptions())
		verifier, err := NewVerifier(failingStore{record: record}, VerifierConfig{})
		if err != nil {
			t.Fatalf("verifier: %v", err)
		}
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeStorageUnavailable)
	})
	t.Run("cancelled record answers not found", func(t *testing.T) {
		record := mintRecord(t, defaultMintOptions())
		verifier := newTestVerifier(t, VerifierConfig{}, testNow)
		storeRecord(t, verifier.Storage, record)
		cancellable, ok := verifier.Storage.(Cancellable)
		if !ok {
			t.Fatalf("the memory store must be cancellable")
		}
		if _, err := cancellable.Cancel(record.Nonce); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		requireCode(t, verifier.Verify(tokenForRecord(t, record), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeRecordNotFound)
	})
}

func itoaTest(value int) string {
	if value == 0 {
		return "0"
	}
	out := ""
	for value > 0 {
		out = string(rune('0'+value%10)) + out
		value /= 10
	}
	return out
}

// failingStore fails every read, the typed outage seam.
type failingStore struct{ record *ChallengeRecord }

func (f failingStore) Find(string) (*ChallengeRecord, error) {
	return nil, ErrStorageUnavailable
}
func (f failingStore) Delete(string) (bool, error) { return false, ErrStorageUnavailable }
func (f failingStore) Consume(string) (*ConsumedRecord, error) {
	return nil, ErrStorageUnavailable
}
func (f failingStore) CommitResult(string, bool, string) (bool, error) {
	return false, ErrStorageUnavailable
}

func TestVerifyConsumedIdentityGate(t *testing.T) {
	options := defaultMintOptions()
	options.bindingIP = testClientIP
	record := mintRecord(t, options)
	verifier := newTestVerifier(t, VerifierConfig{}, testNow)
	storeRecord(t, verifier.Storage, record)
	token := tokenForRecord(t, record)
	first := verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, OperationIdentity: "op-1"})
	requireValid(t, first)
	// The stored success replays only to the exact logical operation.
	replay := verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, OperationIdentity: "op-1"})
	requireValid(t, replay)
	if !replay.FromStoredResult {
		t.Fatalf("the replay must come from the stored result")
	}
	if replay.SolveDurationSet {
		t.Fatalf("a stored-result replay carries no solve duration")
	}
	requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeAlreadyConsumed)
	requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP, OperationIdentity: "op-2"}), ErrCodeAlreadyConsumed)
	// The ip binding is a replay-exempt circumstance: on a consumed
	// record it routes into the identity-gated consumed branch, so the
	// proven operation replays even from another network path.
	requireValid(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "192.0.2.9", OperationIdentity: "op-1"}))
	// A hard verdict is different: the stored success never replays
	// around a security failure. Scope is a hard invariant.
	requireCode(t, verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "comment", ClientIP: testClientIP, OperationIdentity: "op-1"}), ErrCodeWrongScope)
}

func TestVerifyArgon2VectorEndToEnd(t *testing.T) {
	record := vectorRecord(argon2Vector)
	verifier := newTestVerifier(t, VerifierConfig{AcceptLegacyV1: true}, testNow)
	storeRecord(t, verifier.Storage, record)
	outcome := verifier.Verify(vectorToken(argon2Vector, -1, -1), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP})
	requireValid(t, outcome)
}

func TestVerifySolveDurationMeasured(t *testing.T) {
	options := defaultMintOptions()
	options.mintMetaMac = true
	record := mintRecord(t, options)
	verifier := newTestVerifier(t, VerifierConfig{}, testIssuedAt)
	storeRecord(t, verifier.Storage, record)
	outcome := verifier.Verify(tokenForRecord(t, record), VerifyOptions{
		SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP,
		NowNs: record.IssuedAtNs + 12_500_000, NowNsSet: true,
	})
	requireValid(t, outcome)
	if !outcome.SolveDurationSet || outcome.SolveDurationMs != 12_500 {
		t.Fatalf("solve duration drift: %d %v", outcome.SolveDurationMs, outcome.SolveDurationSet)
	}
	// Without the metadata mac the measured duration is withheld.
	unmacced := mintRecord(t, defaultMintOptions())
	second := newTestVerifier(t, VerifierConfig{}, testIssuedAt)
	storeRecord(t, second.Storage, unmacced)
	outcome = second.Verify(tokenForRecord(t, unmacced), VerifyOptions{
		SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP,
		NowNs: unmacced.IssuedAtNs + 12_500_000, NowNsSet: true,
	})
	requireValid(t, outcome)
	if outcome.SolveDurationSet {
		t.Fatalf("an unauthenticated issuance clock must not report a duration")
	}
}

func TestVerifyLegacyV1Gate(t *testing.T) {
	record := vectorRecord(shaVector)
	verifier := newTestVerifier(t, VerifierConfig{}, testNow)
	storeRecord(t, verifier.Storage, record)
	requireCode(t, verifier.Verify(vectorToken(shaVector, -1, -1), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}), ErrCodeMalformedRecord)
	accepting := newTestVerifier(t, VerifierConfig{AcceptLegacyV1: true}, testNow)
	storeRecord(t, accepting.Storage, record)
	requireValid(t, accepting.Verify(vectorToken(shaVector, -1, -1), VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}))
}
