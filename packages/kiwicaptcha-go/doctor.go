package kiwicaptcha

import (
	"crypto/sha256"

	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"time"
)

// The doctor checks: one surface that validates a deployment. The
// command form lives in cmd/kiwicaptcha-doctor and runs four checks
// against a deployment description: the settings shape, the secret
// length, a full store roundtrip (store, find, consume, commit,
// delete) and the proof budget of the configured profile. Exit code 0
// means every check passed.

// DoctorCheck is one named check result.
type DoctorCheck struct {
	Name   string
	OK     bool
	Detail string
}

// profileBudgets map the named profiles onto the algorithm a standard
// issuance mints and its difficulty rung.
var profileBudgets = map[string]struct {
	algorithm string
	bits      int
	memoryKib int
}{
	"standard": {algorithm: "sha256", bits: 12},
	"argon16":  {algorithm: "argon2id", bits: 8, memoryKib: 16},
	"argon32":  {algorithm: "argon2id", bits: 6, memoryKib: 32},
	"argon64":  {algorithm: "argon2id", bits: 4, memoryKib: 64},
}

// DoctorCheckSettings validates the settings shape and the secret
// length.
func DoctorCheckSettings(secret, profile string) DoctorCheck {
	if len(secret) < MinSecretBytes {
		return DoctorCheck{Name: "settings", Detail: fmt.Sprintf("the secret must be at least %d bytes", MinSecretBytes)}
	}
	if !ProfileKnown(profile) {
		return DoctorCheck{Name: "settings", Detail: "the profile must be one of standard, argon16, argon32, argon64"}
	}
	return DoctorCheck{Name: "settings", OK: true, Detail: "the settings shape is valid"}
}

// doctorSelfCheckRecord mints a locally signed self-check record that
// never leaves the store.
func doctorSelfCheckRecord() (*ChallengeRecord, error) {
	secret := "kiwicaptcha-doctor-self-check-secret-0000"
	nonceBytes := make([]byte, NonceB64Bytes)
	if _, err := randomRead(nonceBytes); err != nil {
		return nil, err
	}
	saltBytes := make([]byte, SaltB64Bytes)
	if _, err := randomRead(saltBytes); err != nil {
		return nil, err
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	salt := base64.StdEncoding.EncodeToString(saltBytes)
	now := time.Now().Unix()
	expires := now + 60
	payload := CanonicalPayload(2, nonce, "doctor", "", now, expires, "sha256", 1, 1, 1, 1, salt, 0, "", 1, "", "", 1, "", 0, "", "", false)
	signature, err := SignPayloadV2(payload, secret, "")
	if err != nil {
		return nil, err
	}
	challenge := payload + "." + signature
	prefix := challenge + "|" + salt + "|"
	return &ChallengeRecord{
		Nonce:           nonce,
		Scope:           "doctor",
		BindingTag:      "",
		IssuedAt:        now,
		ExpiresAt:       expires,
		Algorithm:       "sha256",
		MKib:            1,
		T:               1,
		P:               1,
		TargetBits:      1,
		Salt:            salt,
		Prefix:          prefix,
		Challenge:       challenge,
		MinDurationMs:   0,
		ProtocolVersion: 2,
		PolicyVersion:   1,
		Kid:             1,
	}, nil
}

// DoctorCheckStore opens the store url and runs a full one-shot
// roundtrip. The store is closed when the caller passed a closer.
func DoctorCheckStore(storeURL string) (DoctorCheck, Store, error) {
	storage, err := OpenStore(storeURL)
	if err != nil {
		return DoctorCheck{Name: "store", Detail: "the store did not open: " + err.Error()}, nil, nil
	}
	record, err := doctorSelfCheckRecord()
	if err != nil {
		return DoctorCheck{Name: "store", Detail: "the self-check record failed: " + err.Error()}, storage, nil
	}
	storer, ok := storage.(Storer)
	if !ok {
		return DoctorCheck{Name: "store", Detail: "the store cannot accept records"}, storage, nil
	}
	if err := storer.StoreRecord(record); err != nil {
		return DoctorCheck{Name: "store", Detail: "the store rejected the record: " + err.Error()}, storage, nil
	}
	found, err := storage.Find(record.Nonce)
	if err != nil || found == nil {
		return DoctorCheck{Name: "store", Detail: "the store lost the record"}, storage, nil
	}
	consumed, err := storage.Consume(record.Nonce)
	if err != nil || consumed == nil || !consumed.ConsumedNow {
		return DoctorCheck{Name: "store", Detail: "the consume transition did not win"}, storage, nil
	}
	committed, err := storage.CommitResult(record.Nonce, true, "")
	if err != nil || !committed {
		return DoctorCheck{Name: "store", Detail: "the commit refused"}, storage, nil
	}
	deleted, err := storage.Delete(record.Nonce)
	if err != nil || !deleted {
		return DoctorCheck{Name: "store", Detail: "the delete refused"}, storage, nil
	}
	return DoctorCheck{Name: "store", OK: true, Detail: "the store roundtrip is one-shot and clean"}, storage, nil
}

// DoctorCheckScopes validates every configured scope.
func DoctorCheckScopes(scopes []string) DoctorCheck {
	for _, scope := range scopes {
		if !IsValidIdentifier(scope, 128) {
			return DoctorCheck{Name: "scopes", Detail: fmt.Sprintf("the scope %q is not a valid identifier", scope)}
		}
	}
	if len(scopes) == 0 {
		return DoctorCheck{Name: "scopes", OK: true, Detail: "no scopes configured (every scope is accepted)"}
	}
	detail := "every scope is a valid identifier:"
	for _, scope := range scopes {
		detail += " " + scope
	}
	return DoctorCheck{Name: "scopes", OK: true, Detail: detail}
}

// DoctorCheckProofBudget measures the proof budget of the configured
// profile: a sha256 difficulty search or one argon2id derivation.
func DoctorCheckProofBudget(profile string) DoctorCheck {
	budget, ok := profileBudgets[profile]
	if !ok {
		return DoctorCheck{Name: "proof_budget", Detail: "the profile must be one of standard, argon16, argon32, argon64"}
	}
	salt := make([]byte, SaltB64Bytes)
	started := time.Now()
	if budget.algorithm == "sha256" {
		prefix := "doctor|"
		for counter := 0; counter <= 2_000_000; counter++ {
			digest := sha256.Sum256([]byte(prefix + fmt.Sprint(counter) + string(salt)))
			if LeadingZeroBits(digest[:]) >= budget.bits {
				elapsed := time.Since(started).Milliseconds()
				return DoctorCheck{Name: "proof_budget", OK: true, Detail: fmt.Sprintf("sha256 at %d bits solved in %d ms (%d iterations)", budget.bits, elapsed, counter)}
			}
		}
		return DoctorCheck{Name: "proof_budget", Detail: "the sha256 budget search ran away"}
	}
	_ = argon2.IDKey([]byte("doctor"), salt, 3, uint32(budget.memoryKib), 1, 32)
	elapsed := time.Since(started).Milliseconds()
	return DoctorCheck{Name: "proof_budget", OK: true, Detail: fmt.Sprintf("argon2id m=%d t=3 derived in %d ms; the %s rung accepts %d target bits", budget.memoryKib, elapsed, profile, budget.bits)}
}

// DoctorRun executes every check and reports them in order. The store
// returned, when non-nil, stays open for the caller to close.
func DoctorRun(secret, storeURL string, scopes []string, profile string) ([]DoctorCheck, Store) {
	results := []DoctorCheck{DoctorCheckSettings(secret, profile)}
	storeCheck, store, _ := DoctorCheckStore(storeURL)
	results = append(results, storeCheck, DoctorCheckScopes(scopes), DoctorCheckProofBudget(profile))
	return results, store
}
