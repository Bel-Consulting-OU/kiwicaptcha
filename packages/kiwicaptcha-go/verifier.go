package kiwicaptcha

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"time"

	"golang.org/x/crypto/argon2"
)

// The solution verifier: the exact cheap-gate order and the consumed
// resolution of the php Verifier, over the storage seam.
//
// The gate order is normative: nonce match, structure, protocol gate,
// kid revocation, kid resolution, signature, argon2id ceilings, rsw
// bounds, ttl, scope, request binding, ip binding, region, policy
// epoch, issuer, execution binding and minimum duration. The policy
// epoch carries the rollout-floor window. Then comes the opt-in
// telemetry gate, the terminal-state resolution, the admission gate,
// consume, proof, the post-derive final revalidation and the result
// commit.
//
// Verify is pure-local: it never calls out to any network service.
// The only side effects are the storage transitions the one-shot
// model requires. Execution-armed records (the signed e= commitment)
// are refused deterministically with execution_mismatch: the browser
// trace walker is a browser-behavior oracle this SDK does not carry,
// and an armed record must never pass without it.

// RequestBindingExpectation is the explicit request-binding
// enforcement policy. ExactBinding is Option-equality: an empty
// expected binding equals an explicitly unbound record and a set value
// equals the same bound transaction. LegacyBinding reproduces the
// historical nullable behavior, where an empty expected binding
// disables enforcement and a set expectation compares only records
// that carry one. UnenforcedBinding skips the check entirely.
type RequestBindingExpectation struct {
	Enforced               bool
	Expected               string
	RequireBindingPresence bool
}

// UnenforcedBinding skips the request-binding check.
func UnenforcedBinding() RequestBindingExpectation {
	return RequestBindingExpectation{}
}

// ExactBinding requires Option-equality with the expected binding.
func ExactBinding(expected string) RequestBindingExpectation {
	return RequestBindingExpectation{Enforced: true, Expected: expected, RequireBindingPresence: true}
}

// LegacyBinding is the explicitly named compatibility mode.
func LegacyBinding(expected string) RequestBindingExpectation {
	return RequestBindingExpectation{Enforced: expected != "", Expected: expected}
}

// ExecutionEvidence is the execution digest and trace one solution
// token carries.
type ExecutionEvidence struct {
	Digest string
	Trace  string
}

// IsEmpty reports the unarmed evidence shape.
func (e ExecutionEvidence) IsEmpty() bool { return e.Digest == "" && e.Trace == "" }

// ExecutionEvidenceFromToken extracts the evidence of one token.
func ExecutionEvidenceFromToken(token *SolutionToken) ExecutionEvidence {
	return ExecutionEvidence{Digest: token.ExecutionDigest, Trace: token.ExecutionTrace}
}

// AdmissionGate is the admission-gate seam, mirroring the php
// VerificationAdmissionGate. Acquire returns a lease when a slot was
// granted, nil on exhaustion, or an error when the admission backend
// itself failed. Release returns the lease; a failing release must
// never break the verification, since the challenge is already
// consumed. Implement the interface to bind a semaphore, a token
// bucket or any bounded pool.
type AdmissionGate interface {
	Acquire() (lease interface{}, err error)
	Release(lease interface{})
}

// PassThroughGate is the default admission gate that always grants.
type PassThroughGate struct{}

// Acquire grants a slot.
func (PassThroughGate) Acquire() (interface{}, error) { return struct{}{}, nil }

// Release returns the slot.
func (PassThroughGate) Release(interface{}) {}

// ExhaustionGate models a full admission pool: Acquire always refuses.
type ExhaustionGate struct{}

// Acquire refuses.
func (ExhaustionGate) Acquire() (interface{}, error) { return nil, nil }

// Release does nothing.
func (ExhaustionGate) Release(interface{}) {}

// VerifierConfig carries the verifier construction options, mirroring
// the php constructor. NowFunc returns the wall clock and stands in
// for it in tests. SecretsByKid maps positive kid values to secrets of
// at least 32 bytes; an empty map keeps the legacy single-secret path.
// RswModulusN and RswLambda must be configured together or both left
// empty.
type VerifierConfig struct {
	ArgonGate              AdmissionGate
	NowFunc                func() time.Time
	AcceptLegacyV1         bool
	Region                 string
	ExpectedPolicyVersion  int
	ExpectedIssuer         string
	SecretsByKid           map[int]string
	RevokedKids            map[int]bool
	RswModulusN            string
	RswLambda              string
	TenantID               string
	RswVerificationKeys    map[string]RswKeyPair
	AllowLegacyRswIdentity bool
	PolicyVersionFloor     int

	resolvedConfigFields
}

// RswKeyPair is one trapdoor entry of the rotation keyring.
type RswKeyPair struct {
	ModulusN string
	Lambda   string
}

// VerifierBuildError reports an invalid construction.
type VerifierBuildError struct{ Reason string }

func (e *VerifierBuildError) Error() string {
	return "kiwicaptcha: invalid verifier config: " + e.Reason
}

// NewVerifierConfig validates the construction options and resolves
// the rsw trapdoors once at build time, mirroring the php memo.
func NewVerifierConfig(config VerifierConfig) (VerifierConfig, error) {
	for kid, secret := range config.SecretsByKid {
		if kid < 1 || len(secret) < MinSecretBytes {
			return config, &VerifierBuildError{Reason: "secrets by kid must map positive integer kids to secrets of at least 32 bytes"}
		}
	}
	for kid := range config.RevokedKids {
		if kid < 1 {
			return config, &VerifierBuildError{Reason: "revoked kids must be positive integers 1..N"}
		}
	}
	if (config.RswModulusN == "") != (config.RswLambda == "") {
		return config, &VerifierBuildError{Reason: "rsw modulus and lambda must be configured together (the rsw trapdoor pair)"}
	}
	if config.TenantID != "" && !IsValidIdentifier(config.TenantID, 64) {
		return config, &VerifierBuildError{Reason: "tenant id must be 1..64 bytes of [A-Za-z0-9._:-] when set"}
	}
	if config.NowFunc == nil {
		config.NowFunc = time.Now
	}
	if config.ArgonGate == nil {
		config.ArgonGate = PassThroughGate{}
	}
	if config.ExpectedPolicyVersion < 0 || config.PolicyVersionFloor < 0 {
		return config, &VerifierBuildError{Reason: "policy versions are non negative"}
	}
	activeRsw := (*Rsw)(nil)
	if config.RswModulusN != "" {
		decoded, err := NewRsw(config.RswModulusN, config.RswLambda)
		if err != nil {
			return config, err
		}
		activeRsw = decoded
	}
	config.activeRsw = activeRsw
	config.rswByHash = map[string]*Rsw{}
	config.rswModulusByHash = map[string]string{}
	for hash, pair := range config.RswVerificationKeys {
		if !isHex64(hash) {
			return config, &VerifierBuildError{Reason: "rsw verification keys must map a 64 hex modulus sha256 to a pair"}
		}
		if pair.ModulusN == "" || pair.Lambda == "" {
			return config, &VerifierBuildError{Reason: "rsw verification key values must be a non-empty {modulus_n, lambda} pair"}
		}
		if !RswIdentityMatches(hash, pair.ModulusN, config.AllowLegacyRswIdentity) {
			return config, &VerifierBuildError{Reason: "rsw verification key hashes must be the canonical sha256 of the decoded modulus (or its legacy base64-text alias while the migration mode is enabled)"}
		}
		trapdoor, err := NewRsw(pair.ModulusN, pair.Lambda)
		if err != nil {
			return config, err
		}
		identities := map[string]bool{hash: true}
		if fingerprint := RswFingerprint(pair.ModulusN); fingerprint != "" {
			identities[fingerprint] = true
		}
		if config.AllowLegacyRswIdentity {
			identities[RswLegacyIdentity(pair.ModulusN)] = true
		}
		for identity := range identities {
			config.rswByHash[identity] = trapdoor
			config.rswModulusByHash[identity] = pair.ModulusN
		}
	}
	return config, nil
}

// verifierResolved carries the trapdoors NewVerifierConfig resolved.
type resolvedConfigFields struct {
	activeRsw        *Rsw
	rswByHash        map[string]*Rsw
	rswModulusByHash map[string]string
}

// Verifier is the one-shot solution verifier over a store adapter.
type Verifier struct {
	Storage Store
	Config  VerifierConfig
	resolvedConfigFields
}

// NewVerifier builds a verifier over a validated config.
func NewVerifier(storage Store, config VerifierConfig) (*Verifier, error) {
	validated, err := NewVerifierConfig(config)
	if err != nil {
		return nil, err
	}
	return &Verifier{Storage: storage, Config: validated, resolvedConfigFields: resolvedConfigFields{
		activeRsw:        validated.activeRsw,
		rswByHash:        validated.rswByHash,
		rswModulusByHash: validated.rswModulusByHash,
	}}, nil
}

func (v *Verifier) nowSecs() int64 {
	return v.Config.NowFunc().Unix()
}

// VerifyOptions is one verify call's parameters.
type VerifyOptions struct {
	SecretKey              string
	ExpectedScope          string
	ClientIP               string
	NowNs                  int64
	NowNsSet               bool
	EnforceTelemetry       bool
	OperationIdentity      string
	ExpectedRequestBinding string
	BindingExpectation     *RequestBindingExpectation
	// ExecutionPolicy shapes the execution-armed dimension: nil (the
	// default) fails every armed record closed; the sidecar policy
	// delegates that single verification to a co-located
	// kiwicaptcha-verifier sidecar (see sidecar.go).
	ExecutionPolicy *ExecutionPolicy
}

// ValidateRecord is the structural validation of a stored record
// before any crypto or timing work: the protocol grammar, the scope
// shape, the nonce and salt sizes, the ttl ceiling, the prefix
// binding, the per-algorithm difficulty range, the decoy alphabet and
// the execution commitment equivalence. A record failing any check is
// malformed; it cannot have come from a KiwiCaptcha issuer.
func (v *Verifier) ValidateRecord(record *ChallengeRecord) bool {
	if record.ProtocolVersion < 1 || record.ProtocolVersion > MaxProtocolVersion {
		return false
	}
	executionPresent := record.ExecutionProgram != ""
	if !ProtocolExtensionGrammarOk(record.ProtocolVersion, record.DecoyField != "", executionPresent, record.RswModulusSha256 != "") {
		return false
	}
	if !IsValidIdentifier(record.Scope, 128) {
		return false
	}
	if record.DecoyField != "" && !IsValidDecoyFieldName(record.DecoyField) {
		return false
	}
	if executionPresent {
		if record.ExecutionVersion < 1 || record.ExecutionVersion > MaxExecutionVersion || record.ExecutionCommitment == "" {
			return false
		}
		if !isHex64(record.ExecutionCommitment) {
			return false
		}
		if !ConstantTimeEquals(ExecutionCommitment(record.ExecutionProgram), record.ExecutionCommitment) {
			return false
		}
	} else if record.ExecutionVersion != 0 || record.ExecutionCommitment != "" {
		return false
	}
	if record.RswModulusSha256 != "" {
		if record.Algorithm != "rsw" || !isHex64(record.RswModulusSha256) {
			return false
		}
	}
	nonceBytes, ok := canonicalB64Decode(record.Nonce)
	if !ok || len(nonceBytes) != NonceB64Bytes {
		return false
	}
	saltBytes, ok := canonicalB64Decode(record.Salt)
	if !ok || len(saltBytes) != SaltB64Bytes {
		return false
	}
	if record.ExpiresAt <= record.IssuedAt || record.ExpiresAt-record.IssuedAt > MaxTtlSecs {
		return false
	}
	if !ConstantTimeEquals(record.Challenge+"|"+record.Salt+"|", record.Prefix) {
		return false
	}
	if record.TargetBits < MinDifficulty || record.TargetBits > MaxDifficulty {
		return false
	}
	if executionPresent && !IsValidExecutionProgram(record.ExecutionProgram) {
		return false
	}
	return true
}

// isRevokedKid reports the compromise-revocation gate.
func (v *Verifier) isRevokedKid(kid int) bool {
	return v.Config.RevokedKids[kid]
}

// secretForKey selects the signature secret for a record. With an
// empty secrets set the legacy single-secret path stays. An unknown
// kid, or one beyond the newest configured kid, yields ok false: the
// rollback and forward guard keeps a future-keyed challenge from
// verifying on an older node.
func (v *Verifier) secretForKey(record *ChallengeRecord, legacySecret string) (string, bool) {
	if len(v.Config.SecretsByKid) == 0 {
		return legacySecret, true
	}
	newest := 0
	for kid := range v.Config.SecretsByKid {
		if kid > newest {
			newest = kid
		}
	}
	kid := record.KidOrOne()
	if kid > newest {
		return "", false
	}
	secret, ok := v.Config.SecretsByKid[kid]
	if !ok {
		return "", false
	}
	return secret, true
}

// argon2CeilingsOk applies the absolute process ceilings to the signed
// parameters before any allocation. True for sha256 records.
func (v *Verifier) argon2CeilingsOk(record *ChallengeRecord) bool {
	if record.Algorithm != "argon2id" {
		return true
	}
	return record.MKib >= MinArgonMemoryKib && record.MKib <= MaxArgonMemoryKib &&
		record.T >= MinArgonTime && record.T <= MaxArgonTime &&
		record.P >= MinParallelism && record.P <= MaxParallelism
}

// rswParamsOk bounds the signed sequential cost to the issuance range.
// The verifier-side trapdoor check costs one modular exponentiation
// regardless of T, so the bound keeps the signed parameter space
// canonical rather than capping server work. True for non-rsw records.
func (v *Verifier) rswParamsOk(record *ChallengeRecord) bool {
	if record.Algorithm != "rsw" {
		return true
	}
	return record.T >= MinRswT && record.T <= MaxRswT
}

// checkAuthenticatedShape is the authenticated hard core of the cheap
// phase: structural validation, the protocol version gate, kid
// revocation and resolution, the hmac signature re-check, and the
// process ceilings. Shared by the cheap phase and the compositional
// replay gate.
func (v *Verifier) checkAuthenticatedShape(record *ChallengeRecord, legacySecret string) (VerifyError, string) {
	if !v.ValidateRecord(record) {
		return ErrCodeMalformedRecord, ""
	}
	if record.ProtocolVersion == 1 && !v.Config.AcceptLegacyV1 {
		return ErrCodeMalformedRecord, ""
	}
	if v.isRevokedKid(record.KidOrOne()) {
		return ErrCodeUnknownKid, ""
	}
	signingSecret, ok := v.secretForKey(record, legacySecret)
	if !ok {
		return ErrCodeUnknownKid, ""
	}
	if !VerifyRecordSignature(record, signingSecret, v.Config.TenantID) {
		return ErrCodeBadSignature, ""
	}
	if !v.argon2CeilingsOk(record) {
		return ErrCodeUnsupportedArgon2, signingSecret
	}
	if !v.rswParamsOk(record) {
		return ErrCodeUnsupportedRswParams, signingSecret
	}
	return "", signingSecret
}

// checkTtl is the ttl window on the verifier's clock: expired, or an
// issuance more than the future-skew bound ahead. The exempt expiry
// circumstance, deliberately excluded from the compositional replay
// gate.
func (v *Verifier) checkTtl(record *ChallengeRecord) VerifyError {
	now := v.nowSecs()
	if now >= record.ExpiresAt {
		return ErrCodeExpired
	}
	if record.IssuedAt > now+MaxClockSkew {
		return ErrCodeExpired
	}
	return ""
}

// checkRequestBinding is the single request-binding check: exact
// Option-equality between the record's signed request binding and the
// expectation's authoritative binding, compared in constant time when
// both sides carry a string.
func (v *Verifier) checkRequestBinding(record *ChallengeRecord, expectation RequestBindingExpectation) VerifyError {
	if !expectation.Enforced {
		return ""
	}
	if record.RequestBinding == "" || expectation.Expected == "" {
		if record.RequestBinding == "" && !expectation.RequireBindingPresence {
			return ""
		}
		if record.RequestBinding == expectation.Expected {
			return ""
		}
		return ErrCodeRequestBinding
	}
	if ConstantTimeEquals(record.RequestBinding, expectation.Expected) {
		return ""
	}
	return ErrCodeRequestBinding
}

// checkScopeAndBinding runs the scope validation and the expected
// request binding, hard authorization invariants in cheap-phase order.
// The expected scope is REQUIRED: an empty scope option answers the
// typed required_scope failure instead of silently accepting a token
// minted for any scope the issuer serves.
func (v *Verifier) checkScopeAndBinding(record *ChallengeRecord, expectedScope string, expectation RequestBindingExpectation) VerifyError {
	if expectedScope == "" {
		return ErrCodeRequiredScope
	}
	if record.Scope != expectedScope {
		return ErrCodeWrongScope
	}
	return v.checkRequestBinding(record, expectation)
}

// checkIPBinding is the ip binding check. The stored record is
// authoritative. An empty binding tag means binding is disabled. A
// nonempty tag means the challenge is bound, so a missing client ip
// fails closed instead of silently skipping the check. A client ip
// that cannot be canonicalized at all resolves to the typed mismatch
// instead of an escaped error.
func (v *Verifier) checkIPBinding(record *ChallengeRecord, clientIP, signingSecret string) VerifyError {
	if record.BindingTag == "" {
		return ""
	}
	if clientIP == "" {
		return ErrCodeMissingClientIP
	}
	var expectedTag string
	if record.ProtocolVersion == 1 {
		expectedTag = HashIPV1(clientIP, signingSecret)
	} else {
		computed, err := BindingTag(record.Nonce, clientIP, signingSecret, v.Config.TenantID)
		if err != nil {
			return ErrCodeIPMismatch
		}
		expectedTag = computed
	}
	if !ConstantTimeEquals(expectedTag, record.BindingTag) {
		return ErrCodeIPMismatch
	}
	return ""
}

// policyVersionAccepted reports whether the record's security-policy
// epoch satisfies the configured expectations: no expected epoch
// disables the check entirely; no declared floor keeps the strict
// equality contract; a declared rollout window accepts
// floor <= epoch <= expected. A floor above the expected epoch accepts
// nothing, so the window is fail-closed, never a licence to verify
// below the newest declared epoch.
func (v *Verifier) policyVersionAccepted(recordVersion int) bool {
	if v.Config.ExpectedPolicyVersion == 0 {
		return true
	}
	if v.Config.PolicyVersionFloor == 0 {
		return recordVersion == v.Config.ExpectedPolicyVersion
	}
	return v.Config.PolicyVersionFloor <= recordVersion && recordVersion <= v.Config.ExpectedPolicyVersion
}

// checkDeploymentExpectations runs region, policy epoch and issuer,
// hard invariants in cheap-phase order.
func (v *Verifier) checkDeploymentExpectations(record *ChallengeRecord) VerifyError {
	if v.Config.Region != "" && record.Region != v.Config.Region {
		return ErrCodeWrongRegion
	}
	if !v.policyVersionAccepted(record.PolicyVersionOrOne()) {
		return ErrCodeWrongPolicyVersion
	}
	if v.Config.ExpectedIssuer != "" && record.Issuer != v.Config.ExpectedIssuer {
		return ErrCodeWrongIssuer
	}
	return ""
}

// checkExecutionBinding is the execution binding check. An unarmed
// record demands no digest: a presented digest is stray execution
// evidence and is rejected deterministically, never silently ignored.
//
// An armed record demands the browser-trace walker, a browser-behavior
// oracle this SDK does not carry. The armed dimension fails closed:
// the record's own authenticated program and commitment still verify,
// but no submission can satisfy the armed binding, matching the
// mandate that a missing capability must never widen acceptance.
func (v *Verifier) checkExecutionBinding(record *ChallengeRecord, evidence ExecutionEvidence) VerifyError {
	if record.ExecutionProgram == "" {
		if evidence.IsEmpty() {
			return ""
		}
		return ErrCodeExecutionMismatch
	}
	return ErrCodeExecutionMismatch
}

// checkMinDuration is the server-measured minimum duration. Elapsed
// time is the gap between the record's high-resolution issuance
// timestamp and the verification receipt time. The client-reported
// duration is forgeable, so it never drives the check; a record
// without an authenticated issuance clock cannot be timed and fails
// closed.
func (v *Verifier) checkMinDuration(record *ChallengeRecord, nowNs int64, nowNsSet bool) VerifyError {
	if record.IssuedAtNs <= 0 {
		return ErrCodeMalformedRecord
	}
	floor := record.MinDurationMs
	if floor < 0 {
		floor = 0
	}
	if floor == 0 {
		return ""
	}
	if record.ServerMac == "" {
		// The issuance clock is unauthenticated: a storage writer could
		// have backdated it, so the floor cannot be evaluated and fails
		// closed. The mac itself was verified with the signature before
		// this check.
		return ErrCodeMalformedRecord
	}
	receiptNs := nowNs
	if !nowNsSet {
		receiptNs = time.Now().UnixMicro()
	}
	if receiptNs >= record.IssuedAtNs {
		if receiptNs-record.IssuedAtNs < int64(floor)*1_000 {
			return ErrCodeTooFast
		}
	} else if record.IssuedAtNs-receiptNs > SkewToleranceUs {
		// Receipt before issuance by more than the skew bound is
		// physically impossible. Within the bound the two hosts' clocks
		// are unsynced, so the elapsed time cannot be measured reliably,
		// the floor check is skipped and the proof-of-work check still
		// applies.
		return ErrCodeTooFast
	}
	return ""
}

// measurableSolveDurationMs is the server-measured solve duration of a
// verified record in milliseconds: the span between the record's
// issuance timestamp and this verification's receipt clock. Exposed
// only on the valid outcome of a fresh derivation. A stored-success
// replay carries no value: the retry's receipt is not the solve's
// endpoint, so the value remains unforgeable behavioral evidence. The
// second return reports whether a value was measured.
func (v *Verifier) measurableSolveDurationMs(record *ChallengeRecord, receiptNs int64, receiptSet bool) (int64, bool) {
	if record.ServerMac == "" || record.IssuedAtNs <= 0 || !receiptSet || receiptNs < record.IssuedAtNs {
		return 0, false
	}
	return (receiptNs - record.IssuedAtNs) / 1_000, true
}

// cheapPhaseCheck runs the shared security checks in the order of the
// ordinary path; the first failing check decides the outcome.
func (v *Verifier) cheapPhaseCheck(
	record *ChallengeRecord,
	tokenNonce, secretKey, expectedScope, clientIP string,
	checkTiming bool,
	nowNs int64, nowNsSet bool,
	expectation RequestBindingExpectation,
	evidence ExecutionEvidence,
	delegateExecution bool,
) VerifyError {
	if record.Nonce != tokenNonce {
		return ErrCodeMalformedRecord
	}
	err, _ := v.checkAuthenticatedShape(record, secretKey)
	if err != "" {
		return err
	}
	signingSecret, _ := v.secretForKey(record, secretKey)
	if checkTiming {
		if err := v.checkTtl(record); err != "" {
			return err
		}
	}
	if err := v.checkScopeAndBinding(record, expectedScope, expectation); err != "" {
		return err
	}
	if err := v.checkIPBinding(record, clientIP, signingSecret); err != "" {
		return err
	}
	if err := v.checkDeploymentExpectations(record); err != "" {
		return err
	}
	if !delegateExecution {
		// The delegation path leaves the execution gate to the
		// sidecar's full-core pass; every other gate stays local.
		if err := v.checkExecutionBinding(record, evidence); err != "" {
			return err
		}
	}
	if checkTiming {
		if err := v.checkMinDuration(record, nowNs, nowNsSet); err != "" {
			return err
		}
	}
	return ""
}

// replaySecurityCheck is the compositional replay gate: every
// non-exempt hard invariant, evaluated with the exempt circumstances
// left out. Those circumstances may have caused the cheap phase's
// first failure on a consumed record, and an exempt failure that sits
// early in the cheap-phase order would otherwise shadow every later
// hard verdict. When the cheap phase fails with a replay-exempt error
// on a consumed record, this check re-evaluates the full hard set on
// the same record; any failure wins outright with the consumed
// evidence preserved.
func (v *Verifier) replaySecurityCheck(
	record *ChallengeRecord,
	secretKey, expectedScope string,
	expectation RequestBindingExpectation,
	evidence ExecutionEvidence,
	receiptNs int64, receiptSet bool,
) VerifyError {
	if err, _ := v.checkAuthenticatedShape(record, secretKey); err != "" {
		return err
	}
	if err := v.checkScopeAndBinding(record, expectedScope, expectation); err != "" {
		return err
	}
	if err := v.checkDeploymentExpectations(record); err != "" {
		return err
	}
	if err := v.checkExecutionBinding(record, evidence); err != "" {
		return err
	}
	if err := v.checkMinDuration(record, receiptNs, receiptSet); err != "" {
		return err
	}
	return ""
}

// retainedConsumedState is the retained consumed-state tri-state,
// best-effort read. The second return reports readability: a read
// failure is fail-closed, since the record may be consumed evidence
// that must never be deleted.
func (v *Verifier) retainedConsumedState(nonce string) (status string, readable bool) {
	reader, capable := v.Storage.(ConsumedStateReader)
	if !capable {
		return "unknown", true
	}
	consumed, err := reader.ConsumedState(nonce)
	if err != nil {
		return "unreadable", false
	}
	if consumed != nil {
		return "consumed", true
	}
	return "pending", true
}

func (v *Verifier) bestEffortDelete(nonce string) {
	_, _ = v.Storage.Delete(nonce)
}

// deriveHash re-derives the proof-of-work hash. sha256 hashes
// prefix, counter and salt bytes; argon2id derives with the signed
// parameters and a 32-byte tag. Returns an unsupported-algorithm
// marker for an rsw record and an error for a parameter profile this
// verifier cannot reproduce.
var errUnsupportedDerivation = errors.New("kiwicaptcha: the derivation cannot be computed")

func (v *Verifier) deriveHash(record *ChallengeRecord, counter int) ([]byte, error) {
	saltBytes, ok := canonicalB64Decode(record.Salt)
	if !ok {
		return nil, errUnsupportedDerivation
	}
	password := record.Prefix + strconv.Itoa(counter)
	switch record.Algorithm {
	case "sha256":
		sum := sha256.Sum256(append([]byte(password), saltBytes...))
		return sum[:], nil
	case "argon2id":
		return v.argon2idDerive(password, saltBytes, record)
	default:
		return nil, errUnsupportedDerivation
	}
}

// argon2idDerive applies the protocol profile split: p must be 1 and t
// at least 3. Parameters outside the profile are authentic but
// unsupported, so the derivation fails closed with a distinguishable
// error instead of silently verifying wrong bytes.
func (v *Verifier) argon2idDerive(password string, saltBytes []byte, record *ChallengeRecord) ([]byte, error) {
	if record.P != 1 || record.T < 3 {
		return nil, errUnsupportedDerivation
	}
	if record.MKib*1024 < 8192 {
		return nil, errUnsupportedDerivation
	}
	return argon2.IDKey([]byte(password), saltBytes, uint32(record.T), uint32(record.MKib), 1, 32), nil
}

// resolveRsw picks the trapdoor for a record: the authenticated
// identity selects the keyring first, then the active pair. A legacy
// base64-text alias resolves only a pre-v5 identity. An identity in
// neither fails closed.
func (v *Verifier) resolveRsw(record *ChallengeRecord) *Rsw {
	if record.RswModulusSha256 != "" {
		allowAlias := v.Config.AllowLegacyRswIdentity && record.ProtocolVersion <= 4
		identity := record.RswModulusSha256
		if modulus, ok := v.rswModulusByHash[identity]; ok && RswIdentityMatches(identity, modulus, allowAlias) {
			return v.rswByHash[identity]
		}
		if v.resolvedConfigFields.activeRsw != nil && RswIdentityMatches(identity, v.Config.RswModulusN, allowAlias) {
			return v.resolvedConfigFields.activeRsw
		}
		return nil
	}
	return v.resolvedConfigFields.activeRsw
}

// recomputeValidProof is the deterministic proof verdict of a
// presented token against a record, per algorithm. The boolean result
// is the verdict; the error marks a derivation this verifier cannot
// compute, mapped per algorithm by the caller.
func (v *Verifier) recomputeValidProof(record *ChallengeRecord, token *SolutionToken) (bool, error) {
	if record.Algorithm == "rsw" {
		rsw := v.resolveRsw(record)
		if rsw == nil {
			return false, errUnsupportedDerivation
		}
		if token.Counter != 0 || token.RswProof == "" {
			return false, nil
		}
		expected := rsw.ExpectedProofHex(record.Prefix, record.Nonce, record.T)
		return ConstantTimeEquals(expected, token.RswProof), nil
	}
	if token.RswProof != "" {
		// An rsw final value is rsw evidence only, so a sha256 or
		// argon2id record presented with one is rejected outright: the
		// hash is never derived for it.
		return false, nil
	}
	digest, err := v.deriveHash(record, token.Counter)
	if err != nil {
		return false, err
	}
	return LeadingZeroBits(digest) >= record.TargetBits, nil
}

func (v *Verifier) commitConsumedResult(record *ChallengeRecord, valid bool, operationIdentity, secret string) bool {
	binding := record.RequestBinding
	if committer, capable := v.Storage.(AuthenticatedResultCommit); capable {
		macKey, err := ServerStateMacKey(secret, v.Config.TenantID)
		if err != nil {
			return false
		}
		mac := ServerStateMacConsumedResult(macKey, record.Challenge, valid, binding, operationIdentity)
		committed, err := committer.CommitAuthenticatedResult(record.Nonce, ConsumedResult{Valid: valid, Binding: binding, Mac: mac})
		if err != nil {
			return false
		}
		return committed
	}
	committed, err := v.Storage.CommitResult(record.Nonce, valid, binding)
	if err != nil {
		return false
	}
	return committed
}

func (v *Verifier) bestEffortCommit(record *ChallengeRecord, valid bool, operationIdentity, secret string) {
	_ = v.commitConsumedResult(record, valid, operationIdentity, secret)
}

// storedSuccessAuthentic reports whether a consumed record's
// committed success is authentic enough to replay. A storage writer
// without the master secret cannot produce the server-state mac, so a
// forged stored success is refused.
func (v *Verifier) storedSuccessAuthentic(consumed *ConsumedRecord, secretKey string) bool {
	result := consumed.ConsumedResult
	if result == nil || !result.Valid {
		return false
	}
	if result.Mac == "" {
		_, capable := v.Storage.(AuthenticatedResultCommit)
		return !capable
	}
	secret, ok := v.secretForKey(consumed.Record, secretKey)
	if !ok {
		return false
	}
	key, err := ServerStateMacKey(secret, v.Config.TenantID)
	if err != nil {
		return false
	}
	expected := ServerStateMacConsumedResult(key, consumed.Record.Challenge, result.Valid, result.Binding, consumed.OperationIdentity)
	return ConstantTimeEquals(expected, result.Mac)
}

// resolveConsumedRecord resolves an already-consumed record's
// retained state into the deterministic verification outcome, shared
// by the consume-returned envelope and the pre-admission
// terminal-state check, so the two paths can never diverge. A stored
// invalid outcome is deterministic and replays to any caller. A
// stored success is an authorization grant: it replays only when the
// caller proves the exact logical operation. A retry with any other
// identity is refused as already consumed. A consumed record without
// a committed result is ambiguous and reported as indeterminate.
func (v *Verifier) resolveConsumedRecord(consumed *ConsumedRecord, tokenNonce, operationIdentity, secretKey string) VerifyOutcome {
	if consumed.Record.Nonce != tokenNonce {
		return InvalidOutcome(ErrCodeMalformedRecord)
	}
	if consumed.ConsumedResult == nil {
		return InvalidOutcome(ErrCodeConsumeIndeterminate)
	}
	if !consumed.ConsumedResult.Valid {
		return InvalidOutcome(ErrCodeInsufficientWork)
	}
	if operationIdentity != "" && consumed.OperationIdentity != "" &&
		ConstantTimeEquals(consumed.OperationIdentity, operationIdentity) {
		if !v.storedSuccessAuthentic(consumed, secretKey) {
			return InvalidOutcome(ErrCodeMalformedRecord)
		}
		return ValidOutcome(consumed.Record.Nonce, consumed.ConsumedResult.Binding, true, 0, false, consumed.Record.DecoyField)
	}
	return InvalidOutcome(ErrCodeAlreadyConsumed)
}

// Verify runs the one-shot verification of one solution token against
// this verifier's store. The full cheap-gate order, the replay-exempt
// split, the consumed resolution, the proof phase and the post-derive
// final revalidation mirror the php Verifier exactly.
func (v *Verifier) Verify(rawToken string, options VerifyOptions) VerifyOutcome {
	expectation := UnenforcedBinding()
	if options.BindingExpectation != nil {
		expectation = *options.BindingExpectation
	} else {
		expectation = ExactBinding(options.ExpectedRequestBinding)
	}
	secretKey := options.SecretKey
	token, err := DecodeToken(rawToken)
	if err != nil {
		var decodeErr *DecodeError
		reason := DecodeErrMalformed
		if errors.As(err, &decodeErr) {
			reason = decodeErr.Code
		}
		return MalformedTokenOutcome(reason)
	}

	receiptNs := options.NowNs
	receiptSet := options.NowNsSet
	if !receiptSet {
		receiptNs = time.Now().UnixMicro()
		receiptSet = true
	}
	evidence := ExecutionEvidenceFromToken(token)

	var runtimeState ChallengeRuntimeState
	hasRuntime := false
	var peek *ChallengeRecord
	if reader, capable := v.Storage.(RuntimeStateReader); capable {
		runtimeState, err = reader.RuntimeState(token.Nonce)
		if err != nil {
			return InvalidOutcome(ErrCodeStorageUnavailable)
		}
		hasRuntime = true
		if runtimeState.Kind == RuntimeMissing {
			return InvalidOutcome(ErrCodeRecordNotFound)
		}
		peek = runtimeState.Record
	}
	if peek == nil {
		peek, err = v.Storage.Find(token.Nonce)
		if err != nil {
			return InvalidOutcome(ErrCodeStorageUnavailable)
		}
		if peek == nil {
			return InvalidOutcome(ErrCodeRecordNotFound)
		}
	}

	// The execution delegation plane: an armed record under a sidecar
	// policy delegates the execution dimension to the sidecar instead
	// of failing closed, after the cheap phase proved everything the
	// SDK checks locally. The cheap phase skips its own execution gate
	// on this path: the sidecar's full-core pass is the gate.
	delegateExecution := delegateExecutionFor(peek, options)
	failure := v.cheapPhaseCheck(peek, token.Nonce, secretKey, options.ExpectedScope, options.ClientIP, true, receiptNs, receiptSet, expectation, evidence, delegateExecution)
	if failure == "" && delegateExecution {
		// The opt-in telemetry gate runs locally BEFORE the delegation
		// return: the sidecar's /verify API does not accept
		// enforce_telemetry, so skipping it here would drop the
		// caller's gate entirely.
		if options.EnforceTelemetry &&
			(token.Telemetry == nil || token.Telemetry.Len() == 0 || ScoreTelemetry(token.Telemetry, token.DurationMs)) &&
			!(hasRuntime && runtimeState.Kind == RuntimeConsumed) {
			return InvalidOutcome(ErrCodeTelemetryRejected)
		}
		return delegateExecutionVerify(rawToken, peek, options, options.ExecutionPolicy)
	}
	if failure != "" {
		if cleanup, capable := v.Storage.(AtomicDeleteIfPending); capable && failure != ErrCodeMissingClientIP {
			cleanupResult, err := cleanup.DeleteIfPending(token.Nonce)
			if err != nil {
				return InvalidOutcome(ErrCodeStorageUnavailable)
			}
			if !cleanupResult.WasConsumed() {
				return InvalidOutcome(failure)
			}
			if !failure.IsReplayExempt() {
				return InvalidOutcome(failure)
			}
			if hard := v.replaySecurityCheck(peek, secretKey, options.ExpectedScope, expectation, evidence, receiptNs, receiptSet); hard != "" {
				return InvalidOutcome(hard)
			}
		} else {
			retained, readable := "unknown", true
			if hasRuntime {
				if runtimeState.Kind == RuntimeConsumed {
					retained = "consumed"
				} else {
					retained = "pending"
				}
			} else {
				retained, readable = v.retainedConsumedState(token.Nonce)
			}
			if !readable {
				return InvalidOutcome(ErrCodeStorageUnavailable)
			}
			if retained == "consumed" && !failure.IsReplayExempt() {
				return InvalidOutcome(failure)
			}
			if retained == "consumed" {
				if hard := v.replaySecurityCheck(peek, secretKey, options.ExpectedScope, expectation, evidence, receiptNs, receiptSet); hard != "" {
					return InvalidOutcome(hard)
				}
			} else {
				if failure != ErrCodeMissingClientIP {
					v.bestEffortDelete(token.Nonce)
				}
				return InvalidOutcome(failure)
			}
		}
	}

	// The opt-in telemetry gate. The telemetry is client-controlled,
	// so this is a defense-in-depth signal, not a hard gate. An empty
	// telemetry payload is itself a bot signal and must not bypass
	// strict mode. The gate is replay-exempt: it is client-side
	// evidence about the original solve.
	telemetryEmpty := token.Telemetry == nil || token.Telemetry.Len() == 0
	if options.EnforceTelemetry && (telemetryEmpty || ScoreTelemetry(token.Telemetry, token.DurationMs)) &&
		!(hasRuntime && runtimeState.Kind == RuntimeConsumed) {
		if cleanup, capable := v.Storage.(AtomicDeleteIfPending); capable {
			cleanupResult, err := cleanup.DeleteIfPending(token.Nonce)
			if err != nil {
				return InvalidOutcome(ErrCodeStorageUnavailable)
			}
			if !cleanupResult.WasConsumed() {
				return InvalidOutcome(ErrCodeTelemetryRejected)
			}
		} else {
			retained, readable := "unknown", true
			if hasRuntime {
				if runtimeState.Kind == RuntimeConsumed {
					retained = "consumed"
				} else {
					retained = "pending"
				}
			} else {
				retained, readable = v.retainedConsumedState(token.Nonce)
			}
			if !readable {
				return InvalidOutcome(ErrCodeStorageUnavailable)
			}
			if retained != "consumed" {
				v.bestEffortDelete(token.Nonce)
				return InvalidOutcome(ErrCodeTelemetryRejected)
			}
		}
	}

	// Terminal-state resolution before the admission gate: a cancelled
	// or already-consumed record must never acquire a scarce admission
	// slot, and a terminal record's outcome is fully determined.
	if hasRuntime {
		switch runtimeState.Kind {
		case RuntimeCancelled:
			return InvalidOutcome(ErrCodeRecordNotFound)
		case RuntimeConsumed:
			if runtimeState.Consumed != nil {
				return v.resolveConsumedRecord(runtimeState.Consumed, token.Nonce, options.OperationIdentity, secretKey)
			}
			if reader, capable := v.Storage.(ConsumedStateReader); capable {
				retained, err := reader.ConsumedState(token.Nonce)
				if err != nil {
					return InvalidOutcome(ErrCodeStorageUnavailable)
				}
				if retained != nil {
					return v.resolveConsumedRecord(retained, token.Nonce, options.OperationIdentity, secretKey)
				}
			}
		}
	}

	// Argon2id admission: the memory-hard hash is expensive, so an
	// optional gate bounds concurrency. Exhaustion rejects without
	// consuming or deleting the record; the client can retry.
	var lease interface{}
	leaseHeld := false
	if peek.Algorithm == "argon2id" {
		acquired, gateErr := v.Config.ArgonGate.Acquire()
		if gateErr != nil {
			// A broken admission backend is a typed, non-consuming
			// result: the challenge stays intact and can be retried once
			// the backend recovers.
			return InvalidOutcome(ErrCodeAdmissionUnavailable)
		}
		if acquired == nil {
			return InvalidOutcome(ErrCodeCapacityExceeded)
		}
		lease, leaseHeld = acquired, true
	}

	defer func() {
		if leaseHeld {
			func() {
				defer func() { _ = recover() }()
				v.Config.ArgonGate.Release(lease)
			}()
		}
	}()

	consumed, err := v.consumeRecord(token.Nonce, options.OperationIdentity)
	if err != nil {
		// A lost transition response, including an identity the storage
		// boundary refused, is ambiguous: the challenge may or may not
		// have been consumed.
		return InvalidOutcome(ErrCodeConsumeIndeterminate)
	}
	if consumed == nil {
		return InvalidOutcome(ErrCodeRecordNotFound)
	}
	if consumed.ConsumedBefore {
		return v.resolveConsumedRecord(consumed, token.Nonce, options.OperationIdentity, secretKey)
	}
	record := consumed.Record

	// The consumed instance must be the same challenge that was
	// validated and mac-checked via the peek. The v2 signature covers
	// every immutable parameter, so full revalidation and signature
	// re-verification on the consumed instance is the check that holds:
	// a swapped or racing record fails closed instead of verifying
	// against bytes that were never validated.
	consumedSecret, secretOK := v.secretForKey(record, secretKey)
	if !ConstantTimeEquals(peek.Challenge, record.Challenge) ||
		v.isRevokedKid(record.KidOrOne()) ||
		!secretOK ||
		!v.ValidateRecord(record) ||
		!VerifyRecordSignature(record, consumedSecret, v.Config.TenantID) {
		return InvalidOutcome(ErrCodeMalformedRecord)
	}
	if !v.argon2CeilingsOk(record) {
		return InvalidOutcome(ErrCodeUnsupportedArgon2)
	}
	if !v.rswParamsOk(record) {
		return InvalidOutcome(ErrCodeUnsupportedRswParams)
	}
	if !v.policyVersionAccepted(record.PolicyVersionOrOne()) {
		return InvalidOutcome(ErrCodeWrongPolicyVersion)
	}
	if v.Config.ExpectedIssuer != "" && record.Issuer != v.Config.ExpectedIssuer {
		return InvalidOutcome(ErrCodeWrongIssuer)
	}

	valid, proofErr := v.recomputeValidProof(record, token)
	if proofErr != nil {
		switch record.Algorithm {
		case "rsw":
			return InvalidOutcome(ErrCodeUnsupportedRswParams)
		case "argon2id":
			return InvalidOutcome(ErrCodeUnsupportedArgon2)
		default:
			return InvalidOutcome(ErrCodeMalformedRecord)
		}
	}

	// Post-derive final revalidation: re-check against the current
	// server clock and the current expectations before the verdict,
	// for both a valid and an invalid derivation. A record that expired
	// during the derivation commits expired, never a stale
	// insufficient-work.
	now := v.nowSecs()
	if now >= record.ExpiresAt {
		return InvalidOutcome(ErrCodeExpired)
	}
	if !v.policyVersionAccepted(record.PolicyVersionOrOne()) {
		return InvalidOutcome(ErrCodeWrongPolicyVersion)
	}
	if v.Config.Region != "" && record.Region != v.Config.Region {
		return InvalidOutcome(ErrCodeWrongRegion)
	}
	if v.Config.ExpectedIssuer != "" && record.Issuer != v.Config.ExpectedIssuer {
		return InvalidOutcome(ErrCodeWrongIssuer)
	}

	if !valid {
		v.bestEffortCommit(record, false, consumed.OperationIdentity, consumedSecret)
		return InvalidOutcome(ErrCodeInsufficientWork)
	}
	v.bestEffortCommit(record, true, consumed.OperationIdentity, consumedSecret)
	durationMs, measured := v.measurableSolveDurationMs(record, receiptNs, receiptSet)
	return ValidOutcome(record.Nonce, record.RequestBinding, false, durationMs, measured, record.DecoyField)
}

func (v *Verifier) consumeRecord(nonce string, operationIdentity string) (*ConsumedRecord, error) {
	if operationIdentity != "" {
		if aware, capable := v.Storage.(OperationIdentityAware); capable {
			return aware.ConsumeWithOperationIdentity(nonce, operationIdentity)
		}
	}
	return v.Storage.Consume(nonce)
}
