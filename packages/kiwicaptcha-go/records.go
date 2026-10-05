package kiwicaptcha

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ChallengeRecord is the server side challenge state persisted by the
// storage backend. The JSON keys mirror the Rust serde schema one to
// one, so a Go service and a php or Rust service share the same
// records.
//
// Optional fields use the empty string as the unset sentinel: the
// identifier alphabets never admit an empty value on the wire, so the
// mapping is total. Protocol versions 1 through 5 are accepted and the
// protocol versus extension grammar is total: v1 and v2 carry neither
// extension, v3 requires the decoy and carries no execution, v4
// requires the execution triplet and may carry the decoy, and v5
// requires the rsw identity.
type ChallengeRecord struct {
	Nonce         string
	Scope         string
	BindingTag    string
	IssuedAt      int64
	ExpiresAt     int64
	Algorithm     string
	MKib          int
	T             int
	P             int
	TargetBits    int
	Salt          string
	Prefix        string
	Challenge     string
	MinDurationMs int

	IssuedAtNs      int64
	ProtocolVersion int
	Region          string
	PolicyVersion   int
	RequestBinding  string
	Issuer          string
	Kid             int
	Hostname        string

	DecoyField          string
	ExecutionProgram    string
	ExecutionVersion    int
	ExecutionCommitment string
	RswModulusSha256    string
	ServerMac           string
}

// Wire keys of the canonical schema, in emission order. IPHash is the
// legacy v1 alias for the binding tag and is never emitted beside it.
var wireKeys = []string{
	"nonce", "scope", "binding_tag", "issued_at", "expires_at",
	"algorithm", "m_kib", "t", "p", "target_bits", "salt", "prefix",
	"challenge", "min_duration_ms", "issued_at_ns", "protocol_version",
	"attempts_used", "region", "policy_version", "request_binding",
	"issuer", "kid", "hostname", "decoy_field", "execution_program",
	"execution_version", "execution_commitment", "rsw_modulus_sha256",
	"server_mac",
}

var wireKeySet = func() map[string]bool {
	set := make(map[string]bool, len(wireKeys))
	for _, key := range wireKeys {
		set[key] = true
	}
	return set
}()

var requiredKeys = []string{
	"nonce", "scope", "binding_tag", "issued_at", "expires_at",
	"algorithm", "m_kib", "t", "p", "target_bits", "salt", "prefix",
	"challenge", "min_duration_ms",
}

const u32Max = 4_294_967_295
const u64Max int64 = 9_223_372_036_854_775_807

// IPHash is the legacy v1 name of the binding tag. For v1 records the
// tag is exactly the legacy sha256 of secret plus ip.
func (r *ChallengeRecord) IPHash() string { return r.BindingTag }

// PolicyVersionOrOne degrades an unset epoch to the default 1, the
// Rust u32 reader's view of the record.
func (r *ChallengeRecord) PolicyVersionOrOne() int {
	if r.PolicyVersion == 0 {
		return 1
	}
	return r.PolicyVersion
}

// KidOrOne degrades an unset key id to the default 1.
func (r *ChallengeRecord) KidOrOne() int {
	if r.Kid == 0 {
		return 1
	}
	return r.Kid
}

// ProtocolExtensionGrammarOk is the one protocol versus extension
// matrix every boundary applies, so the decoder and the verifier can
// never disagree about which records are structurally valid.
func ProtocolExtensionGrammarOk(protocolVersion int, decoyPresent, executionPresent, rswIdentityPresent bool) bool {
	switch protocolVersion {
	case 1:
		return !decoyPresent && !executionPresent && !rswIdentityPresent
	case BaseProtocolVersion:
		return !decoyPresent && !executionPresent
	case DecoyProtocolVersion:
		return decoyPresent && !executionPresent
	case ExecutionProtocolVersion:
		return executionPresent
	case RswIdentityProtocolVersion:
		return rswIdentityPresent
	default:
		return false
	}
}

// IsValidIdentifier reports the narrow security identifier alphabet
// with a length cap: 1 to maxBytes bytes of [A-Za-z0-9._:-].
func IsValidIdentifier(value string, maxBytes int) bool {
	if len(value) < 1 || len(value) > maxBytes {
		return false
	}
	for _, by := range []byte(value) {
		switch {
		case by >= 'A' && by <= 'Z':
		case by >= 'a' && by <= 'z':
		case by >= '0' && by <= '9':
		case by == '.' || by == '_' || by == ':' || by == '-':
		default:
			return false
		}
	}
	return true
}

// IsValidDecoyFieldName reports the honeypot field name alphabet:
// 1 to 64 bytes of [A-Za-z0-9_-]. The alphabet excludes the canonical
// separators, so a stored name can never alter the structure of the
// signed payload.
func IsValidDecoyFieldName(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, by := range []byte(value) {
		switch {
		case by >= 'A' && by <= 'Z':
		case by >= 'a' && by <= 'z':
		case by >= '0' && by <= '9':
		case by == '_' || by == '-':
		default:
			return false
		}
	}
	return true
}

func isHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, by := range []byte(value) {
		if (by < '0' || by > '9') && (by < 'a' || by > 'f') {
			return false
		}
	}
	return true
}

// ErrMalformedRecord is the strict wire schema violation.
type ErrMalformedRecord struct{ Reason string }

func (e *ErrMalformedRecord) Error() string {
	return "kiwicaptcha: malformed record: " + e.Reason
}

func malformedf(format string, args ...interface{}) error {
	return &ErrMalformedRecord{Reason: fmt.Sprintf(format, args...)}
}

// ToWireMap renders the canonical wire schema for storage. The legacy
// ip_hash key is never emitted beside binding_tag, and the optional
// extension keys are omitted when unset, so unarmed records keep the
// exact pre-extension byte format.
func (r *ChallengeRecord) ToWireMap() map[string]interface{} {
	data := map[string]interface{}{
		"nonce":            r.Nonce,
		"scope":            r.Scope,
		"binding_tag":      r.BindingTag,
		"issued_at":        r.IssuedAt,
		"expires_at":       r.ExpiresAt,
		"algorithm":        r.Algorithm,
		"m_kib":            r.MKib,
		"t":                r.T,
		"p":                r.P,
		"target_bits":      r.TargetBits,
		"salt":             r.Salt,
		"prefix":           r.Prefix,
		"challenge":        r.Challenge,
		"min_duration_ms":  r.MinDurationMs,
		"issued_at_ns":     r.IssuedAtNs,
		"protocol_version": r.ProtocolVersion,
		"attempts_used":    0,
		"region":           jsonNullString(r.Region),
		"policy_version":   r.PolicyVersionOrOne(),
		"request_binding":  jsonNullString(r.RequestBinding),
		"issuer":           jsonNullString(r.Issuer),
		"kid":              r.KidOrOne(),
		"hostname":         jsonNullString(r.Hostname),
	}
	if r.DecoyField != "" {
		data["decoy_field"] = r.DecoyField
	}
	if r.ExecutionProgram != "" {
		data["execution_program"] = r.ExecutionProgram
	}
	if r.ExecutionVersion != 0 {
		data["execution_version"] = r.ExecutionVersion
	}
	if r.ExecutionCommitment != "" {
		data["execution_commitment"] = r.ExecutionCommitment
	}
	if r.RswModulusSha256 != "" {
		data["rsw_modulus_sha256"] = r.RswModulusSha256
	}
	if r.ServerMac != "" {
		data["server_mac"] = r.ServerMac
	}
	return data
}

func jsonNullString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

// MarshalJSON emits the wire schema in the canonical key order, with
// json null for the always present option fields, byte-compatible with
// the php and Rust writers.
func (r *ChallengeRecord) MarshalJSON() ([]byte, error) {
	var sb strings.Builder
	sb.WriteByte('{')
	writeField := func(name string, raw []byte, first *bool) {
		if !*first {
			sb.WriteByte(',')
		}
		*first = false
		key, _ := json.Marshal(name)
		sb.Write(key)
		sb.WriteByte(':')
		sb.Write(raw)
	}
	first := true
	nullableString := func(v string) []byte {
		if v == "" {
			return []byte("null")
		}
		out, _ := json.Marshal(v)
		return out
	}
	integer := func(v int64) []byte { return []byte(strconv.FormatInt(v, 10)) }
	writeField("nonce", mustJSON(r.Nonce), &first)
	writeField("scope", mustJSON(r.Scope), &first)
	writeField("binding_tag", mustJSON(r.BindingTag), &first)
	writeField("issued_at", integer(r.IssuedAt), &first)
	writeField("expires_at", integer(r.ExpiresAt), &first)
	writeField("algorithm", mustJSON(r.Algorithm), &first)
	writeField("m_kib", integer(int64(r.MKib)), &first)
	writeField("t", integer(int64(r.T)), &first)
	writeField("p", integer(int64(r.P)), &first)
	writeField("target_bits", integer(int64(r.TargetBits)), &first)
	writeField("salt", mustJSON(r.Salt), &first)
	writeField("prefix", mustJSON(r.Prefix), &first)
	writeField("challenge", mustJSON(r.Challenge), &first)
	writeField("min_duration_ms", integer(int64(r.MinDurationMs)), &first)
	writeField("issued_at_ns", integer(r.IssuedAtNs), &first)
	writeField("protocol_version", integer(int64(r.ProtocolVersion)), &first)
	writeField("attempts_used", []byte("0"), &first)
	writeField("region", nullableString(r.Region), &first)
	writeField("policy_version", integer(int64(r.PolicyVersionOrOne())), &first)
	writeField("request_binding", nullableString(r.RequestBinding), &first)
	writeField("issuer", nullableString(r.Issuer), &first)
	writeField("kid", integer(int64(r.KidOrOne())), &first)
	writeField("hostname", nullableString(r.Hostname), &first)
	if r.DecoyField != "" {
		writeField("decoy_field", mustJSON(r.DecoyField), &first)
	}
	if r.ExecutionProgram != "" {
		writeField("execution_program", mustJSON(r.ExecutionProgram), &first)
	}
	if r.ExecutionVersion != 0 {
		writeField("execution_version", integer(int64(r.ExecutionVersion)), &first)
	}
	if r.ExecutionCommitment != "" {
		writeField("execution_commitment", mustJSON(r.ExecutionCommitment), &first)
	}
	if r.RswModulusSha256 != "" {
		writeField("rsw_modulus_sha256", mustJSON(r.RswModulusSha256), &first)
	}
	if r.ServerMac != "" {
		writeField("server_mac", mustJSON(r.ServerMac), &first)
	}
	sb.WriteByte('}')
	return []byte(sb.String()), nil
}

func mustJSON(v string) []byte {
	out, err := json.Marshal(v)
	if err != nil {
		return []byte(`""`)
	}
	return out
}

// ParseChallengeRecord is the strict serde mirror parser over stored
// bytes. It accepts exactly what the Rust ChallengeRecord parser
// accepts, including the legacy ip_hash alias, which must never appear
// beside binding_tag. Unknown keys, partial execution triplets,
// forbidden protocol and extension combinations, duplicate keys and
// out-of-range integers are rejected.
func ParseChallengeRecord(data []byte) (*ChallengeRecord, error) {
	value, err := decodeStrictJSON(data)
	if err != nil {
		return nil, malformedf("%s", err)
	}
	obj, ok := value.(map[string]interface{})
	if !ok {
		return nil, malformedf("a record must decode from a json object")
	}
	return challengeRecordFromMap(obj)
}

func challengeRecordFromMap(data map[string]interface{}) (*ChallengeRecord, error) {
	for key := range data {
		if key != "ip_hash" && !wireKeySet[key] {
			return nil, malformedf("unknown record key: %s", key)
		}
	}
	rawBinding, hasBinding := data["binding_tag"]
	if ipHashValue, hasIPHash := data["ip_hash"]; hasIPHash {
		if hasBinding {
			return nil, malformedf("binding_tag and ip_hash are duplicate fields")
		}
		rawBinding, hasBinding = ipHashValue, true
	}
	for _, field := range requiredKeys {
		if field == "binding_tag" {
			if !hasBinding {
				return nil, malformedf("missing record field: %s", field)
			}
			continue
		}
		if _, ok := data[field]; !ok {
			return nil, malformedf("missing record field: %s", field)
		}
	}
	requireString := func(field string) (string, error) {
		value, ok := data[field]
		if !ok {
			return "", malformedf("missing record field: %s", field)
		}
		return wireString(value, field)
	}
	nonce, err := requireString("nonce")
	if err != nil {
		return nil, err
	}
	scope, err := requireString("scope")
	if err != nil {
		return nil, err
	}
	bindingTag, err := wireString(rawBinding, "binding_tag")
	if err != nil {
		return nil, err
	}
	salt, err := requireString("salt")
	if err != nil {
		return nil, err
	}
	prefix, err := requireString("prefix")
	if err != nil {
		return nil, err
	}
	challenge, err := requireString("challenge")
	if err != nil {
		return nil, err
	}
	issuedAt, err := wireInt(data["issued_at"], "issued_at", 0, u64Max)
	if err != nil {
		return nil, err
	}
	expiresAt, err := wireInt(data["expires_at"], "expires_at", 0, u64Max)
	if err != nil {
		return nil, err
	}
	minDurationMs, err := wireInt(data["min_duration_ms"], "min_duration_ms", 0, u64Max)
	if err != nil {
		return nil, err
	}
	issuedAtNs := int64(0)
	if value, ok := data["issued_at_ns"]; ok {
		issuedAtNs, err = wireInt(value, "issued_at_ns", 0, u64Max)
		if err != nil {
			return nil, err
		}
	}
	mKib, t, p, targetBits := 0, 0, 0, 0
	for _, field := range []struct {
		name   string
		target *int
	}{{"m_kib", &mKib}, {"t", &t}, {"p", &p}, {"target_bits", &targetBits}} {
		value, present := data[field.name]
		if !present {
			continue
		}
		parsed, err := wireInt(value, field.name, 0, u32Max)
		if err != nil {
			return nil, err
		}
		*field.target = int(parsed)
	}
	if value, ok := data["attempts_used"]; ok {
		if _, err := wireInt(value, "attempts_used", 0, u32Max); err != nil {
			return nil, err
		}
	}
	policyVersion, kid := 1, 1
	if value, ok := data["policy_version"]; ok {
		parsed, err := wireInt(value, "policy_version", 0, u32Max)
		if err != nil {
			return nil, err
		}
		policyVersion = int(parsed)
	}
	if value, ok := data["kid"]; ok {
		parsed, err := wireInt(value, "kid", 0, u32Max)
		if err != nil {
			return nil, err
		}
		kid = int(parsed)
	}
	protocolVersion := 1
	if value, ok := data["protocol_version"]; ok {
		parsed, err := wireInt(value, "protocol_version", 1, MaxProtocolVersion)
		if err != nil {
			return nil, err
		}
		protocolVersion = int(parsed)
	}
	algorithm, err := requireString("algorithm")
	if err != nil {
		return nil, err
	}
	if algorithm != "sha256" && algorithm != "argon2id" && algorithm != "rsw" {
		return nil, malformedf("invalid algorithm: %s", algorithm)
	}
	optionalIdentifier := func(field string, cap int) (string, error) {
		value, present := data[field]
		if !present || value == nil {
			return "", nil
		}
		text, err := wireString(value, field)
		if err != nil {
			return "", err
		}
		if !IsValidIdentifier(text, cap) {
			return "", malformedf("%s must match the narrow identifier alphabet", field)
		}
		return text, nil
	}
	region, err := optionalIdentifier("region", 64)
	if err != nil {
		return nil, err
	}
	requestBinding, err := optionalIdentifier("request_binding", 128)
	if err != nil {
		return nil, err
	}
	issuer, err := optionalIdentifier("issuer", 128)
	if err != nil {
		return nil, err
	}
	decoyField := ""
	if value, present := data["decoy_field"]; present && value != nil {
		decoyField, err = wireString(value, "decoy_field")
		if err != nil {
			return nil, err
		}
		if !IsValidDecoyFieldName(decoyField) {
			return nil, malformedf("invalid decoy field name")
		}
	}
	executionProgram := ""
	if value, present := data["execution_program"]; present && value != nil {
		executionProgram, err = wireString(value, "execution_program")
		if err != nil {
			return nil, err
		}
		if len(executionProgram) > MaxProgramBase64 {
			return nil, malformedf("execution_program exceeds the wire cap")
		}
		if !IsValidExecutionProgram(executionProgram) {
			return nil, malformedf("invalid execution program")
		}
	}
	hasExecutionVersion := false
	executionVersion := 0
	if value, present := data["execution_version"]; present && value != nil {
		hasExecutionVersion = true
		parsed, err := wireInt(value, "execution_version", 0, 255)
		if err != nil {
			return nil, err
		}
		executionVersion = int(parsed)
		if executionVersion < 1 || executionVersion > MaxExecutionVersion {
			return nil, malformedf("invalid execution version: %d", executionVersion)
		}
	}
	hasExecutionCommitment := false
	executionCommitment := ""
	if value, present := data["execution_commitment"]; present && value != nil {
		hasExecutionCommitment = true
		executionCommitment, err = wireString(value, "execution_commitment")
		if err != nil {
			return nil, err
		}
		if !isHex64(executionCommitment) {
			return nil, malformedf("invalid execution commitment")
		}
	}
	if executionProgram != "" || hasExecutionVersion || hasExecutionCommitment {
		if executionProgram == "" || !hasExecutionVersion || !hasExecutionCommitment {
			return nil, malformedf("incomplete execution fields")
		}
		if ExecutionCommitment(executionProgram) != executionCommitment {
			return nil, malformedf("execution commitment mismatch")
		}
	}
	rswIdentity, err := parseRswIdentity(data, algorithm, protocolVersion)
	if err != nil {
		return nil, err
	}
	if !ProtocolExtensionGrammarOk(protocolVersion, decoyField != "", executionProgram != "", rswIdentity != "") {
		return nil, malformedf("invalid protocol and extension combination: %d", protocolVersion)
	}
	serverMac := ""
	if value, present := data["server_mac"]; present && value != nil {
		serverMac, err = wireString(value, "server_mac")
		if err != nil {
			return nil, err
		}
		if !isHex64(serverMac) {
			return nil, malformedf("server_mac must be 64 lowercase hex characters")
		}
	}
	hostname := ""
	if value, present := data["hostname"]; present && value != nil {
		hostname, err = wireString(value, "hostname")
		if err != nil {
			return nil, err
		}
		if hostname == "" {
			return nil, malformedf("hostname must be a non-empty string or null")
		}
		if strings.ContainsAny(hostname, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x7f") {
			return nil, malformedf("hostname must carry no whitespace or control characters")
		}
	}
	return &ChallengeRecord{
		Nonce:               nonce,
		Scope:               scope,
		BindingTag:          bindingTag,
		IssuedAt:            issuedAt,
		ExpiresAt:           expiresAt,
		Algorithm:           algorithm,
		MKib:                mKib,
		T:                   t,
		P:                   p,
		TargetBits:          targetBits,
		Salt:                salt,
		Prefix:              prefix,
		Challenge:           challenge,
		MinDurationMs:       int(minDurationMs),
		IssuedAtNs:          issuedAtNs,
		ProtocolVersion:     protocolVersion,
		Region:              region,
		PolicyVersion:       policyVersion,
		RequestBinding:      requestBinding,
		Issuer:              issuer,
		Kid:                 kid,
		Hostname:            hostname,
		DecoyField:          decoyField,
		ExecutionProgram:    executionProgram,
		ExecutionVersion:    executionVersion,
		ExecutionCommitment: executionCommitment,
		RswModulusSha256:    rswIdentity,
		ServerMac:           serverMac,
	}, nil
}

func parseRswIdentity(data map[string]interface{}, algorithm string, protocolVersion int) (string, error) {
	value, present := data["rsw_modulus_sha256"]
	if !present || value == nil {
		return "", nil
	}
	identity, err := wireString(value, "rsw_modulus_sha256")
	if err != nil {
		return "", err
	}
	if !isHex64(identity) {
		return "", malformedf("rsw_modulus_sha256 must be 64 lowercase hex characters")
	}
	if algorithm != "rsw" {
		return "", malformedf("rsw_modulus_sha256 may only ride an rsw record")
	}
	if protocolVersion == 1 {
		return "", malformedf("rsw_modulus_sha256 may not ride the v1 canonical")
	}
	return identity, nil
}

func wireString(value interface{}, field string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", malformedf("%s must be a string", field)
	}
	if len(text) > MaxStringBytes {
		return "", malformedf("%s exceeds the %d byte wire cap", field, MaxStringBytes)
	}
	return text, nil
}

func wireInt(value interface{}, field string, min, max int64) (int64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, malformedf("%s must be an integer within %d..%d", field, min, max)
	}
	parsed, err := number.Int64()
	if err != nil || parsed < min || parsed > max {
		return 0, malformedf("%s must be an integer within %d..%d", field, min, max)
	}
	return parsed, nil
}

// ParseRecordJSON is a convenience wrapper accepting a decoded map,
// used by tests and store adapters that already hold the document.
func ParseRecordJSON(data map[string]interface{}) (*ChallengeRecord, error) {
	return challengeRecordFromMap(data)
}

// ExecutionCommitment is the signed commitment of a program: the hex
// sha256 of the wire string.
func ExecutionCommitment(programB64 string) string {
	sum := sha256.Sum256([]byte(programB64))
	return hex.EncodeToString(sum[:])
}

// ErrRecordEnvelope wraps the typed envelope failure.
var ErrRecordEnvelope = errors.New("kiwicaptcha: unusable record envelope")
