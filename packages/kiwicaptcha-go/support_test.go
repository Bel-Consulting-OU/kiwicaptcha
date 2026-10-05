package kiwicaptcha

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// Shared test support: the canonical vectors, the corpus paths and the
// record and token builders every suite composes. The vector values
// are the Rust-generated protocol corpus the php and Python suites
// pin, so the three implementations hold one acceptance split.

const (
	testSecret   = "0123456789abcdef0123456789abcdef"
	testClientIP = "203.0.113.7"
	testIssuedAt = 1_800_000_000
	testNow      = 1_800_000_100
	testIPHash   = "9c50b8d493de847656a168d0408bd4455994df2fc0b1e94bab5a85d64850034b"
)

func repoProtocolPath(t *testing.T, relative string) string {
	t.Helper()
	absolute, err := filepath.Abs(filepath.Join("..", "..", "protocol", relative))
	if err != nil {
		t.Fatalf("protocol path: %v", err)
	}
	if _, err := os.Stat(absolute); err != nil {
		t.Skipf("the shared protocol corpus is not present: %s", absolute)
	}
	return absolute
}

func goldenPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", "golden", name)
}

func readGolden(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(goldenPath(t, name))
	if err != nil {
		t.Fatalf("golden fixture %s: %v", name, err)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("golden fixture %s: %v", name, err)
	}
	return document
}

func goldenRecord(t *testing.T, name string) *ChallengeRecord {
	t.Helper()
	document := readGolden(t, name)
	raw, err := json.Marshal(document["record"])
	if err != nil {
		t.Fatalf("golden record %s: %v", name, err)
	}
	record, err := ParseChallengeRecord(raw)
	if err != nil {
		t.Fatalf("golden record %s does not parse: %v", name, err)
	}
	return record
}

// protocolVector is one entry of the Rust-generated canonical corpus.
type protocolVector struct {
	Nonce      string
	Challenge  string
	Salt       string
	Prefix     string
	Algorithm  string
	MKib       int
	T          int
	P          int
	TargetBits int
	Counter    int
}

var shaVector = protocolVector{
	Nonce: "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
	Challenge: "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58" +
		"OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1" +
		"ZDY0ODUwMDM0YnwxODAwMDAwMDAw." +
		"dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba",
	Salt: "phUfA189G9A5KMv3r+wzLA==",
	Prefix: "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58" +
		"OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1" +
		"ZDY0ODUwMDM0YnwxODAwMDAwMDAw." +
		"dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba" +
		"|phUfA189G9A5KMv3r+wzLA==|",
	Algorithm:  "sha256",
	MKib:       0,
	T:          1,
	P:          1,
	TargetBits: 8,
	Counter:    158,
}

var argon2Vector = protocolVector{
	Nonce: "Sn89Ua2qPftlfNO2K9jZSWB52OpcuYwRD1kf2GDhAX4=",
	Challenge: "U244OVVhMnFQZnRsZk5PMks5alpTV0I1Mk9wY3VZd1JEMWtmMkdEaEFYND18bG9naW58" +
		"OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1" +
		"ZDY0ODUwMDM0YnwxODAwMDAwMDAw." +
		"2757c7cdabe01a52d31cb91900d64eaaae881dd25353dd79267ce35298b3c239",
	Salt: "6HL5BOgvD4ryefTBPNhS8A==",
	Prefix: "U244OVVhMnFQZnRsZk5PMks5alpTV0I1Mk9wY3VZd1JEMWtmMkdEaEFYND18bG9naW58" +
		"OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1" +
		"ZDY0ODUwMDM0YnwxODAwMDAwMDAw." +
		"2757c7cdabe01a52d31cb91900d64eaaae881dd25353dd79267ce35298b3c239" +
		"|6HL5BOgvD4ryefTBPNhS8A==|",
	Algorithm:  "argon2id",
	MKib:       64,
	T:          3,
	P:          1,
	TargetBits: 4,
	Counter:    21,
}

func vectorRecord(vector protocolVector) *ChallengeRecord {
	return &ChallengeRecord{
		Nonce:           vector.Nonce,
		Scope:           "login",
		BindingTag:      testIPHash,
		IssuedAt:        testIssuedAt,
		ExpiresAt:       testIssuedAt + 120,
		Algorithm:       vector.Algorithm,
		MKib:            vector.MKib,
		T:               vector.T,
		P:               vector.P,
		TargetBits:      vector.TargetBits,
		Salt:            vector.Salt,
		Prefix:          vector.Prefix,
		Challenge:       vector.Challenge,
		MinDurationMs:   0,
		IssuedAtNs:      testIssuedAt * 1_000_000,
		ProtocolVersion: 1,
	}
}

func vectorToken(vector protocolVector, counter, durationMs int) string {
	telemetry := NewJSONObject(
		JSONPair{Key: "wd", Value: false},
		JSONPair{Key: "me", Value: jsonNumber("3")},
		JSONPair{Key: "ke", Value: jsonNumber("1")},
		JSONPair{Key: "et", Value: []interface{}{jsonNumber("100"), jsonNumber("250"), jsonNumber("480")}},
	)
	if counter < 0 {
		counter = vector.Counter
	}
	if durationMs < 0 {
		durationMs = 5000
	}
	return CreateToken(vector.Nonce, counter, durationMs, telemetry, "", "", "").Encode()
}

type mintOptions struct {
	nonceBytes       []byte
	saltBytes        []byte
	scope            string
	bindingIP        string
	requestBinding   string
	issuedAt         int64
	ttl              int64
	algorithm        string
	mKib             int
	t                int
	targetBits       int
	minDurationMs    int
	region           string
	policyVersion    int
	issuer           string
	kid              int
	protocolVersion  int
	decoyField       string
	hostname         string
	mintMetaMac      bool
	tenantID         string
	executionProgram string
}

func defaultMintOptions() mintOptions {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	return mintOptions{
		nonceBytes:      nonce,
		saltBytes:       salt,
		scope:           "login",
		issuedAt:        testIssuedAt,
		ttl:             120,
		algorithm:       "sha256",
		mKib:            1,
		t:               1,
		targetBits:      4,
		policyVersion:   1,
		kid:             1,
		protocolVersion: 2,
	}
}

func mintRecord(t *testing.T, options mintOptions) *ChallengeRecord {
	t.Helper()
	nonce := base64.StdEncoding.EncodeToString(options.nonceBytes)
	salt := base64.StdEncoding.EncodeToString(options.saltBytes)
	expiresAt := options.issuedAt + options.ttl
	issuedAtNs := options.issuedAt * 1_000_000
	bindingTag := ""
	if options.protocolVersion == 1 {
		bindingTag = sha256Hex(testSecret + clientOrDefaultIP(options))
	} else {
		if options.bindingIP != "" {
			tag, err := BindingTag(nonce, clientOrDefaultIP(options), testSecret, options.tenantID)
			if err != nil {
				t.Fatalf("mint binding tag: %v", err)
			}
			bindingTag = tag
		}
	}
	payload, err := CanonicalPayloadChecked(
		options.protocolVersion,
		nonce,
		options.scope,
		bindingTag,
		options.issuedAt,
		expiresAt,
		options.algorithm,
		options.mKib,
		options.t,
		1,
		options.targetBits,
		salt,
		options.minDurationMs,
		options.region,
		options.policyVersion,
		options.requestBinding,
		options.issuer,
		options.kid,
		options.decoyField,
		executionVersionFor(options),
		executionCommitmentFor(options),
		"",
		options.mintMetaMac,
	)
	if err != nil {
		t.Fatalf("mint canonical: %v", err)
	}
	signature, err := SignPayloadV2(payload, testSecret, options.tenantID)
	if err != nil {
		t.Fatalf("mint signature: %v", err)
	}
	challenge := base64.StdEncoding.EncodeToString([]byte(payload)) + "." + signature
	serverMac := ""
	if options.mintMetaMac {
		key, err := ServerStateMacKey(testSecret, options.tenantID)
		if err != nil {
			t.Fatalf("mint mac key: %v", err)
		}
		serverMac = ServerStateMacRecordMeta(key, challenge, issuedAtNs, options.hostname)
	}
	return &ChallengeRecord{
		Nonce:               nonce,
		Scope:               options.scope,
		BindingTag:          bindingTag,
		IssuedAt:            options.issuedAt,
		ExpiresAt:           expiresAt,
		Algorithm:           options.algorithm,
		MKib:                options.mKib,
		T:                   options.t,
		P:                   1,
		TargetBits:          options.targetBits,
		Salt:                salt,
		Prefix:              challenge + "|" + salt + "|",
		Challenge:           challenge,
		MinDurationMs:       options.minDurationMs,
		IssuedAtNs:          issuedAtNs,
		ProtocolVersion:     options.protocolVersion,
		Region:              options.region,
		PolicyVersion:       options.policyVersion,
		RequestBinding:      options.requestBinding,
		Issuer:              options.issuer,
		Kid:                 options.kid,
		Hostname:            options.hostname,
		DecoyField:          options.decoyField,
		ExecutionProgram:    options.executionProgram,
		ExecutionVersion:    executionVersionFor(options),
		ExecutionCommitment: executionCommitmentFor(options),
		ServerMac:           serverMac,
	}
}

func clientOrDefaultIP(options mintOptions) string {
	if options.bindingIP != "" {
		return options.bindingIP
	}
	return testClientIP
}

func executionVersionFor(options mintOptions) int {
	if options.executionProgram != "" {
		return 1
	}
	return 0
}

func executionCommitmentFor(options mintOptions) string {
	if options.executionProgram != "" {
		return ExecutionCommitment(options.executionProgram)
	}
	return ""
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum)
}

// minimalProgramB64 builds one well-formed v1 program blob: eight add
// records.
func minimalProgramB64(scope, action string) string {
	body := []byte{1, byte(len(scope))}
	body = append(body, scope...)
	body = append(body, byte(len(action)))
	body = append(body, action...)
	body = append(body, 1, 8)
	for i := 0; i < 8; i++ {
		body = append(body, 0)
		body = append(body, byte(i+1), 0, 0, 0)
		body = append(body, 1, 0, 0, 0)
	}
	return base64.StdEncoding.EncodeToString(body)
}

// solveSha searches the sha256 counter to the target difficulty.
func solveSha(prefix, saltB64 string, targetBits int) int {
	saltBytes, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return -1
	}
	counter := 0
	for {
		digest := sha256.Sum256([]byte(prefix + strconv.Itoa(counter) + string(saltBytes)))
		if LeadingZeroBits(digest[:]) >= targetBits {
			return counter
		}
		counter++
	}
}

// solveRsw performs the client's T sequential squarings.
func solveRsw(prefix, nonce string, n *big.Int, t int) string {
	value := RswDeriveBase(prefix, nonce, n)
	squared := new(big.Int)
	for i := 0; i < t; i++ {
		squared.Mul(value, value)
		squared.Mod(squared, n)
		value, squared = squared, value
	}
	return RswProofHex(value)
}

// requireCode asserts the outcome's error code.
func requireCode(t *testing.T, outcome VerifyOutcome, expected VerifyError) {
	t.Helper()
	if outcome.Valid {
		t.Fatalf("expected %s, got a valid outcome", expected)
	}
	if outcome.Error != expected {
		t.Fatalf("expected %s, got %s (detail %q)", expected, outcome.Error, outcome.Detail)
	}
}

func requireValid(t *testing.T, outcome VerifyOutcome) {
	t.Helper()
	if !outcome.Valid {
		t.Fatalf("expected a valid outcome, got %s (detail %q)", outcome.Error, outcome.Detail)
	}
}

// newTestVerifier builds a verifier over a fresh memory store with a
// clock pinned to the given unix second.
func newTestVerifier(t *testing.T, config VerifierConfig, now int64) *Verifier {
	t.Helper()
	config.NowFunc = func() time.Time { return time.Unix(now, 0) }
	verifier, err := NewVerifier(NewMemoryStorage(), config)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return verifier
}

// storeRecord stores one record through the Storer seam.
func storeRecord(t *testing.T, store Store, record *ChallengeRecord) {
	t.Helper()
	storer, ok := store.(Storer)
	if !ok {
		t.Fatalf("the store does not accept records")
	}
	if err := storer.StoreRecord(record); err != nil {
		t.Fatalf("store record: %v", err)
	}
}

// base64Std encodes one plain string as standard base64.
func base64Std(plain string) string {
	return base64.StdEncoding.EncodeToString([]byte(plain))
}

// base64DecodeString decodes standard base64 for test assembly.
func base64DecodeString(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}

// base64EncodeBytes encodes bytes as standard base64.
func base64EncodeBytes(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

// solveArgon2 searches the argon2id counter to the target difficulty.
// The memory cost is bounded by the record's own signed m_kib, so the
// search stays proportional to the challenge budget.
func solveArgon2(prefix, saltB64 string, targetBits, t, mKib int) int {
	saltBytes, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return -1
	}
	for counter := 0; ; counter++ {
		digest := argon2.IDKey([]byte(prefix+strconv.Itoa(counter)), saltBytes, uint32(t), uint32(mKib), 1, 32)
		if LeadingZeroBits(digest) >= targetBits {
			return counter
		}
	}
}
