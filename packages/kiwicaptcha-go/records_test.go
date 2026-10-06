package kiwicaptcha

import (
	"encoding/json"
	"testing"
)

func parseRecordMap(t *testing.T, document string) (*ChallengeRecord, error) {
	t.Helper()
	return ParseChallengeRecord([]byte(document))
}

func mustParseRecord(t *testing.T, document string) *ChallengeRecord {
	t.Helper()
	record, err := parseRecordMap(t, document)
	if err != nil {
		t.Fatalf("record must parse: %v", err)
	}
	return record
}

func TestRecordGoldenFilesParse(t *testing.T) {
	for _, name := range []string{
		"golden_sha256_v2.json", "golden_argon2id_v2.json", "golden_rsw_v5.json",
		"golden_policy_epoch2_v2.json", "golden_region_issuer_v2.json",
		"golden_decoy_v3.json", "golden_execution_v4.json", "golden_request_binding_v2.json",
	} {
		record := goldenRecord(t, name)
		if record.Nonce == "" {
			t.Fatalf("%s parsed empty", name)
		}
	}
}

func TestRecordMarshalRoundTrip(t *testing.T) {
	record := goldenRecord(t, "golden_decoy_v3.json")
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	reparsed, err := ParseChallengeRecord(encoded)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if *reparsed != *record {
		t.Fatalf("marshal round-trip drift:\n%+v\n%+v", reparsed, record)
	}
	// The emitted key order is the canonical wire order.
	expectedOrder := []string{
		`"nonce":`, `"scope":`, `"binding_tag":`, `"issued_at":`, `"expires_at":`,
		`"algorithm":`, `"m_kib":`, `"t":`, `"p":`, `"target_bits":`, `"salt":`,
		`"prefix":`, `"challenge":`, `"min_duration_ms":`, `"issued_at_ns":`,
		`"protocol_version":`, `"attempts_used":`, `"region":`, `"policy_version":`,
		`"request_binding":`, `"issuer":`, `"kid":`, `"hostname":`, `"decoy_field":`,
	}
	encodedText := string(encoded)
	cursor := 0
	for _, key := range expectedOrder {
		position := indexFrom(encodedText, key, cursor)
		if position < 0 {
			t.Fatalf("key %s missing or out of order in %s", key, encodedText)
		}
		cursor = position + 1
	}
}

func indexFrom(haystack, needle string, start int) int {
	if start > len(haystack) {
		return -1
	}
	index := indexOf(haystack[start:], needle)
	if index < 0 {
		return -1
	}
	return start + index
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestRecordStrictParserRejects(t *testing.T) {
	base := goldenRecord(t, "golden_sha256_v2.json")
	raw, err := json.Marshal(base.ToWireMap())
	if err != nil {
		t.Fatalf("wire map: %v", err)
	}
	baseText := string(raw)

	mutations := map[string]func(document map[string]interface{}){
		"unknown key":        func(d map[string]interface{}) { d["foreign"] = 1 },
		"missing nonce":      func(d map[string]interface{}) { delete(d, "nonce") },
		"missing challenge":  func(d map[string]interface{}) { delete(d, "challenge") },
		"float timestamp":    func(d map[string]interface{}) { d["issued_at"] = 1.5 },
		"string integer":     func(d map[string]interface{}) { d["issued_at"] = "1900000000" },
		"negative m_kib":     func(d map[string]interface{}) { d["m_kib"] = -1 },
		"protocol zero":      func(d map[string]interface{}) { d["protocol_version"] = 0 },
		"protocol beyond":    func(d map[string]interface{}) { d["protocol_version"] = 6 },
		"bad algorithm":      func(d map[string]interface{}) { d["algorithm"] = "scrypt" },
		"bad region":         func(d map[string]interface{}) { d["region"] = "eu|west" },
		"bad decoy":          func(d map[string]interface{}) { d["decoy_field"] = "a.b" },
		"bad server mac":     func(d map[string]interface{}) { d["server_mac"] = "NOTHEX" },
		"oversized string":   func(d map[string]interface{}) { d["scope"] = make([]byte, 5000); d["scope"] = stringOf(5000) },
		"identifier newline": func(d map[string]interface{}) { d["region"] = "eu\nwest" },
		"bad hostname":       func(d map[string]interface{}) { d["hostname"] = "has space" },
	}
	for name, mutate := range mutations {
		var document map[string]interface{}
		if err := json.Unmarshal([]byte(baseText), &document); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		mutate(document)
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := ParseChallengeRecord(encoded); err == nil {
			t.Fatalf("%s: record must be rejected", name)
		}
	}
}

func stringOf(length int) string {
	out := make([]byte, length)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}

func TestRecordDuplicateKeysRejected(t *testing.T) {
	if _, err := ParseChallengeRecord([]byte(`{"nonce":"a","nonce":"b"}`)); err == nil {
		t.Fatalf("duplicate keys must be rejected")
	}
	nested := `{"nonce":"a","telemetry":{"state":"x"}}`
	if _, err := ParseChallengeRecord([]byte(nested)); err == nil {
		// A nested foreign key is an unknown top-level key here; the
		// document must not parse as a record either way.
		t.Fatalf("a foreign key must be rejected")
	}
}

func TestRecordLegacyIPHashAlias(t *testing.T) {
	document := goldenRecord(t, "golden_sha256_v2.json")
	wire := document.ToWireMap()
	delete(wire, "binding_tag")
	wire["ip_hash"] = document.BindingTag
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseChallengeRecord(encoded)
	if err != nil {
		t.Fatalf("the ip_hash alias must parse: %v", err)
	}
	if parsed.BindingTag != document.BindingTag {
		t.Fatalf("alias value drift")
	}
	// Both spellings together are the serde duplicate-field rejection.
	wire["binding_tag"] = document.BindingTag
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ParseChallengeRecord(encoded); err == nil {
		t.Fatalf("ip_hash beside binding_tag must be rejected")
	}
}

func TestRecordExecutionGrammarMatrix(t *testing.T) {
	program := minimalProgramB64("login", "submit")
	commitment := ExecutionCommitment(program)
	build := func(protocolVersion int, withProgram bool, withDecoy bool, extra map[string]interface{}) string {
		options := defaultMintOptions()
		options.protocolVersion = protocolVersion
		options.decoyField = ""
		if withDecoy {
			options.decoyField = "hp_field"
		}
		if withProgram {
			options.executionProgram = program
		}
		record := mintRecord(t, options)
		wire := record.ToWireMap()
		for key, value := range extra {
			wire[key] = value
		}
		encoded, err := json.Marshal(wire)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(encoded)
	}
	if _, err := parseRecordMap(t, build(2, false, false, nil)); err != nil {
		t.Fatalf("v2 unarmed must parse: %v", err)
	}
	if _, err := parseRecordMap(t, build(3, false, true, nil)); err != nil {
		t.Fatalf("v3 decoy must parse: %v", err)
	}
	if _, err := parseRecordMap(t, build(4, true, false, nil)); err != nil {
		t.Fatalf("v4 execution must parse: %v", err)
	}
	if _, err := parseRecordMap(t, build(4, true, true, nil)); err != nil {
		t.Fatalf("v4 execution plus decoy must parse: %v", err)
	}
	// The forbidden combinations.
	if _, err := parseRecordMap(t, build(2, false, true, nil)); err == nil {
		t.Fatalf("v2 with a decoy must be rejected")
	}
	if _, err := parseRecordMap(t, build(2, true, false, nil)); err == nil {
		t.Fatalf("v2 with execution must be rejected")
	}
	if _, err := parseRecordMap(t, build(3, true, true, nil)); err == nil {
		t.Fatalf("v3 with execution must be rejected")
	}
	if _, err := parseRecordMap(t, build(4, false, false, nil)); err == nil {
		t.Fatalf("executionless v4 must be rejected")
	}
	// A partial execution triplet.
	partial := map[string]interface{}{"execution_program": program}
	if _, err := parseRecordMap(t, build(4, false, false, partial)); err == nil {
		t.Fatalf("a partial execution triplet must be rejected")
	}
	// A commitment that does not match the program.
	wrong := map[string]interface{}{
		"execution_program":    program,
		"execution_version":    1,
		"execution_commitment": stringsRepeat("0", 64),
	}
	if _, err := parseRecordMap(t, build(4, true, false, wrong)); err == nil {
		t.Fatalf("a commitment mismatch must be rejected")
	}
	_ = commitment
}

func TestRecordRswIdentityRules(t *testing.T) {
	identity := stringsRepeat("a", 64)
	options := defaultMintOptions()
	options.algorithm = "rsw"
	options.protocolVersion = 5
	options.targetBits = RswTargetBitsPin
	record := mintRecord(t, options)
	// The minted canonical does not sign the identity; the parser is
	// shape only, so the grammar matrix runs through the wire map.
	wire := record.ToWireMap()
	wire["rsw_modulus_sha256"] = identity
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ParseChallengeRecord(encoded); err != nil {
		t.Fatalf("a v5 rsw map with a shaped identity must parse: %v", err)
	}
	// The v5 grammar requires the identity.
	wire = record.ToWireMap()
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ParseChallengeRecord(encoded); err == nil {
		t.Fatalf("a v5 record without the identity must be rejected")
	}
	// The identity may not ride a non-rsw record.
	plain := mintRecord(t, defaultMintOptions())
	wire = plain.ToWireMap()
	wire["rsw_modulus_sha256"] = identity
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ParseChallengeRecord(encoded); err == nil {
		t.Fatalf("the rsw identity may only ride an rsw record")
	}
	// The identity may not ride the v1 canonical.
	v1 := mintRecord(t, defaultMintOptions())
	v1.ProtocolVersion = 1
	wire = v1.ToWireMap()
	wire["rsw_modulus_sha256"] = identity
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ParseChallengeRecord(encoded); err == nil {
		t.Fatalf("the rsw identity may not ride the v1 canonical")
	}
	// The identity shape is 64 lowercase hex.
	wire = record.ToWireMap()
	wire["rsw_modulus_sha256"] = stringsRepeat("A", 64)
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ParseChallengeRecord(encoded); err == nil {
		t.Fatalf("the identity must be 64 lowercase hex characters")
	}
}

func TestExecutionProgramLanguage(t *testing.T) {
	if !IsValidExecutionProgram(minimalProgramB64("login", "submit")) {
		t.Fatalf("the minimal program must parse")
	}
	// Trailing bytes are rejected.
	trimmed := minimalProgramB64("login", "submit")
	decoded, err := base64DecodeString(trimmed)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if IsValidExecutionProgram(base64EncodeBytes(append(decoded, 0))) {
		t.Fatalf("trailing bytes must be rejected")
	}
	// Too few ops.
	if IsValidExecutionProgram(base64EncodeBytes(decoded[:len(decoded)-9])) {
		t.Fatalf("an op count below the floor must be rejected")
	}
	// A foreign scope alphabet.
	if IsValidExecutionProgram(minimalProgramB64("bad scope", "submit")) {
		t.Fatalf("a scope outside the identifier alphabet must be rejected")
	}
	// The v1 opcode space ends at 32.
	limited := minimalProgramB64("login", "submit")
	limitedBytes, _ := base64DecodeString(limited)
	limitedBytes[len(limitedBytes)-27] = 33 // the first opcode byte of eight
	if IsValidExecutionProgram(base64EncodeBytes(limitedBytes)) {
		t.Fatalf("an opcode beyond the version ceiling must be rejected")
	}
}

func buildProgramB64(opVersion byte, ops [][2]interface{}) string {
	// ops entries are (opcode byte, operand payload bytes).
	body := []byte{ExecutionFormatVersion}
	body = append(body, byte(len("login")))
	body = append(body, []byte("login")...)
	body = append(body, byte(len("act")))
	body = append(body, []byte("act")...)
	body = append(body, opVersion, byte(len(ops)))
	for _, op := range ops {
		body = append(body, op[0].(byte))
		body = append(body, op[1].([]byte)...)
	}
	return base64EncodeBytes(body)
}

func TestExecutionVersionSixGrammar(t *testing.T) {
	idOperand := []byte{4, 'a', 'b', 'c', 'd'}
	addOperand := []byte{1, 0, 0, 0, 1, 0, 0, 0}
	css := append(append([]byte{}, idOperand...), 7, 3)
	mut := append(append([]byte{}, idOperand...), 1, 2, 5)
	evp := append(append([]byte{}, idOperand...), 9)
	rng := append(append([]byte{}, idOperand...), 4, 5, 6)
	iob := append(append(append([]byte{}, idOperand...), 8), 1)
	ops := [][2]interface{}{
		{byte(opCssGeom), css},
		{byte(opMutOrder), mut},
		{byte(opEvPhaseFull), evp},
		{byte(opRangeOrder), rng},
		{byte(opIntObs), iob},
		{byte(opAdd), addOperand},
		{byte(opAdd), addOperand},
		{byte(opAdd), addOperand},
	}
	program := buildProgramB64(6, ops)
	if !IsValidExecutionProgram(program) {
		t.Fatalf("the version-6 probe program must parse")
	}
	// The same opcodes under the version-5 ceiling are refused.
	if IsValidExecutionProgram(buildProgramB64(5, ops)) {
		t.Fatalf("the version-5 opcode ceiling must refuse the version-6 probes")
	}
	// A truncated probe operand is refused.
	broken := [][2]interface{}{
		{byte(opCssGeom), idOperand},
		{byte(opAdd), addOperand},
		{byte(opAdd), addOperand},
		{byte(opAdd), addOperand},
		{byte(opAdd), addOperand},
		{byte(opAdd), addOperand},
		{byte(opAdd), addOperand},
		{byte(opAdd), addOperand},
	}
	if IsValidExecutionProgram(buildProgramB64(6, broken)) {
		t.Fatalf("a truncated version-6 probe operand must be refused")
	}
}

func TestIssuerGuardRefusesUnverifiableRungs(t *testing.T) {
	if !RungVerifiable(16*1024, 3, 1) || !RungVerifiable(64*1024, 3, 1) {
		t.Fatalf("the argon profile rungs must be verifiable in this runtime")
	}
	if RungVerifiable(64*1024, 2, 1) {
		t.Fatalf("a time cost below the derivation profile must refuse")
	}
	if RungVerifiable(64*1024, 3, 2) {
		t.Fatalf("parallelism outside the protocol profile must refuse")
	}
	settings := Settings{Secret: "0123456789abcdef0123456789abcdef", Profile: "argon128", Store: "memory://"}
	if _, err := settings.BuildVerifier(); err == nil {
		t.Fatalf("an unknown profile must be a loud configuration error")
	}
	good := Settings{Secret: "0123456789abcdef0123456789abcdef", Profile: "argon64", Store: "memory://"}
	if _, err := good.BuildVerifier(); err != nil {
		t.Fatalf("a verifiable rung must boot: %v", err)
	}
}
