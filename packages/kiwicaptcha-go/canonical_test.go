package kiwicaptcha

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestCanonicalV1VectorSignatures(t *testing.T) {
	for _, vector := range []protocolVector{shaVector, argon2Vector} {
		payloadB64, signature, found := strings.Cut(vector.Challenge, ".")
		if !found {
			t.Fatalf("vector challenge carries no signature tag")
		}
		payload, err := base64.StdEncoding.DecodeString(payloadB64)
		if err != nil {
			t.Fatalf("vector payload: %v", err)
		}
		if got := SignPayloadV1(string(payload), testSecret); got != signature {
			t.Fatalf("v1 signature drift: got %s want %s", got, signature)
		}
	}
}

func TestVerifyRecordSignatureAcceptsVectors(t *testing.T) {
	for _, vector := range []protocolVector{shaVector, argon2Vector} {
		record := vectorRecord(vector)
		if !VerifyRecordSignature(record, testSecret, "") {
			t.Fatalf("the %s vector signature must verify", vector.Algorithm)
		}
		record.Nonce = vector.Nonce[:10] + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		if VerifyRecordSignature(record, testSecret, "") {
			t.Fatalf("a tampered record must not verify")
		}
	}
}

func TestBindingTagMatchesGolden(t *testing.T) {
	// The sha256 golden record was issued by php for 198.51.100.7; the
	// tag pins the canonical ip family bytes and the purpose key.
	record := goldenRecord(t, "golden_sha256_v2.json")
	tag, err := BindingTag(record.Nonce, "198.51.100.7", testSecret, "")
	if err != nil {
		t.Fatalf("binding tag: %v", err)
	}
	if tag != record.BindingTag {
		t.Fatalf("binding tag drift: got %s want %s", tag, record.BindingTag)
	}
}

func TestCanonicalIPFamilyForms(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":        "\x04\xcb\x00\x71\x07",
		"::ffff:203.0.113.7": "\x04\xcb\x00\x71\x07",
		"2001:db8::1":        "\x06\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
	}
	for input, expected := range cases {
		got, err := CanonicalIPFamily(input)
		if err != nil {
			t.Fatalf("canonical ip %s: %v", input, err)
		}
		if string(got) != expected {
			t.Fatalf("canonical ip %s: got %x want %x", input, got, expected)
		}
	}
	for _, bad := range []string{"", "fe80::1%eth0", "999.1.1.1", "1.1.1.01", "not-an-ip"} {
		if _, err := CanonicalIPFamily(bad); err == nil {
			t.Fatalf("canonical ip %q must fail", bad)
		}
	}
}

func TestServerStateMacMatchesGolden(t *testing.T) {
	record := goldenRecord(t, "golden_sha256_v2.json")
	key, err := ServerStateMacKey(testSecret, "")
	if err != nil {
		t.Fatalf("mac key: %v", err)
	}
	mac := ServerStateMacRecordMeta(key, record.Challenge, record.IssuedAtNs, record.Hostname)
	if mac != record.ServerMac {
		t.Fatalf("record metadata mac drift: got %s want %s", mac, record.ServerMac)
	}
	if !ConstantTimeEquals(mac, record.ServerMac) {
		t.Fatalf("mac compare failed")
	}
}

func TestSignedCanonicalCommitsRecordMeta(t *testing.T) {
	if !SignedCanonicalCommitsRecordMeta(goldenRecord(t, "golden_sha256_v2.json").Challenge) {
		t.Fatalf("the golden record carries the m=1 marker")
	}
	record := mintRecord(t, defaultMintOptions())
	if SignedCanonicalCommitsRecordMeta(record.Challenge) {
		t.Fatalf("a record minted without the marker must not commit the mac")
	}
}

func TestPolicyRolloutWindow(t *testing.T) {
	verifier := newTestVerifier(t, VerifierConfig{
		ExpectedPolicyVersion: 3,
		PolicyVersionFloor:    2,
	}, testNow)
	if !verifier.policyVersionAccepted(2) || !verifier.policyVersionAccepted(3) {
		t.Fatalf("the rollout window accepts floor through expected")
	}
	if verifier.policyVersionAccepted(1) || verifier.policyVersionAccepted(4) {
		t.Fatalf("the rollout window must fail closed outside the window")
	}
	strict := newTestVerifier(t, VerifierConfig{ExpectedPolicyVersion: 3}, testNow)
	if strict.policyVersionAccepted(2) {
		t.Fatalf("without a floor only the exact epoch verifies")
	}
}

func TestLeadingZeroBits(t *testing.T) {
	if got := LeadingZeroBits([]byte{0x00, 0x40, 0x00}); got != 9 {
		t.Fatalf("leading zero bits: got %d want 9", got)
	}
	if got := LeadingZeroBits([]byte{0xff}); got != 0 {
		t.Fatalf("leading zero bits: got %d want 0", got)
	}
	if got := LeadingZeroBits(make([]byte, 32)); got != 256 {
		t.Fatalf("leading zero bits: got %d want 256", got)
	}
}

func TestDerivedKeysMatchGoldenSignature(t *testing.T) {
	// The golden v2 challenge was signed by php under the derived
	// challenge purpose key, so a recomputed v2 signature pins the
	// whole derivation.
	record := goldenRecord(t, "golden_sha256_v2.json")
	if !VerifyRecordSignature(record, testSecret, "") {
		t.Fatalf("the php signed golden v2 record must verify")
	}
	keys, err := DerivedKeysFromMaster(testSecret, "acme")
	if err != nil {
		t.Fatalf("derived keys: %v", err)
	}
	tenantKeys, err := DerivedKeysFromMaster(testSecret, "acme")
	if err != nil {
		t.Fatalf("derived keys: %v", err)
	}
	if string(keys.ChallengeKey) != string(tenantKeys.ChallengeKey) {
		t.Fatalf("the derivation must be deterministic")
	}
	globalKeys, err := DerivedKeysFromMaster(testSecret, "")
	if err != nil {
		t.Fatalf("derived keys: %v", err)
	}
	if string(globalKeys.ChallengeKey) == string(keys.ChallengeKey) {
		t.Fatalf("a tenant scope must change the purpose keys")
	}
}

func TestFixedClockHelper(t *testing.T) {
	config, err := NewVerifierConfig(VerifierConfig{NowFunc: func() time.Time { return time.Unix(testNow, 0) }})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if config.NowFunc().Unix() != testNow {
		t.Fatalf("the clock override must be honored")
	}
}
