package kiwicaptcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// The signed canonical payload, revision 4, byte-identical with the
// php Issuer and the Rust canonical_signing_input_v2:
//
//	v4|protocol_version|nonce|scope|binding_tag|issued_at|expires_at|
//	  algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|
//	  policy_version|request_binding|issuer|kid[|d=decoy][|e=v,hex]
//	  [|r=hex][|m=1]
//
// Unset optional fields render as the empty segment. Every armed
// extension is appended tagged in capability order, and the record
// metadata mac marker lands last, so stripping the mac breaks the
// signature.
func CanonicalPayload(
	protocolVersion int,
	nonce, scope, bindingTag string,
	issuedAt, expiresAt int64,
	algorithm string,
	mKib, t, p, targetBits int,
	salt string,
	minDurationMs int,
	region string,
	policyVersion int,
	requestBinding string,
	issuer string,
	kid int,
	decoyField string,
	executionVersion int,
	executionCommitment string,
	rswModulusSha256 string,
	serverMacCommitted bool,
) string {
	var b strings.Builder
	b.Grow(256)
	b.WriteString("v4|")
	b.WriteString(strconv.Itoa(protocolVersion))
	b.WriteByte('|')
	b.WriteString(nonce)
	b.WriteByte('|')
	b.WriteString(scope)
	b.WriteByte('|')
	b.WriteString(bindingTag)
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(issuedAt, 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(expiresAt, 10))
	b.WriteByte('|')
	b.WriteString(algorithm)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(mKib))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(t))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(p))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(targetBits))
	b.WriteByte('|')
	b.WriteString(salt)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(minDurationMs))
	b.WriteByte('|')
	b.WriteString(region)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(policyVersion))
	b.WriteByte('|')
	b.WriteString(requestBinding)
	b.WriteByte('|')
	b.WriteString(issuer)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(kid))
	if decoyField != "" {
		b.WriteString("|d=")
		b.WriteString(decoyField)
	}
	if executionVersion != 0 || executionCommitment != "" {
		b.WriteString("|e=")
		b.WriteString(strconv.Itoa(executionVersion))
		b.WriteByte(',')
		b.WriteString(executionCommitment)
	}
	if rswModulusSha256 != "" {
		b.WriteString("|r=")
		b.WriteString(rswModulusSha256)
	}
	if serverMacCommitted {
		b.WriteString("|m=1")
	}
	return b.String()
}

// ErrCanonicalExecutionPair is raised when exactly one half of the
// execution commitment pair is presented. The canonical can never be
// ambiguous across languages.
var ErrCanonicalExecutionPair = errors.New("kiwicaptcha: execution_version and execution_commitment must be passed together")

// CanonicalPayloadChecked is CanonicalPayload with the execution pair
// arity error the php helper raises. Call it from issuers; the
// verifier only reassembles records whose parser already enforced the
// pair.
func CanonicalPayloadChecked(
	protocolVersion int,
	nonce, scope, bindingTag string,
	issuedAt, expiresAt int64,
	algorithm string,
	mKib, t, p, targetBits int,
	salt string,
	minDurationMs int,
	region string,
	policyVersion int,
	requestBinding string,
	issuer string,
	kid int,
	decoyField string,
	executionVersion int,
	executionCommitment string,
	rswModulusSha256 string,
	serverMacCommitted bool,
) (string, error) {
	if (executionVersion != 0) != (executionCommitment != "") {
		return "", ErrCanonicalExecutionPair
	}
	return CanonicalPayload(protocolVersion, nonce, scope, bindingTag, issuedAt, expiresAt,
		algorithm, mKib, t, p, targetBits, salt, minDurationMs, region, policyVersion,
		requestBinding, issuer, kid, decoyField, executionVersion, executionCommitment,
		rswModulusSha256, serverMacCommitted), nil
}

// b64CanonicalDecode decodes strict canonical standard base64: the
// input must be exactly the canonical padded encoding of its bytes.
func b64CanonicalDecode(raw string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, false
	}
	if base64.StdEncoding.EncodeToString(decoded) != raw {
		return nil, false
	}
	return decoded, true
}

// SignedCanonicalCommitsRecordMeta reports whether the signed
// canonical carries the m=1 marker. The marker is parsed from the
// challenge string itself, never inferred from the stored mac
// presence, so an m=1 record must carry a valid mac regardless of any
// stored value.
func SignedCanonicalCommitsRecordMeta(challenge string) bool {
	dot := strings.LastIndexByte(challenge, '.')
	if dot < 0 {
		return false
	}
	canonical, ok := b64CanonicalDecode(challenge[:dot])
	if !ok {
		return false
	}
	text := string(canonical)
	return strings.HasPrefix(text, "v4|") && strings.HasSuffix(text, "|m=1")
}

// LegacyV1Payload is the legacy v1 canonical: four untagged segments.
func LegacyV1Payload(nonce, scope, ipHash string, issuedAt int64) string {
	return nonce + "|" + scope + "|" + ipHash + "|" + strconv.FormatInt(issuedAt, 10)
}

// SignPayloadV1 is the legacy v1 signature: the hex hmac under the
// master secret directly.
func SignPayloadV1(payload, secretKey string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignPayloadV2 is the v2 signature: the hex hmac under the derived
// challenge purpose key. The master secret is never used directly as
// the signing key.
func SignPayloadV2(payload, secretKey, tenantID string) (string, error) {
	keys, err := DerivedKeysFromMaster(secretKey, tenantID)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, keys.ChallengeKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// SignatureFromChallenge returns the hex tag after the last dot of the
// challenge string.
func SignatureFromChallenge(challenge string) string {
	dot := strings.LastIndexByte(challenge, '.')
	if dot < 0 {
		return ""
	}
	return challenge[dot+1:]
}

// HashIPV1 is the legacy v1 binding value: the sha256 hex of
// secret plus ip.
func HashIPV1(ip, secret string) string {
	sum := sha256.Sum256([]byte(secret + ip))
	return hex.EncodeToString(sum[:])
}

// ErrInvalidIP is raised for an input that is not a plain IPv4 or IPv6
// address. The ip binding check resolves it to the typed mismatch.
var ErrInvalidIP = errors.New("kiwicaptcha: invalid ip address")

// CanonicalIPFamily returns the family byte plus the packed bytes of
// one address: 0x04 plus the 4-byte form, or 0x06 plus the 16-byte
// form. An IPv4-mapped or deprecated IPv4-compatible IPv6 form folds
// to its 4-byte form, so two textual spellings of one address produce
// the same bytes. A zoned IPv6 literal is rejected.
func CanonicalIPFamily(ip string) ([]byte, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, ErrInvalidIP
	}
	if addr.Zone() != "" {
		return nil, ErrInvalidIP
	}
	if addr.Is4() {
		four := addr.As4()
		out := make([]byte, 5)
		out[0] = 0x04
		copy(out[1:], four[:])
		return out, nil
	}
	raw := addr.As16()
	var low4 [4]byte
	copy(low4[:], raw[12:])
	mapped := raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 &&
		raw[4] == 0 && raw[5] == 0 && raw[6] == 0 && raw[7] == 0 &&
		raw[8] == 0 && raw[9] == 0 && raw[10] == 0xff && raw[11] == 0xff
	compatiblePrefix := raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 &&
		raw[4] == 0 && raw[5] == 0 && raw[6] == 0 && raw[7] == 0 &&
		raw[8] == 0 && raw[9] == 0 && raw[10] == 0 && raw[11] == 0
	compatible := compatiblePrefix && !(low4 == [4]byte{}) && low4 != [4]byte{0, 0, 0, 1}
	if mapped || compatible {
		out := make([]byte, 5)
		out[0] = 0x04
		copy(out[1:], low4[:])
		return out, nil
	}
	out := make([]byte, 17)
	out[0] = 0x06
	copy(out[1:], raw[:])
	return out, nil
}

// BindingTag is the v2 binding tag: a nonce bound hmac over the
// canonical ip bytes, keyed by the ip binding purpose key. The tag is
// a nonce bound hmac, never a stable ip derived identifier.
func BindingTag(nonce, ip, secret, tenantID string) (string, error) {
	family, err := CanonicalIPFamily(ip)
	if err != nil {
		return "", err
	}
	keys, err := DerivedKeysFromMaster(secret, tenantID)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, keys.IPBindKey)
	mac.Write([]byte(IPBindDomain + "\x00" + nonce + "\x00"))
	mac.Write(family)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ConstantTimeEquals compares two strings without short-circuiting.
func ConstantTimeEquals(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// LeadingZeroBits counts the leading zero bits of a digest in
// big-endian bit order, identical to the Rust leading_zero_bits.
func LeadingZeroBits(digest []byte) int {
	count := 0
	for _, by := range digest {
		if by == 0 {
			count += 8
			continue
		}
		for by&0x80 == 0 {
			count++
			by <<= 1
		}
		break
	}
	return count
}

// ServerStateMac authenticates the server written state the signature
// skips: the record metadata (issued_at_ns and hostname) and the
// committed consumed result. Both are mac'ed under the dedicated
// server state purpose key, so a storage writer without the master
// secret can neither backdate the issuance clock nor forge a stored
// success. The mac input binds the full challenge string and
// length-prefixes every variable field, so a mac can never be
// transplanted to another record.
type ServerStateMac struct{}

// ServerStateMacKey derives the server state purpose key.
func ServerStateMacKey(secret, tenantID string) ([]byte, error) {
	keys, err := DerivedKeysFromMaster(secret, tenantID)
	if err != nil {
		return nil, err
	}
	return keys.ServerStateKey, nil
}

func macLengthPrefix(sb *strings.Builder, value string) {
	sb.WriteString(strconv.Itoa(len(value)))
	sb.WriteByte(':')
	sb.WriteString(value)
}

func macOptional(sb *strings.Builder, value string) {
	if value == "" {
		// An unset optional renders as "0"; a set value renders as
		// "1:" plus its length prefix. Callers pass the empty string
		// for unset, which the wire never carries as a real value.
		sb.WriteString("0")
		return
	}
	sb.WriteString("1:")
	macLengthPrefix(sb, value)
}

// RecordMetaInput assembles the record metadata mac input.
func RecordMetaInput(challenge string, issuedAtNs int64, hostname string) string {
	var sb strings.Builder
	sb.WriteString(RecordMetaDomain)
	sb.WriteByte('\n')
	macLengthPrefix(&sb, challenge)
	sb.WriteByte('\n')
	sb.WriteString(strconv.FormatInt(issuedAtNs, 10))
	sb.WriteByte('\n')
	macOptional(&sb, hostname)
	return sb.String()
}

// ConsumedResultInput assembles the consumed result mac input.
func ConsumedResultInput(challenge string, valid bool, binding, operationIdentity string) string {
	var sb strings.Builder
	sb.WriteString(ConsumedResultDomain)
	sb.WriteByte('\n')
	macLengthPrefix(&sb, challenge)
	sb.WriteByte('\n')
	if valid {
		sb.WriteString("1")
	} else {
		sb.WriteString("0")
	}
	sb.WriteByte('\n')
	macOptional(&sb, binding)
	sb.WriteByte('\n')
	macOptional(&sb, operationIdentity)
	return sb.String()
}

func hmacHex(key []byte, input string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}

// ServerStateMacRecordMeta computes the record metadata mac.
func ServerStateMacRecordMeta(key []byte, challenge string, issuedAtNs int64, hostname string) string {
	return hmacHex(key, RecordMetaInput(challenge, issuedAtNs, hostname))
}

// ServerStateMacConsumedResult computes the consumed result mac.
func ServerStateMacConsumedResult(key []byte, challenge string, valid bool, binding, operationIdentity string) string {
	return hmacHex(key, ConsumedResultInput(challenge, valid, binding, operationIdentity))
}

// VerifyRecordSignature recomputes the expected signature of a record
// and compares it constant-time. Protocol v1 uses the legacy canonical
// signed under the master secret; v2 and above use the full parameter
// canonical signed under the derived challenge key. The signed m=1
// marker requires a valid record metadata mac; a record signed without
// the marker accepts an absent mac and always verifies a present one.
func VerifyRecordSignature(record *ChallengeRecord, secretKey, tenantID string) bool {
	commitsMac := SignedCanonicalCommitsRecordMeta(record.Challenge)
	var expected string
	if record.ProtocolVersion == 1 {
		expected = SignPayloadV1(
			LegacyV1Payload(record.Nonce, record.Scope, record.BindingTag, record.IssuedAt),
			secretKey,
		)
	} else {
		payload, err := CanonicalPayloadChecked(
			record.ProtocolVersion,
			record.Nonce,
			record.Scope,
			record.BindingTag,
			record.IssuedAt,
			record.ExpiresAt,
			record.Algorithm,
			record.MKib,
			record.T,
			record.P,
			record.TargetBits,
			record.Salt,
			record.MinDurationMs,
			record.Region,
			record.PolicyVersionOrOne(),
			record.RequestBinding,
			record.Issuer,
			record.KidOrOne(),
			record.DecoyField,
			record.ExecutionVersion,
			record.ExecutionCommitment,
			record.RswModulusSha256,
			commitsMac,
		)
		if err != nil {
			return false
		}
		signed, err := SignPayloadV2(payload, secretKey, tenantID)
		if err != nil {
			return false
		}
		expected = signed
	}
	if !ConstantTimeEquals(expected, SignatureFromChallenge(record.Challenge)) {
		return false
	}
	key, err := ServerStateMacKey(secretKey, tenantID)
	if err != nil {
		return false
	}
	if commitsMac {
		return record.ServerMac != "" &&
			ConstantTimeEquals(
				ServerStateMacRecordMeta(key, record.Challenge, record.IssuedAtNs, record.Hostname),
				record.ServerMac,
			)
	}
	return record.ServerMac == "" ||
		ConstantTimeEquals(
			ServerStateMacRecordMeta(key, record.Challenge, record.IssuedAtNs, record.Hostname),
			record.ServerMac,
		)
}
