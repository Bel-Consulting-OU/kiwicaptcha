package kiwicaptcha

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The client submitted solution token and its wire grammar, a port of
// the php SolutionToken. The wire format is
// base64(nonce "." counter "." duration_ms "." telemetry_json
// ["." execution_digest[":" execution_trace]] ["." rsw_proof]).
// The telemetry segment may contain dots, so decoding splits on all
// dots and peels the optional suffix segments right to left,
// independently. The rsw final value peels first, exactly when the
// last segment is 512 lowercase hex. The execution evidence segment
// that precedes it peels next. The unarmed token keeps the exact four
// segment shape.
//
// Numeric segments are canonical decimal: digits only, a leading zero
// rejected unless the whole segment is exactly "0", so each value has
// exactly one wire spelling in every implementation.

// DecodeError reasons, identical to the php codes.
const (
	DecodeErrInvalidBase64  = "invalid_base64"
	DecodeErrInvalidUTF8    = "invalid_utf8"
	DecodeErrMalformed      = "malformed"
	DecodeErrInvalidCounter = "invalid_counter"
	DecodeErrInvalidCount   = "counter exceeds solver maximum"
	DecodeErrInvalidDur     = "invalid_duration"
)

// DecodeError is a solution token wire grammar failure. The Code is
// the machine readable reason carried as the malformed_token outcome
// detail.
type DecodeError struct{ Code string }

func (e *DecodeError) Error() string { return "kiwicaptcha: token decode error: " + e.Code }

// Token byte bounds of the wire grammar.
const (
	maxTokenBytes     = 32_768
	maxTraceB64Length = 10_924
)

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, by := range []byte(s) {
		if by < '0' || by > '9' {
			return false
		}
	}
	return true
}

func canonicalDecimal(s string) (int, bool) {
	if !isDigits(s) {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	value, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return value, true
}

func isHexN(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, by := range []byte(s) {
		if (by < '0' || by > '9') && (by < 'a' || by > 'f') {
			return false
		}
	}
	return true
}

// canonicalB64Decode decodes strict canonical standard base64: one
// spelling per byte string. Rejects every character outside the
// standard alphabet, including the base64url alphabet and whitespace,
// and the canonical re-encode check rejects non-canonical padding and
// non-zero trailing bits.
func canonicalB64Decode(raw string) ([]byte, bool) {
	return b64CanonicalDecode(raw)
}

// SolutionToken is a decoded solution token. Telemetry is always an
// ordered object: the wire grammar requires a json object, so an array
// or scalar fails closed, and the key order of the wire bytes is
// preserved for the encoder.
type SolutionToken struct {
	Nonce           string
	Counter         int
	DurationMs      int
	Telemetry       *JSONObject
	ExecutionDigest string
	ExecutionTrace  string
	RswProof        string
}

// TelemetryBool returns the named boolean field.
func (t *SolutionToken) TelemetryBool(key string) (bool, bool) {
	if t.Telemetry == nil {
		return false, false
	}
	value, ok := t.Telemetry.Get(key)
	if !ok {
		return false, false
	}
	b, ok := value.(bool)
	return b, ok
}

// TelemetryEvents returns the "et" event list when it is an array of
// non negative integers.
func (t *SolutionToken) TelemetryEvents() []int {
	if t.Telemetry == nil {
		return nil
	}
	value, ok := t.Telemetry.Get("et")
	if !ok {
		return nil
	}
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}
	events := make([]int, 0, len(items))
	for _, item := range items {
		number, ok := item.(jsonNumber)
		if !ok {
			continue
		}
		parsed, err := strconv.Atoi(string(number))
		if err != nil || parsed < 0 {
			continue
		}
		events = append(events, parsed)
	}
	return events
}

// Encode assembles the canonical wire bytes. The telemetry segment is
// always a json object, so an empty object encodes as {} and never
// []. The execution trace travels as unpadded base64url; a standard
// base64 trace is translated, never double encoded. An unarmed token
// stays byte identical to the four segment shape.
func (t *SolutionToken) Encode() string {
	plain := t.Nonce + "." + strconv.Itoa(t.Counter) + "." + strconv.Itoa(t.DurationMs) + "." + t.Telemetry.Encode()
	if t.ExecutionDigest != "" {
		plain += "." + t.ExecutionDigest
		if t.ExecutionTrace != "" {
			translated := strings.NewReplacer("+", "-", "/", "_").Replace(t.ExecutionTrace)
			translated = strings.TrimRight(translated, "=")
			plain += ":" + translated
		}
	}
	if t.RswProof != "" {
		plain += "." + t.RswProof
	}
	return base64.StdEncoding.EncodeToString([]byte(plain))
}

func b64urlToStandard(trace string) string {
	standard := strings.NewReplacer("-", "+", "_", "/").Replace(trace)
	pad := (4 - len(standard)%4) % 4
	return standard + strings.Repeat("=", pad)
}

// canonicalB64urlCheck requires one canonical unpadded base64url
// spelling, the driver's format.
func canonicalB64urlCheck(trace string) bool {
	if trace == "" || len(trace) > maxTraceB64Length {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(b64urlToStandard(trace))
	if err != nil {
		return false
	}
	reencoded := base64.StdEncoding.EncodeToString(decoded)
	reencoded = strings.NewReplacer("+", "-", "/", "_").Replace(reencoded)
	reencoded = strings.TrimRight(reencoded, "=")
	return reencoded == trace
}

// DecodeToken parses wire bytes and returns a typed error on any
// grammar violation.
func DecodeToken(raw string) (*SolutionToken, error) {
	if len(raw) > maxTokenBytes {
		return nil, &DecodeError{Code: DecodeErrMalformed}
	}
	plainBytes, ok := canonicalB64Decode(raw)
	if !ok {
		return nil, &DecodeError{Code: DecodeErrInvalidBase64}
	}
	if !utf8.Valid(plainBytes) {
		return nil, &DecodeError{Code: DecodeErrInvalidUTF8}
	}
	plain := string(plainBytes)
	parts := strings.Split(plain, ".")
	if len(parts) < 4 {
		return nil, &DecodeError{Code: DecodeErrMalformed}
	}
	end := len(parts)
	rswProof := ""
	executionDigest := ""
	executionTrace := ""
	if end >= 5 && isHexN(parts[end-1], 512) {
		rswProof = parts[end-1]
		end--
	}
	if end >= 5 {
		segment := parts[end-1]
		colon := strings.IndexByte(segment, ':')
		digestPart := segment
		if colon >= 0 {
			digestPart = segment[:colon]
		}
		if isHexN(digestPart, 64) {
			executionDigest = digestPart
			if colon >= 0 {
				executionTrace = segment[colon+1:]
				if !canonicalB64urlCheck(executionTrace) {
					return nil, &DecodeError{Code: DecodeErrMalformed}
				}
			}
			end--
		}
	}
	telemetryStr := strings.Join(parts[3:end], ".")
	nonce, counterStr, durationStr := parts[0], parts[1], parts[2]

	// The nonce is base64 of 32 random bytes: exactly 44 chars with one
	// padding character. The shape check alone is not enough, so the
	// canonical re-encode check pins exactly one wire spelling.
	if len(nonce) != 44 || !strings.HasSuffix(nonce, "=") || strings.ContainsAny(nonce, "-_") {
		return nil, &DecodeError{Code: DecodeErrMalformed}
	}
	nonceBytes, ok := canonicalB64Decode(nonce)
	if !ok || len(nonceBytes) != NonceB64Bytes {
		return nil, &DecodeError{Code: DecodeErrMalformed}
	}
	counter, ok := canonicalDecimal(counterStr)
	if !ok {
		return nil, &DecodeError{Code: DecodeErrInvalidCounter}
	}
	if len(counterStr) > 8 || counter >= MaxSolverCounter {
		return nil, &DecodeError{Code: DecodeErrInvalidCount}
	}
	duration, ok := canonicalDecimal(durationStr)
	if !ok {
		return nil, &DecodeError{Code: DecodeErrInvalidDur}
	}
	if duration > MaxDurationMs {
		return nil, &DecodeError{Code: DecodeErrInvalidDur}
	}
	telemetry, err := parseJSONObject(telemetryStr)
	if err != nil {
		return nil, &DecodeError{Code: DecodeErrMalformed}
	}
	if executionDigest != "" && !isHexN(executionDigest, 64) {
		return nil, &DecodeError{Code: DecodeErrMalformed}
	}
	return &SolutionToken{
		Nonce:           nonce,
		Counter:         counter,
		DurationMs:      duration,
		Telemetry:       telemetry,
		ExecutionDigest: executionDigest,
		ExecutionTrace:  executionTrace,
		RswProof:        rswProof,
	}, nil
}

// ErrTokenEncode is raised by CreateToken on an impossible shape.
var ErrTokenEncode = errors.New("kiwicaptcha: token encode error")

// CreateToken assembles one solution token, the mirror of decode for
// tests and native solvers.
func CreateToken(nonce string, counter, durationMs int, telemetry *JSONObject, executionDigest, executionTrace, rswProof string) *SolutionToken {
	return &SolutionToken{
		Nonce:           nonce,
		Counter:         counter,
		DurationMs:      durationMs,
		Telemetry:       telemetry,
		ExecutionDigest: executionDigest,
		ExecutionTrace:  executionTrace,
		RswProof:        rswProof,
	}
}
