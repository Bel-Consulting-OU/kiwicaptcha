package kiwicaptcha

import "fmt"

// VerifyError is one machine readable failure of the verify path.
// Every value is a stable snake_case wire code, the vocabulary shared
// with the php enum and the Rust code mapping; logs, metrics and
// cross-service consumers switch on it without parsing prose.
type VerifyError string

// The failure vocabulary of the verify path.
const (
	ErrCodeBadSignature         VerifyError = "bad_signature"
	ErrCodeExpired              VerifyError = "expired"
	ErrCodeWrongScope           VerifyError = "wrong_scope"
	ErrCodeRequiredScope        VerifyError = "required_scope"
	ErrCodeIPMismatch           VerifyError = "ip_mismatch"
	ErrCodeMissingClientIP      VerifyError = "missing_client_ip"
	ErrCodeWrongRegion          VerifyError = "wrong_region"
	ErrCodeWrongIssuer          VerifyError = "wrong_issuer"
	ErrCodeWrongPolicyVersion   VerifyError = "wrong_policy_version"
	ErrCodeUnknownKid           VerifyError = "unknown_kid"
	ErrCodeTooFast              VerifyError = "too_fast"
	ErrCodeInsufficientWork     VerifyError = "insufficient_work"
	ErrCodeMalformedRecord      VerifyError = "malformed_record"
	ErrCodeRecordNotFound       VerifyError = "record_not_found"
	ErrCodeMalformedToken       VerifyError = "malformed_token"
	ErrCodeUnsupportedArgon2    VerifyError = "unsupported_argon2_params"
	ErrCodeTooManyAttempts      VerifyError = "too_many_attempts"
	ErrCodeTelemetryRejected    VerifyError = "telemetry_rejected"
	ErrCodeCapacityExceeded     VerifyError = "capacity_exceeded"
	ErrCodeAdmissionUnavailable VerifyError = "admission_unavailable"
	ErrCodeStorageUnavailable   VerifyError = "storage_unavailable"
	ErrCodeConsumeIndeterminate VerifyError = "consume_indeterminate"
	ErrCodeAlreadyConsumed      VerifyError = "already_consumed"
	ErrCodeRequestBinding       VerifyError = "request_binding_mismatch"
	ErrCodeExecutionMismatch    VerifyError = "execution_mismatch"
	ErrCodeUnsupportedRswParams VerifyError = "unsupported_rsw_params"
)

// Code returns the wire code of this failure.
func (e VerifyError) Code() string { return string(e) }

// Description returns the operator facing explanation; switch on the
// code, not this.
func (e VerifyError) Description() string {
	if text, ok := verifyErrorDescriptions[e]; ok {
		return text
	}
	return string(e)
}

// IsReplayExempt reports whether this failure is exempt from the
// one-shot policy. The exempt set describes the original redemption's
// circumstances: the signed expiry, the network binding, the missing
// client ip, and the client side telemetry evidence. A consumed record
// failing one of them may still resolve through the consumed branch.
// Every security verdict stands regardless of a matching operation
// identity.
func (e VerifyError) IsReplayExempt() bool {
	switch e {
	case ErrCodeExpired, ErrCodeIPMismatch, ErrCodeMissingClientIP, ErrCodeTelemetryRejected:
		return true
	default:
		return false
	}
}

var verifyErrorDescriptions = map[VerifyError]string{
	ErrCodeBadSignature:         "challenge signature is invalid",
	ErrCodeExpired:              "challenge has expired",
	ErrCodeWrongScope:           "challenge was issued for a different scope",
	ErrCodeRequiredScope:        "the scope option is required: verify refuses to accept a token for any scope",
	ErrCodeIPMismatch:           "challenge was issued to a different client ip",
	ErrCodeMissingClientIP:      "challenge is ip-bound but no client ip was supplied",
	ErrCodeWrongRegion:          "challenge was issued for a different region",
	ErrCodeWrongIssuer:          "challenge was issued by a different deployment",
	ErrCodeWrongPolicyVersion:   "challenge was issued under a different security-policy epoch",
	ErrCodeUnknownKid:           "unknown signing key id",
	ErrCodeTooFast:              "solution arrived faster than the theoretical minimum, server measured",
	ErrCodeInsufficientWork:     "solution does not meet the difficulty target",
	ErrCodeMalformedRecord:      "stored challenge record is malformed",
	ErrCodeRecordNotFound:       "challenge record not found, unknown or already deleted",
	ErrCodeMalformedToken:       "solution token is malformed",
	ErrCodeUnsupportedArgon2:    "argon2id parameters exceed the supported process ceilings",
	ErrCodeTooManyAttempts:      "too many verification attempts",
	ErrCodeTelemetryRejected:    "bot-signal telemetry rejected the solution",
	ErrCodeCapacityExceeded:     "verification capacity exceeded, try again shortly",
	ErrCodeAdmissionUnavailable: "verification admission backend unavailable, try again shortly",
	ErrCodeStorageUnavailable:   "verification storage backend unavailable, try again shortly",
	ErrCodeConsumeIndeterminate: "verification storage response indeterminate, the challenge may or may not have been consumed",
	ErrCodeAlreadyConsumed:      "the challenge was already consumed by a different logical operation",
	ErrCodeRequestBinding:       "the challenge is not bound to the expected application transaction",
	ErrCodeExecutionMismatch:    "the execution digest does not match the expected program trace of the challenge",
	ErrCodeUnsupportedRswParams: "the rsw challenge cannot be verified: this verifier is not configured with the matching rsw trapdoor, or the signed sequential cost is outside the supported bounds",
}

// VerifyOutcome is the result of one solution verification. A valid
// outcome exposes the nonce, the consumed record's application
// transaction binding, the server-measured solve duration and the
// authenticated honeypot field name. Every field is the zero value on
// a non-valid outcome; the solve duration is also zero on a
// stored-result replay, whose receipt is not the solve's endpoint.
type VerifyOutcome struct {
	Valid            bool
	Error            VerifyError
	Detail           string
	Nonce            string
	RequestBinding   string
	FromStoredResult bool
	SolveDurationMs  int64
	SolveDurationSet bool
	DecoyField       string
}

// ValidOutcome builds the success shape.
func ValidOutcome(nonce, requestBinding string, fromStoredResult bool, solveDurationMs int64, solveDurationSet bool, decoyField string) VerifyOutcome {
	return VerifyOutcome{
		Valid:            true,
		Nonce:            nonce,
		RequestBinding:   requestBinding,
		FromStoredResult: fromStoredResult,
		SolveDurationMs:  solveDurationMs,
		SolveDurationSet: solveDurationSet,
		DecoyField:       decoyField,
	}
}

// InvalidOutcome builds one typed failure.
func InvalidOutcome(err VerifyError) VerifyOutcome {
	return VerifyOutcome{Error: err}
}

// MalformedTokenOutcome builds the malformed_token failure with the
// decoder's reason.
func MalformedTokenOutcome(detail string) VerifyOutcome {
	return VerifyOutcome{Error: ErrCodeMalformedToken, Detail: detail}
}

// IsOK reports whether the proof verified.
func (o VerifyOutcome) IsOK() bool { return o.Valid }

// Code returns the machine readable error code, empty when valid.
func (o VerifyOutcome) Code() string { return o.Error.Code() }

// String renders the outcome for logs without leaking record bytes.
func (o VerifyOutcome) String() string {
	if o.Valid {
		return fmt.Sprintf("VerifyOutcome(valid=true, nonce redacted)")
	}
	return fmt.Sprintf("VerifyOutcome(valid=false, error=%s)", o.Error)
}
