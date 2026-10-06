package kiwicaptcha

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The execution delegation plane: an execution-armed record demands the
// browser-trace walker, an oracle this SDK does not carry. The default
// policy is fail-closed (today's behavior, documented): every
// execution-armed record answers execution_mismatch. The sidecar policy
// delegates that single verification to a co-located
// kiwicaptcha-verifier sidecar over HTTP — the sidecar carries the full
// Rust core with the real execution verifier, consumes the record
// (single-use semantics preserved: the sidecar consumes, this SDK never
// double-consumes) and answers the provider-shaped verdict this SDK
// maps back into its own vocabulary.
//
// Trust boundary: the sidecar decides acceptances, so it must be
// co-located and trusted to the same standard as the verifier itself.
// The bearer credential is required whenever the sidecar has one
// configured (its loopback boundary is the only other auth), and this
// SDK refuses to delegate when the sidecar rejects the credential.

// ExecutionPolicy shapes the execution-armed dimension of one verify.
// The zero value (and a nil pointer) is the fail-closed default.
type ExecutionPolicy struct {
	// SidecarURL is the kiwicaptcha-verifier base URL
	// (http://127.0.0.1:7371). Empty keeps the fail-closed default.
	SidecarURL string
	// BearerToken is the sidecar's own credential, sent as the
	// Authorization bearer on every delegation.
	BearerToken string
	// TimeoutMs bounds one delegation call; 0 uses the sidecar's own
	// default budget (5000 ms).
	TimeoutMs int
}

// sidecarDelegationEnabled reports whether the policy delegates the
// execution-armed dimension.
func (p *ExecutionPolicy) sidecarDelegationEnabled() bool {
	return p != nil && strings.TrimSpace(p.SidecarURL) != ""
}

// delegationTimeout is the bounded HTTP budget of one delegation.
func (p *ExecutionPolicy) delegationTimeout() time.Duration {
	if p.TimeoutMs > 0 {
		return time.Duration(p.TimeoutMs) * time.Millisecond
	}
	return 5000 * time.Millisecond
}

// sidecarVerifyRequest is the delegation body.
type sidecarVerifyRequest struct {
	Token    string `json:"token"`
	Scope    string `json:"scope"`
	RemoteIP string `json:"remoteip,omitempty"`
}

// sidecarVerifyResponse is the provider-shaped answer plus the
// additive kiwi-code core wire code.
type sidecarVerifyResponse struct {
	Success  bool     `json:"success"`
	KiwiCode string   `json:"kiwi-code"`
	Errors   []string `json:"error-codes"`
}

// delegateExecutionVerify hands one execution-armed verification to the
// sidecar and maps its verdict into this SDK's outcome vocabulary. The
// SDK does not consume its own copy of the record: the sidecar's
// consume is the one-shot boundary, so a deployment that shares one
// store between the SDK and the sidecar keeps exact single-use
// semantics, and a replay after a delegated verify answers
// already_consumed from the shared store.
func delegateExecutionVerify(rawToken string, record *ChallengeRecord, options VerifyOptions, policy *ExecutionPolicy) VerifyOutcome {
	body, err := json.Marshal(sidecarVerifyRequest{
		Token:    rawToken,
		Scope:    options.ExpectedScope,
		RemoteIP: options.ClientIP,
	})
	if err != nil {
		return InvalidOutcome(ErrCodeExecutionMismatch)
	}
	url := strings.TrimRight(policy.SidecarURL, "/") + "/verify"
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return InvalidOutcome(ErrCodeExecutionMismatch)
	}
	request.Header.Set("Content-Type", "application/json")
	if policy.BearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+policy.BearerToken)
	}
	client := &http.Client{Timeout: policy.delegationTimeout()}
	response, err := client.Do(request)
	if err != nil {
		// The sidecar is unreachable: the capability is unavailable,
		// fail closed with the retry disposition. The local record is
		// untouched, so the retry after recovery is clean.
		return InvalidOutcome(ErrCodeStorageUnavailable)
	}
	defer func() { _ = response.Body.Close() }()
	decoded := sidecarVerifyResponse{}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return InvalidOutcome(ErrCodeExecutionMismatch)
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		// The sidecar refused the credential: the delegation plane is
		// untrusted, never retried into, fail closed with a deny.
		return InvalidOutcome(ErrCodeExecutionMismatch)
	case response.StatusCode >= 500:
		return InvalidOutcome(ErrCodeStorageUnavailable)
	case response.StatusCode != http.StatusOK:
		return InvalidOutcome(ErrCodeExecutionMismatch)
	}
	if decoded.Success {
		// The record's application-transaction binding rides the
		// outcome: the sidecar verified the proof, the local record
		// supplies the binding the application re-checks.
		return ValidOutcome(record.RequestBinding, "", true, 0, false, record.DecoyField)
	}
	// The sidecar's kiwi-code IS the shared wire vocabulary; a code
	// this SDK does not know stays a deny with the code carried
	// verbatim, never widened into an acceptance.
	if decoded.KiwiCode != "" {
		return InvalidOutcome(VerifyError(decoded.KiwiCode))
	}
	return InvalidOutcome(ErrCodeExecutionMismatch)
}

// delegateExecutionFor reports whether the record and the options
// select the delegation path: an armed record under a sidecar policy.
func delegateExecutionFor(record *ChallengeRecord, options VerifyOptions) bool {
	return record.ExecutionProgram != "" && options.ExecutionPolicy.sidecarDelegationEnabled()
}

// describeDelegation renders the policy for logs without the token.
func (p *ExecutionPolicy) describeDelegation() string {
	if !p.sidecarDelegationEnabled() {
		return "fail-closed"
	}
	return fmt.Sprintf("sidecar %s", p.SidecarURL)
}
