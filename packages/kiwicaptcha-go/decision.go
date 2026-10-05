package kiwicaptcha

import "strconv"

// Decision dispositions of the contract level answer.
const (
	DispositionAllow = "allow"
	DispositionDeny  = "deny"
	DispositionRetry = "retry"
)

// retryCodes are the transient conditions where the same token may
// legitimately be resubmitted once the backend recovers.
var retryCodes = map[VerifyError]bool{
	ErrCodeStorageUnavailable:   true,
	ErrCodeCapacityExceeded:     true,
	ErrCodeAdmissionUnavailable: true,
	ErrCodeConsumeIndeterminate: true,
}

// VerifyDecision is the contract level answer of verify: the shared
// server SDK shape {ok, disposition, decision_handle, price}.
//
// Disposition is allow when the proof verified, deny for a definitive
// rejection, and retry for a transient condition. DecisionHandle is
// the verified nonce, the canonical replay id the outcomes ledger
// addresses. Price is the work ladder rung the challenge carried,
// derived from its authenticated parameters.
type VerifyDecision struct {
	OK             bool
	Disposition    string
	DecisionHandle string
	Price          string
	Error          string
	Outcome        VerifyOutcome
}

// DecisionFromOutcome maps a verify outcome onto the decision plane.
func DecisionFromOutcome(outcome VerifyOutcome, price string) VerifyDecision {
	if outcome.Valid {
		return VerifyDecision{
			OK:             true,
			Disposition:    DispositionAllow,
			DecisionHandle: outcome.Nonce,
			Price:          price,
			Outcome:        outcome,
		}
	}
	disposition := DispositionDeny
	if retryCodes[outcome.Error] {
		disposition = DispositionRetry
	}
	return VerifyDecision{
		OK:          false,
		Disposition: disposition,
		Error:       outcome.Code(),
		Outcome:     outcome,
	}
}

// PriceRung names the work ladder rung of one record's authenticated
// parameters. The sha rungs carry their difficulty, the argon rungs
// their memory, and the sequential time-lock rung is rsw.
func PriceRung(algorithm string, targetBits, mKib int) string {
	switch algorithm {
	case "sha256":
		return "sha" + strconv.Itoa(targetBits)
	case "argon2id":
		return "argon" + strconv.Itoa(mKib)
	default:
		return "rsw"
	}
}
