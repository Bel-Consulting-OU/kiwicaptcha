package kiwicaptcha

import (
	"errors"
	"strings"
)

// The store adapter seam: record envelopes, runtime states and the
// capability interfaces the verifier composes.
//
// Every backend implements Store. The narrower capabilities are
// optional: the verifier probes them with a Go type assertion and
// follows the same fallbacks as the php verifier. The fallbacks cover
// the plain consume without an identity, the one-shot delete on a
// cheap failure, and the legacy commit without a server-state mac.
// The shipped memory and Redis backends implement every capability
// here.

// EnvelopeMaxBytes is the byte ceiling of one stored envelope.
const EnvelopeMaxBytes = 131_072

// EnvelopeDefaultPrefix is the Redis key prefix of the shipped
// adapter, shared with the php and Python writers.
const EnvelopeDefaultPrefix = "kiwicaptcha:"

// ErrStorageUnavailable is the typed fail-closed storage failure the
// verifier resolves as an unavailable store.
var ErrStorageUnavailable = errors.New("kiwicaptcha: storage backend unavailable")

// ErrOperationIdentity reports an invalid logical-operation identity
// before any transition runs. A valid identity is 1..128 bytes of
// [A-Za-z0-9_-].
var ErrOperationIdentity = errors.New("kiwicaptcha: operation identity must be 1..128 bytes of [A-Za-z0-9_-]")

// ValidateOperationIdentity validates one logical-operation identity.
func ValidateOperationIdentity(operationIdentity string) (string, error) {
	if operationIdentity == "" {
		return "", nil
	}
	if len(operationIdentity) > 128 {
		return "", ErrOperationIdentity
	}
	for _, by := range []byte(operationIdentity) {
		switch {
		case by >= 'A' && by <= 'Z':
		case by >= 'a' && by <= 'z':
		case by >= '0' && by <= '9':
		case by == '_' || by == '-':
		default:
			return "", ErrOperationIdentity
		}
	}
	return operationIdentity, nil
}

// RuntimeStateKind classifies one storage key.
type RuntimeStateKind int

// The runtime states of a stored record.
const (
	RuntimeMissing RuntimeStateKind = iota
	RuntimePending
	RuntimeConsumed
	RuntimeCancelled
)

// ChallengeRuntimeState is one runtime-state snapshot: the kind plus
// the decoded payloads. Record is set for every non-missing kind.
// Consumed carries the retained consumed envelope exactly when the
// kind is the consumed one.
type ChallengeRuntimeState struct {
	Kind     RuntimeStateKind
	Record   *ChallengeRecord
	Consumed *ConsumedRecord
}

// ConsumedResult is the committed deterministic outcome of one
// consumed challenge. Mac is the server-state mac over the record's
// challenge, the verdict, the binding and the operation identity, or
// empty on a legacy commit from a backend that cannot carry one.
type ConsumedResult struct {
	Valid   bool
	Binding string
	Mac     string
}

// ConsumedRecord is the consume transition's return: the record plus
// its new state. ConsumedNow marks the call that won the pending to
// consumed flip; ConsumedBefore marks a retry against an already
// consumed record.
type ConsumedRecord struct {
	Record            *ChallengeRecord
	ConsumedNow       bool
	ConsumedBefore    bool
	ConsumedResult    *ConsumedResult
	OperationIdentity string
}

// DeleteIfPendingStatus values of the fused cleanup transition.
const (
	DeleteStatusMissing        = "missing"
	DeleteStatusDeletedPending = "deleted-pending"
	DeleteStatusConsumed       = "consumed"
	DeleteStatusCancelled      = "cancelled"
	DeleteStatusCorrupt        = "corrupt"
)

// DeleteIfPendingResult is the fused cheap-failure cleanup outcome.
// Status mirrors the tri-state contract of the Redis Lua script.
type DeleteIfPendingResult struct {
	Status   string
	Consumed *ConsumedRecord
}

// WasConsumed reports the consumed retention outcome.
func (r DeleteIfPendingResult) WasConsumed() bool { return r.Status == DeleteStatusConsumed }

// CancellationStatus values of the cancel transition.
const (
	CancelStatusCancelledNow = "cancelled-now"
	CancelStatusCancelled    = "cancelled"
	CancelStatusConsumed     = "consumed"
)

// CancellationResult is the cancel transition's outcome: a fresh flip,
// an idempotent repeat, or the refusal on a finalized record.
type CancellationResult struct{ Status string }

// Store is the mandatory store adapter surface.
type Store interface {
	// Find returns nil without error for an absent or expired record.
	Find(nonce string) (*ChallengeRecord, error)
	// Delete removes one record and reports whether it existed.
	Delete(nonce string) (bool, error)
	// Consume runs the one-shot pending to consumed transition and
	// returns the retained envelope on a consumed-before retry.
	Consume(nonce string) (*ConsumedRecord, error)
	// CommitResult commits the deterministic outcome of a consumed
	// record; only the first commit wins.
	CommitResult(nonce string, valid bool, binding string) (bool, error)
}

// ConsumedStateReader is the retained consumed-envelope read.
type ConsumedStateReader interface {
	ConsumedState(nonce string) (*ConsumedRecord, error)
}

// RuntimeStateReader is the single get runtime-state snapshot read.
type RuntimeStateReader interface {
	RuntimeState(nonce string) (ChallengeRuntimeState, error)
}

// AtomicDeleteIfPending is the fused read-and-delete-on-pending
// transition.
type AtomicDeleteIfPending interface {
	DeleteIfPending(nonce string) (DeleteIfPendingResult, error)
}

// OperationIdentityAware is the identity-bearing consume transition.
type OperationIdentityAware interface {
	ConsumeWithOperationIdentity(nonce string, operationIdentity string) (*ConsumedRecord, error)
}

// AuthenticatedResultCommit is the server-state-mac commit for a
// consumed result.
type AuthenticatedResultCommit interface {
	CommitAuthenticatedResult(nonce string, result ConsumedResult) (bool, error)
}

// Cancellable is the terminal cancellation marker transition.
type Cancellable interface {
	Cancel(nonce string) (*CancellationResult, error)
}

// Storer is the write side every shipped backend carries: persist one
// pending record ahead of its verification.
type Storer interface {
	StoreRecord(record *ChallengeRecord) error
}

// OpenStore builds a store adapter from a URL. memory:// builds the
// in-process store, redis://host:port or rediss:// builds the shared
// backend over the shipped wire protocol client, and sqlite://path
// builds the file-backed single-node adapter over the pure-Go
// modernc.org/sqlite driver (the schema and state machine of the php
// SqliteStorage). The empty url defaults to memory://.
func OpenStore(url string) (Store, error) {
	scheme := url
	if idx := strings.Index(url, "://"); idx >= 0 {
		scheme = url[:idx]
	}
	switch strings.ToLower(scheme) {
	case "", "memory":
		return NewMemoryStorage(), nil
	case "redis", "rediss":
		client, err := DialRedis(url)
		if err != nil {
			return nil, err
		}
		return NewRedisStorage(client, EnvelopeDefaultPrefix), nil
	case "sqlite":
		path := strings.TrimPrefix(strings.TrimPrefix(url, "sqlite://"), "sqlite:")
		if path == "" {
			path = "kiwicaptcha.sqlite3"
		}
		return NewSqliteStorage(path, 5000, 60)
	default:
		return nil, errors.New("kiwicaptcha: unsupported store url scheme: use memory://, redis:// or sqlite://")
	}
}
