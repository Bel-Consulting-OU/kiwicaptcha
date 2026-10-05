package kiwicaptcha

import (
	"errors"
	"sync"
	"time"
)

// The versioned outcomes mapping and its reporting client, a port of
// packages/kiwicaptcha-risk-php/src/Outcomes. One mapping table
// resolves each of the eight typed outcomes onto the risk-v1 event
// channels, the always-on outcome ledger and the long-memory marks.
// The trust polarity is a table property: exactly the three
// server-confirmed trust outcomes may subtract risk, and exactly the
// four abuse outcomes write marks; the two classes are disjoint. The
// vectors at protocol/risk-v1/outcomes-vectors.json pin the table
// contents across the languages.

// OutcomesVersion is the mapping table version.
const OutcomesVersion = 1

// Outcome is one of the eight typed outcome wire names.
type Outcome string

// The typed outcome vocabulary, in table order.
const (
	OutcomeConfirmedLegitimate   Outcome = "confirmedLegitimate"
	OutcomeStepUpCompleted       Outcome = "stepUpCompleted"
	OutcomeAuthenticationSuccess Outcome = "authenticationSuccess"
	OutcomeAuthenticationFailure Outcome = "authenticationFailure"
	OutcomeSpamReported          Outcome = "spamReported"
	OutcomeChargeback            Outcome = "chargeback"
	OutcomeAccountBanned         Outcome = "accountBanned"
	OutcomeFraudConfirmed        Outcome = "fraudConfirmed"
)

// The risk-v1 event channel values.
const (
	ChannelConfirmedLegitimate    = 12
	ChannelProtectedActionSuccess = 8
	ChannelAuthenticationSuccess  = 10
	ChannelAuthenticationFailure  = 11
	ChannelProtectedActionFailure = 9
	ChannelConfirmedAbuse         = 13
)

// HandleDimension is one subject-address dimension with its key role.
type HandleDimension string

// The six subject-address dimensions.
const (
	DimensionNonce      HandleDimension = "nonce"
	DimensionDecisionID HandleDimension = "decisionId"
	DimensionPrincipal  HandleDimension = "principal"
	DimensionTarget     HandleDimension = "target"
	DimensionSession    HandleDimension = "session"
	DimensionAgent      HandleDimension = "agent"
)

// IsLedger reports the two ledger dimensions, whose entries confirm
// decisions.
func (d HandleDimension) IsLedger() bool {
	return d == DimensionNonce || d == DimensionDecisionID
}

// IsIdentity reports the four identity dimensions, which carry
// pseudonyms only.
func (d HandleDimension) IsIdentity() bool { return !d.IsLedger() }

// MarkDimension names the mark bucket of an identity dimension, empty
// for the ledger ones.
func (d HandleDimension) MarkDimension() string {
	if d.IsLedger() {
		return ""
	}
	return string(d)
}

// HandleDimensionOrder is the vocabulary order of the dimensions.
var HandleDimensionOrder = []HandleDimension{
	DimensionNonce, DimensionDecisionID, DimensionPrincipal,
	DimensionTarget, DimensionSession, DimensionAgent,
}

// IdentityDimensions are the four identity dimensions.
var IdentityDimensions = []HandleDimension{DimensionPrincipal, DimensionTarget, DimensionSession, DimensionAgent}

// LedgerDimensions are the two ledger dimensions.
var LedgerDimensions = []HandleDimension{DimensionNonce, DimensionDecisionID}

var pseudonymRunes = func() map[byte]bool {
	set := map[byte]bool{}
	for _, by := range []byte("0123456789abcdef") {
		set[by] = true
	}
	return set
}()

func isPseudonym(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, by := range []byte(value) {
		if !pseudonymRunes[by] {
			return false
		}
	}
	return true
}

// AssertKeySafeIdentifier is the shared key-safety rule for
// caller-supplied identifiers. A 32-char lowercase hex id always
// passes; otherwise the value must be non-empty and free of control
// characters, ':' and '}', the key separator and the hash-tag closing
// byte.
func AssertKeySafeIdentifier(value string) error {
	if isPseudonym(value) {
		return nil
	}
	if value == "" {
		return errors.New("kiwicaptcha: identifiers must be a 32-char lowercase hex id or a non-empty value free of control characters, ':' and '}'")
	}
	for _, by := range []byte(value) {
		if by <= 0x1f || by == 0x7f || by == ':' || by == '}' {
			return errors.New("kiwicaptcha: identifiers must be free of control characters, ':' and '}'")
		}
	}
	// The utf-8 continuation bytes of the reference control set.
	for i := 0; i < len(value); i++ {
		if value[i] == 0xc2 && i+1 < len(value) && value[i+1] >= 0x80 && value[i+1] <= 0x9f {
			return errors.New("kiwicaptcha: identifiers must be free of control characters, ':' and '}'")
		}
	}
	return nil
}

// OutcomeHandle is one subject address of a typed outcome report. The
// principal, target and session dimensions carry pseudonyms, never raw
// identifiers, so a raw-looking value is rejected at construction,
// fail-closed. The agent and the ledger dimensions accept the shared
// key-safety rule instead: a 32-char lowercase hex id, or a non-empty
// value free of control characters, ':' and '}'.
type OutcomeHandle struct {
	Dimension HandleDimension
	ID        string
}

// NewOutcomeHandle validates one handle.
func NewOutcomeHandle(dimension HandleDimension, identifier string) (OutcomeHandle, error) {
	pseudonymOnly := dimension == DimensionPrincipal || dimension == DimensionTarget || dimension == DimensionSession
	if pseudonymOnly && !isPseudonym(identifier) {
		return OutcomeHandle{}, errors.New("kiwicaptcha: identity handles must carry the 32-char lowercase hex pseudonym, never a raw identifier")
	}
	if !pseudonymOnly {
		if err := AssertKeySafeIdentifier(identifier); err != nil {
			return OutcomeHandle{}, err
		}
	}
	return OutcomeHandle{Dimension: dimension, ID: identifier}, nil
}

// OutcomeMapping is one immutable table row: channel, ledger and mark
// behavior.
type OutcomeMapping struct {
	Outcome          Outcome
	Channel          int
	LedgerLegitimate *bool
	WritesAbuseMark  bool
	ServerConfirmed  bool
	MaySubtractRisk  bool
	AcceptedHandles  []HandleDimension
}

// Accepts reports whether the dimension is reportable for the row.
func (m OutcomeMapping) Accepts(dimension HandleDimension) bool {
	for _, accepted := range m.AcceptedHandles {
		if accepted == dimension {
			return true
		}
	}
	return false
}

// MarkKind names the abuse mark the row writes, empty when none.
func (m OutcomeMapping) MarkKind() string {
	if m.WritesAbuseMark {
		return string(m.Outcome)
	}
	return ""
}

// HasLedgerAction reports whether the row books a ledger entry.
func (m OutcomeMapping) HasLedgerAction() bool { return m.LedgerLegitimate != nil }

func boolPtr(value bool) *bool { return &value }

var outcomeTable = map[Outcome]OutcomeMapping{
	OutcomeConfirmedLegitimate: {
		Outcome:          OutcomeConfirmedLegitimate,
		Channel:          ChannelConfirmedLegitimate,
		LedgerLegitimate: boolPtr(true),
		ServerConfirmed:  true,
		MaySubtractRisk:  true,
		AcceptedHandles:  HandleDimensionOrder,
	},
	OutcomeStepUpCompleted: {
		Outcome:         OutcomeStepUpCompleted,
		Channel:         ChannelProtectedActionSuccess,
		ServerConfirmed: true,
		MaySubtractRisk: true,
		AcceptedHandles: IdentityDimensions,
	},
	OutcomeAuthenticationSuccess: {
		Outcome:         OutcomeAuthenticationSuccess,
		Channel:         ChannelAuthenticationSuccess,
		ServerConfirmed: true,
		MaySubtractRisk: true,
		AcceptedHandles: IdentityDimensions,
	},
	OutcomeAuthenticationFailure: {
		Outcome:         OutcomeAuthenticationFailure,
		Channel:         ChannelAuthenticationFailure,
		AcceptedHandles: IdentityDimensions,
	},
	OutcomeSpamReported: {
		Outcome:         OutcomeSpamReported,
		Channel:         ChannelProtectedActionFailure,
		WritesAbuseMark: true,
		ServerConfirmed: true,
		AcceptedHandles: IdentityDimensions,
	},
	OutcomeChargeback: {
		Outcome:          OutcomeChargeback,
		Channel:          ChannelConfirmedAbuse,
		LedgerLegitimate: boolPtr(false),
		WritesAbuseMark:  true,
		ServerConfirmed:  true,
		AcceptedHandles:  HandleDimensionOrder,
	},
	OutcomeAccountBanned: {
		Outcome:          OutcomeAccountBanned,
		Channel:          ChannelConfirmedAbuse,
		LedgerLegitimate: boolPtr(false),
		WritesAbuseMark:  true,
		ServerConfirmed:  true,
		AcceptedHandles:  HandleDimensionOrder,
	},
	OutcomeFraudConfirmed: {
		Outcome:          OutcomeFraudConfirmed,
		Channel:          ChannelConfirmedAbuse,
		LedgerLegitimate: boolPtr(false),
		WritesAbuseMark:  true,
		ServerConfirmed:  true,
		AcceptedHandles:  HandleDimensionOrder,
	},
}

// OutcomeMap is the one versioned mapping table, total over the
// vocabulary.
type OutcomeMap struct{}

// ForOutcome resolves the row of one outcome.
func (OutcomeMap) ForOutcome(outcome Outcome) (OutcomeMapping, error) {
	row, ok := outcomeTable[outcome]
	if !ok {
		return OutcomeMapping{}, errors.New("kiwicaptcha: no outcome mapping row for " + string(outcome))
	}
	return row, nil
}

// All returns the rows in vocabulary order.
func (OutcomeMap) All() []OutcomeMapping {
	order := []Outcome{
		OutcomeConfirmedLegitimate, OutcomeStepUpCompleted, OutcomeAuthenticationSuccess,
		OutcomeAuthenticationFailure, OutcomeSpamReported, OutcomeChargeback,
		OutcomeAccountBanned, OutcomeFraudConfirmed,
	}
	rows := make([]OutcomeMapping, 0, len(order))
	for _, outcome := range order {
		rows = append(rows, outcomeTable[outcome])
	}
	return rows
}

// OutcomeReceipt is the outcome of one report: what was booked where.
type OutcomeReceipt struct {
	Outcome         Outcome
	HandleDimension HandleDimension
	Status          int
	ChannelBooked   bool
	MarksWritten    int
	MarkCount       int
	EventID         string
}

// OutcomeSink is the injectable dispatch surface of the reporting
// client. The shipped memory sink keeps marks and ledger actions
// in-process; binding the sink to a shared deployment is a deployment
// composition, not a protocol concern.
type OutcomeSink interface {
	ConfirmOutcome(decisionID string, legitimate bool) int
	RegisterOutcome(decisionID string, atMs int64)
	WriteMark(dimension, identifier, kind string, atMs int64) int
	ForgetMarks(dimension, identifier string) int
	RecordOutcomeFeedback(channel int, idempotencyKey string) string
}

// MemoryOutcomeSink is the in-process sink. Status follows the ledger
// confirm contract: 1 confirmed as legitimate, minus 1 confirmed as
// abusive, 0 when no ledger entry existed. Marks accumulate per key.
type MemoryOutcomeSink struct {
	Namespace string

	mu     sync.Mutex
	ledger map[string][]ledgerEntry
	marks  map[string][]markEntry
}

type ledgerEntry struct {
	legitimate bool
	atMs       int64
}

type markEntry struct {
	kind string
	atMs int64
}

// NewMemoryOutcomeSink builds the sink under one namespace.
func NewMemoryOutcomeSink(namespace string) *MemoryOutcomeSink {
	return &MemoryOutcomeSink{
		Namespace: namespace,
		ledger:    map[string][]ledgerEntry{},
		marks:     map[string][]markEntry{},
	}
}

// MarkKey renders the mark bucket key of one subject.
func (s *MemoryOutcomeSink) MarkKey(dimension, identifier string) string {
	return "mark:{kiwi:" + s.Namespace + "}:" + dimension + ":" + identifier
}

// ConfirmOutcome books one ledger confirmation.
func (s *MemoryOutcomeSink) ConfirmOutcome(decisionID string, legitimate bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.ledger[decisionID]
	if len(entries) == 0 {
		return 0
	}
	last := entries[len(entries)-1].atMs
	s.ledger[decisionID] = append(entries, ledgerEntry{legitimate: legitimate, atMs: last})
	if legitimate {
		return 1
	}
	return -1
}

// RegisterOutcome opens one ledger entry.
func (s *MemoryOutcomeSink) RegisterOutcome(decisionID string, atMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ledger[decisionID] = append(s.ledger[decisionID], ledgerEntry{atMs: atMs})
}

// WriteMark appends one abuse mark.
func (s *MemoryOutcomeSink) WriteMark(dimension, identifier, kind string, atMs int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.MarkKey(dimension, identifier)
	s.marks[key] = append(s.marks[key], markEntry{kind: kind, atMs: atMs})
	return 1
}

// ForgetMarks clears the marks of one subject and reports the count.
func (s *MemoryOutcomeSink) ForgetMarks(dimension, identifier string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.MarkKey(dimension, identifier)
	removed := len(s.marks[key])
	delete(s.marks, key)
	return removed
}

// RecordOutcomeFeedback dispatches one channel event and returns the
// idempotency key.
func (s *MemoryOutcomeSink) RecordOutcomeFeedback(channel int, idempotencyKey string) string {
	return idempotencyKey
}

// MarksOf lists the live marks of one subject, for tests.
func (s *MemoryOutcomeSink) MarksOf(dimension, identifier string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.marks[s.MarkKey(dimension, identifier)]
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.kind)
	}
	return out
}

// OutcomesClient is the typed outcome reporter, mirroring the php
// KiwiOutcomes.
type OutcomesClient struct {
	Sink OutcomeSink
	Now  func() time.Time
}

// NewOutcomesClient binds the reporter to a sink.
func NewOutcomesClient(sink OutcomeSink) *OutcomesClient {
	return &OutcomesClient{Sink: sink, Now: time.Now}
}

// Report books one typed outcome onto one handle. The mapping decides
// acceptance, the ledger action and the abuse mark, so a report can
// never bypass the table's trust polarity.
func (c *OutcomesClient) Report(outcome Outcome, handle OutcomeHandle, idempotencyKey string, atMs int64) (OutcomeReceipt, error) {
	mapping, err := (OutcomeMap{}).ForOutcome(outcome)
	if err != nil {
		return OutcomeReceipt{}, err
	}
	if !mapping.Accepts(handle.Dimension) {
		return OutcomeReceipt{}, errors.New("kiwicaptcha: outcome " + string(outcome) + " cannot be reported on a " + string(handle.Dimension) + " handle")
	}
	if atMs == 0 {
		if c.Now != nil {
			atMs = c.Now().UnixMilli()
		} else {
			atMs = time.Now().UnixMilli()
		}
	}
	receipt := OutcomeReceipt{Outcome: outcome, HandleDimension: handle.Dimension}
	if handle.Dimension.IsLedger() {
		if mapping.HasLedgerAction() {
			receipt.Status = c.Sink.ConfirmOutcome(handle.ID, *mapping.LedgerLegitimate)
		}
		if receipt.Status != 0 {
			receipt.EventID = c.Sink.RecordOutcomeFeedback(mapping.Channel, idempotencyKey)
			receipt.ChannelBooked = true
		}
	} else {
		if mapping.WritesAbuseMark {
			receipt.MarkCount = c.Sink.WriteMark(handle.Dimension.MarkDimension(), handle.ID, mapping.MarkKind(), atMs)
			receipt.MarksWritten = 1
		}
		receipt.EventID = c.Sink.RecordOutcomeFeedback(mapping.Channel, idempotencyKey)
		receipt.ChannelBooked = true
	}
	return receipt, nil
}

// Forget clears the marks of one handle's subject.
func (c *OutcomesClient) Forget(handle OutcomeHandle) int {
	dimension := handle.Dimension.MarkDimension()
	if dimension == "" {
		return 0
	}
	return c.Sink.ForgetMarks(dimension, handle.ID)
}
