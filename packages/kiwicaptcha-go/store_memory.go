package kiwicaptcha

import (
	"sort"
	"sync"
	"time"
)

// In-memory storage: single process, non-persistent, a port of the
// php ArrayStorage. The mutex serializes the read-modify-write
// transitions, so consume stays one-shot under concurrency. Consume
// marks the record consumed and keeps it until deletion, so replay
// protection is the consumed marker, never absence. Expiry follows
// the Redis ttl semantics: an entry whose expires_at has passed is
// absent from every read and transition and is evicted lazily on
// first observation. Store prunes expired entries and evicts the
// earliest-expiring entries at the hard cap, so a long-lived process
// never accumulates unbounded state.

// DefaultMaxEntries is the store's entry cap.
const DefaultMaxEntries = 10_000

type memoryEntry struct {
	record    *ChallengeRecord
	consumed  bool
	cancelled bool
	result    *ConsumedResult
	identity  string
}

// MemoryStorage is the in-process store adapter.
type MemoryStorage struct {
	mu         sync.Mutex
	now        func() time.Time
	maxEntries int
	records    map[string]*memoryEntry
}

// NewMemoryStorage builds the in-process store.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		now:        time.Now,
		maxEntries: DefaultMaxEntries,
		records:    map[string]*memoryEntry{},
	}
}

// NewMemoryStorageWithClock builds the store over a test clock.
func NewMemoryStorageWithClock(now func() time.Time) *MemoryStorage {
	return &MemoryStorage{
		now:        now,
		maxEntries: DefaultMaxEntries,
		records:    map[string]*memoryEntry{},
	}
}

func (m *MemoryStorage) nowSecs() int64 {
	return m.now().Unix()
}

func (m *MemoryStorage) entry(nonce string) *memoryEntry {
	entry, ok := m.records[nonce]
	if !ok {
		return nil
	}
	if m.nowSecs() >= entry.record.ExpiresAt {
		delete(m.records, nonce)
		return nil
	}
	return entry
}

func (m *MemoryStorage) pruneExpired() {
	now := m.nowSecs()
	for nonce, entry := range m.records {
		if now >= entry.record.ExpiresAt {
			delete(m.records, nonce)
		}
	}
}

// StoreRecord persists one pending record with bounded retention.
func (m *MemoryStorage) StoreRecord(record *ChallengeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpired()
	if _, exists := m.records[record.Nonce]; !exists {
		needed := len(m.records) + 1 - m.maxEntries
		if needed > 0 {
			nonces := make([]string, 0, len(m.records))
			for nonce := range m.records {
				nonces = append(nonces, nonce)
			}
			sort.Slice(nonces, func(i, j int) bool {
				return m.records[nonces[i]].record.ExpiresAt < m.records[nonces[j]].record.ExpiresAt
			})
			for _, nonce := range nonces[:needed] {
				delete(m.records, nonce)
			}
		}
	}
	m.records[record.Nonce] = &memoryEntry{record: record}
	return nil
}

// Find returns the pending or retained record, absent once expired.
func (m *MemoryStorage) Find(nonce string) (*ChallengeRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entry(nonce)
	if entry == nil {
		return nil, nil
	}
	return entry.record, nil
}

func (m *MemoryStorage) classify(nonce string) *memoryEntry {
	entry := m.entry(nonce)
	if entry == nil || entry.cancelled {
		return nil
	}
	return entry
}

// Consume runs the one-shot transition.
func (m *MemoryStorage) Consume(nonce string) (*ConsumedRecord, error) {
	return m.ConsumeWithOperationIdentity(nonce, "")
}

// ConsumeWithOperationIdentity runs the one-shot transition and
// records the logical-operation identity atomically with the flip.
func (m *MemoryStorage) ConsumeWithOperationIdentity(nonce string, operationIdentity string) (*ConsumedRecord, error) {
	identity, err := ValidateOperationIdentity(operationIdentity)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.classify(nonce)
	if entry == nil {
		return nil, nil
	}
	if entry.consumed {
		return &ConsumedRecord{
			Record:            entry.record,
			ConsumedBefore:    true,
			ConsumedResult:    entry.result,
			OperationIdentity: entry.identity,
		}, nil
	}
	if entry.result != nil || entry.identity != "" {
		return nil, nil
	}
	entry.consumed = true
	if identity != "" {
		entry.identity = identity
	}
	return &ConsumedRecord{Record: entry.record, ConsumedNow: true, OperationIdentity: entry.identity}, nil
}

// ConsumedState reads the retained consumed envelope.
func (m *MemoryStorage) ConsumedState(nonce string) (*ConsumedRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entry(nonce)
	if entry == nil || !entry.consumed {
		return nil, nil
	}
	return &ConsumedRecord{
		Record:            entry.record,
		ConsumedBefore:    true,
		ConsumedResult:    entry.result,
		OperationIdentity: entry.identity,
	}, nil
}

// CommitResult commits the deterministic outcome of a consumed record.
func (m *MemoryStorage) CommitResult(nonce string, valid bool, binding string) (bool, error) {
	return m.CommitAuthenticatedResult(nonce, ConsumedResult{Valid: valid, Binding: binding})
}

// CommitAuthenticatedResult commits the outcome with its server-state
// mac. Only the first commit wins.
func (m *MemoryStorage) CommitAuthenticatedResult(nonce string, result ConsumedResult) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entry(nonce)
	if entry == nil || !entry.consumed || entry.result != nil {
		return false, nil
	}
	stored := result
	entry.result = &stored
	return true, nil
}

// Delete removes one record.
func (m *MemoryStorage) Delete(nonce string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.records[nonce]
	if ok {
		delete(m.records, nonce)
	}
	return ok, nil
}

// DeleteIfPending runs the fused cleanup transition. A consumed or
// cancelled record is returned verbatim and kept; only the exact
// pending state is deleted.
func (m *MemoryStorage) DeleteIfPending(nonce string) (DeleteIfPendingResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entry(nonce)
	if entry == nil {
		return DeleteIfPendingResult{Status: DeleteStatusMissing}, nil
	}
	if entry.consumed {
		return DeleteIfPendingResult{
			Status: DeleteStatusConsumed,
			Consumed: &ConsumedRecord{
				Record:            entry.record,
				ConsumedBefore:    true,
				ConsumedResult:    entry.result,
				OperationIdentity: entry.identity,
			},
		}, nil
	}
	if entry.cancelled {
		return DeleteIfPendingResult{Status: DeleteStatusCancelled}, nil
	}
	delete(m.records, nonce)
	return DeleteIfPendingResult{Status: DeleteStatusDeletedPending}, nil
}

// RuntimeState reads the terminal-aware snapshot.
func (m *MemoryStorage) RuntimeState(nonce string) (ChallengeRuntimeState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entry(nonce)
	if entry == nil {
		return ChallengeRuntimeState{Kind: RuntimeMissing}, nil
	}
	if entry.cancelled {
		return ChallengeRuntimeState{Kind: RuntimeCancelled, Record: entry.record}, nil
	}
	if entry.consumed {
		return ChallengeRuntimeState{
			Kind:   RuntimeConsumed,
			Record: entry.record,
			Consumed: &ConsumedRecord{
				Record:            entry.record,
				ConsumedBefore:    true,
				ConsumedResult:    entry.result,
				OperationIdentity: entry.identity,
			},
		}, nil
	}
	return ChallengeRuntimeState{Kind: RuntimePending, Record: entry.record}, nil
}

// Cancel flips the terminal cancellation marker. A consumed record is
// terminal and never cancellable; a cancelled record is idempotent.
func (m *MemoryStorage) Cancel(nonce string) (*CancellationResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entry(nonce)
	if entry == nil {
		return nil, nil
	}
	if entry.consumed {
		return &CancellationResult{Status: CancelStatusConsumed}, nil
	}
	if entry.cancelled {
		return &CancellationResult{Status: CancelStatusCancelled}, nil
	}
	entry.cancelled = true
	return &CancellationResult{Status: CancelStatusCancelledNow}, nil
}

// Len reports the live entry count.
func (m *MemoryStorage) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpired()
	return len(m.records)
}
