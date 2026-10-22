package kiwicaptcha

import (
	"container/heap"
	"math"
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
// never accumulates unbounded state. The per-store sweep is gated on
// the earliest known expiry so a store call before that horizon is a
// cheap comparison; cap eviction walks an expiry-ordered min-heap
// instead of re-sorting every key.

// DefaultMaxEntries is the store's entry cap.
const DefaultMaxEntries = 10_000

type memoryEntry struct {
	record    *ChallengeRecord
	consumed  bool
	cancelled bool
	result    *ConsumedResult
	identity  string
}

// expiryItem is one heap key: the record's expiry and its nonce, so
// equal expiries still break ties deterministically.
type expiryItem struct {
	expires int64
	nonce   string
}

// expiryHeap is a min-heap on (expires, nonce).
type expiryHeap []expiryItem

func (h expiryHeap) Len() int { return len(h) }
func (h expiryHeap) Less(i, j int) bool {
	if h[i].expires != h[j].expires {
		return h[i].expires < h[j].expires
	}
	return h[i].nonce < h[j].nonce
}
func (h expiryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)   { *h = append(*h, x.(expiryItem)) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// MemoryStorage is the in-process store adapter.
type MemoryStorage struct {
	mu         sync.Mutex
	now        func() time.Time
	maxEntries int
	records    map[string]*memoryEntry
	// nextExpiry is the earliest expires_at among live entries;
	// math.MaxInt64 when empty. The per-store sweep only runs once
	// now has reached it.
	nextExpiry int64
	byExpiry   expiryHeap
}

// NewMemoryStorage builds the in-process store.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		now:        time.Now,
		maxEntries: DefaultMaxEntries,
		records:    map[string]*memoryEntry{},
		nextExpiry: math.MaxInt64,
	}
}

// NewMemoryStorageWithClock builds the store over a test clock.
func NewMemoryStorageWithClock(now func() time.Time) *MemoryStorage {
	return &MemoryStorage{
		now:        now,
		maxEntries: DefaultMaxEntries,
		records:    map[string]*memoryEntry{},
		nextExpiry: math.MaxInt64,
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

// pruneExpired reclaims expired rows only once the earliest known
// expiry has been reached; a full scan past that horizon is earned.
func (m *MemoryStorage) pruneExpired() {
	now := m.nowSecs()
	if now < m.nextExpiry {
		return
	}
	for nonce, entry := range m.records {
		if now >= entry.record.ExpiresAt {
			delete(m.records, nonce)
		}
	}
	m.rebuildHorizon()
}

// rebuildHorizon rescans the live rows: the next sweep gate and the
// heap are refreshed from scratch. Callers must hold the mutex.
func (m *MemoryStorage) rebuildHorizon() {
	m.nextExpiry = math.MaxInt64
	m.byExpiry = make(expiryHeap, 0, len(m.records))
	for nonce, entry := range m.records {
		expires := entry.record.ExpiresAt
		if expires < m.nextExpiry {
			m.nextExpiry = expires
		}
		m.byExpiry = append(m.byExpiry, expiryItem{expires: expires, nonce: nonce})
	}
	heap.Init(&m.byExpiry)
}

// evictToCap drops the earliest-expiring live entries until one slot
// is free for the incoming record. Stale heap items (deleted or
// replaced rows) are skipped. Callers must hold the mutex.
func (m *MemoryStorage) evictToCap() {
	for len(m.records) >= m.maxEntries && m.byExpiry.Len() > 0 {
		item := heap.Pop(&m.byExpiry).(expiryItem)
		entry, ok := m.records[item.nonce]
		if !ok || entry.record.ExpiresAt != item.expires {
			continue // stale heap item
		}
		delete(m.records, item.nonce)
	}
}

// StoreRecord persists one pending record with bounded retention.
func (m *MemoryStorage) StoreRecord(record *ChallengeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpired()
	if _, exists := m.records[record.Nonce]; !exists {
		if len(m.records)+1 > m.maxEntries {
			m.evictToCap()
		}
	}
	m.records[record.Nonce] = &memoryEntry{record: record}
	heap.Push(&m.byExpiry, expiryItem{expires: record.ExpiresAt, nonce: record.Nonce})
	if record.ExpiresAt < m.nextExpiry {
		m.nextExpiry = record.ExpiresAt
	}
	// Compaction: deletes leave stale heap items; rescan once they
	// dominate, so amortized cost stays O(1) per store.
	if len(m.byExpiry) > 4*len(m.records)+64 {
		m.rebuildHorizon()
	}
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
