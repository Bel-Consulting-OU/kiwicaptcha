package kiwicaptcha

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func sqliteTestRecord(nonce, algorithm string, mKib, t, targetBits int) *ChallengeRecord {
	if algorithm == "" {
		algorithm = "sha256"
	}
	if algorithm == "argon2id" && t == 1 {
		t = 3
	}
	return &ChallengeRecord{
		Nonce:           nonce,
		Scope:           "login",
		BindingTag:      "tag-1",
		IssuedAt:        1_800_000_000,
		ExpiresAt:       1_800_000_000 + 120,
		Algorithm:       algorithm,
		MKib:            mKib,
		T:               t,
		P:               1,
		TargetBits:      targetBits,
		Salt:            "c2FsdA==",
		Prefix:          "pre-",
		Challenge:       "challenge",
		MinDurationMs:   0,
		IssuedAtNs:      1_800_000_000_000_000,
		ProtocolVersion: 2,
	}
}

func newSqliteTestStore(t *testing.T) (*SqliteStorage, string, *int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.db")
	var now int64 = 1_800_000_010
	store, err := newSqliteStorage(path, 5000, 60, func() int64 { return atomic.LoadInt64(&now) })
	if err != nil {
		t.Fatalf("the sqlite store must open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path, &now
}

func TestSqliteStorageConsumeIsExactlyOnceUnderRacingStores(t *testing.T) {
	store, path, clock := newSqliteTestStore(t)
	if err := store.StoreRecord(sqliteTestRecord("race-nonce", "", 0, 1, 8)); err != nil {
		t.Fatalf("store: %v", err)
	}
	var won, consumedBefore, missing int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			racer, err := newSqliteStorage(path, 5000, 60, func() int64 { return atomic.LoadInt64(clock) })
			if err != nil {
				t.Errorf("racer store must open: %v", err)
				return
			}
			defer func() { _ = racer.Close() }()
			consumed, err := racer.Consume("race-nonce")
			if err != nil {
				t.Errorf("racer consume failed: %v", err)
				return
			}
			switch {
			case consumed == nil:
				atomic.AddInt64(&missing, 1)
			case consumed.ConsumedNow:
				atomic.AddInt64(&won, 1)
			case consumed.ConsumedBefore:
				atomic.AddInt64(&consumedBefore, 1)
			}
		}()
	}
	wg.Wait()
	if won != 1 || consumedBefore != 7 || missing != 0 {
		t.Fatalf("exactly one racer wins the flip: won=%d before=%d missing=%d", won, consumedBefore, missing)
	}
}

func TestSqliteStorageReplayAnswersTheRetainedEnvelope(t *testing.T) {
	store, _, _ := newSqliteTestStore(t)
	record := sqliteTestRecord("replay-nonce", "argon2id", 64, 3, 4)
	if err := store.StoreRecord(record); err != nil {
		t.Fatalf("store: %v", err)
	}
	first, err := store.Consume("replay-nonce")
	if err != nil || first == nil || !first.ConsumedNow {
		t.Fatalf("the first consume wins: %v %+v", err, first)
	}
	if ok, err := store.CommitAuthenticatedResult("replay-nonce", ConsumedResult{Valid: true, Binding: "tag-1", Mac: "aabb"}); err != nil || !ok {
		t.Fatalf("the first commit wins: %v %v", err, ok)
	}
	if ok, err := store.CommitResult("replay-nonce", false, "other"); err != nil || ok {
		t.Fatalf("only the first commit wins: %v %v", err, ok)
	}

	replay, err := store.Consume("replay-nonce")
	if err != nil || replay == nil {
		t.Fatalf("the replay answers the envelope: %v", err)
	}
	if replay.ConsumedNow || !replay.ConsumedBefore {
		t.Fatalf("the replay is consumed-before: %+v", replay)
	}
	if replay.ConsumedResult == nil || !replay.ConsumedResult.Valid || replay.ConsumedResult.Binding != "tag-1" || replay.ConsumedResult.Mac != "aabb" {
		t.Fatalf("the retained verdict rides the envelope: %+v", replay.ConsumedResult)
	}
	state, err := store.RuntimeState("replay-nonce")
	if err != nil || state.Kind != RuntimeConsumed {
		t.Fatalf("the runtime snapshot is consumed: %v %+v", err, state)
	}
}

func TestSqliteStorageCleanupCancellationAndExpiry(t *testing.T) {
	store, _, clock := newSqliteTestStore(t)
	if err := store.StoreRecord(sqliteTestRecord("cleanup-nonce", "", 0, 1, 8)); err != nil {
		t.Fatalf("store: %v", err)
	}
	result, err := store.DeleteIfPending("cleanup-nonce")
	if err != nil || result.Status != DeleteStatusDeletedPending {
		t.Fatalf("the pending row deletes: %v %+v", err, result)
	}
	if result, err = store.DeleteIfPending("cleanup-nonce"); err != nil || result.Status != DeleteStatusMissing {
		t.Fatalf("the deleted row is missing: %v %+v", err, result)
	}

	if err := store.StoreRecord(sqliteTestRecord("cancel-nonce", "", 0, 1, 8)); err != nil {
		t.Fatalf("store: %v", err)
	}
	cancelled, err := store.Cancel("cancel-nonce")
	if err != nil || cancelled == nil || cancelled.Status != CancelStatusCancelledNow {
		t.Fatalf("the fresh flip: %v %+v", err, cancelled)
	}
	if cancelled, err = store.Cancel("cancel-nonce"); err != nil || cancelled.Status != CancelStatusCancelled {
		t.Fatalf("the repeat is idempotent: %v %+v", err, cancelled)
	}
	if _, err := store.Consume("cancel-nonce"); err != nil {
		t.Fatalf("a cancelled row is never consumable but never errors: %v", err)
	}

	// Past the retention margin the row is absent to every read.
	atomic.StoreInt64(clock, 1_800_000_120+61)
	if record, err := store.Find("cancel-nonce"); err != nil || record != nil {
		t.Fatalf("the expired row is absent: %v %+v", err, record)
	}
}

func TestSqliteStorageInteropsWithThePhpWrittenFixture(t *testing.T) {
	fixture := filepath.Join("testdata", "sqlite", "php_interop.db")
	work := filepath.Join(t.TempDir(), "interop.db")
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("the php-written fixture must ship with the tests: %v", err)
	}
	if err := os.WriteFile(work, data, 0o600); err != nil {
		t.Fatalf("copy: %v", err)
	}
	var now int64 = 1_800_000_010
	store, err := newSqliteStorage(work, 5000, 60, func() int64 { return atomic.LoadInt64(&now) })
	if err != nil {
		t.Fatalf("the php-written database must open: %v", err)
	}
	defer func() { _ = store.Close() }()

	// The pending row: minted by php, decoded here, consumed exactly
	// once, and the deterministic outcome lands in the php schema.
	pending, err := store.Find("interop-pending-nonce-0000000001")
	if err != nil || pending == nil {
		t.Fatalf("the php-written pending row reads: %v", err)
	}
	if pending.Scope != "login" || pending.Algorithm != "sha256" || pending.TargetBits != 8 || pending.Prefix != "pre-" {
		t.Fatalf("the php record decodes verbatim: %+v", pending)
	}
	consumed, err := store.ConsumeWithOperationIdentity("interop-pending-nonce-0000000001", "op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil || consumed == nil || !consumed.ConsumedNow {
		t.Fatalf("the pending row consumes exactly once: %v %+v", err, consumed)
	}
	if ok, err := store.CommitResult("interop-pending-nonce-0000000001", true, "tag-1"); err != nil || !ok {
		t.Fatalf("the outcome commits: %v %v", err, ok)
	}
	after, err := store.ConsumedState("interop-pending-nonce-0000000001")
	if err != nil || after == nil || after.OperationIdentity != "op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("the identity rides the retained envelope: %v %+v", err, after)
	}

	// The consumed row: php wrote the verdict, the binding and the
	// identity; the consume-before replay answers them verbatim.
	retained, err := store.Consume("interop-consumed-nonce-000000001")
	if err != nil || retained == nil || !retained.ConsumedBefore {
		t.Fatalf("the consumed row answers the envelope: %v %+v", err, retained)
	}
	if retained.OperationIdentity != "op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("the php-written identity rides back: %+v", retained)
	}
	if retained.ConsumedResult == nil || !retained.ConsumedResult.Valid || retained.ConsumedResult.Binding != "tag-2" {
		t.Fatalf("the php-written verdict rides back: %+v", retained.ConsumedResult)
	}
	state, err := store.RuntimeState("interop-consumed-nonce-000000001")
	if err != nil || state.Kind != RuntimeConsumed {
		t.Fatalf("the snapshot is consumed: %v %+v", err, state)
	}
}

func TestSqliteStorageCorruptRowFailsClosed(t *testing.T) {
	store, _, _ := newSqliteTestStore(t)
	if err := store.StoreRecord(sqliteTestRecord("corrupt-nonce", "", 0, 1, 8)); err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, err := store.db.Exec("UPDATE kiwicaptcha_challenge_records SET record_json = '{not json' WHERE nonce = 'corrupt-nonce'"); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if record, err := store.Find("corrupt-nonce"); err != nil || record != nil {
		t.Fatalf("a corrupt row is absent, never partial: %v %+v", err, record)
	}
	state, err := store.RuntimeState("corrupt-nonce")
	if err != nil || state.Kind != RuntimeMissing {
		t.Fatalf("a corrupt row is missing to the snapshot: %v %+v", err, state)
	}
	if result, err := store.DeleteIfPending("corrupt-nonce"); err != nil || result.Status != DeleteStatusCorrupt {
		t.Fatalf("the fused cleanup reports corrupt: %v %+v", err, result)
	}
}
