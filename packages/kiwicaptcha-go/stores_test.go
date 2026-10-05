package kiwicaptcha

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMemoryStorageTransitions(t *testing.T) {
	store := NewMemoryStorageWithClock(func() time.Time { return time.Unix(testIssuedAt, 0) })
	record := mintRecord(t, defaultMintOptions())
	storeRecord(t, store, record)
	found, err := store.Find(record.Nonce)
	if err != nil || found == nil || found.Challenge != record.Challenge {
		t.Fatalf("find must return the record")
	}
	// Consume is one-shot: the winner flips, the retry observes it.
	consumed, err := store.Consume(record.Nonce)
	if err != nil || consumed == nil || !consumed.ConsumedNow {
		t.Fatalf("the first consume must win")
	}
	retry, err := store.Consume(record.Nonce)
	if err != nil || retry == nil || !retry.ConsumedBefore {
		t.Fatalf("the retry must observe the consumed state")
	}
	state, err := store.ConsumedState(record.Nonce)
	if err != nil || state == nil {
		t.Fatalf("the consumed state must be readable")
	}
	committed, err := store.CommitResult(record.Nonce, true, "tx-1")
	if err != nil || !committed {
		t.Fatalf("the first commit must win")
	}
	replayed, err := store.CommitResult(record.Nonce, false, "")
	if err != nil || replayed {
		t.Fatalf("only the first commit wins")
	}
	// A missing record consumes to nil.
	missing, err := store.Consume("missing-nonce")
	if err != nil || missing != nil {
		t.Fatalf("a missing record must consume to nil")
	}
}

func TestMemoryStorageExpiry(t *testing.T) {
	clock := testIssuedAt
	store := NewMemoryStorageWithClock(func() time.Time { return time.Unix(int64(clock), 0) })
	record := mintRecord(t, defaultMintOptions())
	storeRecord(t, store, record)
	clock = testIssuedAt + 121
	if found, err := store.Find(record.Nonce); err != nil || found != nil {
		t.Fatalf("an expired record must be absent")
	}
	if store.Len() != 0 {
		t.Fatalf("the expired entry must be pruned")
	}
}

func TestMemoryStorageCapEviction(t *testing.T) {
	store := NewMemoryStorageWithClock(func() time.Time { return time.Unix(testIssuedAt, 0) })
	store.maxEntries = 2
	for i := 0; i < 4; i++ {
		options := defaultMintOptions()
		options.nonceBytes = repeatBytes(byte(i), 32)
		options.ttl = int64(60 + i)
		storeRecord(t, store, mintRecord(t, options))
	}
	if store.Len() != 2 {
		t.Fatalf("the cap must hold: %d", store.Len())
	}
}

func repeatBytes(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}

func TestMemoryStorageConcurrency(t *testing.T) {
	store := NewMemoryStorage()
	record := mintRecord(t, defaultMintOptions())
	storeRecord(t, store, record)
	const racers = 16
	winners := make(chan bool, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			consumed, err := store.Consume(record.Nonce)
			if err == nil && consumed != nil && consumed.ConsumedNow {
				winners <- true
			}
		}()
	}
	wg.Wait()
	close(winners)
	count := 0
	for range winners {
		count++
	}
	if count != 1 {
		t.Fatalf("exactly one racer must win the consume: %d", count)
	}
}

func TestEnvelopeDecodesPythonWriter(t *testing.T) {
	data, err := os.ReadFile(goldenPath(t, "envelope_pending.txt"))
	if err != nil {
		t.Fatalf("envelope fixture: %v", err)
	}
	doc, err := decodeEnvelope(string(data))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.record == nil || doc.state != "pending" || doc.result != nil || doc.identity != "" {
		t.Fatalf("envelope decode drift: %+v", doc)
	}
	reference := goldenRecord(t, "golden_sha256_v2.json")
	if *doc.record != *reference {
		t.Fatalf("the decoded record must equal the golden record")
	}
}

func TestEnvelopeEncodeMatchesPythonWriter(t *testing.T) {
	record := goldenRecord(t, "golden_sha256_v2.json")
	fake := &captureClient{}
	storage := NewRedisStorage(fake, EnvelopeDefaultPrefix)
	if err := storage.StoreRecord(record); err != nil {
		t.Fatalf("store: %v", err)
	}
	if fake.lastSet == nil {
		t.Fatalf("the store must write the envelope")
	}
	expected, err := os.ReadFile(goldenPath(t, "envelope_pending.txt"))
	if err != nil {
		t.Fatalf("envelope fixture: %v", err)
	}
	if fake.lastSet.value != string(expected) {
		t.Fatalf("envelope byte drift:\n got %s\nwant %s", fake.lastSet.value, string(expected))
	}
}

func TestEnvelopeDuplicateAndCorruptValuesAreAbsent(t *testing.T) {
	for _, raw := range []string{
		`{"nonce":"a","nonce":"b"}`,
		"{\"st\\u0061te\":\"pending\"}",
		"not json",
		"[1,2]",
		`{"nonce":1}`,
	} {
		doc, err := decodeEnvelope(raw)
		if err != nil {
			t.Fatalf("%s: decode must not fail: %v", raw, err)
		}
		if doc.record != nil {
			t.Fatalf("%s: an unusable document is an absent record", raw)
		}
	}
}

func TestConsumeScriptWiresTheEnvelope(t *testing.T) {
	// The consume script is the php text: the state splice and the
	// reply shape it produces must match the adapter's expectations.
	if !strings.Contains(ConsumeScript, "kiwiReplaceTopLevel(v, 'state', '\"consumed\"')") {
		t.Fatalf("the consume script must splice the state field")
	}
	if !strings.Contains(ConsumeScript, "identitySpliced = 1") {
		t.Fatalf("the consume script must report the identity splice")
	}
	if !strings.Contains(CommitScript, "resume_owner") {
		t.Fatalf("the commit script must carry the claim fence")
	}
	if !strings.Contains(DeleteIfPendingScript, "'deleted-pending'") {
		t.Fatalf("the cleanup script must report the deleted-pending status")
	}
	if !strings.Contains(CancelScript, "'cancelled-now'") {
		t.Fatalf("the cancel script must report the fresh flip")
	}
}

// captureClient records the writes for the envelope test.
type captureClient struct {
	lastSet *struct {
		key   string
		value string
		ttlMs int64
	}
	values map[string]string
}

func (c *captureClient) Get(key string) (string, bool, error) {
	value, ok := c.values[key]
	return value, ok, nil
}
func (c *captureClient) SetWithTTL(key, value string, ttlMillis int64) error {
	c.lastSet = &struct {
		key   string
		value string
		ttlMs int64
	}{key, value, ttlMillis}
	return nil
}
func (c *captureClient) Pttl(string) (int64, error) { return 60_000, nil }
func (c *captureClient) Del(string) (bool, error)   { return true, nil }
func (c *captureClient) Eval(string, []string, []string) (RedisReply, error) {
	return nil, nil
}
func (c *captureClient) EvalSha(string, []string, []string) (RedisReply, error) {
	return nil, nil
}
func (c *captureClient) ScriptLoad(string) (string, error) { return "", nil }
func (c *captureClient) Close() error                      { return nil }

func TestOpenStoreURLs(t *testing.T) {
	memory, err := OpenStore("memory://")
	if err != nil || memory == nil {
		t.Fatalf("memory store must open")
	}
	empty, err := OpenStore("")
	if err != nil || empty == nil {
		t.Fatalf("the empty url defaults to memory")
	}
	if _, err := OpenStore("gopher://x"); err == nil {
		t.Fatalf("an unknown scheme must be refused")
	}
}
