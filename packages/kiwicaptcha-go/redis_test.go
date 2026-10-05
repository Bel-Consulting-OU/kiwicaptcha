package kiwicaptcha

import (
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"
)

// The Redis suite runs against a scratch redis-server on a test port,
// started and skipped like the repo's other redis-gated tests: a run
// without the binary stays green everywhere.

var redisBinary = func() string {
	path, err := exec.LookPath("redis-server")
	if err != nil {
		return ""
	}
	return path
}()

func startRedis(t *testing.T) (*RespClient, func()) {
	t.Helper()
	if redisBinary == "" {
		t.Skip("redis-server binary not available")
	}
	tmpdir, err := os.MkdirTemp("", "kiwi-redis-test-")
	if err != nil {
		t.Fatalf("tmpdir: %v", err)
	}
	port := 6399 + os.Getpid()%100
	command := exec.Command(redisBinary,
		"--port", strconv.Itoa(port),
		"--save", "",
		"--appendonly", "no",
		"--dir", tmpdir,
	)
	if err := command.Start(); err != nil {
		t.Fatalf("redis start: %v", err)
	}
	client, err := dialWithRetry("127.0.0.1", port, 10*time.Second)
	if err != nil {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		_ = os.RemoveAll(tmpdir)
		t.Fatalf("the scratch redis-server never came up: %v", err)
	}
	cleanup := func() {
		_ = client.Close()
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		_ = os.RemoveAll(tmpdir)
	}
	if err := client.Ping(); err != nil {
		cleanup()
		t.Fatalf("redis ping: %v", err)
	}
	if _, err := client.Command("FLUSHALL"); err != nil {
		cleanup()
		t.Fatalf("flush: %v", err)
	}
	return client, cleanup
}

func dialWithRetry(host string, port int, timeout time.Duration) (*RespClient, error) {
	deadline := time.Now().Add(timeout)
	for {
		client, err := DialRedis(fmt.Sprintf("redis://%s:%d", host, port))
		if err == nil {
			if pingErr := client.Ping(); pingErr == nil {
				return client, nil
			}
			_ = client.Close()
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRedisStoreTransitions(t *testing.T) {
	client, cleanup := startRedis(t)
	defer cleanup()
	storage := NewRedisStorage(client, EnvelopeDefaultPrefix)
	record := mintRecord(t, defaultMintOptions())
	if err := storage.StoreRecord(record); err != nil {
		t.Fatalf("store: %v", err)
	}
	found, err := storage.Find(record.Nonce)
	if err != nil || found == nil || found.Challenge != record.Challenge {
		t.Fatalf("find: %+v %v", found, err)
	}
	// The stored envelope carries the runtime markers.
	raw, present, err := client.Get(EnvelopeDefaultPrefix + record.Nonce)
	if err != nil || !present {
		t.Fatalf("the envelope must be stored: %v", err)
	}
	doc, err := decodeEnvelope(raw)
	if err != nil || doc.state != "pending" {
		t.Fatalf("the envelope must carry the pending state")
	}
	consumed, err := storage.Consume(record.Nonce)
	if err != nil || consumed == nil || !consumed.ConsumedNow {
		t.Fatalf("the consume must win: %+v %v", consumed, err)
	}
	retry, err := storage.Consume(record.Nonce)
	if err != nil || retry == nil || !retry.ConsumedBefore {
		t.Fatalf("the retry must observe the consumed state: %+v %v", retry, err)
	}
	state, err := storage.ConsumedState(record.Nonce)
	if err != nil || state == nil {
		t.Fatalf("the consumed state must be readable")
	}
	committed, err := storage.CommitAuthenticatedResult(record.Nonce, ConsumedResult{Valid: true, Binding: "tx-1", Mac: stringsRepeat("a", 64)})
	if err != nil || !committed {
		t.Fatalf("the authenticated commit must win: %v", err)
	}
	again, err := storage.CommitResult(record.Nonce, false, "")
	if err != nil || again {
		t.Fatalf("only the first commit wins")
	}
	kept, err := storage.Find(record.Nonce)
	if err != nil || kept == nil {
		t.Fatalf("the consumed record is retained until its ttl")
	}
	deleted, err := storage.Delete(record.Nonce)
	if err != nil || !deleted {
		t.Fatalf("delete: %v", err)
	}
	gone, err := storage.Find(record.Nonce)
	if err != nil || gone != nil {
		t.Fatalf("the deleted record must be absent")
	}
}

func TestRedisDeleteIfPendingAndCancel(t *testing.T) {
	client, cleanup := startRedis(t)
	defer cleanup()
	storage := NewRedisStorage(client, EnvelopeDefaultPrefix)
	record := mintRecord(t, defaultMintOptions())
	storeRecord(t, storage, record)
	result, err := storage.DeleteIfPending(record.Nonce)
	if err != nil || result.Status != DeleteStatusDeletedPending {
		t.Fatalf("delete if pending: %+v %v", result, err)
	}
	if found, err := storage.Find(record.Nonce); err != nil || found != nil {
		t.Fatalf("the pending record must be gone")
	}
	// A consumed record is retained by the cleanup.
	second := mintRecord(t, defaultMintOptions())
	storeRecord(t, storage, second)
	if _, err := storage.Consume(second.Nonce); err != nil {
		t.Fatalf("consume: %v", err)
	}
	result, err = storage.DeleteIfPending(second.Nonce)
	if err != nil || result.Status != DeleteStatusConsumed || result.Consumed == nil {
		t.Fatalf("the consumed envelope must be returned: %+v %v", result, err)
	}
	if found, err := storage.Find(second.Nonce); err != nil || found == nil {
		t.Fatalf("the consumed record is retained")
	}
	// The cancellation flip is terminal and idempotent.
	third := mintRecord(t, defaultMintOptions())
	storeRecord(t, storage, third)
	cancelled, err := storage.Cancel(third.Nonce)
	if err != nil || cancelled.Status != CancelStatusCancelledNow {
		t.Fatalf("cancel: %+v %v", cancelled, err)
	}
	again, err := storage.Cancel(third.Nonce)
	if err != nil || again.Status != CancelStatusCancelled {
		t.Fatalf("cancel is idempotent: %+v %v", again, err)
	}
	state, err := storage.RuntimeState(third.Nonce)
	if err != nil || state.Kind != RuntimeCancelled {
		t.Fatalf("the cancelled state must surface: %+v %v", state, err)
	}
	if consumed, err := storage.Consume(third.Nonce); err != nil || consumed != nil {
		t.Fatalf("a cancelled record is never consumable")
	}
}

func TestRedisVerifyExactlyOnce(t *testing.T) {
	client, cleanup := startRedis(t)
	defer cleanup()
	storage := NewRedisStorage(client, EnvelopeDefaultPrefix)
	record := mintRecord(t, defaultMintOptions())
	storeRecord(t, storage, record)
	verifier := newTestVerifier(t, VerifierConfig{}, testNow)
	verifier.Storage = storage
	options := VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: testClientIP}
	token := tokenForRecord(t, record)
	requireValid(t, verifier.Verify(token, options))
	// The replay answers already consumed from the retained envelope.
	requireCode(t, verifier.Verify(token, options), ErrCodeAlreadyConsumed)
}

func TestRedisConsumeRace(t *testing.T) {
	client, cleanup := startRedis(t)
	defer cleanup()
	storage := NewRedisStorage(client, EnvelopeDefaultPrefix)
	record := mintRecord(t, defaultMintOptions())
	storeRecord(t, storage, record)
	const racers = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	observedBefore := 0
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			consumed, err := storage.Consume(record.Nonce)
			if err != nil || consumed == nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if consumed.ConsumedNow {
				winners++
			}
			if consumed.ConsumedBefore {
				observedBefore++
			}
		}()
	}
	wg.Wait()
	if winners != 1 || observedBefore != racers-1 {
		t.Fatalf("exactly one racer wins: winners=%d before=%d", winners, observedBefore)
	}
}

func TestRedisGoldenRswVerification(t *testing.T) {
	client, cleanup := startRedis(t)
	defer cleanup()
	storage := NewRedisStorage(client, EnvelopeDefaultPrefix)
	document := readGolden(t, "golden_rsw_v5.json")
	record := goldenRecord(t, "golden_rsw_v5.json")
	rswDocument := document["rsw"].(map[string]interface{})
	if err := storage.StoreRecord(record); err != nil {
		t.Fatalf("store: %v", err)
	}
	verifier := newTestVerifier(t, VerifierConfig{
		RswModulusN: rswDocument["modulus_n"].(string),
		RswLambda:   rswDocument["lambda"].(string),
	}, goldenIssuedAt)
	verifier.Storage = storage
	n := new(big.Int)
	n.SetBytes(mustDecodeB64(t, rswDocument["modulus_n"].(string)))
	solved := solveRsw(record.Prefix, record.Nonce, n, record.T)
	token := CreateToken(record.Nonce, 0, 5000, NewJSONObject(), "", "", solved).Encode()
	outcome := verifier.Verify(token, VerifyOptions{SecretKey: testSecret, ExpectedScope: "login", ClientIP: "198.51.100.7"})
	requireValid(t, outcome)
	replay, err := storage.ConsumedState(record.Nonce)
	if err != nil || replay == nil || replay.ConsumedResult == nil || !replay.ConsumedResult.Valid {
		t.Fatalf("the php issued rsw success must be committed: %+v %v", replay, err)
	}
}

func TestRedisRespRoundTrip(t *testing.T) {
	client, cleanup := startRedis(t)
	defer cleanup()
	if err := client.SetWithTTL("kiwi:probe", "hello", 60_000); err != nil {
		t.Fatalf("set: %v", err)
	}
	value, found, err := client.Get("kiwi:probe")
	if err != nil || !found || value != "hello" {
		t.Fatalf("get: %q %v %v", value, found, err)
	}
	ttl, err := client.Pttl("kiwi:probe")
	if err != nil || ttl <= 0 || ttl > 61_000 {
		t.Fatalf("pttl: %d %v", ttl, err)
	}
	sha, err := client.ScriptLoad("return 1")
	if err != nil || sha == "" {
		t.Fatalf("script load: %v", err)
	}
	reply, err := client.EvalSha(sha, nil, nil)
	if err != nil || reply != int64(1) {
		t.Fatalf("evalsha: %v %v", reply, err)
	}
	// A lua nil truncates a RESP2 array; false renders as a null bulk.
	arrayReply, err := client.Eval("return {1, 'x', false}", nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	items, ok := arrayReply.([]interface{})
	if !ok || len(items) != 3 || items[0] != int64(1) || items[1] != "x" || items[2] != nil {
		t.Fatalf("eval array decode drift: %#v", arrayReply)
	}
	removed, err := client.Del("kiwi:probe")
	if err != nil || !removed {
		t.Fatalf("del: %v", err)
	}
	if _, found, _ := client.Get("kiwi:probe"); found {
		t.Fatalf("the probe must be gone")
	}
}

func TestRedisScriptErrorSurfaces(t *testing.T) {
	client, cleanup := startRedis(t)
	defer cleanup()
	_, err := client.Eval("return redis.error_reply('boom')", nil, nil)
	redisErr, ok := err.(*RedisError)
	if !ok || redisErr.Message != "ERR boom" {
		t.Fatalf("the typed error must surface: %v", err)
	}
}
