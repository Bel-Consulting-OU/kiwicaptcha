package kiwicaptcha

import (
	"fmt"
	"sync"
	"time"
)

// Redis storage: the shared-backend store adapter, a port of the php
// RedisStorage. The stored envelope is one json document per nonce
// key: the flattened record fields plus the state, consumed_result
// and operation_identity runtime markers. The consume, delete-if-
// pending, cancel and commit transitions run the exact Lua scripts of
// the php adapter, so envelopes written by either SDK are
// interchangeable, byte for byte.

// RedisStorageTTL is the retention margin, in seconds, added to the
// signed lifetime so a consumed record outlives its expiry window and
// a replay answers from the retained envelope.
const RedisStorageTTL = 60

// RedisStorage is the Redis store adapter over the narrow client
// surface.
type RedisStorage struct {
	client    RedisClient
	prefix    string
	ttlMargin time.Duration
	shaMu     sync.Mutex
	shaCache  map[string]string
}

// NewRedisStorage binds the adapter to a client.
func NewRedisStorage(client RedisClient, prefix string) *RedisStorage {
	if prefix == "" {
		prefix = EnvelopeDefaultPrefix
	}
	return &RedisStorage{
		client:    client,
		prefix:    prefix,
		ttlMargin: RedisStorageTTL * time.Second,
		shaCache:  map[string]string{},
	}
}

// eval runs one script through the sha cache with the noscript
// fallback to a plain eval. The cache is guarded, so concurrent
// verifications share one adapter safely.
func (r *RedisStorage) eval(script string, keys, args []string) (RedisReply, error) {
	r.shaMu.Lock()
	sha, cached := r.shaCache[script]
	r.shaMu.Unlock()
	if cached {
		reply, err := r.client.EvalSha(sha, keys, args)
		if err == nil {
			return reply, nil
		}
		var redisErr *RedisError
		if !errorsAs(err, &redisErr) || !redisErr.IsNoScript() {
			return nil, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
		}
	}
	loaded, err := r.client.ScriptLoad(script)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	if loaded != "" {
		r.shaMu.Lock()
		r.shaCache[script] = loaded
		r.shaMu.Unlock()
	}
	reply, err := r.client.Eval(script, keys, args)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	return reply, nil
}

// envelopeDoc is one decoded stored envelope: the record plus its
// runtime markers, all from the same bytes.
type envelopeDoc struct {
	record   *ChallengeRecord
	state    string
	identity string
	result   *ConsumedResult
}

// decodeEnvelope decodes one stored envelope. A nil record with a nil
// error means the value is absent; an unusable document is also an
// absent record, never a partially trusted one, mirroring the php
// strict json gate.
func decodeEnvelope(raw string) (*envelopeDoc, error) {
	if raw == "" || len(raw) > EnvelopeMaxBytes {
		return &envelopeDoc{}, nil
	}
	value, err := decodeStrictJSON([]byte(raw))
	if err != nil {
		return &envelopeDoc{}, nil
	}
	data, ok := value.(map[string]interface{})
	if !ok {
		return &envelopeDoc{}, nil
	}
	doc := &envelopeDoc{}
	if state, ok := data["state"].(string); ok {
		doc.state = state
	}
	if identity, ok := data["operation_identity"].(string); ok {
		doc.identity = identity
	}
	if rawResult, present := data["consumed_result"]; present {
		if resultMap, ok := rawResult.(map[string]interface{}); ok {
			result, err := consumedResultFromMap(resultMap)
			if err == nil {
				doc.result = result
			}
		}
	}
	recordData := make(map[string]interface{}, len(data))
	for key, item := range data {
		switch key {
		case "state", "consumed_result", "operation_identity", "resume_owner", "resume_until":
			continue
		}
		recordData[key] = item
	}
	record, err := challengeRecordFromMap(recordData)
	if err != nil {
		return &envelopeDoc{}, nil
	}
	doc.record = record
	return doc, nil
}

func consumedResultFromMap(data map[string]interface{}) (*ConsumedResult, error) {
	for key := range data {
		if key != "valid" && key != "binding" && key != "mac" {
			return nil, fmt.Errorf("consumed_result carries unsupported keys")
		}
	}
	result := &ConsumedResult{}
	switch valid := data["valid"].(type) {
	case bool:
		result.Valid = valid
	case jsonNumber:
		// The production Lua accepts the legacy 1 or 0 form.
		result.Valid = string(valid) == "1"
	default:
		return nil, fmt.Errorf("consumed_result.valid must be a boolean")
	}
	if binding, ok := data["binding"].(string); ok {
		result.Binding = binding
	} else if data["binding"] == nil {
		result.Binding = ""
	} else {
		return nil, fmt.Errorf("consumed_result.binding must be a string or null")
	}
	switch mac := data["mac"].(type) {
	case nil:
	case string:
		if !isHex64(mac) {
			return nil, fmt.Errorf("consumed_result.mac must be 64 lowercase hex characters")
		}
		result.Mac = mac
	default:
		return nil, fmt.Errorf("consumed_result.mac must be a string or null")
	}
	return result, nil
}

// StoreRecord persists one pending record with a lifetime of the
// signed remainder plus the retention margin.
func (r *RedisStorage) StoreRecord(record *ChallengeRecord) error {
	envelope := record.ToWireMap()
	envelope["state"] = "pending"
	envelope["consumed_result"] = nil
	envelope["operation_identity"] = nil
	encoded, err := encodeEnvelopeJSON(envelope)
	if err != nil {
		return err
	}
	ttl := time.Duration(record.ExpiresAt-time.Now().Unix())*time.Second + r.ttlMargin
	if ttl < time.Second {
		ttl = time.Second
	}
	if err := r.client.SetWithTTL(r.prefix+record.Nonce, encoded, ttl.Milliseconds()); err != nil {
		return fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	return nil
}

// Find reads the record from the envelope.
func (r *RedisStorage) Find(nonce string) (*ChallengeRecord, error) {
	raw, found, err := r.client.Get(r.prefix + nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	if !found {
		return nil, nil
	}
	doc, err := decodeEnvelope(raw)
	if err != nil {
		return nil, err
	}
	return doc.record, nil
}

func (r *RedisStorage) consume(nonce string, identityJSON string) (*ConsumedRecord, error) {
	key := r.prefix + nonce
	reply, err := r.eval(ConsumeScript, []string{key}, []string{identityJSON})
	if err != nil {
		return nil, err
	}
	items, ok := reply.([]interface{})
	if !ok || len(items) < 3 || items[0] == nil {
		return nil, nil
	}
	payload, ok := items[0].(string)
	if !ok {
		return nil, nil
	}
	doc, err := decodeEnvelope(payload)
	if err != nil {
		return nil, err
	}
	if doc.record == nil {
		return nil, nil
	}
	return &ConsumedRecord{
		Record:            doc.record,
		ConsumedNow:       replyInt(items[1]) == 1,
		ConsumedBefore:    replyInt(items[2]) == 1,
		ConsumedResult:    doc.result,
		OperationIdentity: doc.identity,
	}, nil
}

// Consume runs the fused one-shot transition.
func (r *RedisStorage) Consume(nonce string) (*ConsumedRecord, error) {
	return r.consume(nonce, "")
}

// ConsumeWithOperationIdentity runs the fused transition and records
// the validated identity atomically with the flip.
func (r *RedisStorage) ConsumeWithOperationIdentity(nonce string, operationIdentity string) (*ConsumedRecord, error) {
	identity, err := ValidateOperationIdentity(operationIdentity)
	if err != nil {
		return nil, err
	}
	identityJSON := ""
	if identity != "" {
		identityJSON = encodeJSONString(identity)
	}
	return r.consume(nonce, identityJSON)
}

// ConsumedState reads the retained consumed envelope.
func (r *RedisStorage) ConsumedState(nonce string) (*ConsumedRecord, error) {
	raw, found, err := r.client.Get(r.prefix + nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	if !found {
		return nil, nil
	}
	doc, err := decodeEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if doc.record == nil || doc.state != "consumed" {
		return nil, nil
	}
	return &ConsumedRecord{
		Record:            doc.record,
		ConsumedBefore:    true,
		ConsumedResult:    doc.result,
		OperationIdentity: doc.identity,
	}, nil
}

// DeleteIfPending runs the fused atomic cleanup.
func (r *RedisStorage) DeleteIfPending(nonce string) (DeleteIfPendingResult, error) {
	key := r.prefix + nonce
	reply, err := r.eval(DeleteIfPendingScript, []string{key}, nil)
	if err != nil {
		return DeleteIfPendingResult{}, err
	}
	items, ok := reply.([]interface{})
	if !ok || len(items) == 0 {
		return DeleteIfPendingResult{}, fmt.Errorf("%w: delete-if-pending returned an unexpected reply", ErrStorageUnavailable)
	}
	status, _ := items[0].(string)
	if status == DeleteStatusConsumed {
		if len(items) < 2 {
			return DeleteIfPendingResult{}, fmt.Errorf("%w: delete-if-pending lost the consumed envelope", ErrStorageUnavailable)
		}
		payload, _ := items[1].(string)
		doc, err := decodeEnvelope(payload)
		if err != nil {
			return DeleteIfPendingResult{}, fmt.Errorf("%w: delete-if-pending returned an undecodable envelope", ErrStorageUnavailable)
		}
		if doc.record == nil {
			return DeleteIfPendingResult{}, fmt.Errorf("%w: delete-if-pending returned an undecodable envelope", ErrStorageUnavailable)
		}
		return DeleteIfPendingResult{
			Status: DeleteStatusConsumed,
			Consumed: &ConsumedRecord{
				Record:            doc.record,
				ConsumedBefore:    true,
				ConsumedResult:    doc.result,
				OperationIdentity: doc.identity,
			},
		}, nil
	}
	if status == "" {
		status = DeleteStatusCorrupt
	}
	return DeleteIfPendingResult{Status: status}, nil
}

// RuntimeState reads the terminal-aware snapshot.
func (r *RedisStorage) RuntimeState(nonce string) (ChallengeRuntimeState, error) {
	raw, found, err := r.client.Get(r.prefix + nonce)
	if err != nil {
		return ChallengeRuntimeState{}, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	if !found {
		return ChallengeRuntimeState{Kind: RuntimeMissing}, nil
	}
	doc, err := decodeEnvelope(raw)
	if err != nil {
		return ChallengeRuntimeState{}, err
	}
	if doc.record == nil {
		return ChallengeRuntimeState{Kind: RuntimeMissing}, nil
	}
	switch doc.state {
	case "cancelled":
		return ChallengeRuntimeState{Kind: RuntimeCancelled, Record: doc.record}, nil
	case "consumed":
		consumed := &ConsumedRecord{
			Record:            doc.record,
			ConsumedBefore:    true,
			ConsumedResult:    doc.result,
			OperationIdentity: doc.identity,
		}
		return ChallengeRuntimeState{Kind: RuntimeConsumed, Record: doc.record, Consumed: consumed}, nil
	case "pending":
		return ChallengeRuntimeState{Kind: RuntimePending, Record: doc.record}, nil
	default:
		return ChallengeRuntimeState{Kind: RuntimeMissing}, nil
	}
}

// Cancel flips the terminal cancellation marker through the fused
// script.
func (r *RedisStorage) Cancel(nonce string) (*CancellationResult, error) {
	key := r.prefix + nonce
	reply, err := r.eval(CancelScript, []string{key}, nil)
	if err != nil {
		return nil, err
	}
	items, ok := reply.([]interface{})
	if !ok || len(items) == 0 {
		return nil, nil
	}
	status, _ := items[0].(string)
	if status == "" {
		return nil, nil
	}
	return &CancellationResult{Status: status}, nil
}

// Delete removes one key.
func (r *RedisStorage) Delete(nonce string) (bool, error) {
	removed, err := r.client.Del(r.prefix + nonce)
	if err != nil {
		return false, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	return removed, nil
}

// CommitResult commits the deterministic outcome without a mac.
func (r *RedisStorage) CommitResult(nonce string, valid bool, binding string) (bool, error) {
	return r.CommitAuthenticatedResult(nonce, ConsumedResult{Valid: valid, Binding: binding})
}

// CommitAuthenticatedResult commits the outcome with its server-state
// mac through the fused script. The write preserves the key's
// remaining lifetime and refuses a key without one.
func (r *RedisStorage) CommitAuthenticatedResult(nonce string, result ConsumedResult) (bool, error) {
	key := r.prefix + nonce
	args := []string{
		boolArg(result.Valid),
		result.Binding,
		boolArg(result.Binding != ""),
		"",
		result.Mac,
	}
	reply, err := r.eval(CommitScript, []string{key}, args)
	if err != nil {
		return false, err
	}
	return replyInt(reply) == 1, nil
}

func replyInt(reply RedisReply) int64 {
	if value, ok := reply.(int64); ok {
		return value
	}
	return 0
}

func boolArg(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
