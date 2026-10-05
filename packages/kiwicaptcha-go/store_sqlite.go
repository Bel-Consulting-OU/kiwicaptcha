package kiwicaptcha

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SqliteStorage is the file-backed single-node adapter over the pure-Go
// modernc.org/sqlite driver. The schema, the state machine and the wire
// shapes are the ones the php SqliteStorage writes: one table keyed by
// nonce, the canonical record JSON beside the runtime columns, WAL
// journaling, and every durable transition inside one
// BEGIN IMMEDIATE transaction, so two racing consumers of one nonce
// can never both observe the pending row. Expiry mirrors the Redis
// TTLs: a row past its retained_until is absent to every read and
// transition.
type SqliteStorage struct {
	db        *sql.DB
	ttlMargin int64
	nowSecs   func() int64
}

const sqliteSchemaVersion = 1

// NewSqliteStorage opens (or creates) the database file with the
// shared schema. busyTimeoutMs bounds the wait for the single write
// lock; ttlMarginSecs is the retention past expires_at, mirroring the
// Redis backend's margin.
func NewSqliteStorage(path string, busyTimeoutMs int, ttlMarginSecs int64) (*SqliteStorage, error) {
	return newSqliteStorage(path, busyTimeoutMs, ttlMarginSecs, func() int64 { return time.Now().Unix() })
}

func newSqliteStorage(path string, busyTimeoutMs int, ttlMarginSecs int64, now func() int64) (*SqliteStorage, error) {
	if busyTimeoutMs < 0 || ttlMarginSecs < 0 {
		return nil, fmt.Errorf("%w: the sqlite busy timeout and ttl margin must be >= 0", ErrStorageUnavailable)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)", path, busyTimeoutMs)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	// The single connection serializes this process's writers; the
	// immediate transaction serializes everyone else on the file.
	db.SetMaxOpenConns(1)
	s := &SqliteStorage{db: db, ttlMargin: ttlMarginSecs, nowSecs: now}
	if err := s.initializeSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database connection.
func (s *SqliteStorage) Close() error { return s.db.Close() }

func (s *SqliteStorage) initializeSchema() error {
	return s.write("schema initialization", func() error {
		var version int
		if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		if version > sqliteSchemaVersion {
			return fmt.Errorf("%w: the database carries schema version %d, newer than the %d this adapter supports; upgrade the kiwicaptcha-go package", ErrStorageUnavailable, version, sqliteSchemaVersion)
		}
		if version == sqliteSchemaVersion {
			var present int
			if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'kiwicaptcha_challenge_records'").Scan(&present); err != nil {
				return err
			}
			if present != 1 {
				return fmt.Errorf("%w: the database is stamped with the kiwicaptcha schema version but the challenge table is missing; the file is damaged", ErrStorageUnavailable)
			}
			return nil
		}
		if _, err := s.db.Exec("CREATE TABLE IF NOT EXISTS kiwicaptcha_challenge_records (" +
			"nonce TEXT PRIMARY KEY, " +
			"record_json TEXT NOT NULL, " +
			"state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')), " +
			"consumed_result_json TEXT, " +
			"operation_identity TEXT, " +
			"resume_owner TEXT, " +
			"resume_until INTEGER, " +
			"retained_until INTEGER NOT NULL)"); err != nil {
			return err
		}
		if _, err := s.db.Exec("CREATE INDEX IF NOT EXISTS kiwicaptcha_challenge_records_retained_until_idx " +
			"ON kiwicaptcha_challenge_records (retained_until)"); err != nil {
			return err
		}
		_, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", sqliteSchemaVersion))
		return err
	})
}

// StoreRecord persists one pending record, sweeping expired rows in
// the same transaction.
func (s *SqliteStorage) StoreRecord(record *ChallengeRecord) error {
	data, err := record.MarshalJSON()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	return s.write("challenge issuance", func() error {
		if _, err := s.db.Exec("DELETE FROM kiwicaptcha_challenge_records WHERE retained_until <= ?", s.nowSecs()); err != nil {
			return err
		}
		_, err := s.db.Exec("INSERT INTO kiwicaptcha_challenge_records "+
			"(nonce, record_json, state, consumed_result_json, operation_identity, resume_owner, resume_until, retained_until) "+
			"VALUES (?, ?, 'pending', NULL, NULL, NULL, NULL, ?) "+
			"ON CONFLICT(nonce) DO UPDATE SET record_json = excluded.record_json, state = excluded.state, "+
			"consumed_result_json = excluded.consumed_result_json, operation_identity = excluded.operation_identity, "+
			"resume_owner = excluded.resume_owner, resume_until = excluded.resume_until, retained_until = excluded.retained_until",
			record.Nonce, string(data), record.ExpiresAt+s.ttlMargin)
		return err
	})
}

// Find returns the pending or retained record, absent once expired.
func (s *SqliteStorage) Find(nonce string) (*ChallengeRecord, error) {
	row, err := s.liveRow(nonce)
	if err != nil || row == nil {
		return nil, err
	}
	return decodeSqliteRecord(row.recordJSON)
}

// Delete removes one record and reports whether it existed.
func (s *SqliteStorage) Delete(nonce string) (bool, error) {
	var existed bool
	err := s.write("the record deletion", func() error {
		result, err := s.db.Exec("DELETE FROM kiwicaptcha_challenge_records WHERE nonce = ?", nonce)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		existed = affected > 0
		return nil
	})
	return existed, err
}

// Consume runs the one-shot pending to consumed transition.
func (s *SqliteStorage) Consume(nonce string) (*ConsumedRecord, error) {
	return s.ConsumeWithOperationIdentity(nonce, "")
}

// ConsumeWithOperationIdentity runs the one-shot transition and
// records the logical-operation identity atomically with the flip.
func (s *SqliteStorage) ConsumeWithOperationIdentity(nonce string, operationIdentity string) (*ConsumedRecord, error) {
	identity, err := ValidateOperationIdentity(operationIdentity)
	if err != nil {
		return nil, err
	}
	var consumed *ConsumedRecord
	err = s.write("the pending-to-consumed transition", func() error {
		row, err := s.liveRow(nonce)
		if err != nil || row == nil {
			return err
		}
		record, err := decodeSqliteRecord(row.recordJSON)
		if err != nil || record == nil {
			return err
		}
		switch row.state {
		case "consumed":
			consumed = consumedEnvelope(row, record)
			return nil
		case "pending":
		default:
			return nil
		}
		if row.consumedResultJSON != nil || row.operationIdentity != nil || row.resumeOwner != nil {
			return nil
		}
		var identityArg interface{}
		if identity != "" {
			identityArg = identity
		}
		if _, err := s.db.Exec("UPDATE kiwicaptcha_challenge_records SET state = 'consumed', operation_identity = ? WHERE nonce = ?", identityArg, nonce); err != nil {
			return err
		}
		consumed = &ConsumedRecord{Record: record, ConsumedNow: true, OperationIdentity: identity}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return consumed, nil
}

// ConsumedState reads the retained consumed envelope.
func (s *SqliteStorage) ConsumedState(nonce string) (*ConsumedRecord, error) {
	row, err := s.liveRow(nonce)
	if err != nil || row == nil || row.state != "consumed" {
		return nil, err
	}
	record, err := decodeSqliteRecord(row.recordJSON)
	if err != nil || record == nil {
		return nil, err
	}
	return consumedEnvelope(row, record), nil
}

// CommitResult commits the deterministic outcome of a consumed record;
// only the first commit wins.
func (s *SqliteStorage) CommitResult(nonce string, valid bool, binding string) (bool, error) {
	return s.CommitAuthenticatedResult(nonce, ConsumedResult{Valid: valid, Binding: binding})
}

// CommitAuthenticatedResult commits the outcome with its server-state
// mac; only the first commit wins.
func (s *SqliteStorage) CommitAuthenticatedResult(nonce string, result ConsumedResult) (bool, error) {
	committed := false
	err := s.write("the result commit", func() error {
		row, err := s.liveRow(nonce)
		if err != nil || row == nil || row.state != "consumed" || row.consumedResultJSON != nil {
			return err
		}
		if _, err := decodeSqliteRecord(row.recordJSON); err != nil {
			return err
		}
		if _, err := s.db.Exec("UPDATE kiwicaptcha_challenge_records SET consumed_result_json = ? WHERE nonce = ?", marshalConsumedResult(result), nonce); err != nil {
			return err
		}
		committed = true
		return nil
	})
	return committed, err
}

// DeleteIfPending runs the fused read-and-delete-on-pending transition.
func (s *SqliteStorage) DeleteIfPending(nonce string) (DeleteIfPendingResult, error) {
	var result DeleteIfPendingResult
	err := s.write("the delete-if-pending transition", func() error {
		row, err := s.liveRow(nonce)
		if err != nil || row == nil {
			result = DeleteIfPendingResult{Status: DeleteStatusMissing}
			return err
		}
		record, err := decodeSqliteRecord(row.recordJSON)
		if err != nil {
			return err
		}
		if record == nil {
			result = DeleteIfPendingResult{Status: DeleteStatusCorrupt}
			return nil
		}
		switch row.state {
		case "consumed":
			result = DeleteIfPendingResult{Status: DeleteStatusConsumed, Consumed: consumedEnvelope(row, record)}
		case "cancelled":
			result = DeleteIfPendingResult{Status: DeleteStatusCancelled}
		case "pending":
			if _, err := s.db.Exec("DELETE FROM kiwicaptcha_challenge_records WHERE nonce = ?", nonce); err != nil {
				return err
			}
			result = DeleteIfPendingResult{Status: DeleteStatusDeletedPending}
		default:
			result = DeleteIfPendingResult{Status: DeleteStatusCorrupt}
		}
		return nil
	})
	return result, err
}

// RuntimeState reads the terminal-aware snapshot.
func (s *SqliteStorage) RuntimeState(nonce string) (ChallengeRuntimeState, error) {
	row, err := s.liveRow(nonce)
	if err != nil {
		return ChallengeRuntimeState{}, err
	}
	if row == nil {
		return ChallengeRuntimeState{Kind: RuntimeMissing}, nil
	}
	record, err := decodeSqliteRecord(row.recordJSON)
	if err != nil {
		return ChallengeRuntimeState{}, err
	}
	if record == nil {
		// A corrupt row fails closed as missing, never pending.
		return ChallengeRuntimeState{Kind: RuntimeMissing}, nil
	}
	switch row.state {
	case "cancelled":
		return ChallengeRuntimeState{Kind: RuntimeCancelled, Record: record}, nil
	case "consumed":
		return ChallengeRuntimeState{Kind: RuntimeConsumed, Record: record, Consumed: consumedEnvelope(row, record)}, nil
	case "pending":
		return ChallengeRuntimeState{Kind: RuntimePending, Record: record}, nil
	default:
		return ChallengeRuntimeState{Kind: RuntimeMissing}, nil
	}
}

// Cancel flips the terminal cancellation marker.
func (s *SqliteStorage) Cancel(nonce string) (*CancellationResult, error) {
	var result *CancellationResult
	err := s.write("the pending-to-cancelled transition", func() error {
		row, err := s.liveRow(nonce)
		if err != nil || row == nil {
			return err
		}
		if _, err := decodeSqliteRecord(row.recordJSON); err != nil {
			return err
		}
		switch row.state {
		case "consumed":
			result = &CancellationResult{Status: CancelStatusConsumed}
		case "cancelled":
			result = &CancellationResult{Status: CancelStatusCancelled}
		case "pending":
			if _, err := s.db.Exec("UPDATE kiwicaptcha_challenge_records SET state = 'cancelled' WHERE nonce = ?", nonce); err != nil {
				return err
			}
			result = &CancellationResult{Status: CancelStatusCancelledNow}
		}
		return nil
	})
	return result, err
}

type sqliteRow struct {
	recordJSON         *string
	state              string
	consumedResultJSON *string
	operationIdentity  *string
	resumeOwner        *string
	resumeUntil        *int64
	retainedUntil      int64
}

func (s *SqliteStorage) liveRow(nonce string) (*sqliteRow, error) {
	row := &sqliteRow{}
	err := s.db.QueryRow("SELECT record_json, state, consumed_result_json, operation_identity, resume_owner, resume_until, retained_until "+
		"FROM kiwicaptcha_challenge_records WHERE nonce = ?", nonce).
		Scan(&row.recordJSON, &row.state, &row.consumedResultJSON, &row.operationIdentity, &row.resumeOwner, &row.resumeUntil, &row.retainedUntil)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	if s.nowSecs() >= row.retainedUntil {
		return nil, nil
	}
	return row, nil
}

func (s *SqliteStorage) write(what string, body func() error) error {
	if _, err := s.db.Exec("BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("%w: sqlite storage failure during %s: %s", ErrStorageUnavailable, what, err)
	}
	if err := body(); err != nil {
		_, _ = s.db.Exec("ROLLBACK")
		if strings.Contains(err.Error(), "locked") || strings.Contains(err.Error(), "busy") {
			return fmt.Errorf("%w: sqlite storage failure during %s: %s; the write lock stayed held past the busy timeout, so raise the busy timeout or serialize writers", ErrStorageUnavailable, what, err)
		}
		return err
	}
	if _, err := s.db.Exec("COMMIT"); err != nil {
		_, _ = s.db.Exec("ROLLBACK")
		return fmt.Errorf("%w: sqlite storage failure during %s: %s", ErrStorageUnavailable, what, err)
	}
	return nil
}

func decodeSqliteRecord(recordJSON *string) (*ChallengeRecord, error) {
	if recordJSON == nil {
		return nil, nil
	}
	record, err := ParseChallengeRecord([]byte(*recordJSON))
	if err != nil {
		// An unusable row is nil, never a partially trusted record.
		return nil, nil
	}
	return record, nil
}

func consumedEnvelope(row *sqliteRow, record *ChallengeRecord) *ConsumedRecord {
	var result *ConsumedResult
	if row.consumedResultJSON != nil {
		var decoded struct {
			Valid   *bool  `json:"valid"`
			Binding string `json:"binding"`
			Mac     string `json:"mac"`
		}
		if json.Unmarshal([]byte(*row.consumedResultJSON), &decoded) == nil && decoded.Valid != nil {
			binding := decoded.Binding
			result = &ConsumedResult{Valid: *decoded.Valid, Binding: binding, Mac: decoded.Mac}
		}
	}
	identity := ""
	if row.operationIdentity != nil {
		identity = *row.operationIdentity
	}
	return &ConsumedRecord{Record: record, ConsumedBefore: true, ConsumedResult: result, OperationIdentity: identity}
}

func marshalConsumedResult(result ConsumedResult) string {
	data, _ := json.Marshal(struct {
		Valid   bool    `json:"valid"`
		Binding *string `json:"binding"`
		Mac     *string `json:"mac,omitempty"`
	}{Valid: result.Valid, Binding: &result.Binding, Mac: &result.Mac})
	return string(data)
}
