import type { ChallengeRecord } from '../record.js';
import { challengeRecordFromJson, challengeRecordToJson } from '../record.js';
import {
  DEFAULT_TTL_MARGIN_SECS,
  StoreUnavailableError,
  StoreWriteError,
  validatedOperationIdentity,
  type ConsumedResultRecord,
  type ConsumedRecordSnapshot,
  type DeleteIfPendingOutcome,
  type RuntimeStateSnapshot,
  type StoreAdapter,
} from '../store.js';

/**
 * The SQLite adapter: the zero-infrastructure single-node backend.
 * Every durable transition runs inside one BEGIN IMMEDIATE
 * transaction (the lock taken before the row is read, the commit as
 * the durability point). SQLite serializes writers, so two racing
 * consumers of one nonce cannot both observe the pending row: exactly
 * one caller wins the consume and the loser reads the winner's
 * retained state. This mirrors the PHP SqliteStorage table and
 * semantics row for row, so PHP and Node share one database file.
 */

/**
 * The structural shape of a better-sqlite3 database this adapter
 * drives. Declared structurally so the core package carries zero
 * runtime dependencies.
 */
export interface SqliteLike {
  pragma(source: string, options?: unknown): unknown;
  prepare(sql: string): {
    get(...params: unknown[]): unknown;
    run(...params: unknown[]): unknown;
  };
  exec(sql: string): unknown;
  transaction<T>(fn: () => T): T;
}

export interface SqliteStoreOptions {
  /** Extra retention past the signed expiry. */
  ttlMarginSecs?: number;
  /** The storage clock in epoch seconds; a test seam. */
  now?: () => number;
}

const SCHEMA_VERSION = 1;

interface Row {
  nonce: string;
  record_json: string;
  state: string;
  consumed_result_json: string | null;
  operation_identity: string | null;
  retained_until: number;
}

const SELECT_ROW =
  'SELECT nonce, record_json, state, consumed_result_json, operation_identity, retained_until ' +
  'FROM kiwicaptcha_challenge_records WHERE nonce = ?';

export class SqliteStore implements StoreAdapter {
  readonly authenticatedResultCommit = true;

  private readonly db: SqliteLike;
  private readonly ttlMarginSecs: number;
  private readonly now: () => number;

  constructor(db: SqliteLike, options: SqliteStoreOptions = {}) {
    if (options.ttlMarginSecs !== undefined && options.ttlMarginSecs < 0) {
      throw new RangeError('ttlMarginSecs must be >= 0');
    }
    this.db = db;
    this.ttlMarginSecs = options.ttlMarginSecs ?? DEFAULT_TTL_MARGIN_SECS;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    try {
      this.initializeSchema();
    } catch (error) {
      throw new StoreUnavailableError('sqlite schema initialization failed', { cause: error });
    }
  }

  private initializeSchema(): void {
    this.db.pragma('journal_mode = WAL');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const versionRow = this.db.prepare('PRAGMA user_version').get() as { user_version?: number } | undefined;
      const version = Number(versionRow?.user_version ?? 0);
      if (version > SCHEMA_VERSION) {
        throw new Error(
          `the database carries schema version ${version}, newer than the ${SCHEMA_VERSION} this adapter supports`,
        );
      }
      if (version < SCHEMA_VERSION) {
        // The column set matches the PHP SqliteStorage table exactly
        // (the resume-claim columns ride along, owned by the PHP
        // process), so one database file serves both adapters.
        this.db.exec(
          'CREATE TABLE IF NOT EXISTS kiwicaptcha_challenge_records (' +
            'nonce TEXT PRIMARY KEY, ' +
            'record_json TEXT NOT NULL, ' +
            "state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')), " +
            'consumed_result_json TEXT, ' +
            'operation_identity TEXT, ' +
            'resume_owner TEXT, ' +
            'resume_until INTEGER, ' +
            'retained_until INTEGER NOT NULL)',
        );
        this.db.exec(
          'CREATE INDEX IF NOT EXISTS kiwicaptcha_challenge_records_retained_until_idx ' +
            'ON kiwicaptcha_challenge_records (retained_until)',
        );
        this.db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
      }
      this.db.exec('COMMIT');
    } catch (error) {
      this.safeRollback();
      throw error;
    }
  }

  private safeRollback(): void {
    try {
      this.db.exec('ROLLBACK');
    } catch {
      // The rollback of a broken connection is best-effort.
    }
  }

  /** One durable transition: the lock precedes the body's reads. */
  private writeTransition<T>(what: string, body: () => T): T {
    try {
      this.db.exec('BEGIN IMMEDIATE');
    } catch (error) {
      throw new StoreUnavailableError(`sqlite storage failure during ${what}`, { cause: error });
    }
    try {
      const result = body();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.safeRollback();
      if (error instanceof StoreWriteError) {
        throw error;
      }
      throw new StoreUnavailableError(`sqlite storage failure during ${what}`, { cause: error });
    }
  }

  private nowInSeconds(): number {
    return this.now();
  }

  private row(nonce: string): Row | null {
    const row = this.db.prepare(SELECT_ROW).get(nonce) as Row | undefined;
    return row === undefined ? null : row;
  }

  private liveRow(nonce: string): Row | null {
    const row = this.row(nonce);
    if (row === null) {
      return null;
    }
    if (this.nowInSeconds() >= Number(row.retained_until)) {
      return null;
    }
    return row;
  }

  /**
   * Decode a row into the record, its committed result and its
   * recorded identity: the record JSON passes the strict authority
   * first, a malformed committed result degrades to absent, and any
   * structural failure answers null (an unusable row, never a
   * partially trusted one). The runtime state rides the columns, the
   * PHP SqliteStorage layout.
   */
  private decodeRow(row: Row): { state: string; record: ChallengeRecord; result: ConsumedResultRecord | null; identity: string | null } | null {
    let parsed: unknown;
    try {
      parsed = JSON.parse(row.record_json);
    } catch {
      return null;
    }
    let record: ChallengeRecord;
    try {
      record = challengeRecordFromJson(parsed);
    } catch {
      return null;
    }
    let result: ConsumedResultRecord | null = null;
    const rawResult = row.consumed_result_json;
    if (typeof rawResult === 'string') {
      try {
        const candidate = JSON.parse(rawResult) as Record<string, unknown>;
        const unknownKeys = Object.keys(candidate).filter(
          (key) => key !== 'valid' && key !== 'binding' && key !== 'mac',
        );
        if (unknownKeys.length === 0 && typeof candidate.valid === 'boolean') {
          const binding = candidate.binding;
          const mac = candidate.mac;
          result = {
            valid: candidate.valid,
            binding: typeof binding === 'string' ? binding : null,
            mac: typeof mac === 'string' ? mac : null,
          };
        }
      } catch {
        result = null;
      }
    }
    const identity = typeof row.operation_identity === 'string' && row.operation_identity !== ''
      ? row.operation_identity
      : null;
    return { state: row.state, record, result, identity };
  }

  private consumedFromRow(row: Row): ConsumedRecordSnapshot | null {
    const decoded = this.decodeRow(row);
    if (decoded === null) {
      return null;
    }
    return {
      record: decoded.record,
      consumedNow: false,
      consumedBefore: true,
      consumedResult: decoded.result,
      operationIdentity: decoded.identity,
    };
  }

  async store(record: ChallengeRecord): Promise<void> {
    const json = JSON.stringify(challengeRecordToJson(record));
    const retainedUntil = record.expiresAt + this.ttlMarginSecs;
    this.writeTransition('challenge issuance', () => {
      this.db
        .prepare('DELETE FROM kiwicaptcha_challenge_records WHERE retained_until <= ?')
        .run(this.nowInSeconds());
      this.db
        .prepare(
          'INSERT INTO kiwicaptcha_challenge_records ' +
            '(nonce, record_json, state, consumed_result_json, operation_identity, retained_until) ' +
            'VALUES (?, ?, ?, NULL, NULL, ?) ' +
            'ON CONFLICT(nonce) DO UPDATE SET ' +
            'record_json = excluded.record_json, state = excluded.state, ' +
            'consumed_result_json = excluded.consumed_result_json, ' +
            'operation_identity = excluded.operation_identity, ' +
            'retained_until = excluded.retained_until',
        )
        .run(record.nonce, json, 'pending', retainedUntil);
    });
  }

  async find(nonce: string): Promise<ChallengeRecord | null> {
    try {
      const row = this.liveRow(nonce);
      if (row === null) {
        return null;
      }
      const decoded = this.decodeRow(row);
      return decoded === null ? null : decoded.record;
    } catch (error) {
      throw new StoreUnavailableError('sqlite storage failure while reading the record', { cause: error });
    }
  }

  async runtimeState(nonce: string): Promise<RuntimeStateSnapshot> {
    try {
      const row = this.liveRow(nonce);
      if (row === null) {
        return { kind: 'missing', record: null, consumed: null };
      }
      const decoded = this.decodeRow(row);
      if (decoded === null) {
        // A corrupt row fails closed as missing, never pending.
        return { kind: 'missing', record: null, consumed: null };
      }
      if (row.state === 'cancelled') {
        return { kind: 'cancelled', record: decoded.record, consumed: null };
      }
      if (row.state === 'consumed') {
        return {
          kind: 'consumed',
          record: decoded.record,
          consumed: {
            record: decoded.record,
            consumedNow: false,
            consumedBefore: true,
            consumedResult: decoded.result,
            operationIdentity: decoded.identity,
          },
        };
      }
      if (row.state === 'pending') {
        return { kind: 'pending', record: decoded.record, consumed: null };
      }
      return { kind: 'missing', record: null, consumed: null };
    } catch (error) {
      throw new StoreUnavailableError('sqlite storage failure while reading the runtime state', { cause: error });
    }
  }

  async consume(nonce: string, operationIdentity?: string | null): Promise<ConsumedRecordSnapshot | null> {
    const identity = validatedOperationIdentity(operationIdentity);
    return this.writeTransition('the pending-to-consumed transition', () => {
      const row = this.liveRow(nonce);
      if (row === null) {
        return null;
      }
      const decoded = this.decodeRow(row);
      if (decoded === null) {
        return null;
      }
      if (row.state === 'consumed') {
        return {
          record: decoded.record,
          consumedNow: false,
          consumedBefore: true,
          consumedResult: decoded.result,
          operationIdentity: decoded.identity,
        };
      }
      if (row.state !== 'pending') {
        // A cancelled row is never consumable.
        return null;
      }
      // The pending-envelope guard mirrors the Redis script's marker
      // check: a pending row carrying a result or identity is a forged
      // rewrite and reports missing.
      if (row.consumed_result_json !== null || row.operation_identity !== null) {
        return null;
      }
      const update = this.db.prepare(
        'UPDATE kiwicaptcha_challenge_records SET state = ?, operation_identity = ? WHERE nonce = ?',
      );
      update.run('consumed', identity, nonce);
      const after = this.row(nonce);
      if (after === null || after.state !== 'consumed' || (identity !== null && after.operation_identity !== identity)) {
        throw new StoreWriteError(
          'the consume transition could not record the operation identity on the flipped row',
        );
      }
      return {
        record: decoded.record,
        consumedNow: true,
        consumedBefore: false,
        consumedResult: null,
        operationIdentity: identity,
      };
    });
  }

  async commitResult(
    nonce: string,
    valid: boolean,
    binding: string | null,
    mac: string | null,
  ): Promise<boolean> {
    const resultJson = JSON.stringify(mac === null ? { valid, binding } : { valid, binding, mac });
    return this.writeTransition('the result commit', () => {
      const row = this.liveRow(nonce);
      if (
        row === null ||
        this.decodeRow(row) === null ||
        row.state !== 'consumed' ||
        row.consumed_result_json !== null
      ) {
        return false;
      }
      this.db
        .prepare('UPDATE kiwicaptcha_challenge_records SET consumed_result_json = ? WHERE nonce = ?')
        .run(resultJson, nonce);
      return true;
    });
  }

  async deleteIfPending(nonce: string): Promise<DeleteIfPendingOutcome> {
    return this.writeTransition('the delete-if-pending transition', () => {
      const row = this.liveRow(nonce);
      if (row === null) {
        return { kind: 'missing' } as DeleteIfPendingOutcome;
      }
      const decoded = this.decodeRow(row);
      if (decoded === null) {
        return { kind: 'corrupt' } as DeleteIfPendingOutcome;
      }
      if (row.state === 'consumed') {
        const consumed = this.consumedFromRow(row);
        return consumed === null
          ? ({ kind: 'corrupt' } as DeleteIfPendingOutcome)
          : ({ kind: 'consumed', consumed } as DeleteIfPendingOutcome);
      }
      if (row.state === 'cancelled') {
        return { kind: 'cancelled' } as DeleteIfPendingOutcome;
      }
      if (row.state !== 'pending') {
        return { kind: 'corrupt' } as DeleteIfPendingOutcome;
      }
      this.db.prepare('DELETE FROM kiwicaptcha_challenge_records WHERE nonce = ?').run(nonce);
      return { kind: 'deleted-pending' } as DeleteIfPendingOutcome;
    });
  }
}
