import type {
  ChallengeRecord,
} from '../record.js';
import { challengeRecordToJson } from '../record.js';
import {
  DEFAULT_TTL_MARGIN_SECS,
  decodeEnvelope,
  validatedOperationIdentity,
  type ConsumedRecordSnapshot,
  type DeleteIfPendingOutcome,
  type RuntimeStateSnapshot,
  type StoreAdapter,
} from '../store.js';

/**
 * The in-memory adapter: single-process evaluations, tests and tools.
 * The record map is synchronous under the event loop, so the
 * read-decide-write of the consume transition has no interleaving
 * point and exactly-once holds naturally.
 */

interface MemoryRow {
  envelopeJson: string;
  state: 'pending' | 'consumed' | 'cancelled';
  retainedUntil: number;
}

export interface MemoryStoreOptions {
  /** Extra retention past the signed expiry, mirroring the Redis margin. */
  ttlMarginSecs?: number;
  /** The storage clock in epoch seconds; defaults to Date.now()/1000. */
  now?: () => number;
}

export class MemoryStore implements StoreAdapter {
  readonly authenticatedResultCommit = true;

  private readonly rows = new Map<string, MemoryRow>();
  private readonly ttlMarginSecs: number;
  private readonly now: () => number;

  constructor(options: MemoryStoreOptions = {}) {
    this.ttlMarginSecs = options.ttlMarginSecs ?? DEFAULT_TTL_MARGIN_SECS;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Live rows only: a past-retention row is absent to every path. */
  private live(nonce: string): MemoryRow | null {
    const row = this.rows.get(nonce);
    if (row === undefined) {
      return null;
    }
    if (this.now() >= row.retainedUntil) {
      this.rows.delete(nonce);
      return null;
    }
    return row;
  }

  async store(record: ChallengeRecord): Promise<void> {
    this.sweep();
    const envelope = { ...challengeRecordToJson(record), state: 'pending', consumed_result: null, operation_identity: null };
    this.rows.set(record.nonce, {
      envelopeJson: JSON.stringify(envelope),
      state: 'pending',
      retainedUntil: record.expiresAt + this.ttlMarginSecs,
    });
  }

  async find(nonce: string): Promise<ChallengeRecord | null> {
    const row = this.live(nonce);
    if (row === null) {
      return null;
    }
    const decoded = decodeEnvelope(row.envelopeJson);
    return decoded === null ? null : decoded.record;
  }

  async runtimeState(nonce: string): Promise<RuntimeStateSnapshot> {
    const row = this.live(nonce);
    if (row === null) {
      return { kind: 'missing', record: null, consumed: null };
    }
    const decoded = decodeEnvelope(row.envelopeJson);
    if (decoded === null) {
      return { kind: 'missing', record: null, consumed: null };
    }
    if (decoded.state === 'cancelled') {
      return { kind: 'cancelled', record: decoded.record, consumed: null };
    }
    if (decoded.state === 'consumed') {
      const consumed: ConsumedRecordSnapshot = {
        record: decoded.record,
        consumedNow: false,
        consumedBefore: true,
        consumedResult: decoded.result,
        operationIdentity: decoded.identity,
      };
      return { kind: 'consumed', record: decoded.record, consumed };
    }
    if (decoded.state === 'pending') {
      return { kind: 'pending', record: decoded.record, consumed: null };
    }
    return { kind: 'missing', record: null, consumed: null };
  }

  async consume(nonce: string, operationIdentity?: string | null): Promise<ConsumedRecordSnapshot | null> {
    const identity = validatedOperationIdentity(operationIdentity);
    const row = this.live(nonce);
    if (row === null) {
      return null;
    }
    const decoded = decodeEnvelope(row.envelopeJson);
    if (decoded === null) {
      return null;
    }
    if (decoded.state === 'consumed') {
      return {
        record: decoded.record,
        consumedNow: false,
        consumedBefore: true,
        consumedResult: decoded.result,
        operationIdentity: decoded.identity,
      };
    }
    if (decoded.state !== 'pending') {
      // A cancelled row is never consumable.
      return null;
    }
    // The pending-envelope guard mirrors the Redis script: a pending
    // envelope carrying a result or identity marker is a forged rewrite.
    const envelope = JSON.parse(row.envelopeJson) as Record<string, unknown>;
    if (envelope.consumed_result !== null || envelope.operation_identity !== null) {
      return null;
    }
    envelope.state = 'consumed';
    envelope.operation_identity = identity;
    row.envelopeJson = JSON.stringify(envelope);
    row.state = 'consumed';
    return {
      record: decoded.record,
      consumedNow: true,
      consumedBefore: false,
      consumedResult: null,
      operationIdentity: identity,
    };
  }

  async commitResult(
    nonce: string,
    valid: boolean,
    binding: string | null,
    mac: string | null,
  ): Promise<boolean> {
    const row = this.live(nonce);
    if (row === null || row.state !== 'consumed') {
      return false;
    }
    const envelope = JSON.parse(row.envelopeJson) as Record<string, unknown>;
    if (envelope.consumed_result !== null) {
      return false;
    }
    const result: Record<string, unknown> = { valid, binding };
    if (mac !== null) {
      result.mac = mac;
    }
    envelope.consumed_result = result;
    row.envelopeJson = JSON.stringify(envelope);
    return true;
  }

  async deleteIfPending(nonce: string): Promise<DeleteIfPendingOutcome> {
    const row = this.live(nonce);
    if (row === null) {
      return { kind: 'missing' };
    }
    const decoded = decodeEnvelope(row.envelopeJson);
    if (decoded === null) {
      return { kind: 'corrupt' };
    }
    if (decoded.state === 'consumed') {
      return {
        kind: 'consumed',
        consumed: {
          record: decoded.record,
          consumedNow: false,
          consumedBefore: true,
          consumedResult: decoded.result,
          operationIdentity: decoded.identity,
        },
      };
    }
    if (decoded.state === 'cancelled') {
      return { kind: 'cancelled' };
    }
    if (decoded.state === 'pending') {
      this.rows.delete(nonce);
      return { kind: 'deleted-pending' };
    }
    return { kind: 'corrupt' };
  }

  private sweep(): void {
    const now = this.now();
    for (const [nonce, row] of this.rows) {
      if (now >= row.retainedUntil) {
        this.rows.delete(nonce);
      }
    }
  }
}
