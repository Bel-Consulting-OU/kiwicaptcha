import type { ChallengeRecord } from './record.js';
import { challengeRecordFromJson } from './record.js';

/**
 * The store adapter contract of the verifier: the atomic one-shot
 * surface verify() needs, implementable over any backend whose
 * transitions are atomic. The three shipped adapters (memory, Redis,
 * SQLite) each hold the exactly-once guarantee: two racing consumers of
 * one nonce cannot both win the pending-to-consumed transition.
 */

/** The committed deterministic result of a consumed record. */
export interface ConsumedResultRecord {
  valid: boolean;
  binding: string | null;
  /** 64-lowercase-hex server-state MAC when committed authenticated. */
  mac: string | null;
}

/** The consume transition result plus the retained record. */
export interface ConsumedRecordSnapshot {
  record: ChallengeRecord;
  consumedNow: boolean;
  consumedBefore: boolean;
  consumedResult: ConsumedResultRecord | null;
  operationIdentity: string | null;
}

export type RuntimeKind = 'missing' | 'pending' | 'consumed' | 'cancelled';

/** The single-snapshot terminal-state classification of one nonce. */
export interface RuntimeStateSnapshot {
  kind: RuntimeKind;
  record: ChallengeRecord | null;
  consumed: ConsumedRecordSnapshot | null;
}

export type DeleteIfPendingOutcome =
  | { kind: 'missing' }
  | { kind: 'deleted-pending' }
  | { kind: 'cancelled' }
  | { kind: 'corrupt' }
  | { kind: 'consumed'; consumed: ConsumedRecordSnapshot };

/**
 * The atomic store adapter. Every transition is one-shot; a failed
 * transition throws StoreUnavailableError (fail closed as retryable)
 * and never silently passes.
 */
export interface StoreAdapter {
  /**
   * Whether this backend commits consumed results carrying the
   * server-state MAC. A stored success without a MAC under a
   * MAC-committing backend is rejected as forged.
   */
  readonly authenticatedResultCommit: boolean;

  /** Store a pending record, replacing any record with the same nonce. */
  store(record: ChallengeRecord): Promise<void>;

  /** Peek a record, or null when the nonce is unknown or expired. */
  find(nonce: string): Promise<ChallengeRecord | null>;

  /** The terminal-state snapshot: one read, never two. */
  runtimeState(nonce: string): Promise<RuntimeStateSnapshot>;

  /**
   * The one-shot consume transition. Null answers missing, cancelled or
   * corrupt; a null identity records none. Throws StoreWriteError when
   * a non-null identity could not be recorded on a fresh flip.
   */
  consume(nonce: string, operationIdentity?: string | null): Promise<ConsumedRecordSnapshot | null>;

  /**
   * Commit the deterministic result of a consumed record, exactly once.
   * False answers missing, not consumed, or already committed.
   */
  commitResult(
    nonce: string,
    valid: boolean,
    binding: string | null,
    mac: string | null,
  ): Promise<boolean>;

  /** The fused cleanup: only the exact pending record is deleted. */
  deleteIfPending(nonce: string): Promise<DeleteIfPendingOutcome>;
}

/** Raised when a store write could not be recorded atomically. */
export class StoreWriteError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StoreWriteError';
  }
}

/** Raised on backend failure: the verifier answers storage_unavailable. */
export class StoreUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = 'StoreUnavailableError';
    if (options?.cause !== undefined) {
      this.cause = options.cause;
    }
  }
}

const OPERATION_IDENTITY_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

/**
 * Validate a logical-operation identity: 1..128 bytes of
 * [A-Za-z0-9_-], or null. The validation runs before any transition so
 * a malformed identity never lands in storage.
 */
export function validatedOperationIdentity(operationIdentity: string | null | undefined): string | null {
  if (operationIdentity === null || operationIdentity === undefined) {
    return null;
  }
  if (!OPERATION_IDENTITY_PATTERN.test(operationIdentity)) {
    throw new RangeError('operation identity must be 1..128 bytes of [A-Za-z0-9_-]');
  }
  return operationIdentity;
}

/** The default retention margin past the signed expiry (the Redis mirror). */
export const DEFAULT_TTL_MARGIN_SECS = 60;

/**
 * Decode the flat storage envelope the core writes: the record's wire
 * fields plus the top-level state, consumed_result and
 * operation_identity runtime fields. The record parse is strict; a
 * corrupt committed result degrades to absent. Null on any structural
 * failure (fail closed, never partially trusted).
 */
export function decodeEnvelope(
  raw: string,
): { state: string; record: ChallengeRecord; result: ConsumedResultRecord | null; identity: string | null } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }
  const envelope = parsed as Record<string, unknown>;
  const state = envelope.state;
  if (typeof state !== 'string') {
    return null;
  }
  const recordFields: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(envelope)) {
    if (key !== 'state' && key !== 'consumed_result' && key !== 'operation_identity') {
      recordFields[key] = value;
    }
  }
  let record: ChallengeRecord;
  try {
    record = challengeRecordFromJson(recordFields);
  } catch {
    return null;
  }
  let result: ConsumedResultRecord | null = null;
  const rawResult = envelope.consumed_result;
  if (rawResult !== null && rawResult !== undefined) {
    if (typeof rawResult !== 'object' || Array.isArray(rawResult)) {
      return { state, record, result: null, identity: envelopeIdentity(envelope) };
    }
    const candidate = rawResult as Record<string, unknown>;
    const unknownKeys = Object.keys(candidate).filter((key) => key !== 'valid' && key !== 'binding' && key !== 'mac');
    if (unknownKeys.length === 0 && typeof candidate.valid === 'boolean') {
      const binding = candidate.binding;
      const mac = candidate.mac;
      result = {
        valid: candidate.valid,
        binding: typeof binding === 'string' ? binding : null,
        mac: typeof mac === 'string' ? mac : null,
      };
    }
  }
  return { state, record, result, identity: envelopeIdentity(envelope) };
}

function envelopeIdentity(envelope: Record<string, unknown>): string | null {
  const identity = envelope.operation_identity;
  return typeof identity === 'string' && identity !== '' ? identity : null;
}
