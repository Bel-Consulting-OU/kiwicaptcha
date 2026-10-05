import { createHmac } from 'node:crypto';

/**
 * The typed outcomes client: the eight application outcomes resolved
 * through the one versioned mapping table, mirroring the PHP
 * OutcomeMap. The table is the polarity authority: only the
 * server-confirmed trust outcomes may subtract risk, and exactly the
 * abuse outcomes write long-memory marks. The client here carries the
 * mapping, the handle acceptance rules, the mark keys and the
 * idempotency keys; a host binds its own sink through the OutcomeSink
 * interface.
 */

export const OUTCOME_MAP_VERSION = 1;

export const OUTCOMES = [
  'confirmedLegitimate',
  'stepUpCompleted',
  'authenticationSuccess',
  'authenticationFailure',
  'spamReported',
  'chargeback',
  'accountBanned',
  'fraudConfirmed',
] as const;

export type Outcome = (typeof OUTCOMES)[number];

export const HANDLE_DIMENSIONS = [
  'nonce',
  'decisionId',
  'principal',
  'target',
  'session',
  'agent',
] as const;

export type OutcomeHandleDimension = (typeof HANDLE_DIMENSIONS)[number];

export interface OutcomeHandle {
  dimension: OutcomeHandleDimension;
  id: string;
}

const PSEUDONYM_PATTERN = /^[0-9a-f]{32}$/;
const UNSAFE_HANDLE_CHARS = /[\u0000-\u001f\u007f:}]/;

/**
 * The handle id grammar of the cores: principal, target and session
 * carry the 32-char lowercase hex pseudonym, never a raw identifier;
 * the ledger ids and agent keys carry a 32-hex id or a non-empty
 * key-safe string. Raw identifiers are refused before any mark key is
 * built from them.
 */
export function validateOutcomeHandle(handle: OutcomeHandle): void {
  const id = handle.id;
  if (handle.dimension === 'principal' || handle.dimension === 'target' || handle.dimension === 'session') {
    if (!PSEUDONYM_PATTERN.test(id)) {
      throw new RangeError(
        `${handle.dimension} handle must carry the 32-char lowercase hex pseudonym, never a raw identifier`,
      );
    }
    return;
  }
  if (PSEUDONYM_PATTERN.test(id)) {
    return;
  }
  if (id === '' || UNSAFE_HANDLE_CHARS.test(id)) {
    throw new RangeError(
      `${handle.dimension} handle id must be a 32-char lowercase hex id or a non-empty key-safe string`,
    );
  }
}

/** The risk-v1 feedback channel each outcome books. */
export const RISK_EVENT_KINDS = {
  ProtectedActionSuccess: 8,
  ProtectedActionFailure: 9,
  AuthenticationSuccess: 10,
  AuthenticationFailure: 11,
  ConfirmedLegitimate: 12,
  ConfirmedAbuse: 13,
} as const;

export interface OutcomeMapping {
  readonly outcome: Outcome;
  /** The numeric risk-v1 event kind the outcome books on the channel. */
  readonly channel: number;
  /** true confirms L, false confirms A, null = no ledger semantics. */
  readonly ledgerLegitimate: boolean | null;
  readonly writesAbuseMark: boolean;
  readonly serverConfirmed: boolean;
  readonly maySubtractRisk: boolean;
  readonly acceptedHandles: readonly OutcomeHandleDimension[];
}

export function accepts(mapping: OutcomeMapping, dimension: OutcomeHandleDimension): boolean {
  return mapping.acceptedHandles.includes(dimension);
}

/** The mark kind an outcome writes on identity handles, null when none. */
export function markKind(mapping: OutcomeMapping): string | null {
  return mapping.writesAbuseMark ? mapping.outcome : null;
}

export function hasLedgerAction(mapping: OutcomeMapping): boolean {
  return mapping.ledgerLegitimate !== null;
}

const LEDGER_DIMENSIONS: readonly OutcomeHandleDimension[] = ['nonce', 'decisionId'];
const IDENTITY_DIMENSIONS: readonly OutcomeHandleDimension[] = [
  'principal',
  'target',
  'session',
  'agent',
];
const EVERY_DIMENSION: readonly OutcomeHandleDimension[] = [...LEDGER_DIMENSIONS, ...IDENTITY_DIMENSIONS];

const TABLE: Readonly<Record<Outcome, OutcomeMapping>> = {
  confirmedLegitimate: {
    outcome: 'confirmedLegitimate',
    channel: RISK_EVENT_KINDS.ConfirmedLegitimate,
    ledgerLegitimate: true,
    writesAbuseMark: false,
    serverConfirmed: true,
    maySubtractRisk: true,
    acceptedHandles: EVERY_DIMENSION,
  },
  stepUpCompleted: {
    outcome: 'stepUpCompleted',
    channel: RISK_EVENT_KINDS.ProtectedActionSuccess,
    ledgerLegitimate: null,
    writesAbuseMark: false,
    serverConfirmed: true,
    maySubtractRisk: true,
    acceptedHandles: IDENTITY_DIMENSIONS,
  },
  authenticationSuccess: {
    outcome: 'authenticationSuccess',
    channel: RISK_EVENT_KINDS.AuthenticationSuccess,
    ledgerLegitimate: null,
    writesAbuseMark: false,
    serverConfirmed: true,
    maySubtractRisk: true,
    acceptedHandles: IDENTITY_DIMENSIONS,
  },
  authenticationFailure: {
    outcome: 'authenticationFailure',
    channel: RISK_EVENT_KINDS.AuthenticationFailure,
    ledgerLegitimate: null,
    writesAbuseMark: false,
    serverConfirmed: false,
    maySubtractRisk: false,
    acceptedHandles: IDENTITY_DIMENSIONS,
  },
  spamReported: {
    outcome: 'spamReported',
    channel: RISK_EVENT_KINDS.ProtectedActionFailure,
    ledgerLegitimate: null,
    writesAbuseMark: true,
    serverConfirmed: true,
    maySubtractRisk: false,
    acceptedHandles: IDENTITY_DIMENSIONS,
  },
  chargeback: {
    outcome: 'chargeback',
    channel: RISK_EVENT_KINDS.ConfirmedAbuse,
    ledgerLegitimate: false,
    writesAbuseMark: true,
    serverConfirmed: true,
    maySubtractRisk: false,
    acceptedHandles: EVERY_DIMENSION,
  },
  accountBanned: {
    outcome: 'accountBanned',
    channel: RISK_EVENT_KINDS.ConfirmedAbuse,
    ledgerLegitimate: false,
    writesAbuseMark: true,
    serverConfirmed: true,
    maySubtractRisk: false,
    acceptedHandles: EVERY_DIMENSION,
  },
  fraudConfirmed: {
    outcome: 'fraudConfirmed',
    channel: RISK_EVENT_KINDS.ConfirmedAbuse,
    ledgerLegitimate: false,
    writesAbuseMark: true,
    serverConfirmed: true,
    maySubtractRisk: false,
    acceptedHandles: EVERY_DIMENSION,
  },
};

/** The mapping row of one outcome. The table is total over the vocabulary. */
export function outcomeMapping(outcome: Outcome): OutcomeMapping {
  return TABLE[outcome];
}

/** Every row, in vocabulary order (the completeness oracle). */
export function allOutcomeMappings(): readonly OutcomeMapping[] {
  return OUTCOMES.map((outcome) => TABLE[outcome]);
}

/** The ledger dimensions in table order (nonce before decision id). */
export function ledgerDimensions(): readonly OutcomeHandleDimension[] {
  return LEDGER_DIMENSIONS;
}

/** The identity dimensions in table order. */
export function identityDimensions(): readonly OutcomeHandleDimension[] {
  return IDENTITY_DIMENSIONS;
}

/**
 * The long-memory mark key of one identity handle: the Redis
 * hash-tagged key the cores write, namespaced per deployment.
 */
export function markKey(namespace: string, dimension: OutcomeHandleDimension, id: string): string {
  return `mark:{kiwi:${namespace}}:${dimension}:${id}`;
}

/**
 * The outcome-report receipt: the resolution a sink booked, carrying
 * the mapping row the report resolved through.
 */
export interface OutcomeReceipt {
  readonly outcome: Outcome;
  readonly mapping: OutcomeMapping;
  /** The confirmation flip of the ledger path (null on identity handles). */
  readonly ledgerStatus: number | null;
  /** Marks written on the identity path. */
  readonly marksWritten: number;
}

/**
 * The sink a host implements to land outcomes in its risk store: the
 * always-on outcome ledger, the reputation feedback channel and the
 * long-memory marks. The SDK maps and validates; the sink persists.
 */
export interface OutcomeSink {
  confirmLedger(id: string, legitimate: boolean): Promise<number>;
  recordFeedback(
    channel: number,
    idempotencyKey: string,
    handle: OutcomeHandle,
  ): Promise<void>;
  writeMark(key: string, kind: string): Promise<number>;
  forgetMark(key: string): Promise<number>;
}

export class KiwiOutcomes {
  private readonly sink: OutcomeSink;
  private readonly namespace: string;

  constructor(sink: OutcomeSink, namespace = 'd') {
    this.sink = sink;
    this.namespace = namespace;
  }

  /**
   * Report one typed outcome for one handle. Throws RangeError when
   * the mapping accepts no such handle dimension for the outcome.
   */
  async report(
    outcome: Outcome,
    handle: OutcomeHandle,
    idempotencyKey?: string | null,
  ): Promise<OutcomeReceipt> {
    const mapping = outcomeMapping(outcome);
    validateOutcomeHandle(handle);
    if (!accepts(mapping, handle.dimension)) {
      throw new RangeError(
        `outcome ${outcome} cannot be reported on a ${handle.dimension} handle ` +
          `(accepted: ${mapping.acceptedHandles.join(', ')})`,
      );
    }
    let ledgerStatus: number | null = null;
    let marksWritten = 0;
    if (LEDGER_DIMENSIONS.includes(handle.dimension)) {
      ledgerStatus = await this.sink.confirmLedger(handle.id, mapping.ledgerLegitimate === true);
      const key = idempotencyKey ?? defaultIdempotencyKey(handle);
      await this.sink.recordFeedback(mapping.channel, key, handle);
      return { outcome, mapping, ledgerStatus, marksWritten };
    }
    const kind = markKind(mapping);
    if (kind !== null) {
      marksWritten = await this.sink.writeMark(markKey(this.namespace, handle.dimension, handle.id), kind);
    }
    const key = idempotencyKey ?? defaultIdempotencyKey(handle);
    await this.sink.recordFeedback(mapping.channel, key, handle);
    return { outcome, mapping, ledgerStatus, marksWritten };
  }

  /** Remove the long-memory marks of the handle's dimension (erasure path). */
  async forget(handle: OutcomeHandle): Promise<number> {
    if (LEDGER_DIMENSIONS.includes(handle.dimension)) {
      return 0;
    }
    return this.sink.forgetMark(markKey(this.namespace, handle.dimension, handle.id));
  }
}

/** The idempotency key of a handle report: bounded HMAC(request id). */
export function defaultIdempotencyKey(handle: OutcomeHandle, secret?: string): string {
  const value = `${handle.dimension}:${handle.id}`;
  const key = secret ?? 'kiwicaptcha/outcomes-idem/v1';
  return createHmac('sha256', key).update(value).digest('hex').slice(0, 32);
}
