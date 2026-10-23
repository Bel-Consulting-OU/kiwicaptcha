/**
 * Proposed integration outline. Not an existing exported KiwiCaptcha API.
 * (KiwiCaptcha_Visual_Identity.pdf, Typed adapter outline — edition 6.)
 *
 * The ten source DOM states remain the lifecycle authority; running and
 * mismatch are presentation aliases only and map in at this boundary.
 * Factor delivery and code phases are an orthogonal view model. The host
 * form survives recovery; every active operation carries an AbortController
 * and a generation ID so late responses fail the generation test before
 * writing token, form or success UI.
 *
 * Production must still add request/resend deduplication, server Retry-After
 * gating, authoritative clock handling, expiry events, host binding clearing,
 * delivery status and tests. This outline is intentionally not a backend.
 */

export type DriverState =
  | 'pending'
  | 'idle'
  | 'connecting'
  | 'solving'
  | 'done'
  | 'failed'
  | 'expired'
  | 'worker-unavailable'
  | 'execution-unavailable'
  | 'solver-mismatch';

export type FactorView =
  | 'requested'
  | 'address'
  | 'sending'
  | 'code'
  | 'verifying'
  | 'delivery-error'
  | 'code-error'
  | 'expired'
  | 'rate-limited'
  | 'service-unavailable'
  | 'response';

export type BoundResult = {
  kind: 'pow' | 'ownership-grant';
  value: string;
  demandId: string;
  operationId?: string;
  expiresAt: number;
};

export type Demand = {
  id: string;
  kind: 'email-ownership' | 'transaction-factor';
  operationId?: string;
  expiresAt: number;
  safeOperationSummary?: string;
};

/** Typed safe reasons only — never raw server exception text. */
export type FactorErrorReason =
  | 'delivery-failed'
  | 'code-invalid'
  | 'code-expired'
  | 'rate-limited'
  | 'service-unavailable';

export class FactorError extends Error {
  constructor(
    readonly reason: FactorErrorReason,
    message?: string,
    readonly retryAfterMs?: number,
  ) {
    super(message ?? reason);
    this.name = 'FactorError';
  }
}

export interface FactorPort {
  requestCode(
    demand: Demand,
    address: string,
    signal: AbortSignal,
  ): Promise<{
    attemptId: string;
    expiresAt: number;
    resendAt: number;
    safeAddress: string;
  }>;
  verifyCode(
    demand: Demand,
    attemptId: string,
    code: string,
    signal: AbortSignal,
  ): Promise<BoundResult>;
  cancelDemand(demand: Demand): Promise<void>;
}

const VIEW_BY_REASON: Record<FactorErrorReason, FactorView> = {
  'delivery-failed': 'delivery-error',
  'code-invalid': 'code-error',
  'code-expired': 'expired',
  'rate-limited': 'rate-limited',
  'service-unavailable': 'service-unavailable',
};

export class FactorCoordinator {
  private generation = 0;
  private abort?: AbortController;
  private result?: BoundResult;

  constructor(
    private port: FactorPort,
    private emit: (view: FactorView) => void,
  ) {}

  private begin() {
    this.abort?.abort();
    this.abort = new AbortController();
    this.result = undefined;
    return { generation: ++this.generation, signal: this.abort.signal };
  }

  async requestCode(demand: Demand, address: string) {
    const request = this.begin();
    this.emit('sending');
    try {
      const accepted = await this.port.requestCode(demand, address, request.signal);
      if (request.signal.aborted || request.generation !== this.generation) return;
      if (Date.now() >= Math.min(accepted.expiresAt, demand.expiresAt)) {
        this.emit('expired');
        return;
      }
      this.emit('code');
    } catch (error) {
      if (request.signal.aborted || request.generation !== this.generation) return;
      this.emit(VIEW_BY_REASON[toSafeReason(error)]);
    }
  }

  async verify(demand: Demand, attemptId: string, code: string) {
    if (!/^\d{6}$/.test(code)) {
      this.emit('code-error');
      return;
    }
    const request = this.begin();
    this.emit('verifying');
    try {
      const result = await this.port.verifyCode(demand, attemptId, code, request.signal);
      if (request.signal.aborted || request.generation !== this.generation) return;
      if (result.demandId !== demand.id || result.operationId !== demand.operationId) {
        throw new Error('Binding mismatch');
      }
      if (Date.now() >= Math.min(result.expiresAt, demand.expiresAt)) {
        this.result = undefined;
        this.emit('expired');
        return;
      }
      this.result = result;
      this.emit('response');
      // Deliver to the host's authoritative verifier. Never authorize here.
    } catch (error) {
      if (request.signal.aborted || request.generation !== this.generation) return;
      this.result = undefined;
      this.emit(VIEW_BY_REASON[toSafeReason(error)]);
    }
  }

  async cancel(demand: Demand) {
    this.dispose();
    await this.port.cancelDemand(demand);
  }

  dispose() {
    ++this.generation;
    this.abort?.abort();
    this.result = undefined;
  }

  /** The bound result for hand-off to the host verifier, if any. */
  bound(): BoundResult | undefined {
    return this.result;
  }
}

function toSafeReason(error: unknown): FactorErrorReason {
  return error instanceof FactorError ? error.reason : 'service-unavailable';
}
