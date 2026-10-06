import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { delegationEnabled, delegateToSidecar, type ExecutionPolicy } from './sidecar.js';
import {
  ALL_VERIFY_ERROR_CODES,
  VerifyErrorCode,
  describeVerifyError,
  isReplayExempt,
} from './errors.js';
import { decodeStdBase64 } from './base64.js';
import {
  bindingTag,
  canonicalPayload,
  hashIp,
  signPayloadV1,
  signPayloadV2,
  signedCanonicalCommitsRecordMeta,
  executionCommitment,
} from './canonical.js';
import { decodeToken, type SolutionToken } from './token.js';
import {
  isValidDecoyFieldName,
  protocolExtensionGrammarOk,
  MAX_EXECUTION_VERSION,
  type ChallengeRecord,
} from './record.js';
import { consumedResultMac, recordMetaMac, serverStateKey, timingSafeEqualsHex } from './mac.js';
import { deriveSha256Hash, meetsTarget } from './pow.js';
import { Rsw, rswIdentityMatches, RSW_T_MAX, RSW_T_MIN } from './rsw.js';
import { digestOverTrace, isValidProgram as programValid, verifyExecutedTrace } from './execution.js';
import { scoreTelemetry } from './telemetry.js';
import type { ConsumedRecordSnapshot, StoreAdapter } from './store.js';
import { validatedOperationIdentity } from './store.js';

/** Hard ceiling for a stored record's lifetime (expires_at - issued_at). */
export const MAX_TTL_SECS = 300;

/** Maximum tolerated future skew for a record's issuance timestamp. */
export const MAX_CLOCK_SKEW = 60;

/** Host-clock skew tolerance for the minimum-duration check, microseconds. */
export const SKEW_TOLERANCE_US = 5_000_000;

export const MIN_ARGON_MEMORY_KIB = 8;
export const MAX_ARGON_MEMORY_KIB = 65536;
export const MIN_ARGON_TIME = 3;
export const MAX_ARGON_TIME = 16;
export const MIN_PARALLELISM = 1;
export const MAX_PARALLELISM = 4;

export const MIN_DIFFICULTY = 1;
export const MAX_DIFFICULTY = 20;

export interface RswVerifierConfig {
  /** Canonical standard base64 of the 2048-bit composite modulus. */
  modulusN: string;
  /** Canonical standard base64 of the secret lambda = lcm(p-1, q-1). */
  lambda: string;
  /** Rotation keyring keyed by the authenticated modulus fingerprint. */
  verificationKeys?: Record<string, { modulusN: string; lambda: string }>;
  /** Accept the legacy base64-text identity alias below protocol v5. */
  allowLegacyIdentity?: boolean;
}

export interface VerifyOptions {
  /** The store adapter backing the one-shot consume. */
  storage: StoreAdapter;
  /** The master secret (or the legacy secret when secretsByKid is set). */
  secretKey: string | Buffer;
  /** Required challenge scope: the typed required_scope refusal
    * answers an empty option, never an any-scope acceptance. */
  expectedScope: string;
  /** The client IP for the optional IP binding. */
  clientIp?: string | null;
  /** Server receipt time in epoch microseconds; a test hook. */
  nowNs?: number | null;
  /** The TTL clock in epoch seconds; a test hook. */
  now?: () => number;
  /** Reject bot-signal telemetry (opt-in defense in depth). */
  enforceTelemetry?: boolean;
  /** The logical-operation identity recorded with the consume. */
  operationIdentity?: string | null;
  /** The application transaction binding a bound record must equal. */
  expectedRequestBinding?: string | null;
  /** exact (default) requires option equality; legacy permits unbound. */
  bindingExpectation?: 'exact' | 'legacy';
  /**
   * The execution-armed dimension policy: absent (the default) fails
   * every armed record closed; the sidecar policy delegates that
   * single verification to a co-located kiwicaptcha-verifier sidecar.
   */
  executionPolicy?: ExecutionPolicy | null;
  /** The current security-policy epoch; null disables the check. */
  expectedPolicyVersion?: number | null;
  /** The declared rollout-window floor; null keeps strict equality. */
  policyVersionFloor?: number | null;
  /** Expected deployment region; null disables the check. */
  region?: string | null;
  /** Expected deployment issuer; null disables the check. */
  expectedIssuer?: string | null;
  /** Secret set keyed by signing kid; empty keeps the single-secret path. */
  secretsByKid?: Record<number, string | Buffer>;
  /** Compromised kid ids, refused before any signature work. */
  revokedKids?: readonly number[];
  /** Tenant scope of the derived purpose keys. */
  tenantId?: string | null;
  /** Accept protocol v1 challenges during a migration window only. */
  acceptLegacyV1?: boolean;
  /** The rsw trapdoor configuration; null refuses signed rsw records. */
  rsw?: RswVerifierConfig | null;
}

/**
 * The verification result of the shared server-SDK contract:
 * {ok, disposition, decisionHandle, price} with the additive evidence
 * fields (nonce, binding, decoy, measured duration) the cores expose.
 */
export interface VerifyResult {
  ok: boolean;
  /** allow on a valid proof, deny on every failure. */
  disposition: 'allow' | 'deny';
  /** The verified challenge nonce (the replay id); null on failure. */
  decisionHandle: string | null;
  /** The paid work-ladder rung; null on failure. */
  price: string | null;
  /** The machine-readable failure code; '' when ok. */
  code: VerifyErrorCode | '';
  /** The operator-facing failure description; null when ok. */
  detail: string | null;
  requestBinding: string | null;
  fromStoredResult: boolean;
  solveDurationMs: number | null;
  decoyField: string | null;
}

function invalid(code: VerifyErrorCode): VerifyResult {
  return {
    ok: false,
    disposition: 'deny',
    decisionHandle: null,
    price: null,
    code,
    detail: describeVerifyError(code),
    requestBinding: null,
    fromStoredResult: false,
    solveDurationMs: null,
    decoyField: null,
  };
}

function valid(
  nonce: string,
  price: string,
  requestBinding: string | null,
  fromStoredResult: boolean,
  solveDurationMs: number | null,
  decoyField: string | null,
): VerifyResult {
  return {
    ok: true,
    disposition: 'allow',
    decisionHandle: nonce,
    price,
    code: '',
    detail: null,
    requestBinding,
    fromStoredResult,
    solveDurationMs,
    decoyField,
  };
}

/** The work-ladder rung name of a verified record's signed parameters. */
export function ladderRung(record: ChallengeRecord): string {
  if (record.algorithm === 'rsw') {
    return 'rsw';
  }
  if (record.algorithm === 'argon2id') {
    const mib = record.mKib / 1024;
    return mib === 16 || mib === 32 || mib === 64 ? `argon${mib}` : `argon${record.mKib}kib`;
  }
  return record.targetBits === 16 || record.targetBits === 18 || record.targetBits === 20
    ? `sha${record.targetBits}`
    : `sha${record.targetBits}bit`;
}

interface ResolvedSecrets {
  secretsByKid: Map<number, Buffer>;
  revokedKids: Set<number>;
  newestKid: number | null;
}

interface VerifierConfigInternal {
  storage: StoreAdapter;
  secretKey: Buffer;
  expectedScope: string;
  clientIp: string | null;
  nowNs: number | null;
  now: () => number;
  enforceTelemetry: boolean;
  operationIdentity: string | null;
  expectedRequestBinding: string | null;
  legacyBinding: boolean;
  expectedPolicyVersion: number | null;
  policyVersionFloor: number | null;
  region: string | null;
  expectedIssuer: string | null;
  tenantId: string | null;
  acceptLegacyV1: boolean;
  rsw: RswVerifierConfig | null;
}

/**
 * Verify a client-submitted solution token against the store: the pure
 * local operation of the shared server-SDK contract. The cheap-gate
 * order mirrors the PHP and Rust verifiers exactly: structural
 * validation, protocol gate, kid gate and resolution, HMAC signature,
 * process ceilings, TTL, scope, request binding, IP binding, region,
 * policy epoch (with the rollout floor window), issuer, execution
 * binding, minimum duration, telemetry, then the one-shot consume and
 * the proof re-derivation with the post-derive final revalidation.
 */
export async function verify(rawToken: string, options: VerifyOptions): Promise<VerifyResult> {
  const secrets: ResolvedSecrets = {
    secretsByKid: new Map(
      Object.entries(options.secretsByKid ?? {}).map(([kid, secret]) => [
        Number(kid),
        Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8'),
      ]),
    ),
    revokedKids: new Set(options.revokedKids ?? []),
    newestKid: null,
  };
  const config: VerifierConfigInternal = {
    storage: options.storage,
    secretKey: Buffer.isBuffer(options.secretKey) ? options.secretKey : Buffer.from(options.secretKey, 'utf8'),
    expectedScope: options.expectedScope,
    clientIp: options.clientIp ?? null,
    nowNs: options.nowNs ?? null,
    now: options.now ?? (() => Math.floor(Date.now() / 1000)),
    enforceTelemetry: options.enforceTelemetry ?? false,
    operationIdentity: options.operationIdentity ?? null,
    expectedRequestBinding: options.expectedRequestBinding ?? null,
    legacyBinding: options.bindingExpectation === 'legacy',
    expectedPolicyVersion: options.expectedPolicyVersion ?? null,
    policyVersionFloor: options.policyVersionFloor ?? null,
    region: options.region ?? null,
    expectedIssuer: options.expectedIssuer ?? null,
    tenantId: options.tenantId ?? null,
    acceptLegacyV1: options.acceptLegacyV1 ?? false,
    rsw: options.rsw ?? null,
  };

  let token: SolutionToken;
  try {
    token = decodeToken(rawToken);
  } catch {
    return invalid(VerifyErrorCode.MalformedToken);
  }
  const receiptNs = config.nowNs ?? Date.now() * 1000;
  const evidence = { digest: token.executionDigest, trace: token.executionTrace };

  let runtime: Awaited<ReturnType<StoreAdapter['runtimeState']>>;
  try {
    runtime = await config.storage.runtimeState(token.nonce);
  } catch {
    return invalid(VerifyErrorCode.StorageUnavailable);
  }
  if (runtime.kind === 'missing') {
    return invalid(VerifyErrorCode.RecordNotFound);
  }
  let peek = runtime.record;
  if (peek === null) {
    try {
      peek = await config.storage.find(token.nonce);
    } catch {
      return invalid(VerifyErrorCode.StorageUnavailable);
    }
    if (peek === null) {
      return invalid(VerifyErrorCode.RecordNotFound);
    }
  }

  // The execution delegation plane: an armed record under a sidecar
  // policy delegates the execution dimension after the cheap phase
  // proved everything the SDK checks locally.
  const delegateExecution = delegationEnabled(peek, options.executionPolicy);
  // The cheap-phase security checks, in the canonical order; the first
  // failing check decides the outcome.
  const failure = cheapPhaseCheck(config, secrets, peek, token, evidence, true, receiptNs, delegateExecution);
  if (failure === null && delegateExecution) {
    // Always forward the binding this verification expects: the legacy
    // shim's unbound-record pass asserts unboundness so the sidecar's
    // exact check agrees, everything else forwards the expected value.
    const delegated = await delegateToSidecar(rawToken, config.expectedScope, config.clientIp, options.executionPolicy!, config.legacyBinding && peek.requestBinding === null ? '' : config.expectedRequestBinding);
    if (delegated.ok) {
      return valid(token.nonce, ladderRung(peek), peek.requestBinding, true, null, peek.decoyField);
    }
    // The sidecar's kiwi-code is the shared wire vocabulary: a known
    // code passes through the deny shape verbatim, an unknown one
    // stays the deterministic execution_mismatch deny (never widened).
    const known = (ALL_VERIFY_ERROR_CODES as readonly string[]).includes(delegated.code)
      ? (delegated.code as VerifyErrorCode)
      : VerifyErrorCode.ExecutionMismatch;
    return invalid(known);
  }
  if (failure !== null) {
    if (failure !== VerifyErrorCode.MissingClientIp) {
      let cleanup: Awaited<ReturnType<StoreAdapter['deleteIfPending']>>;
      try {
        cleanup = await config.storage.deleteIfPending(token.nonce);
      } catch {
        return invalid(VerifyErrorCode.StorageUnavailable);
      }
      if (cleanup.kind !== 'consumed') {
        // Missing, deleted-pending, cancelled or corrupt: the one-shot
        // verdict stands.
        return invalid(failure);
      }
      if (!isReplayExempt(failure)) {
        // A hard security verdict on a consumed record: the failure
        // stands and the evidence stays preserved.
        return invalid(failure);
      }
      // Consumed plus an exempt circumstance: the exempt failure may
      // not mask a hard verdict on the same request.
      const hard = replaySecurityCheck(config, secrets, peek, token, evidence, receiptNs);
      if (hard !== null) {
        return invalid(hard);
      }
      return resolveConsumedRecord(
        config,
        secrets,
        cleanup.consumed,
        token.nonce,
        config.operationIdentity,
      );
    }
    // MissingClientIp never deletes: the caller can retry with the IP.
    // A consumed record resolves through the compositional replay gate,
    // exactly like the fused path.
    if (runtime.kind === 'consumed' && runtime.consumed !== null) {
      const hard = replaySecurityCheck(config, secrets, peek, token, evidence, receiptNs);
      if (hard !== null) {
        return invalid(hard);
      }
      return resolveConsumedRecord(
        config,
        secrets,
        runtime.consumed,
        token.nonce,
        config.operationIdentity,
      );
    }
    return invalid(failure);
  }

  // The opt-in telemetry gate: client-controlled evidence about the
  // original solve, replay-exempt, deletion only for a pending record.
  if (
    config.enforceTelemetry &&
    (Object.keys(token.telemetry).length === 0 || scoreTelemetry(token.telemetry, token.durationMs)) &&
    runtime.kind !== 'consumed'
  ) {
    let cleanup: Awaited<ReturnType<StoreAdapter['deleteIfPending']>>;
    try {
      cleanup = await config.storage.deleteIfPending(token.nonce);
    } catch {
      return invalid(VerifyErrorCode.StorageUnavailable);
    }
    if (cleanup.kind !== 'consumed') {
      return invalid(VerifyErrorCode.TelemetryRejected);
    }
    const hard = replaySecurityCheck(config, secrets, peek, token, evidence, receiptNs);
    if (hard !== null) {
      return invalid(hard);
    }
    return resolveConsumedRecord(
      config,
      secrets,
      cleanup.consumed,
      token.nonce,
      config.operationIdentity,
    );
  }

  // Terminal-state resolution before the consume: a cancelled or
  // already-consumed record never burns the proof phase.
  if (runtime.kind === 'cancelled') {
    return invalid(VerifyErrorCode.RecordNotFound);
  }
  if (runtime.kind === 'consumed' && runtime.consumed !== null) {
    return resolveConsumedRecord(
      config,
      secrets,
      runtime.consumed,
      token.nonce,
      config.operationIdentity,
    );
  }

  // The one-shot consume and the proof re-derivation.
  let consumed: ConsumedRecordSnapshot | null;
  try {
    validatedOperationIdentity(config.operationIdentity);
    consumed = await config.storage.consume(token.nonce, config.operationIdentity);
  } catch {
    // A lost transition response is ambiguous: the challenge may or
    // may not have been consumed.
    return invalid(VerifyErrorCode.ConsumeIndeterminate);
  }
  if (consumed === null) {
    return invalid(VerifyErrorCode.RecordNotFound);
  }
  if (consumed.consumedBefore) {
    return resolveConsumedRecord(
      config,
      secrets,
      consumed,
      token.nonce,
      config.operationIdentity,
    );
  }
  const record = consumed.record;

  // The consumed instance must be the challenge that was validated and
  // signed-checked via the peek: a swapped record fails closed.
  const consumedSecret = secretForKey(secrets, record, config.secretKey);
  if (
    record.nonce !== token.nonce ||
    peek.challenge !== record.challenge ||
    secrets.revokedKids.has(record.kid) ||
    consumedSecret === null ||
    !validateRecord(record) ||
    !verifyRecordSignature(config, record, consumedSecret)
  ) {
    return invalid(VerifyErrorCode.MalformedRecord);
  }
  if (!argon2CeilingsOk(record)) {
    return invalid(VerifyErrorCode.UnsupportedArgon2Params);
  }
  if (!rswParamsOk(record)) {
    return invalid(VerifyErrorCode.UnsupportedRswParams);
  }
  if (!policyVersionAccepted(config, record.policyVersion)) {
    return invalid(VerifyErrorCode.WrongPolicyVersion);
  }
  if (config.expectedIssuer !== null && record.issuer !== config.expectedIssuer) {
    return invalid(VerifyErrorCode.WrongIssuer);
  }

  const validProof = recomputeValidProof(config, record, token);
  if (validProof === null) {
    // Authentic but unrepresentable by this verifier: the per-algorithm
    // mapping of the cores.
    const mapped =
      record.algorithm === 'rsw'
        ? VerifyErrorCode.UnsupportedRswParams
        : record.algorithm === 'argon2id'
          ? VerifyErrorCode.UnsupportedArgon2Params
          : VerifyErrorCode.MalformedRecord;
    return invalid(mapped);
  }

  // Post-derive final revalidation against the current clock and the
  // current expectations, for both valid and invalid derivations.
  const now = config.now();
  if (now >= record.expiresAt) {
    return invalid(VerifyErrorCode.Expired);
  }
  if (!policyVersionAccepted(config, record.policyVersion)) {
    return invalid(VerifyErrorCode.WrongPolicyVersion);
  }
  if (config.region !== null && record.region !== config.region) {
    return invalid(VerifyErrorCode.WrongRegion);
  }
  if (config.expectedIssuer !== null && record.issuer !== config.expectedIssuer) {
    return invalid(VerifyErrorCode.WrongIssuer);
  }

  if (!validProof) {
    await bestEffortCommit(config, secrets, consumed, false);
    return invalid(VerifyErrorCode.InsufficientWork);
  }
  await bestEffortCommit(config, secrets, consumed, true);
  return valid(
    record.nonce,
    ladderRung(record),
    record.requestBinding,
    false,
    measurableSolveDurationMs(record, receiptNs),
    record.decoyField,
  );
}

type CheapCheck = VerifyErrorCode | null;

function cheapPhaseCheck(
  config: VerifierConfigInternal,
  secrets: ResolvedSecrets,
  record: ChallengeRecord,
  token: SolutionToken,
  evidence: { digest: string | null; trace: string | null },
  checkTiming: boolean,
  nowNs: number | null,
  delegateExecution = false,
): CheapCheck {
  // 0. The record must carry the nonce it was loaded under.
  if (record.nonce !== token.nonce) {
    return VerifyErrorCode.MalformedRecord;
  }
  // 1-2b. Structure, protocol gate, kid gate, signature, ceilings.
  const shape = checkAuthenticatedShape(config, secrets, record, config.secretKey);
  if (shape !== null) {
    return shape;
  }
  const signingSecret = secretForKey(secrets, record, config.secretKey) as Buffer;
  // 3. TTL.
  if (checkTiming) {
    const ttl = checkTtl(config, record);
    if (ttl !== null) {
      return ttl;
    }
  }
  // 4-4b. Scope and the expected request binding.
  const scopeOrBinding = checkScopeAndBinding(config, record);
  if (scopeOrBinding !== null) {
    return scopeOrBinding;
  }
  // 5. IP binding.
  const ipBinding = checkIpBinding(config, record, signingSecret);
  if (ipBinding !== null) {
    return ipBinding;
  }
  // 5b-5d. Region, policy epoch, issuer.
  const deployment = checkDeploymentExpectations(config, record);
  if (deployment !== null) {
    return deployment;
  }
  // 5e. The execution binding. The delegation path leaves this gate
  // to the sidecar's full-core pass; every other gate stays local.
  if (!delegateExecution) {
    const execution = checkExecutionBinding(record, evidence);
    if (execution !== null) {
      return execution;
    }
  }
  // 6. Server-measured minimum duration.
  if (checkTiming) {
    const duration = checkMinDuration(record, nowNs);
    if (duration !== null) {
      return duration;
    }
  }
  return null;
}

function replaySecurityCheck(
  config: VerifierConfigInternal,
  secrets: ResolvedSecrets,
  record: ChallengeRecord,
  token: SolutionToken,
  evidence: { digest: string | null; trace: string | null },
  receiptNs: number | null,
): CheapCheck {
  const shape = checkAuthenticatedShape(config, secrets, record, config.secretKey);
  if (shape !== null) {
    return shape;
  }
  const scopeOrBinding = checkScopeAndBinding(config, record);
  if (scopeOrBinding !== null) {
    return scopeOrBinding;
  }
  const deployment = checkDeploymentExpectations(config, record);
  if (deployment !== null) {
    return deployment;
  }
  const execution = checkExecutionBinding(record, evidence);
  if (execution !== null) {
    return execution;
  }
  return checkMinDuration(record, receiptNs);
}

function checkAuthenticatedShape(
  config: VerifierConfigInternal,
  secrets: ResolvedSecrets,
  record: ChallengeRecord,
  legacySecret: Buffer,
): CheapCheck {
  if (!validateRecord(record)) {
    return VerifyErrorCode.MalformedRecord;
  }
  if (record.protocolVersion === 1 && !config.acceptLegacyV1) {
    return VerifyErrorCode.MalformedRecord;
  }
  if (secrets.revokedKids.has(record.kid)) {
    return VerifyErrorCode.UnknownKid;
  }
  const signingSecret = secretForKey(secrets, record, legacySecret);
  if (signingSecret === null) {
    return VerifyErrorCode.UnknownKid;
  }
  if (!verifyRecordSignature(config, record, signingSecret)) {
    return VerifyErrorCode.BadSignature;
  }
  if (!argon2CeilingsOk(record)) {
    return VerifyErrorCode.UnsupportedArgon2Params;
  }
  if (!rswParamsOk(record)) {
    return VerifyErrorCode.UnsupportedRswParams;
  }
  return null;
}

function checkTtl(config: VerifierConfigInternal, record: ChallengeRecord): CheapCheck {
  const now = config.now();
  if (now >= record.expiresAt) {
    return VerifyErrorCode.Expired;
  }
  if (record.issuedAt > now + MAX_CLOCK_SKEW) {
    return VerifyErrorCode.Expired;
  }
  return null;
}

function checkScopeAndBinding(config: VerifierConfigInternal, record: ChallengeRecord): CheapCheck {
  // The scope option is required: an empty option refuses with the
  // typed code instead of accepting any scope.
  if (!config.expectedScope) {
    return VerifyErrorCode.RequiredScope;
  }
  if (record.scope !== config.expectedScope) {
    return VerifyErrorCode.WrongScope;
  }
  // Exact option-equality by default: a bound record must present its
  // binding, an unbound record under a presented expectation is
  // refused; the legacy mode permits an unbound record regardless of
  // the expectation.
  if (record.requestBinding === null || config.expectedRequestBinding === null) {
    if (record.requestBinding === null && config.legacyBinding) {
      return null;
    }
    return record.requestBinding === config.expectedRequestBinding
      ? null
      : VerifyErrorCode.RequestBindingMismatch;
  }
  return timingSafeEqualsHex(record.requestBinding, config.expectedRequestBinding)
    ? null
    : VerifyErrorCode.RequestBindingMismatch;
}

function checkIpBinding(
  config: VerifierConfigInternal,
  record: ChallengeRecord,
  signingSecret: Buffer,
): CheapCheck {
  if (record.bindingTag === '') {
    return null;
  }
  if (config.clientIp === null) {
    return VerifyErrorCode.MissingClientIp;
  }
  let expectedTag: string;
  try {
    expectedTag =
      record.protocolVersion === 1
        ? hashIp(config.clientIp, signingSecret.toString('latin1'))
        : bindingTag(record.nonce, config.clientIp, signingSecret, config.tenantId);
  } catch {
    return VerifyErrorCode.IpMismatch;
  }
  return timingSafeEqualsHex(expectedTag, record.bindingTag) ? null : VerifyErrorCode.IpMismatch;
}

/** Whether the record's policy epoch satisfies the configured window. */
export function policyVersionAccepted(config: VerifierConfigInternal, recordVersion: number): boolean {
  if (config.expectedPolicyVersion === null) {
    return true;
  }
  if (config.policyVersionFloor === null) {
    return recordVersion === config.expectedPolicyVersion;
  }
  return config.policyVersionFloor <= recordVersion && recordVersion <= config.expectedPolicyVersion;
}

function checkDeploymentExpectations(config: VerifierConfigInternal, record: ChallengeRecord): CheapCheck {
  if (config.region !== null && record.region !== config.region) {
    return VerifyErrorCode.WrongRegion;
  }
  if (!policyVersionAccepted(config, record.policyVersion ?? 1)) {
    return VerifyErrorCode.WrongPolicyVersion;
  }
  if (config.expectedIssuer !== null && record.issuer !== config.expectedIssuer) {
    return VerifyErrorCode.WrongIssuer;
  }
  return null;
}

function checkExecutionBinding(
  record: ChallengeRecord,
  evidence: { digest: string | null; trace: string | null },
): CheapCheck {
  if (record.executionProgram === null) {
    // Stray execution evidence on an unarmed record is never ignored.
    return evidence.digest === null && evidence.trace === null ? null : VerifyErrorCode.ExecutionMismatch;
  }
  if (evidence.digest === null || evidence.trace === null) {
    return VerifyErrorCode.ExecutionMismatch;
  }
  // The trace travels on the wire as unpadded base64url; translate it
  // back to the canonical bytes before the strict walk.
  const traceBytes = decodeBase64UrlWire(evidence.trace);
  if (traceBytes === null) {
    return VerifyErrorCode.ExecutionMismatch;
  }
  const verifiedTrace = verifyExecutedTrace(record.executionProgram, record.nonce, traceBytes);
  if (verifiedTrace === null) {
    return VerifyErrorCode.ExecutionMismatch;
  }
  const expected = digestOverTrace(record.executionProgram, record.nonce, verifiedTrace);
  if (expected === null) {
    return VerifyErrorCode.MalformedRecord;
  }
  return timingSafeEqualsHex(expected, evidence.digest) ? null : VerifyErrorCode.ExecutionMismatch;
}

function decodeBase64UrlWire(value: string): string | null {
  if (value === '' || value.length > 10_924 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return null;
  }
  const standard = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  const bytes = Buffer.from(padded, 'base64');
  if (bytes.toString('base64url') !== value) {
    return null;
  }
  return bytes.toString('latin1');
}

function checkMinDuration(record: ChallengeRecord, nowNs: number | null): CheapCheck {
  if (record.issuedAtNs <= 0) {
    return VerifyErrorCode.MalformedRecord;
  }
  const floor = Math.max(0, record.minDurationMs);
  if (floor > 0 && record.serverMac === null) {
    // An unauthenticated issuance clock cannot drive the floor.
    return VerifyErrorCode.MalformedRecord;
  }
  if (floor > 0) {
    const receipt = nowNs ?? Date.now() * 1000;
    if (receipt >= record.issuedAtNs) {
      if (receipt - record.issuedAtNs < floor * 1000) {
        return VerifyErrorCode.TooFast;
      }
    } else if (record.issuedAtNs - receipt > SKEW_TOLERANCE_US) {
      return VerifyErrorCode.TooFast;
    }
  }
  return null;
}

/** Structural validation of the stored record, in the canonical order. */
export function validateRecord(record: ChallengeRecord): boolean {
  if (record.protocolVersion < 1 || record.protocolVersion > 5) {
    return false;
  }
  if (!protocolExtensionGrammarOk(record.protocolVersion, record.decoyField !== null, record.executionProgram !== null, record.rswModulusSha256 !== null)) {
    return false;
  }
  const scopeLen = Buffer.byteLength(record.scope, 'latin1');
  if (scopeLen < 1 || scopeLen > 128 || !/^[A-Za-z0-9._:-]+$/.test(record.scope)) {
    return false;
  }
  if (record.decoyField !== null && !isValidDecoyFieldName(record.decoyField)) {
    return false;
  }
  if (record.executionProgram !== null) {
    if (
      record.executionVersion === null ||
      record.executionVersion < 1 ||
      record.executionVersion > MAX_EXECUTION_VERSION ||
      record.executionCommitment === null
    ) {
      return false;
    }
    if (!/^[0-9a-f]{64}$/.test(record.executionCommitment)) {
      return false;
    }
    const expected = executionCommitment(record.executionProgram);
    if (!timingSafeEqualsHex(expected, record.executionCommitment)) {
      return false;
    }
  } else if (record.executionVersion !== null || record.executionCommitment !== null) {
    return false;
  }
  if (record.rswModulusSha256 !== null) {
    if (record.algorithm !== 'rsw' || !/^[0-9a-f]{64}$/.test(record.rswModulusSha256)) {
      return false;
    }
  }
  const nonceBytes = decodeStdBase64(record.nonce);
  if (nonceBytes === null || nonceBytes.length !== 32) {
    return false;
  }
  const saltBytes = decodeStdBase64(record.salt);
  if (saltBytes === null || saltBytes.length !== 16) {
    return false;
  }
  if (record.expiresAt <= record.issuedAt || record.expiresAt - record.issuedAt > MAX_TTL_SECS) {
    return false;
  }
  if (!timingSafeEqualsHexBytes(record.challenge + '|' + record.salt + '|', record.prefix)) {
    return false;
  }
  if (record.targetBits < MIN_DIFFICULTY || record.targetBits > MAX_DIFFICULTY) {
    return false;
  }
  if (record.executionProgram !== null && !programValid(record.executionProgram)) {
    return false;
  }
  return true;
}

function timingSafeEqualsHexBytes(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'latin1');
  const bb = Buffer.from(b, 'latin1');
  if (ba.length !== bb.length) {
    return false;
  }
  return timingSafeEqual(ba, bb);
}

function argon2CeilingsOk(record: ChallengeRecord): boolean {
  if (record.algorithm !== 'argon2id') {
    return true;
  }
  return (
    record.mKib >= MIN_ARGON_MEMORY_KIB &&
    record.mKib <= MAX_ARGON_MEMORY_KIB &&
    record.t >= MIN_ARGON_TIME &&
    record.t <= MAX_ARGON_TIME &&
    record.p >= MIN_PARALLELISM &&
    record.p <= MAX_PARALLELISM
  );
}

function rswParamsOk(record: ChallengeRecord): boolean {
  if (record.algorithm !== 'rsw') {
    return true;
  }
  return record.t >= RSW_T_MIN && record.t <= RSW_T_MAX;
}

/**
 * Recompute the expected HMAC signature for a record per its protocol
 * version and compare constant-time against the challenge's embedded
 * tag. The v2+ canonical covers every immutable parameter and the
 * tagged armed-extension segments; the signed m=1 marker requires a
 * valid record-metadata MAC.
 */
export function verifyRecordSignature(
  config: VerifierConfigInternal,
  record: ChallengeRecord,
  secretKey: Buffer,
): boolean {
  const commitsMac = signedCanonicalCommitsRecordMeta(record.challenge);
  const expected =
    record.protocolVersion === 1
      ? signPayloadV1(
          `${record.nonce}|${record.scope}|${record.bindingTag}|${record.issuedAt}`,
          secretKey,
        )
      : signPayloadV2(
          canonicalPayload({
            protocolVersion: record.protocolVersion,
            nonce: record.nonce,
            scope: record.scope,
            bindingTag: record.bindingTag,
            issuedAt: record.issuedAt,
            expiresAt: record.expiresAt,
            algorithm: record.algorithm,
            mKib: record.mKib,
            t: record.t,
            p: record.p,
            targetBits: record.targetBits,
            salt: record.salt,
            minDurationMs: record.minDurationMs,
            region: record.region,
            policyVersion: record.policyVersion ?? 1,
            requestBinding: record.requestBinding,
            issuer: record.issuer,
            kid: record.kid ?? 1,
            decoyField: record.decoyField,
            executionVersion: record.executionVersion,
            executionCommitment: record.executionCommitment,
            rswModulusSha256: record.rswModulusSha256,
            serverMacCommitted: commitsMac,
          }),
          secretKey,
          config.tenantId,
        );
  if (!timingSafeEqualsHex(expected, signatureFromChallenge(record.challenge))) {
    return false;
  }
  const key = serverStateKey(secretKey, config.tenantId);
  if (commitsMac) {
    return (
      record.serverMac !== null &&
      timingSafeEqualsHex(
        recordMetaMac(key, record.challenge, record.issuedAtNs, record.hostname),
        record.serverMac,
      )
    );
  }
  return (
    record.serverMac === null ||
    timingSafeEqualsHex(
      recordMetaMac(key, record.challenge, record.issuedAtNs, record.hostname),
      record.serverMac,
    )
  );
}

function signatureFromChallenge(challenge: string): string {
  const pos = challenge.lastIndexOf('.');
  return pos === -1 ? '' : challenge.slice(pos + 1);
}

/** Select the signature secret for a record (kid set or legacy secret). */
export function secretForKey(
  secrets: ResolvedSecrets,
  record: ChallengeRecord,
  legacySecret: Buffer,
): Buffer | null {
  if (secrets.secretsByKid.size === 0) {
    return legacySecret;
  }
  if (secrets.newestKid === null) {
    secrets.newestKid = Math.max(...secrets.secretsByKid.keys());
  }
  if (record.kid > secrets.newestKid) {
    return null;
  }
  return secrets.secretsByKid.get(record.kid) ?? null;
}

/**
 * The deterministic proof verdict of a presented token against a
 * record. SHA-256 re-derives the hash and compares leading zero bits;
 * rsw compares the trapdoor expectation; an argon2id record is
 * authentic but unrepresentable by this runtime (node:crypto carries
 * no Argon2id) and fails closed with the cores' unsupported mapping.
 */
export function recomputeValidProof(
  config: VerifierConfigInternal,
  record: ChallengeRecord,
  token: SolutionToken,
): boolean | null {
  if (record.algorithm === 'rsw') {
    const trapdoor = resolveTrapdoor(config, record);
    if (trapdoor === null) {
      return null;
    }
    if (token.counter !== 0 || token.rswProof === null) {
      return false;
    }
    const expected = trapdoor.expectedProofHex(record.prefix, record.nonce, record.t);
    return timingSafeEqualsHex(expected, token.rswProof);
  }
  if (token.rswProof !== null) {
    // An rsw final value is rsw evidence only; the hash is never
    // derived for a record it does not belong to.
    return false;
  }
  if (record.algorithm === 'argon2id') {
    return null;
  }
  const saltBytes = decodeStdBase64(record.salt);
  if (saltBytes === null) {
    return null;
  }
  const hash = deriveSha256Hash(record.prefix, token.counter, saltBytes);
  return meetsTarget(hash, record.targetBits);
}

function resolveTrapdoor(config: VerifierConfigInternal, record: ChallengeRecord): Rsw | null {
  const active = resolveRswPair(config.rsw);
  const keyring = new Map<string, Rsw>();
  const modulusByHash = new Map<string, string>();
  const allowLegacy = config.rsw?.allowLegacyIdentity === true;
  if (config.rsw !== null) {
    for (const [hash, pair] of Object.entries(config.rsw.verificationKeys ?? {})) {
      if (!/^[0-9a-f]{64}$/.test(hash)) {
        continue;
      }
      let trapdoor: Rsw;
      try {
        trapdoor = new Rsw(pair.modulusN, pair.lambda);
      } catch {
        continue;
      }
      if (rswIdentityMatches(hash, pair.modulusN, allowLegacy)) {
        keyring.set(hash, trapdoor);
        modulusByHash.set(hash, pair.modulusN);
      }
    }
    if (active !== null && config.rsw.modulusN !== '') {
      const fingerprint = fingerprintOf(config.rsw.modulusN, allowLegacy);
      for (const identity of fingerprint) {
        keyring.set(identity, active);
        modulusByHash.set(identity, config.rsw.modulusN);
      }
    }
  }
  if (record.rswModulusSha256 !== null) {
    const identity = record.rswModulusSha256;
    const keyringModulus = modulusByHash.get(identity);
    if (keyringModulus !== undefined && rswIdentityMatches(identity, keyringModulus, allowLegacy)) {
      return keyring.get(identity) ?? null;
    }
    if (
      active !== null &&
      rswIdentityMatches(identity, config.rsw?.modulusN ?? '', allowLegacy)
    ) {
      return active;
    }
    return null;
  }
  return active;
}

function fingerprintOf(modulusN: string, allowLegacy: boolean): string[] {
  const forms = [createHash('sha256').update(Buffer.from(modulusN, 'base64')).digest('hex')];
  if (allowLegacy) {
    forms.push(createHash('sha256').update(modulusN, 'latin1').digest('hex'));
  }
  return forms;
}

function resolveRswPair(config: RswVerifierConfig | null): Rsw | null {
  if (config === null || config.modulusN === '' || config.lambda === '') {
    return null;
  }
  try {
    return new Rsw(config.modulusN, config.lambda);
  } catch {
    return null;
  }
}

/** The server-measured solve duration of a fresh valid outcome. */
export function measurableSolveDurationMs(record: ChallengeRecord, receiptNs: number | null): number | null {
  if (record.serverMac === null || record.issuedAtNs <= 0 || receiptNs === null || receiptNs < record.issuedAtNs) {
    return null;
  }
  return Math.floor((receiptNs - record.issuedAtNs) / 1000);
}

async function bestEffortCommit(
  config: VerifierConfigInternal,
  secrets: ResolvedSecrets,
  consumed: ConsumedRecordSnapshot,
  outcomeValid: boolean,
): Promise<void> {
  try {
    const secret = secretForKey(secrets, consumed.record, config.secretKey);
    if (secret === null) {
      return;
    }
    const mac = consumedResultMac(
      serverStateKey(secret, config.tenantId),
      consumed.record.challenge,
      outcomeValid,
      consumed.record.requestBinding,
      consumed.operationIdentity,
    );
    await config.storage
      .commitResult(consumed.record.nonce, outcomeValid, consumed.record.requestBinding, mac)
      .catch(() => false);
  } catch {
    // Best-effort: a storage failure must not change the outcome.
  }
}

/**
 * Resolve an already-consumed record's retained state. A stored invalid
 * outcome replays to any caller; a stored success replays only under
 * the exact logical operation identity with an authentic MAC; a
 * resultless consumed record is ConsumeIndeterminate.
 */
export function resolveConsumedRecord(
  config: VerifierConfigInternal,
  secrets: ResolvedSecrets,
  consumed: ConsumedRecordSnapshot,
  tokenNonce: string,
  operationIdentity: string | null,
): VerifyResult {
  if (consumed.record.nonce !== tokenNonce) {
    return invalid(VerifyErrorCode.MalformedRecord);
  }
  if (consumed.consumedResult === null) {
    return invalid(VerifyErrorCode.ConsumeIndeterminate);
  }
  if (!consumed.consumedResult.valid) {
    return invalid(VerifyErrorCode.InsufficientWork);
  }
  if (
    operationIdentity !== null &&
    consumed.operationIdentity !== null &&
    timingSafeEqualsHex(consumed.operationIdentity, operationIdentity)
  ) {
    if (!storedSuccessAuthentic(config, secrets, consumed)) {
      return invalid(VerifyErrorCode.MalformedRecord);
    }
    return valid(
      consumed.record.nonce,
      ladderRung(consumed.record),
      consumed.consumedResult.binding,
      true,
      null,
      consumed.record.decoyField,
    );
  }
  return invalid(VerifyErrorCode.AlreadyConsumed);
}

function storedSuccessAuthentic(
  config: VerifierConfigInternal,
  secrets: ResolvedSecrets,
  consumed: ConsumedRecordSnapshot,
): boolean {
  const result = consumed.consumedResult;
  if (result === null || !result.valid) {
    return false;
  }
  if (result.mac === null) {
    return !config.storage.authenticatedResultCommit;
  }
  const secret = secretForKey(secrets, consumed.record, config.secretKey);
  if (secret === null) {
    return false;
  }
  const expected = consumedResultMac(
    serverStateKey(secret, config.tenantId),
    consumed.record.challenge,
    result.valid,
    result.binding,
    consumed.operationIdentity,
  );
  return timingSafeEqualsHex(expected, result.mac);
}
