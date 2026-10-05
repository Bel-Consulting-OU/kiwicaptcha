/**
 * Verify error codes: the machine-readable snake_case vocabulary shared
 * with the PHP and Rust cores. Values are stable wire tokens; logs,
 * metrics and cross-service consumers switch on them without parsing
 * prose.
 */

export const VerifyErrorCode = {
  BadSignature: 'bad_signature',
  Expired: 'expired',
  WrongScope: 'wrong_scope',
  IpMismatch: 'ip_mismatch',
  MissingClientIp: 'missing_client_ip',
  WrongRegion: 'wrong_region',
  WrongIssuer: 'wrong_issuer',
  WrongPolicyVersion: 'wrong_policy_version',
  UnknownKid: 'unknown_kid',
  TooFast: 'too_fast',
  InsufficientWork: 'insufficient_work',
  MalformedRecord: 'malformed_record',
  RecordNotFound: 'record_not_found',
  MalformedToken: 'malformed_token',
  UnsupportedArgon2Params: 'unsupported_argon2_params',
  TooManyAttempts: 'too_many_attempts',
  TelemetryRejected: 'telemetry_rejected',
  CapacityExceeded: 'capacity_exceeded',
  AdmissionUnavailable: 'admission_unavailable',
  StorageUnavailable: 'storage_unavailable',
  ConsumeIndeterminate: 'consume_indeterminate',
  AlreadyConsumed: 'already_consumed',
  RequestBindingMismatch: 'request_binding_mismatch',
  ExecutionMismatch: 'execution_mismatch',
  UnsupportedRswParams: 'unsupported_rsw_params',
} as const;

export type VerifyErrorCode = (typeof VerifyErrorCode)[keyof typeof VerifyErrorCode];

export const ALL_VERIFY_ERROR_CODES: readonly VerifyErrorCode[] = Object.values(
  VerifyErrorCode,
);

/**
 * Whether a failure is exempt from the one-shot policy on a consumed
 * record. The failure describes the original redemption's circumstances
 * (the signed expiry, the network binding, the missing client IP, the
 * client-side telemetry evidence) rather than this request's
 * authorization. Every other verdict is a security verdict: it stands
 * even when the operation identity matches a consumed record's stored
 * success.
 */
export function isReplayExempt(code: VerifyErrorCode): boolean {
  return (
    code === VerifyErrorCode.Expired ||
    code === VerifyErrorCode.IpMismatch ||
    code === VerifyErrorCode.MissingClientIp ||
    code === VerifyErrorCode.TelemetryRejected
  );
}

const DESCRIPTIONS: Readonly<Record<VerifyErrorCode, string>> = {
  bad_signature: 'challenge signature is invalid',
  expired: 'challenge has expired',
  wrong_scope: 'challenge was issued for a different scope',
  ip_mismatch: 'challenge was issued to a different client IP',
  missing_client_ip: 'challenge is IP-bound but no client IP was supplied',
  wrong_region: 'challenge was issued for a different region',
  wrong_issuer: 'challenge was issued by a different deployment',
  wrong_policy_version: 'challenge was issued under a different security-policy epoch',
  unknown_kid: 'unknown signing key id',
  too_fast: 'solution arrived faster than the theoretical minimum (server-measured)',
  insufficient_work: 'solution does not meet the difficulty target',
  malformed_record: 'stored challenge record is malformed',
  record_not_found: 'challenge record not found (unknown or already deleted)',
  malformed_token: 'solution token is malformed',
  unsupported_argon2_params: 'Argon2id parameters exceed the supported process ceilings',
  too_many_attempts: 'too many verification attempts',
  telemetry_rejected: 'bot-signal telemetry rejected the solution',
  capacity_exceeded: 'verification capacity exceeded, try again shortly',
  admission_unavailable: 'verification admission backend unavailable, try again shortly',
  storage_unavailable: 'verification storage backend unavailable, try again shortly',
  consume_indeterminate:
    'verification storage response indeterminate, the challenge may or may not have been consumed',
  already_consumed: 'the challenge was already consumed by a different logical operation',
  request_binding_mismatch:
    'the challenge is not bound to the expected application transaction',
  execution_mismatch:
    'the execution digest does not match the expected program trace of the challenge',
  unsupported_rsw_params:
    'the rsw challenge cannot be verified: this verifier lacks the matching trapdoor, or the signed sequential cost is out of bounds',
};

/** Operator-facing description of one failure code. */
export function describeVerifyError(code: VerifyErrorCode): string {
  return DESCRIPTIONS[code];
}
