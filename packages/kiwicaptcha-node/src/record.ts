import { createHash } from 'node:crypto';
import { decodeStdBase64 } from './base64.js';
import { SERVER_STATE_MAC_PATTERN } from './mac.js';
import type { PowAlgorithm } from './canonical.js';

/**
 * The server-side challenge record and its strict serde-mirror parser,
 * mirroring the Rust ChallengeRecord field names one to one so PHP,
 * Rust and Node share the same Redis and SQLite records.
 */

export const MAX_PROTOCOL_VERSION = 5;
export const BASE_PROTOCOL_VERSION = 2;
export const DECOY_PROTOCOL_VERSION = 3;
export const EXECUTION_PROTOCOL_VERSION = 4;
export const RSW_IDENTITY_PROTOCOL_VERSION = 5;

/** Maximum byte length of any wire string (the serde parse ceiling). */
export const MAX_STRING_BYTES = 4096;

export const MAX_EXECUTION_VERSION = 5;
export const MAX_PROGRAM_BASE64 = 4096;

export interface ChallengeRecord {
  nonce: string;
  scope: string;
  bindingTag: string;
  issuedAt: number;
  expiresAt: number;
  algorithm: PowAlgorithm;
  mKib: number;
  t: number;
  p: number;
  targetBits: number;
  salt: string;
  prefix: string;
  challenge: string;
  minDurationMs: number;
  issuedAtNs: number;
  protocolVersion: number;
  region: string | null;
  policyVersion: number;
  requestBinding: string | null;
  issuer: string | null;
  kid: number;
  hostname: string | null;
  decoyField: string | null;
  executionProgram: string | null;
  executionVersion: number | null;
  executionCommitment: string | null;
  rswModulusSha256: string | null;
  serverMac: string | null;
}

const WIRE_KEYS = new Set([
  'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
  'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
  'challenge', 'min_duration_ms', 'issued_at_ns', 'protocol_version',
  'attempts_used', 'region', 'policy_version', 'request_binding',
  'issuer', 'kid', 'hostname', 'decoy_field', 'execution_program',
  'execution_version', 'execution_commitment', 'rsw_modulus_sha256',
  'server_mac',
]);

const REQUIRED_KEYS = [
  'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
  'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
  'challenge', 'min_duration_ms',
];

const U32_MAX = 4_294_967_295;

/** Thrown by the strict record parser on any structural violation. */
export class MalformedRecordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MalformedRecordError';
  }
}

/**
 * The narrow security-identifier alphabet: deployment-bound identifiers
 * can never smuggle canonical separators, whitespace or multi-byte text
 * into a signed payload segment.
 */
export function isValidIdentifier(value: string, maxBytes: number): boolean {
  return (
    value.length >= 1 &&
    Buffer.byteLength(value, 'utf8') <= maxBytes &&
    /^[A-Za-z0-9._:-]+$/.test(value)
  );
}

/** The decoy (honeypot) field-name grammar: 1..64 bytes of [A-Za-z0-9_-]. */
export function isValidDecoyFieldName(value: string): boolean {
  return value.length >= 1 && value.length <= 64 && /^[A-Za-z0-9_-]+$/.test(value);
}

/**
 * The protocol-vs-extension grammar, the one shared matrix every
 * boundary applies: v1 and v2 carry neither extension, v3 requires the
 * decoy, v4 requires the execution triplet, v5 requires the rsw
 * identity.
 */
export function protocolExtensionGrammarOk(
  protocolVersion: number,
  decoyPresent: boolean,
  executionPresent: boolean,
  rswIdentityPresent: boolean,
): boolean {
  switch (protocolVersion) {
    case 1:
      return !decoyPresent && !executionPresent && !rswIdentityPresent;
    case BASE_PROTOCOL_VERSION:
      return !decoyPresent && !executionPresent;
    case DECOY_PROTOCOL_VERSION:
      return decoyPresent && !executionPresent;
    case EXECUTION_PROTOCOL_VERSION:
      return executionPresent;
    case RSW_IDENTITY_PROTOCOL_VERSION:
      return rswIdentityPresent;
    default:
      return false;
  }
}

function requireString(data: Record<string, unknown>, field: string): string {
  const value = data[field];
  if (typeof value !== 'string') {
    throw new MalformedRecordError(`${field} must be a string`);
  }
  if (Buffer.byteLength(value, 'utf8') > MAX_STRING_BYTES) {
    throw new MalformedRecordError(`${field} exceeds the wire string ceiling`);
  }
  return value;
}

function requireInt(
  data: Record<string, unknown>,
  field: string,
  min: number,
  max: number,
  fallback?: number,
): number {
  const raw = field in data ? data[field] : fallback;
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw)) {
    throw new MalformedRecordError(`${field} must be an integer within ${min}..${max}`);
  }
  if (raw < min || raw > max) {
    throw new MalformedRecordError(`${field} must be an integer within ${min}..${max}`);
  }
  return raw;
}

function optionalString(data: Record<string, unknown>, field: string): string | null {
  const value = data[field];
  if (value === undefined || value === null) {
    return null;
  }
  return requireString(data, field);
}

function validateHostname(data: Record<string, unknown>): string | null {
  const value = data.hostname;
  if (value === undefined || value === null) {
    return null;
  }
  const text = requireString(data, 'hostname');
  if (text === '') {
    throw new MalformedRecordError('hostname must be a non-empty string or null');
  }
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x20\x7f]/.test(text)) {
    throw new MalformedRecordError('hostname must not carry whitespace or control characters');
  }
  return text;
}

function parseRswModulusSha256(data: Record<string, unknown>): string | null {
  const value = data.rsw_modulus_sha256;
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new MalformedRecordError('rsw_modulus_sha256 must be 64 lowercase hex characters');
  }
  if (data.algorithm !== 'rsw') {
    throw new MalformedRecordError('rsw_modulus_sha256 may only ride an rsw record');
  }
  if (Number(data.protocol_version ?? 1) === 1) {
    throw new MalformedRecordError(
      'rsw_modulus_sha256 may not ride the v1 canonical (the v1 signature carries no identity segment)',
    );
  }
  return value;
}

/**
 * Rebuild a record from persisted JSON data with the strict serde
 * semantics: whitelisted keys only, exact algorithm values, strict
 * integer ranges, the legacy ip_hash alias, the total protocol grammar
 * and the exact execution triplet equivalence.
 */
export function challengeRecordFromJson(json: unknown): ChallengeRecord {
  if (json === null || typeof json !== 'object' || Array.isArray(json)) {
    throw new MalformedRecordError('the record must be a JSON object');
  }
  const data = json as Record<string, unknown>;
  for (const key of Object.keys(data)) {
    if (key !== 'ip_hash' && !WIRE_KEYS.has(key)) {
      throw new MalformedRecordError(`unknown record key: ${key}`);
    }
  }
  if ('ip_hash' in data) {
    if ('binding_tag' in data) {
      throw new MalformedRecordError('binding_tag and ip_hash may not appear together');
    }
    data.binding_tag = data.ip_hash;
  }
  for (const field of REQUIRED_KEYS) {
    if (!(field in data)) {
      throw new MalformedRecordError(`missing record field: ${field}`);
    }
  }
  for (const field of ['nonce', 'scope', 'binding_tag', 'salt', 'prefix', 'challenge']) {
    requireString(data, field);
  }
  for (const field of ['issued_at', 'expires_at', 'min_duration_ms']) {
    requireInt(data, field, 0, Number.MAX_SAFE_INTEGER);
  }
  requireInt(data, 'issued_at_ns', 0, Number.MAX_SAFE_INTEGER, 0);
  for (const field of ['m_kib', 't', 'p', 'target_bits', 'attempts_used']) {
    requireInt(data, field, 0, U32_MAX, 0);
  }
  for (const field of ['policy_version', 'kid']) {
    requireInt(data, field, 0, U32_MAX, 1);
  }
  const protocolVersion = requireInt(data, 'protocol_version', 1, MAX_PROTOCOL_VERSION, 1);
  const algorithmRaw = data.algorithm;
  if (algorithmRaw !== 'sha256' && algorithmRaw !== 'argon2id' && algorithmRaw !== 'rsw') {
    throw new MalformedRecordError(`invalid algorithm: ${String(algorithmRaw)}`);
  }
  const algorithm = algorithmRaw as PowAlgorithm;
  for (const field of ['region', 'request_binding', 'issuer']) {
    const value = optionalString(data, field);
    if (value !== null && !isValidIdentifier(value, field === 'region' ? 64 : 128)) {
      throw new MalformedRecordError(`${field} must match the identifier alphabet`);
    }
  }
  const decoyRaw = optionalString(data, 'decoy_field');
  if (decoyRaw !== null && !isValidDecoyFieldName(decoyRaw)) {
    throw new MalformedRecordError('decoy_field must match the decoy name alphabet');
  }
  let executionProgram: string | null = null;
  const executionProgramRaw = optionalString(data, 'execution_program');
  if (executionProgramRaw !== null) {
    if (Buffer.byteLength(executionProgramRaw, 'utf8') > MAX_PROGRAM_BASE64) {
      throw new MalformedRecordError('execution_program exceeds the program ceiling');
    }
    if (!isValidProgramShape(executionProgramRaw)) {
      throw new MalformedRecordError('execution_program is not a well-formed program blob');
    }
    executionProgram = executionProgramRaw;
  }
  const hasExecutionVersion = data.execution_version !== undefined && data.execution_version !== null;
  const hasExecutionCommitment =
    data.execution_commitment !== undefined && data.execution_commitment !== null;
  let executionVersion: number | null = null;
  let executionCommitment: string | null = null;
  if (executionProgram !== null || hasExecutionVersion || hasExecutionCommitment) {
    if (executionProgram === null || !hasExecutionVersion || !hasExecutionCommitment) {
      throw new MalformedRecordError('the execution triplet must be present together');
    }
    executionVersion = requireInt(data, 'execution_version', 1, MAX_EXECUTION_VERSION);
    executionCommitment = requireString(data, 'execution_commitment');
    if (!/^[0-9a-f]{64}$/.test(executionCommitment)) {
      throw new MalformedRecordError('execution_commitment must be 64 lowercase hex characters');
    }
    const expected = createHash('sha256').update(executionProgram, 'latin1').digest('hex');
    if (expected !== executionCommitment) {
      throw new MalformedRecordError('execution_commitment does not match the stored program');
    }
  }
  const rswModulusSha256 = parseRswModulusSha256(data);
  if (!protocolExtensionGrammarOk(protocolVersion, decoyRaw !== null, executionProgram !== null, rswModulusSha256 !== null)) {
    throw new MalformedRecordError(`invalid protocol/extension combination for version ${protocolVersion}`);
  }
  let serverMac: string | null = null;
  const serverMacRaw = data.server_mac;
  if (serverMacRaw !== undefined && serverMacRaw !== null) {
    const mac = requireString(data, 'server_mac');
    if (!SERVER_STATE_MAC_PATTERN.test(mac)) {
      throw new MalformedRecordError('server_mac must be 64 lowercase hex characters');
    }
    serverMac = mac;
  }
  return {
    nonce: data.nonce as string,
    scope: data.scope as string,
    bindingTag: data.binding_tag as string,
    issuedAt: data.issued_at as number,
    expiresAt: data.expires_at as number,
    algorithm,
    mKib: data.m_kib as number,
    t: data.t as number,
    p: data.p as number,
    targetBits: data.target_bits as number,
    salt: data.salt as string,
    prefix: data.prefix as string,
    challenge: data.challenge as string,
    minDurationMs: data.min_duration_ms as number,
    issuedAtNs: (data.issued_at_ns ?? 0) as number,
    protocolVersion,
    region: (data.region ?? null) as string | null,
    policyVersion: (data.policy_version ?? 1) as number,
    requestBinding: (data.request_binding ?? null) as string | null,
    issuer: (data.issuer ?? null) as string | null,
    kid: (data.kid ?? 1) as number,
    hostname: validateHostname(data),
    decoyField: decoyRaw,
    executionProgram,
    executionVersion,
    executionCommitment,
    rswModulusSha256,
    serverMac,
  };
}

/**
 * The base64 wire shape of an execution program: a structural check
 * only (canonical base64 within the ceiling). The full grammar runs in
 * the interpreter; this boundary exists because the parser here must
 * not depend on the interpreter for persisted reads.
 */
function isValidProgramShape(programB64: string): boolean {
  return decodeStdBase64(programB64) !== null;
}

/** Serialize a record to the canonical wire JSON (v2 key set). */
export function challengeRecordToJson(record: ChallengeRecord): Record<string, unknown> {
  const data: Record<string, unknown> = {
    nonce: record.nonce,
    scope: record.scope,
    binding_tag: record.bindingTag,
    issued_at: record.issuedAt,
    expires_at: record.expiresAt,
    algorithm: record.algorithm,
    m_kib: record.mKib,
    t: record.t,
    p: record.p,
    target_bits: record.targetBits,
    salt: record.salt,
    prefix: record.prefix,
    challenge: record.challenge,
    min_duration_ms: record.minDurationMs,
    issued_at_ns: record.issuedAtNs,
    protocol_version: record.protocolVersion,
    attempts_used: 0,
    region: record.region,
    policy_version: record.policyVersion,
    request_binding: record.requestBinding,
    issuer: record.issuer,
    kid: record.kid,
    hostname: record.hostname,
  };
  if (record.decoyField !== null) {
    data.decoy_field = record.decoyField;
  }
  if (record.executionProgram !== null) {
    data.execution_program = record.executionProgram;
  }
  if (record.executionVersion !== null) {
    data.execution_version = record.executionVersion;
  }
  if (record.executionCommitment !== null) {
    data.execution_commitment = record.executionCommitment;
  }
  if (record.rswModulusSha256 !== null) {
    data.rsw_modulus_sha256 = record.rswModulusSha256;
  }
  if (record.serverMac !== null) {
    data.server_mac = record.serverMac;
  }
  return data;
}
