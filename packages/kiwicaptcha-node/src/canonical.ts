import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { derivedKeys } from './keys.js';

/**
 * The canonical signing bytes and the deployment binding tags, shared
 * with the PHP Issuer and the Rust issuer byte for byte.
 *
 * Canonical payload revision 4:
 *
 *   v4|protocol_version|nonce|scope|binding_tag|issued_at|expires_at|
 *     algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|
 *     policy_version|request_binding|issuer|kid
 *
 * followed by the tagged extension segments in capability order:
 *
 *   ...|kid|d={decoy_field}|e={version},{commitment}|r={modulus_sha256}|m=1
 */

export const POW_ALGORITHMS = ['sha256', 'argon2id', 'rsw'] as const;
export type PowAlgorithm = (typeof POW_ALGORITHMS)[number];

export interface CanonicalPayloadArgs {
  protocolVersion: number;
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
  minDurationMs: number;
  region?: string | null;
  policyVersion?: number;
  requestBinding?: string | null;
  issuer?: string | null;
  kid?: number;
  decoyField?: string | null;
  executionVersion?: number | null;
  executionCommitment?: string | null;
  rswModulusSha256?: string | null;
  serverMacCommitted?: boolean;
}

/**
 * Assemble the canonical signing payload. The extension segments append
 * only when armed, so the unarmed base keeps the plain field set. The
 * execution pair and the metadata marker each change the signed bytes,
 * so stripping or splicing any armed field breaks the signature.
 */
export function canonicalPayload(args: CanonicalPayloadArgs): string {
  const base =
    `v4|${args.protocolVersion}|${args.nonce}|${args.scope}|${args.bindingTag}|` +
    `${args.issuedAt}|${args.expiresAt}|${args.algorithm}|${args.mKib}|${args.t}|` +
    `${args.p}|${args.targetBits}|${args.salt}|${args.minDurationMs}|${args.region ?? ''}|` +
    `${args.policyVersion ?? 1}|${args.requestBinding ?? ''}|${args.issuer ?? ''}|${args.kid ?? 1}`;
  let out = base;
  if (args.decoyField !== null && args.decoyField !== undefined) {
    out += `|d=${args.decoyField}`;
  }
  const hasVersion = args.executionVersion !== null && args.executionVersion !== undefined;
  const hasCommitment = args.executionCommitment !== null && args.executionCommitment !== undefined;
  if (hasVersion || hasCommitment) {
    if (!hasVersion || !hasCommitment) {
      throw new TypeError('execution_version and execution_commitment must be passed together');
    }
    out += `|e=${args.executionVersion},${args.executionCommitment}`;
  }
  if (args.rswModulusSha256 !== null && args.rswModulusSha256 !== undefined) {
    out += `|r=${args.rswModulusSha256}`;
  }
  if (args.serverMacCommitted === true) {
    out += '|m=1';
  }
  return out;
}

/**
 * True when the challenge's signed canonical carries the record
 * metadata MAC marker (m=1). The marker is parsed from the embedded
 * canonical, never inferred from the stored MAC presence.
 */
export function signedCanonicalCommitsRecordMeta(challenge: string): boolean {
  const pos = challenge.lastIndexOf('.');
  if (pos < 0) {
    return false;
  }
  const encoded = challenge.slice(0, pos);
  const canonical = Buffer.from(encoded, 'base64');
  if (canonical.toString('base64') !== encoded) {
    return false;
  }
  const text = canonical.toString('latin1');
  return text.startsWith('v4|') && text.endsWith('|m=1');
}

/**
 * The authenticated execution commitment of a stored program: the hex
 * SHA-256 of the program's base64 wire string.
 */
export function executionCommitment(executionProgram: string): string {
  return createHash('sha256').update(executionProgram, 'latin1').digest('hex');
}

/**
 * Legacy v1 IP hash: the hex SHA-256 of salt followed by the raw IP
 * string. Kept for v1 records inside the migration window.
 */
export function hashIp(ip: string, salt: string): string {
  return createHash('sha256').update(Buffer.concat([Buffer.from(salt, 'latin1'), Buffer.from(ip, 'latin1')])).digest('hex');
}

/**
 * The v1 signature: hex HMAC over the v1 payload keyed by the master
 * secret directly. Migration-window compatibility only.
 */
export function signPayloadV1(canonical: string, secretKey: string | Buffer): string {
  return createHmac('sha256', Buffer.from(secretKey as string, 'latin1')).update(canonical, 'latin1').digest('hex');
}

/**
 * The v2+ signature: hex HMAC over the canonical payload keyed by the
 * HKDF-derived challenge-signing purpose key (tenant-scoped when a
 * tenant id is configured).
 */
export function signPayloadV2(
  canonical: string,
  secretKey: string | Buffer,
  tenantId: string | null = null,
): string {
  return createHmac('sha256', derivedKeys(secretKey, tenantId).challengeKey)
    .update(canonical, 'latin1')
    .digest('hex');
}

const V4_STRICT = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseIpv4(ip: string): Buffer | null {
  const m = V4_STRICT.exec(ip);
  if (m === null) {
    return null;
  }
  const octets: number[] = [];
  const groups: readonly string[] = [m[1] ?? '', m[2] ?? '', m[3] ?? '', m[4] ?? ''];
  for (const part of groups) {
    if (part.length > 1 && part.startsWith('0')) {
      // Leading-zero octets are foreign spellings, never accepted.
      return null;
    }
    const value = Number(part);
    if (!Number.isInteger(value) || value > 255) {
      return null;
    }
    octets.push(value);
  }
  return Buffer.from(octets);
}

const IPV6_GROUP = /^[0-9A-Fa-f]{1,4}$/;

function parseIpv6(ip: string): Buffer | null {
  if (ip.includes('%')) {
    // Scoped addresses carry no canonical form here.
    return null;
  }
  const lower = ip.toLowerCase();
  let head: string[];
  let tail: string[];
  const doubleColon = lower.indexOf('::');
  if (doubleColon >= 0) {
    if (lower.indexOf('::', doubleColon + 1) >= 0) {
      return null;
    }
    head = doubleColon === 0 ? [] : lower.slice(0, doubleColon).split(':');
    const rest = lower.slice(doubleColon + 2);
    tail = rest === '' ? [] : rest.split(':');
  } else {
    head = lower.split(':');
    tail = [];
  }
  const tailLast = tail[tail.length - 1];
  const tailHasV4 = tailLast !== undefined && tailLast.includes('.');
  let tailGroups = tail;
  if (tailHasV4) {
    const v4 = parseIpv4(tail[tail.length - 1] as string);
    if (v4 === null) {
      return null;
    }
    tailGroups = tail.slice(0, -1);
  }
  for (const group of [...head, ...tailGroups]) {
    if (group.includes('.') || !IPV6_GROUP.test(group)) {
      return null;
    }
  }
  const explicit = head.length + tailGroups.length + (tailHasV4 ? 2 : 0);
  if (doubleColon >= 0) {
    if (explicit >= 8) {
      return null;
    }
  } else if (explicit !== 8) {
    return null;
  }
  const bytes = Buffer.alloc(16);
  let at = 0;
  const writeGroup = (group: string): void => {
    const value = parseInt(group, 16);
    bytes[at++] = value >> 8;
    bytes[at++] = value & 0xff;
  };
  for (const group of head) {
    writeGroup(group);
  }
  if (doubleColon >= 0) {
    const missing = 8 - explicit;
    at += missing * 2;
  }
  for (const group of tailGroups) {
    writeGroup(group);
  }
  if (tailHasV4) {
    const v4 = parseIpv4(tail[tail.length - 1] as string) as Buffer;
    v4.copy(bytes, 12);
  }
  return bytes;
}

/**
 * Canonical family byte plus packed address bytes: the inet_pton output
 * (4 or 16 bytes) with IPv4-mapped and IPv4-compatible IPv6 spellings
 * normalized to the 4-byte IPv4 form. Two textual spellings of one
 * address therefore produce the same bytes. Returns null for any input
 * outside the strict grammar.
 */
export function canonicalIpFamily(ip: string): Buffer | null {
  if (ip === '') {
    return null;
  }
  if (ip.includes(':')) {
    const v6 = parseIpv6(ip);
    if (v6 === null) {
      return null;
    }
    const prefix = v6.subarray(0, 12);
    const low = v6.subarray(12);
    const zeros = Buffer.alloc(12, 0);
    const mapped = prefix.equals(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]));
    const compatible =
      prefix.equals(zeros) && !low.equals(Buffer.alloc(4, 0)) && !low.equals(Buffer.from([0, 0, 0, 1]));
    if (mapped || compatible) {
      return Buffer.concat([Buffer.of(4), low]);
    }
    return Buffer.concat([Buffer.of(6), v6]);
  }
  const v4 = parseIpv4(ip);
  if (v4 === null) {
    return null;
  }
  return Buffer.concat([Buffer.of(4), v4]);
}

/**
 * The nonce-bound IP binding tag of a v2+ record: hex HMAC over the
 * domain string, the nonce and the canonical family bytes, keyed by the
 * IP-binding purpose key. Throws RangeError for an IP outside the
 * strict grammar, exactly like the PHP issuer.
 */
export function bindingTag(
  nonce: string,
  ip: string,
  secret: string | Buffer,
  tenantId: string | null = null,
): string {
  const family = canonicalIpFamily(ip);
  if (family === null) {
    throw new RangeError(`invalid IP address: ${ip}`);
  }
  const message = Buffer.concat([
    Buffer.from('kiwicaptcha/ip-bind/v2\0', 'latin1'),
    Buffer.from(nonce, 'latin1'),
    Buffer.of(0),
    family,
  ]);
  return createHmac('sha256', derivedKeys(secret, tenantId).ipBindKey).update(message).digest('hex');
}

/** Constant-time equality over equal-length buffers (false on length mismatch). */
export function buffersEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}
