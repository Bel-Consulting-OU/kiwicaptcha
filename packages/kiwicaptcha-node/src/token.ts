import { decodeStdBase64, encodeStdBase64 } from './base64.js';

/**
 * The client-submitted solution, decoded from the kiwi__token hidden
 * input. Wire format: base64(nonce "." counter "." duration_ms "." 
 * telemetry_json ["." execution_digest[":" execution_trace]] ["." 
 * rsw_proof]). The telemetry segment may contain dots, so decoding
 * splits on all dots and peels the optional suffix segments
 * right-to-left, independently.
 */

/** The browser/wasm solver search ceiling (20,000,000 hashes). */
export const SOLVER_MAX_HASHES = 20_000_000;

/** Hard ceiling for the client-reported duration (telemetry only): 1 hour. */
export const MAX_DURATION_MS = 3_600_000;

export type DecodeErrorCode =
  | 'invalid_base64'
  | 'invalid_utf8'
  | 'malformed'
  | 'invalid_counter'
  | 'counter_exceeds_solver_maximum'
  | 'invalid_duration';

/** Failure reasons for token decoding (stable wire codes). */
export class DecodeError extends Error {
  readonly code: DecodeErrorCode;

  constructor(code: DecodeErrorCode) {
    super(code);
    this.code = code;
    this.name = 'DecodeError';
  }
}

export interface SolutionToken {
  nonce: string;
  counter: number;
  durationMs: number;
  telemetry: Record<string, unknown>;
  /** 64-lowercase-hex execution digest, null on the unarmed shape. */
  executionDigest: string | null;
  /** Unpadded base64url execution trace, null without the digest. */
  executionTrace: string | null;
  /** 512-lowercase-hex rsw final value, null on every other shape. */
  rswProof: string | null;
}

function isCanonicalDecimal(segment: string): boolean {
  if (segment === '' || !/^\d+$/.test(segment)) {
    return false;
  }
  return segment.length === 1 || !segment.startsWith('0');
}

/**
 * Encode a solution token to its canonical base64 wire form. The
 * telemetry object is always rendered as a JSON object, never an array.
 */
export function encodeToken(token: SolutionToken): string {
  let plain = `${token.nonce}.${token.counter}.${token.durationMs}.${JSON.stringify(
    token.telemetry,
  )}`;
  if (token.executionDigest !== null) {
    // The trace rides in its wire spelling (unpadded base64url, the
    // driver's format), so a decode/encode round trip is byte-identical.
    const trace = token.executionTrace !== null ? `:${token.executionTrace}` : '';
    plain += `.${token.executionDigest}${trace}`;
  }
  if (token.rswProof !== null) {
    plain += `.${token.rswProof}`;
  }
  return encodeStdBase64(Buffer.from(plain, 'utf8'));
}

/**
 * Decode a raw token string with the exact acceptance split of the PHP
 * and Rust decoders: canonical base64, UTF-8 plaintext, at least four
 * segments, the canonical decimal rules, the solver counter ceiling,
 * the duration ceiling and a JSON-object telemetry segment.
 */
export function decodeToken(raw: string): SolutionToken {
  if (Buffer.byteLength(raw, 'latin1') > 32_768) {
    throw new DecodeError('malformed');
  }
  const plainBytes = decodeStdBase64(raw);
  if (plainBytes === null) {
    throw new DecodeError('invalid_base64');
  }
  let plain: string;
  try {
    plain = new TextDecoder('utf-8', { fatal: true }).decode(plainBytes);
  } catch {
    throw new DecodeError('invalid_utf8');
  }
  const parts = plain.split('.');
  if (parts.length < 4) {
    throw new DecodeError('malformed');
  }
  let end = parts.length;
  let rswProof: string | null = null;
  let executionDigest: string | null = null;
  let executionTrace: string | null = null;
  if (end >= 5 && /^[0-9a-f]{512}$/.test(parts[end - 1] as string)) {
    rswProof = parts[end - 1] as string;
    end -= 1;
  }
  if (end >= 5) {
    const segment = parts[end - 1] as string;
    const colon = segment.indexOf(':');
    const digestPart = colon === -1 ? segment : segment.slice(0, colon);
    if (/^[0-9a-f]{64}$/.test(digestPart)) {
      executionDigest = digestPart;
      if (colon !== -1) {
        executionTrace = segment.slice(colon + 1);
        const decoded = decodeBase64UrlSegment(executionTrace);
        if (decoded === null) {
          throw new DecodeError('malformed');
        }
      }
      end -= 1;
    }
  }
  const telemetryStr = parts.slice(3, end).join('.');
  const [nonce, counterStr, durationStr] = parts as [string, string, string];

  // The nonce is base64 of exactly 32 bytes: 43 alphabet chars plus one
  // padding '='. The strict re-encode check refuses shape-valid
  // spellings whose final sextet carries non-zero unused bits.
  if (nonce.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/.test(nonce)) {
    throw new DecodeError('malformed');
  }
  const nonceBytes = Buffer.from(nonce, 'base64');
  if (nonceBytes.length !== 32 || nonceBytes.toString('base64') !== nonce) {
    throw new DecodeError('malformed');
  }

  if (!isCanonicalDecimal(counterStr)) {
    throw new DecodeError('invalid_counter');
  }
  const counterValue = Number(counterStr);
  if (counterStr.length > 8 || counterValue >= SOLVER_MAX_HASHES) {
    throw new DecodeError('counter_exceeds_solver_maximum');
  }
  if (!isCanonicalDecimal(durationStr)) {
    throw new DecodeError('invalid_duration');
  }
  const durationMs = Number(durationStr);
  if (durationMs > MAX_DURATION_MS) {
    throw new DecodeError('invalid_duration');
  }

  let telemetry: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(telemetryStr);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new DecodeError('malformed');
    }
    telemetry = parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof DecodeError) {
      throw error;
    }
    throw new DecodeError('malformed');
  }
  if (executionDigest !== null && !/^[0-9a-f]{64}$/.test(executionDigest)) {
    throw new DecodeError('malformed');
  }
  return { nonce, counter: counterValue, durationMs, telemetry, executionDigest, executionTrace, rswProof };
}

function decodeBase64UrlSegment(value: string): Buffer | null {
  if (value === '' || value.length > 10_924 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return null;
  }
  const standard = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  const bytes = Buffer.from(padded, 'base64');
  if (bytes.toString('base64url') !== value) {
    return null;
  }
  return bytes;
}
