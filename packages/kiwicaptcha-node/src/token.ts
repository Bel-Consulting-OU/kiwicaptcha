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

/**
 * Maximum nesting depth of the telemetry object, the
 * protocol/limits.json `token_max_telemetry_depth` register row. The
 * scalar level is zero, so the 32nd nested container is accepted and
 * the 33rd is refused.
 */
export const MAX_TELEMETRY_DEPTH = 32;

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
  /**
   * Per-element `et` spelling metadata: true where the wire literal was
   * not an integer literal (a float or exponent spelling). JSON.parse
   * collapses `1` and `1.0` to the same number, but the wire contract
   * treats only integer literals as timestamps, so the decoder
   * preserves the spelling for the telemetry scorer. Absent when the
   * telemetry has no `et` array.
   */
  telemetryEtFloatSpellings?: readonly boolean[];
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

  // An escaped surrogate must form a pair. JSON.parse preserves lone
  // UTF-16 surrogates in the decoded string, while the reference
  // decoders reject the escape, so the same bytes would otherwise
  // verify against a different telemetry value on this host.
  if (hasUnpairedSurrogateEscape(telemetryStr)) {
    throw new DecodeError('malformed');
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
  // The depth ceiling is part of the wire language: JSON.parse itself
  // has no practical limit, while the strictest hosts stopped at the
  // register value, so the same token would decode on one host and
  // reject on another. The walk is iterative so hostile nesting cannot
  // turn the check itself into a stack overflow.
  if (jsonDepthExceeds(telemetry, MAX_TELEMETRY_DEPTH)) {
    throw new DecodeError('malformed');
  }
  if (executionDigest !== null && !/^[0-9a-f]{64}$/.test(executionDigest)) {
    throw new DecodeError('malformed');
  }
  return {
    nonce,
    counter: counterValue,
    durationMs,
    telemetry,
    executionDigest,
    executionTrace,
    rswProof,
    telemetryEtFloatSpellings: floatSpellingsInEt(telemetryStr, telemetry),
  };
}

/** A JSON number literal written as an integer (no fraction or exponent). */
const JSON_INTEGER_LITERAL = /^-?(?:0|[1-9][0-9]*)$/;

/**
 * True when the parsed telemetry tree nests deeper than `max`
 * containers. The scalar level is zero; the outer object is depth one.
 */
function jsonDepthExceeds(value: unknown, max: number): boolean {
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 1 }];
  while (stack.length > 0) {
    const node = stack.pop() as { value: unknown; depth: number };
    const isArray = Array.isArray(node.value);
    const isObject = node.value !== null && typeof node.value === 'object';
    if (!isArray && !isObject) {
      continue;
    }
    if (node.depth > max) {
      return true;
    }
    if (isArray) {
      for (const child of node.value as unknown[]) {
        stack.push({ value: child, depth: node.depth + 1 });
      }
    } else {
      for (const child of Object.values(node.value as Record<string, unknown>)) {
        stack.push({ value: child, depth: node.depth + 1 });
      }
    }
  }
  return false;
}

/**
 * The per-element `et` float-spelling flags. JSON.parse has already
 * validated the document, so the scanner only locates the top-level
 * `et` member (duplicate keys resolve to the last value, as in
 * JSON.parse) and its array element literals. A missing or non-array
 * `et` yields undefined.
 */
function floatSpellingsInEt(
  telemetryText: string,
  telemetry: Record<string, unknown>,
): readonly boolean[] | undefined {
  const events = telemetry['et'];
  if (!Array.isArray(events)) {
    return undefined;
  }
  const etSource = topLevelMemberSource(telemetryText, 'et');
  if (etSource === null) {
    return undefined;
  }
  const sources = topLevelArrayElementSources(etSource);
  if (sources === null || sources.length !== events.length) {
    return undefined;
  }
  return sources.map(
    (source, index) => typeof events[index] === 'number' && !JSON_INTEGER_LITERAL.test(source),
  );
}

/** Skips JSON whitespace; returns the next significant index. */
function skipJsonWhitespace(text: string, start: number): number {
  let index = start;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) {
      index += 1;
    } else {
      break;
    }
  }
  return index;
}

/** Skips one JSON string starting at its opening quote. */
function skipJsonString(text: string, start: number): number {
  let index = start + 1;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code === 0x5c) {
      index += 2;
      continue;
    }
    if (code === 0x22) {
      return index + 1;
    }
    index += 1;
  }
  return index;
}

/** Skips one JSON value (object, array, string, number or literal). */
function skipJsonValue(text: string, start: number): number {
  let index = skipJsonWhitespace(text, start);
  const code = text.charCodeAt(index);
  if (code === 0x22) {
    return skipJsonString(text, index);
  }
  if (code === 0x7b) {
    index += 1;
    while (index < text.length) {
      index = skipJsonWhitespace(text, index);
      if (text.charCodeAt(index) === 0x7d) {
        return index + 1;
      }
      index = skipJsonString(text, index);
      index = skipJsonWhitespace(text, index);
      if (text.charCodeAt(index) !== 0x3a) {
        return index;
      }
      index = skipJsonValue(text, index + 1);
      index = skipJsonWhitespace(text, index);
      if (text.charCodeAt(index) === 0x2c) {
        index += 1;
        continue;
      }
      if (text.charCodeAt(index) === 0x7d) {
        return index + 1;
      }
      return index;
    }
    return index;
  }
  if (code === 0x5b) {
    index += 1;
    while (index < text.length) {
      index = skipJsonWhitespace(text, index);
      if (text.charCodeAt(index) === 0x5d) {
        return index + 1;
      }
      index = skipJsonValue(text, index);
      index = skipJsonWhitespace(text, index);
      if (text.charCodeAt(index) === 0x2c) {
        index += 1;
        continue;
      }
      if (text.charCodeAt(index) === 0x5d) {
        return index + 1;
      }
      return index;
    }
    return index;
  }
  while (index < text.length) {
    const c = text.charCodeAt(index);
    if (
      c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d ||
      c === 0x2c || c === 0x5d || c === 0x7d
    ) {
      break;
    }
    index += 1;
  }
  return index;
}

/**
 * The raw source of the last top-level member named `member`, or null.
 * Returns null when the document is not an object.
 */
function topLevelMemberSource(text: string, member: string): string | null {
  let index = skipJsonWhitespace(text, 0);
  if (text.charCodeAt(index) !== 0x7b) {
    return null;
  }
  index += 1;
  let found: string | null = null;
  while (index < text.length) {
    index = skipJsonWhitespace(text, index);
    if (text.charCodeAt(index) === 0x7d) {
      break;
    }
    const keyStart = index;
    index = skipJsonString(text, index);
    const key = JSON.parse(text.slice(keyStart, index)) as string;
    index = skipJsonWhitespace(text, index);
    if (text.charCodeAt(index) !== 0x3a) {
      return found;
    }
    index = skipJsonWhitespace(text, index + 1);
    const valueStart = index;
    index = skipJsonValue(text, index);
    if (key === member) {
      found = text.slice(valueStart, index);
    }
    index = skipJsonWhitespace(text, index);
    if (text.charCodeAt(index) === 0x2c) {
      index += 1;
      continue;
    }
    if (text.charCodeAt(index) === 0x7d) {
      break;
    }
    return found;
  }
  return found;
}

/** The raw source of each top-level array element, or null. */
function topLevelArrayElementSources(text: string): string[] | null {
  let index = skipJsonWhitespace(text, 0);
  if (text.charCodeAt(index) !== 0x5b) {
    return null;
  }
  index += 1;
  const sources: string[] = [];
  while (index < text.length) {
    index = skipJsonWhitespace(text, index);
    if (text.charCodeAt(index) === 0x5d) {
      return sources;
    }
    const start = index;
    index = skipJsonValue(text, index);
    sources.push(text.slice(start, index));
    index = skipJsonWhitespace(text, index);
    if (text.charCodeAt(index) === 0x2c) {
      index += 1;
      continue;
    }
    if (text.charCodeAt(index) === 0x5d) {
      return sources;
    }
    return null;
  }
  return null;
}

/**
 * True when a JSON string literal carries a \u escape that encodes an
 * unpaired surrogate. Escaped backslashes are skipped, so the literal
 * text `\\ud800` (a backslash followed by the letters u-d-8-0-0) is
 * not mistaken for an escape. Malformed escapes are left for
 * JSON.parse, which rejects them.
 */
function hasUnpairedSurrogateEscape(text: string): boolean {
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (!inString) {
      if (code === 0x22) {
        inString = true;
      }
      continue;
    }
    if (code === 0x22) {
      inString = false;
      continue;
    }
    if (code !== 0x5c) {
      continue;
    }
    if (i + 1 >= text.length) {
      return false;
    }
    if (text.charCodeAt(i + 1) !== 0x75) {
      i += 1;
      continue;
    }
    if (i + 5 >= text.length) {
      return false;
    }
    const unit = Number.parseInt(text.slice(i + 2, i + 6), 16);
    if (Number.isNaN(unit)) {
      return false;
    }
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (
        i + 11 < text.length &&
        text.charCodeAt(i + 6) === 0x5c &&
        text.charCodeAt(i + 7) === 0x75
      ) {
        const low = Number.parseInt(text.slice(i + 8, i + 12), 16);
        if (!Number.isNaN(low) && low >= 0xdc00 && low <= 0xdfff) {
          i += 11;
          continue;
        }
      }
      return true;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
    i += 5;
  }
  return false;
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
