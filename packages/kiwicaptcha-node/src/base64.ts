/**
 * Strict base64 and hex helpers. Node's Buffer.from(base64) is lenient:
 * it skips invalid characters and accepts every padding spelling. The
 * wire protocols here require exactly one canonical spelling per value,
 * mirroring the PHP strict decoder plus the re-encode equality check.
 */

const STANDARD_ALPHABET = /^[A-Za-z0-9+/]*={0,2}$/;
const URL_ALPHABET = /^[A-Za-z0-9_-]*={0,2}$/;

export function encodeStdBase64(bytes: Buffer): string {
  return bytes.toString('base64');
}

/**
 * Decode canonical standard base64. Accepts exactly one spelling:
 * standard alphabet, correct padding, no stray characters. Returns null
 * for anything else.
 */
export function decodeStdBase64(value: string): Buffer | null {
  if (value.length % 4 !== 0 || !STANDARD_ALPHABET.test(value)) {
    return null;
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) {
    return null;
  }
  return bytes;
}

/**
 * Decode canonical base64url (unpadded, the driver's trace format).
 * Returns null for anything outside the unpadded url-safe alphabet.
 */
export function decodeBase64Url(value: string): Buffer | null {
  if (value.length === 0 || value.includes('=') || !/^[A-Za-z0-9_-]+$/.test(value)) {
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

/** Encode to unpadded base64url (the driver's trace wire format). */
export function encodeBase64Url(bytes: Buffer): string {
  return bytes.toString('base64url');
}

const LOWERCASE_HEX = /^[0-9a-f]+$/;

export function isLowercaseHex(value: string, length?: number): boolean {
  if (!LOWERCASE_HEX.test(value)) {
    return false;
  }
  return length === undefined || value.length === length;
}
