import { createHash } from 'node:crypto';

/**
 * The proof-of-work derivation shared with the Rust and PHP cores. The
 * SHA-256 password is prefix || counter; the hash input is password ||
 * raw salt bytes.
 */

/** Count the leading zero bits of a 32-byte hash (big-endian bit order). */
export function leadingZeroBits(hash: Buffer): number {
  let count = 0;
  for (const byte of hash) {
    if (byte === 0) {
      count += 8;
      continue;
    }
    let b = byte;
    while ((b & 0x80) === 0) {
      count += 1;
      b <<= 1;
    }
    break;
  }
  return count;
}

/** Derive the SHA-256 proof hash of a record at one counter value. */
export function deriveSha256Hash(prefix: string, counter: number, saltBytes: Buffer): Buffer {
  const password = Buffer.concat([
    Buffer.from(prefix, 'latin1'),
    Buffer.from(String(counter), 'ascii'),
  ]);
  return createHash('sha256').update(Buffer.concat([password, saltBytes])).digest();
}

/** Whether a derived hash meets the record's difficulty target. */
export function meetsTarget(hash: Buffer, targetBits: number): boolean {
  return leadingZeroBits(hash) >= targetBits;
}

/**
 * Solve a SHA-256 challenge: the first counter whose hash meets the
 * target. Used by the test suite (and available for tooling); the
 * production proof comes from the browser or native solver.
 */
export function solveSha256(prefix: string, saltB64: string, targetBits: number): number {
  const saltBytes = Buffer.from(saltB64, 'base64');
  for (let counter = 0; counter < 20_000_000; counter++) {
    if (meetsTarget(deriveSha256Hash(prefix, counter, saltBytes), targetBits)) {
      return counter;
    }
  }
  throw new Error('no proof found below the solver ceiling');
}
