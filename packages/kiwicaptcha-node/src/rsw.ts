import { createHash } from 'node:crypto';
import { decodeStdBase64 } from './base64.js';

/**
 * The RSW time-lock trapdoor and its shared arithmetic on native
 * BigInt. The client squares a challenge-derived base T times modulo a
 * 2048-bit composite n; the server computes base^(2^T mod lambda) mod n
 * with one modular exponentiation. Byte-compatible with the PHP Rsw
 * class and the Rust rsw module: the expected final value renders as
 * the fixed 512-hex wire form.
 */

export const RSW_MODULUS_BYTES = 256;
export const RSW_PROOF_HEX_LENGTH = 512;
export const RSW_T_MIN = 10_000;
export const RSW_T_MAX = 300_000;

const SMALL_PRIME_LIMIT = 1000;
const SELFTEST_BASES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n];
const MILLER_RABIN_ROUNDS = 40;

let smallPrimesCache: number[] | null = null;

function smallPrimes(): number[] {
  if (smallPrimesCache !== null) {
    return smallPrimesCache;
  }
  const limit = SMALL_PRIME_LIMIT;
  const sieve = new Array<boolean>(limit + 1).fill(true);
  sieve[0] = false;
  sieve[1] = false;
  for (let p = 2; p * p <= limit; p++) {
    if (!sieve[p]) {
      continue;
    }
    for (let m = p * p; m <= limit; m += p) {
      sieve[m] = false;
    }
  }
  const primes: number[] = [];
  for (let candidate = 2; candidate <= limit; candidate++) {
    if (sieve[candidate]) {
      primes.push(candidate);
    }
  }
  smallPrimesCache = primes;
  return primes;
}

function powm(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  if (b < 0n) {
    b += modulus;
  }
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/** Miller-Rabin probabilistic primality with fixed random-free bases plus strong bases. */
function isProbablePrime(n: bigint): boolean {
  if (n < 2n) {
    return false;
  }
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n % p === 0n) {
      return n === p;
    }
  }
  let d = n - 1n;
  let r = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    r += 1;
  }
  // Deterministic base set for 2048-bit inputs is impractical, so mix
  // the fixed bases with a derivative ladder; a genuine 2048-bit
  // composite passes with overwhelming certainty for any base set, and
  // a prime passes always.
  for (let i = 0; i < MILLER_RABIN_ROUNDS; i++) {
    const a = 2n + BigInt((i * 7919 + 104729) % 1_000_003);
    let x = powm(a % n, d, n);
    if (x === 1n || x === n - 1n) {
      continue;
    }
    let composite = true;
    for (let j = 0; j < r - 1; j++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) {
      return false;
    }
  }
  return true;
}

function decodeModulus(modulusB64: string): bigint {
  const bytes = canonicalBase64Bytes(modulusB64, 'rsw_modulus_n');
  if (bytes.length !== RSW_MODULUS_BYTES) {
    throw new RangeError(
      `rsw_modulus_n must be the base64 of exactly ${RSW_MODULUS_BYTES} bytes, got ${bytes.length}`,
    );
  }
  const first = bytes[0] ?? 0;
  const last = bytes[bytes.length - 1] ?? 0;
  if ((first & 0x80) === 0) {
    throw new RangeError('rsw_modulus_n must have its top bit set (a genuine 2048-bit composite)');
  }
  if ((last & 1) === 0) {
    throw new RangeError('rsw_modulus_n must be odd (the product of two odd primes)');
  }
  return BigInt(`0x${bytes.toString('hex')}`);
}

function decodeLambda(lambdaB64: string): bigint {
  const bytes = canonicalBase64Bytes(lambdaB64, 'rsw_lambda');
  if (bytes.length === 0 || bytes.length > RSW_MODULUS_BYTES) {
    throw new RangeError(`rsw_lambda must be the base64 of 1..${RSW_MODULUS_BYTES} bytes`);
  }
  if (((bytes[bytes.length - 1] ?? 0) & 1) === 1) {
    throw new RangeError('rsw_lambda must be even (lcm(p-1, q-1) of two odd primes)');
  }
  return BigInt(`0x${bytes.toString('hex')}`);
}

function canonicalBase64Bytes(value: string, name: string): Buffer {
  if (value === '') {
    throw new RangeError(`${name} must be non-empty base64`);
  }
  const bytes = decodeStdBase64(value);
  if (bytes === null) {
    throw new RangeError(`${name} must be canonical standard base64`);
  }
  return bytes;
}

function rejectSmallPrimeFactor(n: bigint): void {
  for (const prime of smallPrimes()) {
    if (prime === 2) {
      continue;
    }
    if (n % BigInt(prime) === 0n) {
      throw new RangeError(
        `rsw_modulus_n must not be divisible by a small prime (found ${prime})`,
      );
    }
  }
}

function trapdoorConsistent(n: bigint, lambda: bigint): boolean {
  for (const base of SELFTEST_BASES) {
    if (powm(base, lambda, n) !== 1n) {
      return false;
    }
  }
  return true;
}

function proofHex(value: bigint): string {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) {
    hex = `0${hex}`;
  }
  return hex.padStart(RSW_PROOF_HEX_LENGTH, '0');
}

/**
 * The decoded and validated trapdoor pair. Construction validates the
 * shape, the small-prime factors, probable primality and the trapdoor
 * consistency spot-check, mirroring the PHP Rsw rejections.
 */
export class Rsw {
  readonly n: bigint;
  readonly lambda: bigint;
  readonly modulusN: string;

  constructor(modulusB64: string, lambdaB64: string) {
    const n = decodeModulus(modulusB64);
    const lambda = decodeLambda(lambdaB64);
    rejectSmallPrimeFactor(n);
    if (isProbablePrime(n)) {
      throw new RangeError(
        'rsw_modulus_n must not itself be a probable prime (a genuine 2048-bit modulus is the product of two large primes)',
      );
    }
    if (!trapdoorConsistent(n, lambda)) {
      throw new RangeError(
        'rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)',
      );
    }
    this.n = n;
    this.lambda = lambda;
    this.modulusN = modulusB64;
  }

  /**
   * The expected final value of a challenge as the fixed 512-hex wire
   * form: base^(2^T mod lambda) mod n, base the challenge-derived
   * residue.
   */
  expectedProofHex(prefix: string, nonce: string, t: number): string {
    const base = deriveBase(prefix, nonce, this.n);
    const exponent = powm(2n, BigInt(t), this.lambda);
    return proofHex(powm(base, exponent, this.n));
  }
}

/** The challenge-derived base: SHA-256 of prefix plus nonce bytes, reduced modulo n. */
export function deriveBase(prefix: string, nonce: string, n: bigint): bigint {
  const digest = createHash('sha256')
    .update(Buffer.concat([Buffer.from(prefix, 'latin1'), Buffer.from(nonce, 'latin1')]))
    .digest();
  return BigInt(`0x${digest.toString('hex')}`) % n;
}

/** The fixed 512-hex wire form of a residue. */
export function rswProofHex(value: bigint): string {
  return proofHex(value);
}

/**
 * The canonical fingerprint of a modulus: lowercase-hex SHA-256 of the
 * decoded 256-byte modulus, the identity a v5 record pins.
 */
export function modulusFingerprintHex(modulusB64: string): string {
  const bytes = decodeStdBase64(modulusB64);
  if (bytes === null) {
    throw new RangeError('the modulus must be canonical standard base64');
  }
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Whether an identity is the accepted fingerprint form of a modulus:
 * the canonical fingerprint always, the legacy base64-text alias only
 * while the bounded migration mode is enabled.
 */
export function rswIdentityMatches(
  identity: string,
  modulusNBase64: string,
  allowLegacyAlias: boolean,
): boolean {
  if (identity === modulusFingerprintHex(modulusNBase64)) {
    return true;
  }
  if (allowLegacyAlias) {
    return identity === createHash('sha256').update(modulusNBase64, 'latin1').digest('hex');
  }
  return false;
}
