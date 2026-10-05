import {
  KIWI_MAX_ARGON2_M_KIB,
  KIWI_MAX_ARGON2_TARGET_BITS,
  KIWI_MAX_TARGET_BITS,
  KIWI_RSW_T_MAX,
  KIWI_RSW_T_MIN,
  KiwiSolveError,
  type KiwiChallenge,
} from "./types.js";

/**
 * Challenge validation with the exact caps the browser driver enforces
 * (packages/kiwicaptcha-wasm/assets/widget-driver.js) and the native
 * solver crate enforces (packages/kiwicaptcha-solver/src/lib.rs). A
 * challenge outside the contract is refused before any work is spent.
 */

const NONCE_PATTERN = /^[A-Za-z0-9+/]{43}=$/;
const B64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

/** The 2048-bit odd-composite shape the rsw modulus must decode to. */
export function isCanonicalRswModulus(modulusB64: string): boolean {
  const bytes = base64Decode(modulusB64);
  if (!bytes || bytes.length !== 256) return false;
  return (bytes[0] ?? 0) >= 0x80 && (bytes[255] ?? 1) % 2 === 1;
}

export function base64Decode(value: string): Uint8Array | null {
  if (!B64_PATTERN.test(value) || value.length % 4 !== 0) return null;
  const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const clean = value.replace(/=+$/, "");
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (let i = 0; i < clean.length; i++) {
    const idx = table.indexOf(clean.charAt(i));
    if (idx < 0) return null;
    acc = (acc << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/** Validate a challenge document; throws KiwiSolveError on any refusal. */
export function validateChallenge(raw: unknown): KiwiChallenge {
  const data = raw as KiwiChallenge | null;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new KiwiSolveError("malformed", "the challenge response is not an object");
  }
  if (typeof data.execution_program === "string" && data.execution_program.length > 0) {
    throw new KiwiSolveError(
      "execution-unsupported",
      "an execution-armed challenge needs the browser interpreter; the native path refuses it",
    );
  }
  if (typeof data.nonce !== "string" || !NONCE_PATTERN.test(data.nonce)) {
    throw new KiwiSolveError("malformed", "the nonce is not the standard base64 of 32 bytes");
  }
  if (typeof data.prefix !== "string" || data.prefix.length < 1 || data.prefix.length > 4096) {
    throw new KiwiSolveError("malformed", "the prefix length is outside 1..=4096");
  }
  if (
    typeof data.salt !== "string" ||
    data.salt.length < 1 ||
    data.salt.length > 512 ||
    !base64Decode(data.salt)
  ) {
    throw new KiwiSolveError("malformed", "the salt is not decodable base64 or is oversized");
  }
  if (
    data.algorithm !== "sha256" &&
    data.algorithm !== "argon2id" &&
    data.algorithm !== "rsw"
  ) {
    throw new KiwiSolveError("malformed", "the algorithm is not one of sha256, argon2id, rsw");
  }
  if (!Number.isInteger(data.targetBits) || !Number.isInteger(data.mKib) || !Number.isInteger(data.t) || !Number.isInteger(data.p)) {
    throw new KiwiSolveError("malformed", "the numeric parameters are missing or not integers");
  }
  switch (data.algorithm) {
    case "sha256":
      if (data.targetBits < 1 || data.targetBits > KIWI_MAX_TARGET_BITS) {
        throw new KiwiSolveError(
          "difficulty-beyond-cap",
          `target_bits ${data.targetBits} exceeds the sha256 cap ${KIWI_MAX_TARGET_BITS}`,
        );
      }
      break;
    case "argon2id":
      if (data.targetBits < 1 || data.targetBits > KIWI_MAX_ARGON2_TARGET_BITS) {
        throw new KiwiSolveError(
          "difficulty-beyond-cap",
          `target_bits ${data.targetBits} exceeds the argon2id cap ${KIWI_MAX_ARGON2_TARGET_BITS}`,
        );
      }
      if (
        data.mKib < 8 ||
        data.mKib > KIWI_MAX_ARGON2_M_KIB ||
        data.t < 3 ||
        data.t > 6 ||
        data.p !== 1 ||
        data.mKib < 8 * data.p
      ) {
        throw new KiwiSolveError(
          "unsupported-params",
          `argon2id parameters are outside the client contract (m_kib ${data.mKib}, t ${data.t}, p ${data.p})`,
        );
      }
      break;
    case "rsw":
      if (data.t < KIWI_RSW_T_MIN || data.t > KIWI_RSW_T_MAX || data.p !== 1 || data.mKib !== 0) {
        throw new KiwiSolveError(
          "unsupported-params",
          "the rsw parameters are outside the client contract",
        );
      }
      if (typeof data.rsw_modulus !== "string" || !isCanonicalRswModulus(data.rsw_modulus)) {
        throw new KiwiSolveError(
          "unsupported-params",
          "the rsw modulus is not a canonical 2048-bit odd composite",
        );
      }
      break;
  }
  if (
    data.ttlSecs !== undefined &&
    (!Number.isInteger(data.ttlSecs) || data.ttlSecs < 1 || data.ttlSecs > 300)
  ) {
    throw new KiwiSolveError("malformed", "ttlSecs is outside 1..=300");
  }
  return data;
}
