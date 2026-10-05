import { NativeModules } from "react-native";
import {
  KiwiSolveError,
  type KiwiChallenge,
  type KiwiSolution,
  type NativeKiwiSolver,
} from "./types.js";
import { hex, leadingZeroBits, sha256 } from "./sha256.js";
import { base64Decode } from "./validate.js";

/**
 * Solver dispatch.
 *
 * Difficulty ceiling of the pure fallback: a sha256 challenge at or
 * below this many bits may run on the JS thread through the optional
 * quick-crypto peer (or the bundled pure-TS SHA-256), because the
 * expected work stays in the hundreds of hashes. Anything harder, and
 * every argon2id or rsw challenge, goes to the native module: the solve
 * runs on a native thread, never a WebView, never the JS thread.
 */
export const LOW_DIFFICULTY_MAX_BITS = 8;

/**
 * The optional quick-crypto peer. Resolution is lazy and guarded: an
 * absent module resolves to null instead of throwing (fail-closed to
 * the native module), and a failed require is cached so the lookup cost
 * is paid once per session.
 */
let quickCrypto: { createHash: (algo: string) => { update(b: Uint8Array): unknown; digest(): Uint8Array } } | null | undefined;

function loadQuickCrypto(): typeof quickCrypto {
  if (quickCrypto !== undefined) return quickCrypto;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const required = require("react-native-quick-crypto");
    quickCrypto = (required?.default ?? required) as typeof quickCrypto;
  } catch {
    quickCrypto = null;
  }
  return quickCrypto;
}

/** Exposed for tests: force the next require attempt. */
export function resetQuickCryptoCache(): void {
  quickCrypto = undefined;
}

/** The react-native bridge module, or null when the app has none. */
export function nativeSolver(): NativeKiwiSolver | null {
  return (NativeModules.KiwiCaptchaSolver as NativeKiwiSolver | undefined) ?? null;
}

function utf8(value: string): Uint8Array {
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c > 0x7f) throw new Error("the challenge prefix must be ASCII");
    out[i] = c;
  }
  return out;
}

function decimalBytes(n: number): Uint8Array {
  return utf8(String(n));
}

/**
 * Solve a low-difficulty sha256 challenge on the JS thread. Returns null
 * when the target was not met within the search window (the caller then
 * fails closed to the native module).
 */
export function solveSha256Low(challenge: KiwiChallenge): KiwiSolution | null {
  const salt = base64Decode(challenge.salt);
  if (!salt) throw new KiwiSolveError("malformed", "the salt stopped decoding");
  const prefix = utf8(challenge.prefix);
  const started = Date.now();
  const crypto = loadQuickCrypto();
  const cap = 1 << challenge.targetBits;
  for (let counter = 0; counter < cap; counter++) {
    const digest = crypto
      ? (() => {
          const hasher = crypto.createHash("sha256");
          hasher.update(prefix);
          hasher.update(decimalBytes(counter));
          hasher.update(salt);
          return new Uint8Array(hasher.digest());
        })()
      : sha256([prefix, decimalBytes(counter), salt]);
    if (leadingZeroBits(digest) >= challenge.targetBits) {
      return {
        counter,
        durationMs: Date.now() - started,
        hashHex: hex(digest),
      };
    }
  }
  return null;
}

/**
 * Solve through the native module. The module owns its own thread and
 * enforces the same caps; its answer must parse as the KiwiSolution
 * shape or the solve fails closed.
 */
export async function solveNative(
  challenge: KiwiChallenge,
  solver: NativeKiwiSolver,
): Promise<KiwiSolution> {
  let raw: string;
  try {
    raw = await solver.solve(JSON.stringify(challenge));
  } catch (err) {
    throw new KiwiSolveError(
      "solver-unavailable",
      `the native solver refused or failed: ${String(err)}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new KiwiSolveError("solver-unavailable", "the native solver returned a non-JSON answer");
  }
  const solution = parsed as Partial<KiwiSolution> | null;
  if (
    !solution ||
    typeof solution.counter !== "number" ||
    typeof solution.durationMs !== "number"
  ) {
    throw new KiwiSolveError("solver-unavailable", "the native solver answer is malformed");
  }
  if (challenge.algorithm === "rsw" && typeof solution.rswProof !== "string") {
    throw new KiwiSolveError("solver-unavailable", "the native rsw answer carries no proof");
  }
  return solution as KiwiSolution;
}

/** Dispatch one validated challenge to the right solver. */
export async function solve(challenge: KiwiChallenge): Promise<KiwiSolution> {
  if (challenge.algorithm === "sha256" && challenge.targetBits <= LOW_DIFFICULTY_MAX_BITS) {
    const low = solveSha256Low(challenge);
    if (low) return low;
    // The window missed: fail closed to the native module (same
    // profile, never a weaker one).
  }
  const solver = nativeSolver();
  if (!solver) {
    throw new KiwiSolveError(
      "solver-unavailable",
      challenge.algorithm === "sha256"
        ? `target_bits ${challenge.targetBits} is above the low-difficulty ceiling ${LOW_DIFFICULTY_MAX_BITS} and no KiwiCaptchaSolver native module is linked`
        : "this profile needs the KiwiCaptchaSolver native module, which is not linked",
    );
  }
  return solveNative(challenge, solver);
}
