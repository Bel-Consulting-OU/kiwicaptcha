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
 * Progress reports land at most every this many completed attempts on
 * the JS-thread solve. The low-difficulty window holds at most 2^8
 * attempts, so this caps the callback count at a handful even in the
 * pathological case (the winning/exhausted report below is the final
 * one).
 */
export const PROGRESS_ATTEMPT_INTERVAL = 64;

/**
 * Wall-clock floor between progress reports, shared by both solver
 * paths. A native module may report after every hash or squaring; the
 * bridge callback is throttled to this cadence so a fast solve can
 * never flood the JS thread (the first and final reports always pass).
 */
export const PROGRESS_MIN_INTERVAL_MS = 100;

/** The progress shape both solver paths report. */
export interface SolveProgress {
  /** Hashes (or rsw squarings) completed so far. */
  attempted: number;
}

/** Options of the solve entry points. */
export interface SolveOptions {
  /**
   * Progress callback, invoked at a bounded frequency: the first
   * report, periodic reports (attempt- and wall-clock-gated) and one
   * final report. Never once per loop iteration.
   */
  onProgress?: (info: SolveProgress) => void;
}

/**
 * The one progress gate: drops duplicate counts and reports that
 * arrive inside the wall-clock floor. `force` is used for the first and
 * final report so the caller always observes both bounds.
 */
function progressReporter(onProgress: ((info: SolveProgress) => void) | undefined) {
  let lastAttempted = -1;
  let lastReportAt = Number.NEGATIVE_INFINITY;
  return function report(attempted: number, force = false): void {
    if (!onProgress || attempted === lastAttempted) return;
    const now = Date.now();
    if (!force && now - lastReportAt < PROGRESS_MIN_INTERVAL_MS) return;
    lastAttempted = attempted;
    lastReportAt = now;
    onProgress({ attempted });
  };
}

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
export function solveSha256Low(
  challenge: KiwiChallenge,
  onProgress?: (info: SolveProgress) => void,
): KiwiSolution | null {
  const salt = base64Decode(challenge.salt);
  if (!salt) throw new KiwiSolveError("malformed", "the salt stopped decoding");
  const prefix = utf8(challenge.prefix);
  const started = Date.now();
  const crypto = loadQuickCrypto();
  const report = progressReporter(onProgress);
  const cap = 1 << challenge.targetBits;
  report(0, true);
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
      // The final report is forced: the caller always sees the winning
      // count, even when the solve finished inside the throttle window.
      report(counter + 1, true);
      return {
        counter,
        durationMs: Date.now() - started,
        hashHex: hex(digest),
      };
    }
    // Attempt-gated: at most cap / PROGRESS_ATTEMPT_INTERVAL callbacks,
    // then the wall-clock gate drops any that arrive too close together.
    if ((counter + 1) % PROGRESS_ATTEMPT_INTERVAL === 0) report(counter + 1);
  }
  // The search window closed; report the full attempt count before the
  // caller fails closed to the native module.
  report(cap, true);
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
  onProgress?: (info: SolveProgress) => void,
): Promise<KiwiSolution> {
  const report = progressReporter(onProgress);
  report(0, true);
  let raw: string;
  try {
    if (typeof solver.solveWithProgress === "function") {
      // The optional native progress channel: the native side owns the
      // attempt cadence; the reporter still enforces the wall-clock
      // floor and drops duplicates, so the bridge can never flood the
      // JS thread.
      raw = await solver.solveWithProgress(JSON.stringify(challenge), (info) => {
        if (info && Number.isFinite(info.attempted) && info.attempted >= 0) {
          report(Math.floor(info.attempted));
        }
      });
    } else {
      raw = await solver.solve(JSON.stringify(challenge));
    }
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
  // The final report: the winning counter for hash algorithms, the
  // squaring count for rsw. Forced so it is never lost to the throttle.
  report(challenge.algorithm === "rsw" ? challenge.t : solution.counter + 1, true);
  return solution as KiwiSolution;
}

/** Dispatch one validated challenge to the right solver. */
export async function solve(
  challenge: KiwiChallenge,
  options: SolveOptions = {},
): Promise<KiwiSolution> {
  if (challenge.algorithm === "sha256" && challenge.targetBits <= LOW_DIFFICULTY_MAX_BITS) {
    const low = solveSha256Low(challenge, options.onProgress);
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
  return solveNative(challenge, solver, options.onProgress);
}
