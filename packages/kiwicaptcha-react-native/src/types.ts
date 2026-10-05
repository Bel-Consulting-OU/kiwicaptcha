/**
 * The wire contract this package implements, shared with
 * packages/kiwicaptcha-solver and the browser widget driver: the same
 * challenge fields, the same caps (protocol/limits.json), the same
 * token grammar.
 */

/** The proof-of-work algorithms the protocol issues. */
export type KiwiAlgorithm = "sha256" | "argon2id" | "rsw";

/** Protocol caps, mirrored from protocol/limits.json. */
export const KIWI_MAX_TARGET_BITS = 20;
export const KIWI_MAX_ARGON2_TARGET_BITS = 10;
export const KIWI_MAX_ARGON2_M_KIB = 65536;
export const KIWI_RSW_T_MIN = 10000;
export const KIWI_RSW_T_MAX = 300000;
export const KIWI_MAX_DURATION_MS = 3600000;

/** The challenge document the endpoint returns. */
export interface KiwiChallenge {
  nonce: string;
  challenge?: string;
  salt: string;
  algorithm: KiwiAlgorithm;
  mKib: number;
  t: number;
  p: number;
  targetBits: number;
  ttlSecs?: number;
  minDurationMs?: number;
  prefix: string;
  decoy_field?: string;
  execution_program?: string;
  rsw_modulus?: string;
}

/** A completed solve, as the native module or the fallback reports it. */
export interface KiwiSolution {
  /** The winning counter (0 for rsw). */
  counter: number;
  /** Wall-clock solve duration in milliseconds. */
  durationMs: number;
  /** The winning digest, 64 lowercase hex (not used by the token). */
  hashHex?: string;
  /** The rsw final value, 512 lowercase hex. */
  rswProof?: string;
}

/** Why a solve refused to run. */
export type KiwiSolveRefusal =
  | "malformed"
  | "difficulty-beyond-cap"
  | "unsupported-params"
  | "execution-unsupported"
  | "solver-unavailable";

/** The error this package rejects with. `refusal` is machine-readable. */
export class KiwiSolveError extends Error {
  readonly refusal: KiwiSolveRefusal;

  constructor(refusal: KiwiSolveRefusal, message: string) {
    super(message);
    this.name = "KiwiSolveError";
    this.refusal = refusal;
  }
}

/** The native module contract (docs/NATIVE.md is the authoritative spec). */
export interface NativeKiwiSolver {
  /**
   * Solve the challenge document (JSON string) and answer a JSON string
   * of the KiwiSolution shape, or reject with a message.
   */
  solve(challengeJson: string): Promise<string>;
}

/** Options of the orchestration entry point. */
export interface AcquireTokenOptions {
  /** Same-origin challenge endpoint URL. */
  endpoint: string;
  /** Security scope (login, signup, comment, ...). */
  scope: string;
  /** Optional public sitekey; rides the challenge request. */
  sitekey?: string;
  /** Request a non-default profile. */
  algorithm?: KiwiAlgorithm;
  /** Challenge fetch timeout in milliseconds. Default 15000. */
  fetchTimeoutMs?: number;
  /** The fetch implementation; defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** The native solver; defaults to the react-native bridge. */
  nativeSolver?: NativeKiwiSolver | null;
  /** Progress callback from the solver, when the platform reports one. */
  onProgress?: (info: { attempted: number }) => void;
}
