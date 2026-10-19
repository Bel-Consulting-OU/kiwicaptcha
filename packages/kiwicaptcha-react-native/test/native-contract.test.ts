/**
 * The native-contract reference suite.
 *
 * Nothing here mocks a native run. The `referenceNativeSolve` below is
 * a pure-JS MIRROR of exactly what the shipped native modules execute —
 * `android/src/main/java/com/kiwicaptcha/reactnative/KiwiSolverCore.kt`
 * and `ios/KiwiCaptchaSolver.swift` (`solveSync`) — written
 * independently against Node's own crypto so it pins the bridge
 * contract the sources must satisfy:
 *
 * - JSON string in, JSON string out (the NativeKiwiSolver wire shape);
 * - SHA-256 over `prefix || decimal(counter) || salt`: the prefix and
 *   the ASCII decimal counter as bytes, the salt as its decoded base64
 *   bytes, counter starting at 0;
 * - winner: first counter whose digest shows >= targetBits leading zero
 *   bits (big-endian bit order);
 * - bounded by the 20,000,000-hash cap with a typed EXHAUSTED refusal;
 * - typed refusals (MALFORMED / DIFFICULTY_BEYOND_CAP /
 *   UNSUPPORTED_ALGORITHM / EXECUTION_UNSUPPORTED) before any work;
 *   SHA-256 only — argon2id and rsw refuse.
 *
 * Feeding the reference through the JS dispatch proves the JS layer
 * accepts a conforming module byte-for-byte; the Kotlin and Swift
 * sources implement the same algorithm and are pinned against this
 * file by review (no Android/iOS toolchain runs in this suite).
 */
import { createHash } from "node:crypto";
import type { KiwiChallenge } from "../src/types.js";
import { KiwiSolveError } from "../src/types.js";
import { solve, solveSha256Low } from "../src/solve.js";
import type { MockKiwiSolver } from "./react-native-mock";
import { __setNativeSolver } from "./react-native-mock";

const PREFIX = "kiwi|login|";
const SALT = "AAECAw=="; // base64 of 00 01 02 03
const NONCE = "A".repeat(43) + "=";

/** The pinned shared vector (the main suite pins the same one). */
const SHARED_HASH_HEX =
  "00f9718e2a0397b3ca8fe75c44499fccee788e243173dadea546bd4e45af6982";
const SHARED_COUNTER = 45;

function shaChallenge(overrides: Partial<KiwiChallenge> = {}): KiwiChallenge {
  return {
    nonce: NONCE,
    salt: SALT,
    algorithm: "sha256",
    mKib: 0,
    t: 1,
    p: 1,
    targetBits: 8,
    prefix: PREFIX,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// The reference: a pure-JS mirror of KiwiSolverCore.kt / KiwiCaptchaSolver.swift
// ---------------------------------------------------------------------------

const MAX_HASHES = 20_000_000;
const SHA_MAX_TARGET_BITS = 20;

class NativeRefusal extends Error {
  constructor(
    readonly refusal: string,
    message: string,
  ) {
    super(message);
  }
}

/** Leading zero bits, big-endian bit order — mirrors the native helper. */
function leadingZeroBits(digest: Buffer): number {
  let count = 0;
  for (const byte of digest) {
    if (byte === 0) {
      count += 8;
      continue;
    }
    let m = byte;
    while ((m & 0x80) === 0) {
      count++;
      m <<= 1;
    }
    break;
  }
  return count;
}

/** The native loop, byte for byte. JSON string in, JSON string out. */
function referenceNativeSolve(
  challengeJson: string,
  onProgress?: (attempted: number) => void,
  maxHashes: number = MAX_HASHES,
): string {
  // -- parse + the client contract, re-checked before any work ---------
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(challengeJson) as Record<string, unknown>;
  } catch {
    throw new NativeRefusal("MALFORMED", "the challenge document is not valid JSON");
  }
  const str = (key: string): string => {
    const value = document[key];
    if (typeof value !== "string") {
      throw new NativeRefusal("MALFORMED", `the challenge ${key} is not a string`);
    }
    return value;
  };
  const executionProgram = document["execution_program"];
  if (typeof executionProgram === "string" && executionProgram.length > 0) {
    throw new NativeRefusal(
      "EXECUTION_UNSUPPORTED",
      "an execution-armed challenge needs the browser interpreter; the native path refuses it",
    );
  }
  const nonce = str("nonce");
  if (!/^[A-Za-z0-9+/]{43}=$/.test(nonce)) {
    throw new NativeRefusal("MALFORMED", "the nonce is not the standard base64 of 32 bytes");
  }
  const prefix = str("prefix");
  if (prefix.length < 1 || Buffer.byteLength(prefix, "utf8") > 4096) {
    throw new NativeRefusal("MALFORMED", "the prefix length is outside 1..=4096");
  }
  const saltText = str("salt");
  if (saltText.length < 1 || saltText.length > 512 || saltText.length % 4 !== 0) {
    throw new NativeRefusal("MALFORMED", "the salt is oversized, empty or not canonical base64");
  }
  let salt: Buffer;
  try {
    salt = Buffer.from(saltText, "base64");
  } catch {
    throw new NativeRefusal("MALFORMED", "the salt is not decodable base64");
  }
  const algorithm = str("algorithm");
  const targetBits = document["targetBits"];
  if (typeof targetBits !== "number" || !Number.isInteger(targetBits)) {
    throw new NativeRefusal("MALFORMED", "the challenge targetBits is not an integer");
  }
  switch (algorithm) {
    case "sha256":
      if (targetBits < 1 || targetBits > SHA_MAX_TARGET_BITS) {
        throw new NativeRefusal(
          "DIFFICULTY_BEYOND_CAP",
          `target_bits ${targetBits} exceeds the sha256 solver cap ${SHA_MAX_TARGET_BITS}`,
        );
      }
      break;
    // SHA-256 only, like the shipped modules: argon2id and rsw refuse.
    case "argon2id":
    case "rsw":
      throw new NativeRefusal(
        "UNSUPPORTED_ALGORITHM",
        `${algorithm} is not implemented in the KiwiCaptchaSolver native module (SHA-256 only)`,
      );
    default:
      throw new NativeRefusal("MALFORMED", "the algorithm is not one of sha256, argon2id, rsw");
  }

  // -- the search: prefix || decimal(counter) || salt, counter from 0 --
  const prefixBytes = Buffer.from(prefix, "utf8");
  const startedAt = Date.now();
  let lastReportAt = 0;
  for (let counter = 0; counter < maxHashes; counter++) {
    const digest = createHash("sha256")
      .update(prefixBytes)
      .update(Buffer.from(String(counter), "ascii"))
      .update(salt)
      .digest();
    if (leadingZeroBits(digest) >= targetBits) {
      onProgress?.(counter + 1);
      return JSON.stringify({
        counter,
        durationMs: Date.now() - startedAt,
        hashHex: digest.toString("hex"),
      });
    }
    // Bounded cadence, mirroring the native core: at most one report
    // per 1024 attempts AND 100 ms — never once per hash.
    if (onProgress && (counter + 1) % 1024 === 0) {
      const now = Date.now();
      if (now - lastReportAt >= 100) {
        lastReportAt = now;
        onProgress(counter + 1);
      }
    }
  }
  throw new NativeRefusal(
    "EXHAUSTED",
    `no counter met the target within the ${maxHashes}-hash cap`,
  );
}

/** Sentinel duration: proves the answer came through the bridge shape. */
function markNative(answer: string): string {
  const parsed = JSON.parse(answer) as Record<string, unknown>;
  return JSON.stringify({ ...parsed, durationMs: 4321 });
}

/** The reference wired as a conforming NativeKiwiSolver stand-in. */
function referenceModule(maxHashes: number = MAX_HASHES): MockKiwiSolver {
  return {
    solve: async (json) => markNative(referenceNativeSolve(json, undefined, maxHashes)),
    solveWithProgress: async (json, onProgress) =>
      markNative(referenceNativeSolve(json, (a) => onProgress({ attempted: a }), maxHashes)),
  };
}

// ---------------------------------------------------------------------------

beforeEach(() => {
  __setNativeSolver(null);
});

/** The typed refusal code a reference call rejected with (the bridge
 * carries code and message separately, like the native modules do). */
function refusalOf(fn: () => void): string {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(NativeRefusal);
    return (err as NativeRefusal).refusal;
  }
  throw new Error("expected the reference solve to refuse");
}

describe("native-contract reference (pure-JS mirror of the Kotlin/Swift native loop; NOT a mock of a native run)", () => {
  it("solves the shared vector at the same counter with the same digest", () => {
    const answer = JSON.parse(
      referenceNativeSolve(JSON.stringify(shaChallenge({ targetBits: 8 }))),
    ) as { counter: number; durationMs: number; hashHex: string };
    expect(answer.counter).toBe(SHARED_COUNTER);
    expect(answer.hashHex).toBe(SHARED_HASH_HEX);
    expect(typeof answer.durationMs).toBe("number");
  });

  it("agrees byte-for-byte with the pure-TS fallback on the shared vector", () => {
    const answer = JSON.parse(
      referenceNativeSolve(JSON.stringify(shaChallenge({ targetBits: 8 }))),
    ) as { counter: number; hashHex: string };
    const fallback = solveSha256Low(shaChallenge({ targetBits: 8 }));
    expect(fallback).not.toBeNull();
    expect(fallback?.counter).toBe(answer.counter);
    expect(fallback?.hashHex).toBe(answer.hashHex);
  });

  it("refuses argon2id and rsw with the typed UNSUPPORTED_ALGORITHM code", () => {
    expect(
      refusalOf(() =>
        referenceNativeSolve(
          JSON.stringify(
            shaChallenge({ algorithm: "argon2id", targetBits: 5, mKib: 64, t: 3 }),
          ),
        ),
      ),
    ).toBe("UNSUPPORTED_ALGORITHM");
    expect(
      refusalOf(() =>
        referenceNativeSolve(
          JSON.stringify(shaChallenge({ algorithm: "rsw", t: 10000, rsw_modulus: "AA==AA==" })),
        ),
      ),
    ).toBe("UNSUPPORTED_ALGORITHM");
  });

  it("throws the typed EXHAUSTED refusal when the cap closes before a hit", () => {
    // "////" has no winner inside the first 256 counters (the main
    // suite pins that), so a 256-hash cap must exhaust.
    expect(
      refusalOf(() =>
        referenceNativeSolve(JSON.stringify(shaChallenge({ salt: "////" })), undefined, 256),
      ),
    ).toBe("EXHAUSTED");
  });

  it("refuses out-of-contract documents before spending any work", () => {
    expect(
      refusalOf(() =>
        referenceNativeSolve(
          JSON.stringify(shaChallenge({ targetBits: SHA_MAX_TARGET_BITS + 1 })),
        ),
      ),
    ).toBe("DIFFICULTY_BEYOND_CAP");
    expect(
      refusalOf(() =>
        referenceNativeSolve(JSON.stringify(shaChallenge({ execution_program: "YXJtZWQ=" }))),
      ),
    ).toBe("EXECUTION_UNSUPPORTED");
    expect(refusalOf(() => referenceNativeSolve(JSON.stringify(shaChallenge({ nonce: "short" }))))).toBe(
      "MALFORMED",
    );
    expect(
      refusalOf(() => referenceNativeSolve(JSON.stringify({ algorithm: "sha256", targetBits: 8 }))),
    ).toBe("MALFORMED");
  });
});

describe("JS dispatch against a conforming module (the reference wired through the bridge shape)", () => {
  it("prefers the native module for a low-difficulty sha256 challenge", async () => {
    __setNativeSolver(referenceModule());
    const solution = await solve(shaChallenge({ targetBits: 8 }));
    expect(solution.counter).toBe(SHARED_COUNTER);
    expect(solution.hashHex).toBe(SHARED_HASH_HEX);
    // The sentinel duration proves the bridge-shape module answered
    // (the JS fallback would report its own wall-clock duration).
    expect(solution.durationMs).toBe(4321);
  });

  it("falls back cleanly to the pure-TS loop when no native module is linked", async () => {
    const solution = await solve(shaChallenge({ targetBits: 8 }));
    expect(solution.counter).toBe(SHARED_COUNTER);
    expect(solution.hashHex).toBe(SHARED_HASH_HEX);
  });

  it("falls back to the pure-TS loop when the native solve fails inside the low window", async () => {
    __setNativeSolver({
      solve: async () => Promise.reject(new Error("native crash")),
    });
    const solution = await solve(shaChallenge({ targetBits: 8 }));
    expect(solution.counter).toBe(SHARED_COUNTER);
    expect(solution.hashHex).toBe(SHARED_HASH_HEX);
  });

  it("surfaces a typed argon2id refusal from a linked module as solver-unavailable", async () => {
    __setNativeSolver(referenceModule());
    const error = await solve(
      shaChallenge({ algorithm: "argon2id", targetBits: 5, mKib: 64, t: 3 }),
    ).then(
      () => null,
      (err: unknown) => err,
    );
    expect(error).toBeInstanceOf(KiwiSolveError);
    expect((error as KiwiSolveError).refusal).toBe("solver-unavailable");
  });

  it("reports start and final progress through the reference progress channel", async () => {
    __setNativeSolver(referenceModule());
    const events: number[] = [];
    await solve(shaChallenge({ targetBits: 8 }), {
      onProgress: (info) => events.push(info.attempted),
    });
    // The native cadence (1024 attempts) is never reached before the
    // hit at counter 45: start plus the forced winning report only.
    expect(events).toEqual([0, SHARED_COUNTER + 1]);
  });
});
