import {
  KIWI_MAX_ARGON2_M_KIB,
  KIWI_MAX_ARGON2_TARGET_BITS,
  KIWI_MAX_TARGET_BITS,
  KiwiSolveError,
  type KiwiChallenge,
} from "../src/types.js";
import { validateChallenge } from "../src/validate.js";
import { encodeToken } from "../src/token.js";
import {
  LOW_DIFFICULTY_MAX_BITS,
  resetQuickCryptoCache,
  solve,
  solveSha256Low,
} from "../src/solve.js";
import { hex, leadingZeroBits, sha256 } from "../src/sha256.js";
import { acquireToken, verifyRequest } from "../src/acquire.js";
import { __setNativeSolver } from "./react-native-mock";

const PREFIX = "kiwi|login|";
const SALT = "AAECAw==";
const NONCE = "A".repeat(43) + "=";

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

beforeEach(() => {
  __setNativeSolver(null);
  resetQuickCryptoCache();
});

describe("sha256 primitive", () => {
  it("matches the standard vectors", () => {
    const enc = (s: string) => new TextEncoder().encode(s) as Uint8Array;
    expect(hex(sha256([enc("abc")]))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(hex(sha256([enc("")]))) .toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    // A two-chunk concatenation equals the single-chunk digest.
    expect(hex(sha256([enc("ab"), enc("c")]))).toBe(hex(sha256([enc("abc")])));
  });

  it("counts leading zero bits in big-endian order", () => {
    expect(leadingZeroBits(new Uint8Array([0, 0, 1]))).toBe(23);
    expect(leadingZeroBits(new Uint8Array([0x80]))).toBe(0);
    expect(leadingZeroBits(new Uint8Array([0x0f]))).toBe(4);
  });
});

describe("token assembly", () => {
  it("packs the documented grammar and base64", () => {
    const token = encodeToken({
      nonce: NONCE,
      counter: 78,
      durationMs: 1200,
      telemetry: { t: "t" },
    });
    const plain = Buffer.from(token, "base64").toString("utf8");
    expect(plain).toBe(`${NONCE}.78.1200.{"t":"t"}`);
    // Canonical padded base64 round-trips byte-exactly.
    expect(Buffer.from(plain).toString("base64")).toBe(token);
  });

  it("appends the rsw proof as the final 512-hex segment", () => {
    const proof = "ab".repeat(256);
    const token = encodeToken({
      nonce: NONCE,
      counter: 0,
      durationMs: 900,
      rswProof: proof,
    });
    expect(Buffer.from(token, "base64").toString("utf8").endsWith(`.${proof}`)).toBe(true);
  });

  it("refuses a malformed rsw proof", () => {
    expect(() =>
      encodeToken({ nonce: NONCE, counter: 0, durationMs: 1, rswProof: "xyz" }),
    ).toThrow(/512 lowercase hex/);
  });

  it("clamps the duration to the wire ceiling", () => {
    const token = encodeToken({ nonce: NONCE, counter: 1, durationMs: 9_999_999 });
    expect(Buffer.from(token, "base64").toString("utf8")).toContain(".1.3600000.");
  });
});

describe("challenge validation", () => {
  it("accepts a well-formed sha256 challenge", () => {
    expect(validateChallenge(shaChallenge()).prefix).toBe(PREFIX);
  });

  it("refuses a broken nonce, salt, prefix or algorithm", () => {
    expect(() => validateChallenge(shaChallenge({ nonce: "short" }))).toThrow(KiwiSolveError);
    expect(() => validateChallenge(shaChallenge({ salt: "not=b64!" }))).toThrow(KiwiSolveError);
    expect(() => validateChallenge(shaChallenge({ prefix: "" }))).toThrow(KiwiSolveError);
    expect(() =>
      validateChallenge(shaChallenge({ algorithm: "scrypt" as never })),
    ).toThrow(/algorithm/);
  });

  it("refuses difficulty above the shared caps", () => {
    expect(() => validateChallenge(shaChallenge({ targetBits: KIWI_MAX_TARGET_BITS + 1 })))
      .toThrow(/sha256 cap/);
    expect(() =>
      validateChallenge(shaChallenge({ algorithm: "argon2id", targetBits: KIWI_MAX_ARGON2_TARGET_BITS + 1, mKib: 8, t: 3 })),
    ).toThrow(/argon2id cap/);
  });

  it("refuses out-of-contract argon2id parameters", () => {
    expect(() =>
      validateChallenge(
        shaChallenge({ algorithm: "argon2id", targetBits: 5, mKib: KIWI_MAX_ARGON2_M_KIB + 1, t: 3 }),
      ),
    ).toThrow(/client contract/);
    expect(() =>
      validateChallenge(shaChallenge({ algorithm: "argon2id", targetBits: 5, mKib: 64, t: 2 })),
    ).toThrow(/client contract/);
    expect(() =>
      validateChallenge(shaChallenge({ algorithm: "argon2id", targetBits: 5, mKib: 64, t: 3, p: 2 })),
    ).toThrow(/client contract/);
  });

  it("refuses out-of-contract rsw and a bad modulus shape", () => {
    expect(() => validateChallenge(shaChallenge({ algorithm: "rsw", t: 9999 }))).toThrow(
      /client contract/,
    );
    expect(() =>
      validateChallenge(shaChallenge({ algorithm: "rsw", t: 10000, rsw_modulus: "AAAA" })),
    ).toThrow(/modulus/);
  });

  it("refuses execution-armed challenges outright", () => {
    expect(() =>
      validateChallenge(shaChallenge({ execution_program: "YXJtZWQgcHJvZ3JhbQ==",
      })),
    ).toThrow(/interpreter/);
  });
});

describe("solver dispatch", () => {
  it("solves a low-difficulty sha256 challenge on the JS thread", () => {
    const solution = solveSha256Low(shaChallenge({ targetBits: 8 }));
    expect(solution).not.toBeNull();
    expect(solution?.counter).toBe(45);
    expect(solution?.hashHex).toBe("00f9718e2a0397b3ca8fe75c44499fccee788e243173dadea546bd4e45af6982");
  });

  it("returns null when the low window misses", () => {
    // Counter 45 meets targetBits 8 inside the 2^8 window.
    const solution = solveSha256Low(
      shaChallenge({ targetBits: LOW_DIFFICULTY_MAX_BITS, prefix: PREFIX, salt: SALT }),
    );
    expect(solution?.counter).toBe(45);
    // A different salt with no hit inside the first 256 counters.
    expect(solveSha256Low(shaChallenge({ targetBits: 8, salt: "////" }))).toBeNull();
  });

  it("fails closed above the low ceiling with no native module", async () => {
    await expect(solve(shaChallenge({ targetBits: 12 }))).rejects.toThrow(
      /above the low-difficulty ceiling/,
    );
  });

  it("delegates above-ceiling solves to the native module", async () => {
    __setNativeSolver({
      solve: async (json) => {
        const challenge = JSON.parse(json) as KiwiChallenge;
        expect(challenge.targetBits).toBe(12);
        return JSON.stringify({ counter: 4096, durationMs: 55, hashHex: "ff".repeat(32) });
      },
    });
    const solution = await solve(shaChallenge({ targetBits: 12 }));
    expect(solution.counter).toBe(4096);
  });

  it("routes argon2id and rsw to the native module only", async () => {
    await expect(
      solve(shaChallenge({ algorithm: "argon2id", targetBits: 5, mKib: 64, t: 3 })),
    ).rejects.toThrow(/native module/);

    const rswProof = "cd".repeat(256);
    __setNativeSolver({
      solve: async () => JSON.stringify({ counter: 0, durationMs: 8000, rswProof }),
    });
    const solution = await solve(
      shaChallenge({
        algorithm: "rsw",
        t: 10000,
        rsw_modulus: modulusB64(),
      }),
    );
    expect(solution.rswProof).toBe(rswProof);
  });

  it("rejects a malformed native answer", async () => {
    __setNativeSolver({ solve: async () => "not-json" });
    await expect(solve(shaChallenge({ targetBits: 12 }))).rejects.toThrow(/non-JSON/);
    __setNativeSolver({ solve: async () => JSON.stringify({}) });
    await expect(solve(shaChallenge({ targetBits: 12 }))).rejects.toThrow(/malformed/);
  });

  it("reports native failures as solver-unavailable", async () => {
    __setNativeSolver({ solve: async () => Promise.reject(new Error("oom")) });
    await expect(solve(shaChallenge({ targetBits: 12 }))).rejects.toThrow(/refused or failed/);
  });
});

describe("acquireToken orchestration", () => {
  it("runs the full flow: POST, validate, solve, pack", async () => {
    const fetchImpl = jest.fn(async (_url: string | URL, init?: RequestInit) => {
      expect(init?.method).toBe("POST");
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body["scope"]).toBe("login");
      expect(body["sitekey"]).toBe("pk-rn");
      return new Response(JSON.stringify(shaChallenge()), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const token = await acquireToken({
      endpoint: "https://api.example.com/kcaptcha/challenge",
      scope: "login",
      sitekey: "pk-rn",
      fetchImpl,
    });
    const plain = Buffer.from(token, "base64").toString("utf8");
    expect(plain.startsWith(`${NONCE}.45.`)).toBe(true);
  });

  it("refuses a non-200 endpoint answer", async () => {
    const fetchImpl = jest.fn(async () => new Response("no", { status: 500 })) as unknown as typeof fetch;
    await expect(
      acquireToken({ endpoint: "https://x/kc", scope: "login", fetchImpl }),
    ).rejects.toThrow(/answered 500/);
  });

  it("refuses a challenge document that fails validation", async () => {
    const fetchImpl = jest.fn(
      async () => new Response(JSON.stringify({ hello: 1 }), { status: 200 }),
    ) as unknown as typeof fetch;
    await expect(
      acquireToken({ endpoint: "https://x/kc", scope: "login", fetchImpl }),
    ).rejects.toThrow(KiwiSolveError);
  });
});

describe("verifyRequest", () => {
  it("builds the provider-shaped siteverify body", () => {
    const { body } = verifyRequest("s3cret", "tok", "203.0.113.9");
    expect(JSON.parse(body)).toEqual({ secret: "s3cret", response: "tok", remoteip: "203.0.113.9" });
    const minimal = verifyRequest("s3cret", "tok");
    expect(JSON.parse(minimal.body)).toEqual({ secret: "s3cret", response: "tok" });
  });
});

/** A canonical 2048-bit odd composite for rsw tests (not a real trapdoor). */
function modulusB64(): string {
  // (2^1023 + 1) * (2^1023 + 3): 2048 bits, top bit set, odd.
  const a = (1n << 1023n) + 1n;
  const b = (1n << 1023n) + 3n;
  const n = a * b;
  const bytes = new Uint8Array(256);
  let v = n;
  for (let i = 255; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return Buffer.from(bytes).toString("base64");
}
