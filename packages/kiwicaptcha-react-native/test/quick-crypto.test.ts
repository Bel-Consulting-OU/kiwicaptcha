/**
 * The optional `react-native-quick-crypto` peer is a lazy, guarded
 * require, so this suite injects a virtual module before the solver is
 * loaded. The injected createHash is a faithful streaming SHA-256
 * (backed by the package's own pure implementation), which lets the
 * suite prove two things at once: the branch is actually taken
 * (createHash is called) and it produces the exact digest the pure-TS
 * path produces.
 */
jest.mock(
  "react-native-quick-crypto",
  () => {
    const pure = jest.requireActual("../src/sha256") as typeof import("../src/sha256");
    return {
      createHash: jest.fn(() => {
        const chunks: Uint8Array[] = [];
        return {
          update(bytes: Uint8Array) {
            chunks.push(new Uint8Array(bytes));
            return this;
          },
          digest() {
            return pure.sha256(chunks);
          },
        };
      }),
    };
  },
  { virtual: true },
);

import type { KiwiChallenge } from "../src/types.js";
import { resetQuickCryptoCache, solveSha256Low } from "../src/solve.js";

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

type QuickCryptoMock = { createHash: jest.Mock };

beforeEach(() => {
  resetQuickCryptoCache();
  jest.clearAllMocks();
});

describe("optional quick-crypto branch", () => {
  it("takes the branch and produces the same digest as the pure-TS path", () => {
    const quick = jest.requireMock("react-native-quick-crypto") as QuickCryptoMock;
    const solution = solveSha256Low(shaChallenge());
    expect(quick.createHash).toHaveBeenCalled();
    expect(quick.createHash).toHaveBeenCalledWith("sha256");
    expect(solution?.counter).toBe(45);
    // The pinned pure-TS digest from the main suite.
    expect(solution?.hashHex).toBe(
      "00f9718e2a0397b3ca8fe75c44499fccee788e243173dadea546bd4e45af6982",
    );
  });

  it("uses the peer for every attempt up to the winning counter", () => {
    const quick = jest.requireMock("react-native-quick-crypto") as QuickCryptoMock;
    const solution = solveSha256Low(shaChallenge());
    expect(solution?.counter).toBe(45);
    // Counters 0..45 ran through the quick-crypto hasher; the hit at 45
    // ended the search.
    expect(quick.createHash).toHaveBeenCalledTimes(46);
  });
});
