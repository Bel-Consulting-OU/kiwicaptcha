# KiwiCaptcha (Swift, Swift Package)

The native iOS KiwiCaptcha client: SwiftUI and UIKit widgets plus the
proof-of-work solver core, at the browser's own price and inside the
browser's own caps. The challenge/verify wire contract is the shared
one: POST the challenge request, solve (SHA-256 search, the Argon2id
ladder or the rsw time lock), pack the wire token, and hand siteverify
to your backend.

## Install (SPM)

```swift
.package(url: "https://github.com/kiwicaptcha/kiwicaptcha-ios", from: "0.1.0")
```

Targets: `KiwiCaptcha` (library) and `kiwi-selftest` (executable).

## SwiftUI

```swift
import KiwiCaptcha

struct LoginView: View {
    var body: some View {
        KiwiCaptchaView(
            endpoint: URL(string: "https://api.example.com/api/kcaptcha/challenge")!,
            scope: "login",
            sitekey: nil,
            onVerify: { token in submit(token) },
            onError: { message in print("failed: \(message)") },
            onExpire: {})
    }
}
```

The view acquires and solves on appear, shows state and progress, and
exposes a Retry button after a failure or expiry.

## UIKit

```swift
let widget = KiwiCaptchaUIView(
    client: KiwiClient(endpoint: challengeURL, sitekey: sitekey),
    scope: "login")
widget.onVerify = { token in self.tokenField.text = token }
widget.start()  // safe to call again; the previous run is cancelled
```

## Solver (headless, tests, extensions)

```swift
let client = KiwiClient(endpoint: challengeURL)
let challenge = try await client.fetchChallenge(scope: "login")
let solution = try KiwiSolver.solve(challenge: challenge)
let token = KiwiToken.encode(challenge: challenge, solution: solution)
```

`KiwiSolver.solve` validates the client contract first (the same caps
as the widget and the Rust solver, from protocol/limits.json) and
refuses: execution-armed challenges (the browser interpreter is outside
the native path), argon2id parameters outside the shared profile (m
outside 8..=65536 KiB, p != 1, or t outside 3..=6), and rsw or SHA-256
challenges outside the shared bounds.

The SHA-256 search comes from CryptoKit. The rsw time lock runs on this
package's own fixed-width bignum (`Rsw.swift`, 32-bit limbs, the
interleaved CIOS Montgomery loop with a proven per-round bound), and
its wire form is pinned to an externally computed vector in the tests.
Argon2id runs on the vendored reference C implementation (`CArgon2`,
the phc-winner-argon2 20190702 sources, dual-licensed Apache-2.0/CC0,
vendored unmodified under `Sources/CArgon2` with the license and a
provenance notice): the package never ships a home-grown memory-hard
function, and the suites pin the RFC 9106 section 5.3 vector plus a
PHP-libsodium cross-checked derivation.

## Tests

- `swift test` runs the XCTest suite under a full Xcode toolchain.
- `swift run kiwi-selftest` runs the same vectors as a plain
  executable, for toolchains without XCTest (this repository's CI
  runners). It exits non-zero on any failure.

The two suites pin identical vectors: SHA-256 (CryptoKit cross-check),
base64, token grammar bytes, the SHA-256 search counter for a fixed
challenge, the validation refusals, the argon2id RFC 9106 section 5.3
tag, the argon2id solve matched byte-for-byte against PHP's libsodium,
the rsw proof for the composite (2^1023 + 1)(2^1023 + 3) * 3 at
T = 10000 (computed independently with node's BigInt), and the
siteverify body shape.

## What runs where

| Challenge | Path |
| --- | --- |
| sha256 | CryptoKit search on the calling thread (cap 20,000,000) |
| argon2id | vendored reference C (`CArgon2`), m 8..65536 KiB, single lane |
| rsw | internal bignum, T sequential squarings |
| execution_program | refused, `.executionUnsupported` |

The React Native bridge (`packages/kiwicaptcha-react-native`) calls
into this package's solver core through the module contract in its
docs/NATIVE.md.
