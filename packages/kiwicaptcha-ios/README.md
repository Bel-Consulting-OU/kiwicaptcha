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

The challenge POST carries the capability header
`Kiwi-Execution-Max-Version: 0`: the native client runs no execution
interpreter, and the endpoint must not arm `execution_program` against
it.

### Cancellation (cooperative, bounded latency)

`KiwiSolver.solve(challenge:isCancelled:)` takes a cancellation probe
(defaulted to `{ false }`, so existing call sites compile unchanged).
The probe is checked at bounded-latency checkpoints, and once it fires
no further CPU work is spent:

| Search | Checkpoint | Worst-case latency |
| --- | --- | --- |
| sha256 | every 2048 candidates | 2048 hashes |
| argon2id | between candidate derivations | one derivation |
| rsw | every 256 squarings | 256 Montgomery multiplications |

Firing the probe throws the typed `KiwiSolveError.cancelled`.

### Lifecycle (Interactive-Client v1)

The widget implements the shared Interactive-Client Lifecycle v1
contract (protocol/interactive-client-v1/lifecycle-vectors.json):

- `receivedAtMs` is captured immediately after the challenge JSON
  parses. Every clock — expiry and min-submit alike — starts there,
  never after solving.
- `expiresAtMs = receivedAtMs + ttlSecs*1000 - 1000`: a fixed 1 s
  safety margin. The expiry timer is armed at parse time, so it races
  the solve; a solve that outlives the deadline is invalidated at its
  next checkpoint and can never deliver.
- `minSubmitAtMs = receivedAtMs + minDurationMs`: a solve finishing
  early is held (cancellably) to the floor before `onVerify` fires.
  `minSubmitAtMs >= expiresAtMs` means the token would land at or
  after the deadline, so it is never delivered.
- Only the newest generation emits: a restart, a teardown or the
  expiry deadline advances the generation counter, every earlier
  generation's probe fires at its next checkpoint, and superseded
  results are discarded.

The clock arithmetic lives in one pure helper,
`KiwiLifecycle.deliveryDecision(receivedAtMs:ttlSecs:minDurationMs:
solveFinishedAtMs:nowMs) -> (deliver, deliverAtMs, reason)`, with
reasons `"deliver" | "defer" | "expired" | "cancelled"` ("cancelled"
is the caller-side case for a solve stopped at a probe checkpoint).
Every client is tested against the shared vectors file; this package
asserts it in both the XCTest suite and `kiwi-selftest`.

The proof of work runs detached at `.userInitiated` priority — the
SHA search, the argon2id derivations and the rsw squarings are pure
CPU and never execute on the main thread; only UI state updates hop
back through `MainActor.run`, so the host app stays responsive during
argon/rsw challenges.

### Accessibility

The UIKit control does not collapse itself into a single accessibility
element. The Retry button stays a real, reachable button (label
"Retry"), the status label is the live region (`updatesFrequently`,
label "Security check status", value tracking the state word), the
progress bar reports label and percentage, and attention-worthy
transitions (verified, failed, expired) are announced through
`UIAccessibility.post(.announcement)`.

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
T = 10000 (computed independently with node's BigInt), the siteverify
body shape, the solver's cooperative-cancellation probe (typed
`.cancelled` at each checkpoint family), and the Interactive-Client
Lifecycle v1 delivery-decision vectors read from
`protocol/interactive-client-v1/lifecycle-vectors.json` — the same
shared file every client is gated on. The widget suites (restart
cancellation, superseded-generation suppression, min-submit delivery
gating, parse-anchored expiry, accessibility wiring) run wherever
UIKit is importable.

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
