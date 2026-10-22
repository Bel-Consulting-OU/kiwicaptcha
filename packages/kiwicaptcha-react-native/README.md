# @kiwicaptcha/react-native

React Native KiwiCaptcha client: the proof of work runs on a NATIVE
thread through the platform solver module shipped in this package —
`android/` (Kotlin, MessageDigest SHA-256 on a background executor) and
`ios/` (Swift, CryptoKit SHA-256 on a background queue) — no WebView,
no JavaScript-thread search above the low-difficulty ceiling. The
package also carries the JS orchestration (challenge fetch, validation,
dispatch, token assembly); docs/NATIVE.md is the bridge contract. Expo
works through a development build; Expo Go sessions run fail-closed
(low-difficulty sha256 only, with the missing module named honestly in
the error).

## The four-setting quickstart

```ts
import { acquireToken } from "@kiwicaptcha/react-native";

const token = await acquireToken({
  endpoint: "https://api.example.com/api/kcaptcha/challenge", // 1
  sitekey: "pk-mobile-1",                                     // 2
  scope: "login",                                             // 3
  fetchTimeoutMs: 15000,                                      // (lang is the server's per-request scope policy)
});
// token rides the app's authenticated request; the backend verifies.
```

## Solver dispatch

- When the shipped `KiwiCaptchaSolver` module is linked, every
  challenge goes native (the module runs the exact shared contract, so
  answers are byte-identical to the JS loop); argon2id and rsw are
  refused by the module with a typed code and surface as
  `solver-unavailable`.
- With no module linked, sha256 at 8 bits or fewer runs on the JS
  thread through the optional `react-native-quick-crypto` peer (or the
  bundled pure-TS SHA-256); everything harder fails CLOSED, never to a
  weaker profile. A native failure on an in-window sha256 challenge
  retries the same profile on the JS thread.
- An absent module is a fail-closed condition: `KiwiSolveError` with
  `refusal: "solver-unavailable"` names what is missing.
- Execution-armed challenges are refused outright (the browser
  interpreter is outside the native path).

Argon2id status: the `packages/kiwicaptcha-ios` SwiftPM package
implements Argon2id (vendored reference C implementation);
`packages/kiwicaptcha-android` and this package's native modules are
SHA-256 only and refuse argon2id honestly (docs/NATIVE.md has the full
per-platform table).

`acquireToken` POSTs the challenge request, validates the document
with the exact caps the browser driver enforces, dispatches, and packs
the wire token (base64 of nonce.counter.duration.telemetry, rsw proof
as the final 512-hex segment). Verification stays server-to-server.

## Interactive-client lifecycle

The package implements the Interactive-Client Lifecycle v1 delivery
gate (protocol/interactive-client-v1): the expiry clock anchors at
challenge-parse time, a solve that finishes after the deadline is
refused with the typed `expired` refusal (the token is never handed
out), and a solve that beat the minimum-duration floor waits out the
floor before the token is packed. The pure decision
(`deliveryDecision` / `expiresAtMs` / `minSubmitAtMs`) mirrors the
Android reference and is pinned by every vector in
`protocol/interactive-client-v1/lifecycle-vectors.json`.

## Tests

`npm test` runs the Jest suite (ts-jest, `react-native` mapped onto a
controllable mock): the SHA-256 vectors, the token grammar, the
validation refusals, the low-difficulty solve against a pinned
counter, native dispatch and malformed-answer handling, bounded
`onProgress` reporting on both solver paths, the optional
`react-native-quick-crypto` branch, the full acquireToken flow against
a mocked fetch, the lifecycle vectors against the delivery gate (plus
the wired floor-wait and typed-expired probes), the siteverify body,
and the native-contract reference
(a pure-JS mirror of the shipped Kotlin/Swift loop pinned to the
shared vector — not a mock of a native run).
`npm run typecheck` runs the strict `tsc --noEmit`.
