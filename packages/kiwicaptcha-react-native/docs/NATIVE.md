# Native solver module contract

The `@kiwicaptcha/react-native` package performs every proof of work on
a native thread. There is no WebView and no JavaScript-thread search
above the low-difficulty ceiling. This document is the contract the
iOS and Android modules implement; the JS side reads them through the
React Native bridge as `NativeModules.KiwiCaptchaSolver`.

The algorithm, caps and token grammar are shared with the reference
implementations, never forked: `packages/kiwicaptcha-solver` (Rust) is
the normative solver, `protocol/limits.json` the normative caps.

## JS-side lookup

```ts
import { NativeModules } from "react-native";
const solver = NativeModules.KiwiCaptchaSolver; // may be undefined
```

A missing module is a fail-closed condition: argon2id and rsw reject
with `KiwiSolveError` (`refusal: "solver-unavailable"`), and sha256
above the low-difficulty ceiling (8 bits) rejects the same way. sha256
at or below 8 bits runs in JS through the optional
`react-native-quick-crypto` peer (or the bundled pure-TS SHA-256) and
never needs the module.

## Module interface

One asynchronous method, JSON in, JSON out, strings across the bridge:

```
KiwiCaptchaSolver.solve(challengeJson: string): Promise<string>
```

`challengeJson` is the exact challenge document the challenge endpoint
returned (validated by the JS side first). The answer is a JSON string
of the `KiwiSolution` shape:

```json
{
  "counter": 45,
  "durationMs": 120,
  "hashHex": "00f9718e...6982",
  "rswProof": null
}
```

`counter` is the winning search counter (0 for rsw), `durationMs` the
wall-clock solve duration, `hashHex` the winning 64-hex digest
(informational), `rswProof` the 512-hex final value for rsw solves and
`null` otherwise. The promise rejects (or answers a JSON object with an
`error` key) when the challenge is refused; the JS side maps every
rejection to `solver-unavailable`.

## Caps the module must enforce

The module re-checks the client contract before spending work, exactly
like the Rust solver does. Refuse, never degrade:

- nonce: 44 chars, standard base64 of 32 bytes.
- prefix: 1..=4096 bytes. salt: decodable base64, 1..=512 chars.
- sha256: 1 <= targetBits <= 20; search `prefix || decimal(counter) ||
  salt` (counter from 0), cap 20,000,000 hashes.
- argon2id: 1 <= targetBits <= 10, m_kib in 8..=65536 with
  m_kib >= 8 * p, t in 3..=6, p == 1; password `prefix ||
  decimal(counter)`, the issued salt and parameters.
- rsw: t in 10000..=300000, p == 1, m_kib == 0, modulus exactly 256
  bytes with the top bit set and the low bit odd; T sequential modular
  squarings of SHA-256(prefix || nonce) mod n.
- `execution_program` present: refuse. The browser interpreter is
  outside the native path.

## iOS module (Swift)

```swift
@objc(KiwiCaptchaSolver)
final class KiwiCaptchaSolver: NSObject {
  @objc(solve:resolver:rejecter:)
  func solve(
    _ challengeJson: String,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    DispatchQueue.global(qos: .userInitiated).async {
      do {
        let solution = try KiwiSolver().solve(challengeJson: challengeJson)
        resolve(String(data: JSONEncoder().encode(solution), encoding: .utf8))
      } catch {
        reject("solve_failed", String(describing: error), nil)
      }
    }
  }
}
```

The solve core is `packages/kiwicaptcha-ios` (SwiftPM): SHA-256 via
CryptoKit, rsw via its internal bignum, argon2id fail-closed (the
iOS package refuses argon2id honestly rather than shipping a weak
implementation; link a vetted C implementation to lift that).

## Android module (Kotlin)

```kotlin
class KiwiCaptchaSolverModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {
  override fun getName() = "KiwiCaptchaSolver"

  @ReactMethod
  fun solve(challengeJson: String, promise: Promise) {
    task { // a background executor, never the UI thread
      try {
        promise.resolve(KiwiSolver().solveJson(challengeJson))
      } catch (t: Throwable) {
        promise.reject("solve_failed", t.message, t)
      }
    }
  }
}
```

The solve core is `packages/kiwicaptcha-android`: SHA-256 via
`java.security.MessageDigest`, rsw via `java.math.BigInteger`,
argon2id fail-closed for the same reason as iOS.

## Expo

The modules are classic Native Modules; an Expo config plugin (or a
development build with `expo-modules-autolinking` aware pods/gradle
files) exposes them. Expo Go cannot carry native modules, so Expo Go
sessions run in the fail-closed mode: low-difficulty sha256 only, and
the error names the missing module honestly.
