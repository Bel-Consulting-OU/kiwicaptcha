# Native solver modules

The `@kiwicaptcha/react-native` package ships real native modules for
both platforms, in this package:

- `android/` — Kotlin. `KiwiSolverPackage` (a classic `ReactPackage`)
  registers `KiwiCaptchaSolverModule`, which runs the SHA-256 search
  over `java.security.MessageDigest` on the module's own background
  executor.
- `ios/` — Swift + a tiny Obj-C bridge. `KiwiCaptchaSolver`
  (`@objc(KiwiCaptchaSolver)`) runs the SHA-256 search over CryptoKit on
  a serial background queue; `KiwiCaptchaSolverBridge.m` registers it
  with `RCT_EXTERN_MODULE`, and `KiwiCaptchaSolver.podspec` is the pod.
- `src/native.ts` — the JS resolver that finds the module;
  `src/solve.ts` — the dispatch described below.

Every proof of work runs on a native thread when the module is linked.
There is no WebView, and no JavaScript-thread search above the
low-difficulty ceiling. The algorithm, caps and token grammar are
shared with the reference implementations, never forked:
`packages/kiwicaptcha-solver` (Rust) is the normative solver,
`protocol/limits.json` the normative caps. The exact native behavior is
pinned by the Jest suite (`test/native-contract.test.ts`), which runs a
pure-JS mirror of the native loop against the shared vector.

## JS-side lookup

```ts
import { nativeSolver, NATIVE_MODULE_NAME } from "@kiwicaptcha/react-native";
// NATIVE_MODULE_NAME === "KiwiCaptchaSolver"
```

`nativeSolver()` consults `TurboModuleRegistry` first (the New
Architecture, including the legacy-module interop proxy RN 0.74+
serves classic `ReactPackage` modules through) and then
`NativeModules.KiwiCaptchaSolver` (the classic bridge). Both names are
the single bridge name `KiwiCaptchaSolver`, which is what both native
modules register under.

The solved-path split, exactly:

1. **Module linked** — every validated challenge goes native. sha256
   challenges are solved natively (background thread/queue, never the
   JS thread). argon2id and rsw are refused by the module with the
   `UNSUPPORTED_ALGORITHM` code, and the JS side rejects with
   `KiwiSolveError` (`refusal: "solver-unavailable"`). If the native
   solve of a sha256 challenge inside the low-difficulty window
   (8 bits or fewer) fails, the dispatch retries the same profile on
   the JS thread — never a weaker one.
2. **No module linked** — the pure-TS loop is the default for sha256
   at or below the low-difficulty ceiling (8 bits), through the
   optional `react-native-quick-crypto` peer or the bundled pure-TS
   SHA-256. Everything else fails closed: `KiwiSolveError` with
   `refusal: "solver-unavailable"`, naming the missing
   `KiwiCaptchaSolver` module honestly.

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
  "hashHex": "00f9718e...6982"
}
```

`counter` is the winning search counter, `durationMs` the wall-clock
solve duration, `hashHex` the winning 64-hex digest (informational).
The promise rejects with a typed code when the challenge is refused;
the JS side maps every rejection to `solver-unavailable`. The codes:
`MALFORMED`, `DIFFICULTY_BEYOND_CAP`, `UNSUPPORTED_ALGORITHM`,
`EXECUTION_UNSUPPORTED`, `EXHAUSTED` (the 20,000,000-hash search window
closed without a winner).

## The pinned solve contract

The native loop is byte-identical to the pure-TS fallback (same
counter, same digest), because it is the same algorithm:

- preimage: `prefix || decimal(counter) || salt` — the prefix and the
  ASCII decimal counter as bytes, the salt as its decoded base64
  bytes, counter starting at 0;
- winner: the first counter whose SHA-256 digest shows at least
  `targetBits` leading zero bits (big-endian bit order);
- bounds: 1 <= targetBits <= 20, at most 20,000,000 hashes
  (`protocol/limits.json` `solver_max_hashes`), then the typed
  `EXHAUSTED` refusal;
- refusals before any work: an `execution_program`-armed challenge
  (`EXECUTION_UNSUPPORTED`), a broken nonce/prefix/salt
  (`MALFORMED`), difficulty above the shared cap
  (`DIFFICULTY_BEYOND_CAP`), and any non-sha256 algorithm in this
  module (`UNSUPPORTED_ALGORITHM`).

The shared vector pins all of it: prefix `kiwi|login|`, salt
`AAECAw==`, targetBits 8 → counter 45, hashHex
`00f9718e2a0397b3ca8fe75c44499fccee788e243173dadea546bd4e45af6982`.

## Optional progress channel

Both modules additionally implement:

```
KiwiCaptchaSolver.solveWithProgress(
  challengeJson: string,
  onProgress: (info: { attempted: number }) => void
): Promise<string>
```

When present, the JS side dispatches there and forwards the reports
(same JSON answer shape). The module reports at its own bounded
cadence — at most one report per 1024 attempts AND per 100 ms, plus
the winning report, never once per hash — and the JS side additionally
enforces a 100 ms wall-clock floor and drops duplicate counts, so the
bridge can never flood the JS thread. When the method is absent,
`solve` is used and the caller still receives the start
(`attempted: 0`) and final (winning counter + 1) reports.
`AcquireTokenOptions.onProgress` receives the same `{ attempted }`
shape.

## Caps the module enforces

The module re-checks the client contract before spending work, exactly
like the Rust solver does. Refuse, never degrade:

- nonce: 44 chars, standard base64 of 32 bytes.
- prefix: 1..=4096 bytes. salt: decodable base64, 1..=512 chars.
- sha256: 1 <= targetBits <= 20; search `prefix || decimal(counter) ||
  salt` (counter from 0), cap 20,000,000 hashes.
- argon2id / rsw: not implemented in this package's native modules —
  refused with `UNSUPPORTED_ALGORITHM` (see the Argon2id status below).
- `execution_program` present: refuse. The browser interpreter is
  outside the native path.

## Argon2id status, per platform

- **`packages/kiwicaptcha-ios` (SwiftPM)**: implements Argon2id —
  the vendored reference C implementation (phc-winner-argon2, the
  `CArgon2` target), never a home-grown memory-hard function. The old
  "iOS argon2id is fail-closed" claim is obsolete.
- **`packages/kiwicaptcha-android` (JVM/Android library)**: argon2id
  is fail-closed (no vetted JVM implementation ships with Android;
  link BouncyCastle or a native library to lift it).
- **This package's native modules (`android/`, `ios/`)**: SHA-256
  only. Argon2id and rsw are refused with the typed
  `UNSUPPORTED_ALGORITHM` code, and the JS orchestration surfaces
  `solver-unavailable` — there is no JS Argon2 implementation in the
  React Native package to fall back to either. An app that needs
  argon2id on iOS links the SwiftPM package above; the honest refusal
  is the failure mode everywhere else.

## Android integration (Gradle)

Autolinking (React Native 0.73+): nothing to do. The CLI scans the
library's `android/` sources for the `ReactPackage` and adds
`KiwiSolverPackage` to the app.

Manual, if autolinking is disabled:

```kotlin
// MainApplication.kt
override fun getPackages(): List<ReactPackage> =
    PackageList(this).packages.apply {
        add(com.kiwicaptcha.reactnative.KiwiSolverPackage())
    }
```

`android/build.gradle` follows the current RN library template: the
`com.facebook.react` plugin (resolved through the app's includeBuild
of `@react-native/gradle-plugin`), `compileSdkVersion` 35 by default
(the app's `rootProject.ext` values win), `minSdkVersion` 21 by
default, AGP/Kotlin pinned only as standalone fallbacks. The module is
a classic `ReactPackage`, which the New Architecture serves through its
legacy-module interop layer (default-on since RN 0.74) — no codegen
configuration is needed.

## iOS integration (CocoaPods)

Autolinking: nothing to do; `pod install` picks up
`KiwiCaptchaSolver.podspec` from node_modules. Manual:

```ruby
pod 'KiwiCaptchaSolver', :path => '../node_modules/@kiwicaptcha/react-native'
```

The pod depends on `React-Core`, floors iOS/tvOS at 13.4 (CryptoKit
needs 13.0+; RN 0.76+ apps simply set their own higher minimum), and
floors Swift at 5.7 via `s.swift_version` plus
`s.pod_target_xcconfig` — the podspec-legal form of the post-install
pacing (`post_install` itself is a Podfile-only hook). If the app's
Podfile rewrites `SWIFT_VERSION` in its own `post_install`, re-assert
the floor for this pod there:

```ruby
post_install do |installer|
  installer.pods_project.targets.each do |target|
    next unless target.name == 'KiwiCaptchaSolver'
    target.build_configurations.each do |config|
      config.build_settings['SWIFT_VERSION'] = '5.7'
    end
  end
end
```

## Expo

The modules are classic native modules linked by autolinking, so Expo
development builds include them with no config plugin. Expo Go cannot
carry native modules: Expo Go sessions run in the fail-closed mode
(low-difficulty sha256 only), and the error names the missing
`KiwiCaptchaSolver` module honestly.
