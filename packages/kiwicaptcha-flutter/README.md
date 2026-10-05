# kiwicaptcha (Flutter)

The Flutter KiwiCaptcha client: a Material widget plus the Dart
solver, which calls the Rust core over dart:ffi for everything above
the low-difficulty ceiling and keeps a pure-Dart SHA-256 fallback for
small challenges. The wire contract is the shared one: POST the
challenge request, validate, solve, pack the wire token; your backend
runs siteverify.

## Install

```yaml
dependencies:
  kiwicaptcha:
    path: packages/kiwicaptcha-flutter
```

## Widget

```dart
KiwiCaptcha(
  endpoint: Uri.parse('https://api.example.com/api/kcaptcha/challenge'),
  scope: 'login',
  onVerify: (token) => submit(token),
  onError: (message) => setState(() => _error = message),
  onExpire: () => setState(() => _error = 'expired, press Retry'),
)
```

The widget solves off the UI isolate (compute) and surfaces state,
progress and Retry.

## Solver

```dart
final client = KiwiClient(endpoint: challengeUri);
final challenge = await client.fetchChallenge(scope: 'login');
final solution = solveKiwiChallenge(challenge);
final token = encodeKiwiToken(
  nonce: challenge.nonce,
  counter: solution.counter,
  durationMs: solution.durationMs,
  rswProof: solution.rswProof,
);
```

`solveKiwiChallenge` validates the client contract first (the shared
caps of protocol/limits.json) and refuses execution-armed challenges
outright. Low-difficulty SHA-256 (8 bits or fewer) runs in pure Dart.
Everything else goes through the FFI core; when the library is absent
the failure names it (fail-closed, never a weaker profile), and
argon2id is fail-closed everywhere: the Dart side refuses and the Rust
core answers `KIWI_ERR_ARGON_UNAVAILABLE` unless built with a vetted
Argon2 feature.

## The Rust core (required build artifact)

The FFI contract is `src/kiwicaptcha_solver.h` (cbindgen-style): three
C functions over the shared preimage contract, answering int32 error
codes. Build the wrapper crate around packages/kiwicaptcha-solver per
platform:

```sh
cargo build --release
# Android (cargo-ndk), ship the .so in jniLibs:
cargo ndk -t arm64-v8a -t x86_64 -o android/app/src/main/jniLibs build --release
# iOS: static library linked into the app binary
cargo build --release --target aarch64-apple-ios
```

`KiwiFfi` opens `libkiwicaptcha_solver.so` on Android and desktop and
`DynamicLibrary.process()` on iOS.

## Tests and their status in this checkout

`test/kiwicaptcha_test.dart` pins the SHA-256 vectors, the token
grammar bytes, the validation refusals (execution, argon fail-closed,
over-cap, broken nonce), the known low-difficulty counter, and the
siteverify body shape.

Status in this checkout: NOT RUN. The Dart/Flutter toolchain is not
installed here (no `dart`, no `flutter`), so these tests are written
for CI and have not been executed locally; nothing about their result
is claimed. With the toolchain present they run as usual:

```sh
flutter test
```
