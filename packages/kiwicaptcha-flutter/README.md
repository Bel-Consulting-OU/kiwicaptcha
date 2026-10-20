# kiwicaptcha (Flutter)

The Flutter KiwiCaptcha client: a Material widget plus the Dart
solver, which calls the native solver core over dart:ffi for
everything above the low-difficulty ceiling and keeps a pure-Dart
SHA-256 fallback for small challenges. The wire contract is the shared
one: POST the challenge request, validate, solve, pack the wire token;
your backend runs siteverify.

## Install

```yaml
dependencies:
  kiwicaptcha:
    path: packages/kiwicaptcha-flutter
```

The package declares itself as an FFI plugin (`pubspec.yaml`), so a
consuming app build packages the native library per platform: the
Gradle build runs cargo-ndk for the Android ABIs
(`android/build.gradle`) and the CocoaPods build compiles the Rust
static library for the iOS slices (`ios/kiwicaptcha.podspec`). Both
machines need the Rust toolchain (Android additionally the NDK and
`cargo-ndk`; iOS the `rustup` iOS targets) — see `native/README.md`.

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

The widget solves off the UI isolate and surfaces state, progress and
Retry. It follows the Interactive-Client Lifecycle v1 contract
(`protocol/interactive-client-v1/README.md`, shared with the Android
and iOS SDKs):

* the expiry clock (`expiresAtMs = receivedAtMs + ttlSecs*1000 - 1000`,
  a fixed 1 s safety margin) starts the moment the challenge JSON
  parses — never after solving — and the expiry timer is armed then,
  racing the solve;
* delivery waits out the challenge's `minDurationMs` (cancellably,
  re-checked against the clock), so a too-fast solve still delivers at
  `minSubmitAtMs`;
* nothing ever emits after the deadline: a solve outlived by the TTL
  (or a superseded generation) is suppressed, the typed expired state
  replaces success, `onVerify` never fires, `onExpire` does;
* `ttlSecs == 0` means no expiry at all.

Retry restarts the whole flow (fetch, solve, report) and supersedes
any in-flight run; each `start()` mints a new generation and only the
newest one may emit. With `autoStart: false`, drive the widget through
its public state:

```dart
final key = GlobalKey<KiwiCaptchaState>();
KiwiCaptcha(key: key, autoStart: false, /* ... */);
// later, when the user is ready:
key.currentState?.start(); // `execute()` is the same action
```

`KiwiCaptchaState` is exported from `package:kiwicaptcha/kiwicaptcha.dart`.

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
caps of protocol/limits.json: sha256 1..=20 bits, argon2id 1..=10 bits
with `m_kib` 8..=65536 KiB / `t` 3..=6 / `p` = 1, rsw `t`
10,000..=300,000 over a canonical 2048-bit odd modulus) and refuses
execution-armed challenges outright — those need the browser
interpreter. Low-difficulty SHA-256 (8 bits or fewer) runs in pure
Dart; every other solve goes through the native core. A missing or
refusing library surfaces as a `KiwiSolveError` naming the refusal
(fail-closed, never a weaker profile).

### Cooperative cancellation

`solveKiwiChallenge(challenge, {isCancelled})` takes the lifecycle
contract's cancellation probe (`typedef IsCancelled = bool Function()`),
checked once before any work is spent and then at the contract's
cadences — every 2048 sha256 candidates, between argon2id derivations,
every 256 rsw modular squarings. A firing probe raises the typed
`KiwiSolveError.cancelled` (`KiwiRefusal.cancelled`); at most one
batch of stale work remains after it fires. The batched search runs on
new additive native entry points (`kiwi_solve_sha256_range`,
`kiwi_solve_argon2id_range`, `kiwi_rsw_begin` + `kiwi_rsw_square`);
the original three exports keep their whole-search semantics. The
widget drives the probe from its run state and the challenge deadline,
so a solve that loses the expiry race stops burning CPU and surfaces
the expired state, not a failure.

The pure delivery decision lives in `lib/src/lifecycle.dart`
(`kiwiDeliveryDecision`), mirroring the Android `KiwiLifecycle`
exactly; the shared vectors in
`protocol/interactive-client-v1/lifecycle-vectors.json` pin it and are
asserted by the Dart test suite.

### Capability header

`KiwiClient.fetchChallenge` sends `Kiwi-Execution-Max-Version: 0` on
the challenge POST — the lifecycle contract's requirement that native
interactive clients declare (rather than imply) that they cannot run
the execution dimension, so the server can route execution-armed
challenges away from them.

All three algorithms — sha256, argon2id and rsw — are real on the
native side; argon2id is unavailable only when the core is built
`--no-default-features`, in which case the solve throws
`KiwiRefusal.argonUnavailable`.

## The native core (shipped in this package)

The FFI crate lives at `native/` in this package. It exports the three
functions declared in `src/kiwicaptcha_solver.h` plus their batched
cancellation spelling:

```c
int32_t kiwi_solve_sha256(prefix, prefix_len, salt, salt_len,
                          target_bits, max_hashes, out_counter);
int32_t kiwi_solve_rsw(modulus, modulus_len, prefix, prefix_len,
                       nonce, nonce_len, t, out_proof /* 256 bytes */);
int32_t kiwi_solve_argon2id(prefix, prefix_len, salt, salt_len,
                            m_kib, t, p, target_bits, out_counter);

/* batched: windowed searches / in-place squaring batches, driven by
   the Dart solver's cancellation loop at the lifecycle cadences */
int32_t kiwi_solve_sha256_range(prefix, prefix_len, salt, salt_len,
                                target_bits, start_counter, max_hashes,
                                out_counter);
int32_t kiwi_solve_argon2id_range(prefix, prefix_len, salt, salt_len,
                                  m_kib, t, p, target_bits, start_counter,
                                  max_hashes, out_counter);
int32_t kiwi_rsw_begin(modulus, modulus_len, prefix, prefix_len,
                       nonce, nonce_len, out_value /* 256 bytes */);
int32_t kiwi_rsw_square(modulus, modulus_len, value /* 256 bytes, in place */,
                        squarings);
```

Ownership is one-sided: the caller (the Dart side) allocates and frees
every buffer, the library only writes into the caller's out buffers on
`KIWI_OK` (status codes 0..5, mapped onto `KiwiRefusal` in
`ffi_bindings.dart`), so there is no exported free function. The
implementations reuse the workspace core crate (`packages/kiwicaptcha`)
for the protocol caps, the rsw base derivation and the proof
rendering — the same code the server verifier trusts.

Build it per target (`native/README.md` has the full table):

```sh
cd packages/kiwicaptcha-flutter/native
cargo build --release
# Android: cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
#            -o ../android/src/main/jniLibs build --release
# iOS:     cargo build --release --target aarch64-apple-ios
```

`KiwiFfi` opens `libkiwicaptcha_solver.so` on Android/Linux, the
`.dylib` on macOS, the DLL on Windows, and `DynamicLibrary.process()`
on iOS (the podspec links the staticlib with `-force_load`, so the
symbols stay in the app image).

## Tests and their status in this checkout

* **Native (Rust) — RUN, GREEN on macOS arm64 (rustc 1.96).**
  `cargo test` in `native/` loads the built cdylib exactly the way Dart
  does and solves the shared golden PHP vectors
  (`packages/kiwicaptcha-jvm/testdata/golden/golden-php-vectors.json`,
  the records the JVM suite pins) for sha256, argon2id and rsw through
  the EXPORTED C ABI — both whole-search and the batched
  range/begin/square spelling the Dart cancellation loop drives — then
  verifies every solution with the workspace core verifier. Refusal
  codes (cap, malformed, exhausted) are pinned through the ABI too.
  `cargo build --release` produces `libkiwicaptcha_solver.dylib` with
  all seven symbols exported; clippy is clean.
* **Dart/Flutter — NOT RUN.** The Dart/Flutter toolchain is not
  installed here (no `dart`, no `flutter`), so `test/kiwicaptcha_test.dart`
  is written for CI and has not been executed locally; nothing about
  its result is claimed. The Dart sources were made analyzer-correct
  by careful reading (the FFI typedefs mirror the header exactly; the
  lifecycle decision helper is a line-by-line mirror of the Android
  `KiwiLifecycle` and is pinned by the shared vectors; the widget test
  suite covers expiry suppression, min-submit deferral, cancellation
  and superseded-generation suppression). The vector test reads
  `protocol/interactive-client-v1/lifecycle-vectors.json` through a
  repo-relative path, so it runs on the GitHub flutter lane and
  anywhere else with the checkout intact. With the toolchain present
  they run as usual:

```sh
flutter test
```

* **Device packaging — DECLARATIVE ONLY.** `android/build.gradle` and
  `ios/kiwicaptcha.podspec` are correct by inspection (they follow the
  standard FFI-plugin shapes) but were not executed: no Android
  SDK/Gradle and no Xcode/CocoaPods exist in this checkout. The first
  `flutter build apk` / `flutter build ios` in an app that consumes
  the package is what verifies them end to end.
