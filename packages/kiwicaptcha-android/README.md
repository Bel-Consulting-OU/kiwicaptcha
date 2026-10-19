# kiwicaptcha-android

The native Android KiwiCaptcha client: a Jetpack Compose widget, a
classic View, and the proof-of-work solver core on the JVM platform.
The solve runs on a background thread, never a WebView. The wire
contract is the shared one: POST the challenge request, validate,
solve, pack the wire token; your backend runs siteverify.

## Module layout

- `KiwiSolver` / `KiwiToken` / `KiwiBase64` / `KiwiChallenge` — the
  solver core, dependency-free pure Kotlin.
- `Argon2id` / `Blake2b` (`src/main/java`) — the vetted pure-Java
  Argon2id stack, a byte-identical port of the JVM SDK's sources
  (RFC 9106-pinned; the Java sources compile into the Kotlin module).
- `KiwiClient` — the challenge POST (HttpURLConnection) and the
  siteverify body builder.
- `KiwiCaptchaView` — the classic View (state label, progress, Retry).
- `KiwiCaptcha` — the Compose composable over the same lifecycle.

## Quickstart

```kotlin
// Compose
KiwiCaptcha(
    endpoint = "https://api.example.com/api/kcaptcha/challenge",
    scope = "login",
    onVerify = { token -> submit(token) },
)

// View
val view = KiwiCaptchaView(context)
view.endpoint = challengeUrl
view.scope = "login"
view.onVerify = { token -> tokenField.setText(token) }
view.start() // safe to call again; the previous run is cancelled
```

Headless:

```kotlin
val client = KiwiClient(challengeUrl)
val challenge = withContext(Dispatchers.IO) { client.fetchChallenge("login") }
val solution = withContext(Dispatchers.Default) { KiwiSolver.solve(challenge) }
val token = KiwiToken.encode(challenge, solution)
```

## Caps and refusals

`KiwiSolver.validate` enforces the shared client contract
(protocol/limits.json) before any work is spent. SHA-256 comes from
`java.security.MessageDigest`; the rsw time lock from
`java.math.BigInteger` (T sequential `modPow(2, n)` squarings), pinned
to an externally computed vector in the tests. Argon2id runs on the
pure-Java implementation shipped in `src/main/java` (the same vetted
sources and shared vectors the JVM SDK carries — RFC 9106 input set,
reference-build differential tags, and the libsodium lanes-one golden
vector), so the official Android client solves every rung the adaptive
risk engine can issue.

The argon2id client contract mirrors the Rust and Flutter solvers:

- preimage: `Argon2id(prefix || decimal(counter), salt, m_kib, t, p)`
  with a 32-byte tag, `salt` the decoded base64 — the same derivation
  the server verifier re-runs;
- difficulty `target_bits` 1..=10, `m_kib` 8..=65536 KiB (and at least
  `8 * p`), `t` 3..=6, `p` = 1; anything else is refused with the typed
  `DifficultyBeyondCap` / `UnsupportedArgon2Params` errors;
- the search is bounded by `KiwiLimits.MAX_HASHES` (20,000,000) like
  every other SDK solver and ends in the typed `Exhausted` error naming
  the attempted count.

Memory envelope: each derivation allocates the profile's working
memory, up to 64 MiB at the `argon64` ceiling (`m_kib` × 1024 bytes in
`long[]` blocks, no extra copies). The search allocates it per
derivation, so peak heap on a device stays around the challenge's own
memory cost; run the solve off the main thread (the widget already
does). Execution-armed challenges are refused outright — the browser
interpreter is outside the native path.

## Tests

`src/test` holds the JVM unit tests: the BLAKE2b/Argon2id shared
vectors (`Argon2idTest`, the same pins the JVM SDK carries), the
solver-level argon tests (a known winning counter, the wire token
pack, the exhaustion branch, the caps refusals, and a solve at the
64 MiB memory ceiling), the SHA-256 vectors, the known search counter
for a fixed challenge, the token grammar bytes, the rsw external
vector, the validation refusals, the JSON reader, the siteverify body,
and the base64 round trip.

Run them with the pinned wrapper (AGP 8.13 needs Gradle up to 9.5):

```sh
./gradlew testDebugUnitTest
```

The Android widget layer (View, Compose) compiles with the module; the
solver tests run on the local JVM with no device or emulator.
