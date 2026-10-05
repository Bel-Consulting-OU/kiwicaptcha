# kiwicaptcha-android

The native Android KiwiCaptcha client: a Jetpack Compose widget, a
classic View, and the proof-of-work solver core on the JVM platform.
The solve runs on a background thread, never a WebView. The wire
contract is the shared one: POST the challenge request, validate,
solve, pack the wire token; your backend runs siteverify.

## Module layout

- `KiwiSolver` / `KiwiToken` / `KiwiBase64` / `KiwiChallenge` — the
  solver core, dependency-free pure Kotlin.
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
to an externally computed vector in the tests. Argon2id is fail-closed:
the JVM platform ships no vetted Argon2 and this package refuses a
home-grown memory-hard function (link BouncyCastle or a native library
and extend `KiwiSolver` to lift it). Execution-armed challenges are
refused outright — the browser interpreter is outside the native path.

## Tests

`src/test/kotlin` holds the JVM unit tests: the SHA-256 vectors, the
known search counter for a fixed challenge, the token grammar bytes,
the rsw external vector, the validation refusals, the JSON reader, the
siteverify body, and the base64 round trip.

Run them with the pinned wrapper (AGP 8.13 needs Gradle up to 9.5):

```sh
./gradlew testDebugUnitTest
```

The Android widget layer (View, Compose) compiles with the module; the
solver tests run on the local JVM with no device or emulator.
