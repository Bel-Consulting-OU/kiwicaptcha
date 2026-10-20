# kiwicaptcha-android

The native Android KiwiCaptcha client: a Jetpack Compose widget, a
classic View, and the proof-of-work solver core on the JVM platform.
The solve runs on a background thread, never a WebView. The wire
contract is the shared one: POST the challenge request, validate,
solve, pack the wire token; your backend runs siteverify.

## Module layout

- `KiwiSolver` / `KiwiToken` / `KiwiBase64` / `KiwiChallenge` — the
  solver core, dependency-free pure Kotlin.
- `KiwiLifecycle` — the pure Interactive-Client Lifecycle v1 delivery
  gate (`deliveryDecision`), pinned by the shared vectors in
  `protocol/interactive-client-v1/lifecycle-vectors.json`.
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

## Interactive-Client Lifecycle v1

The widget implements the shared lifecycle contract
(protocol/interactive-client-v1). The rules:

- `receivedAtMs` is captured immediately after the challenge JSON
  parses; the expiry clock starts there, never after solving.
- `expiresAtMs = receivedAtMs + ttlSecs*1000 - 1000` (a fixed 1 s
  safety margin); `minSubmitAtMs = receivedAtMs + minDurationMs`
  (`0` when absent). A `ttlSecs == 0` challenge has no expiry.
- The expiry timer arms at parse time and races the solve. A solve
  that loses the race is stopped cooperatively, the token is never
  delivered, `onVerify` is suppressed, and the widget surfaces the
  typed expired state. At every checkpoint and immediately before
  `onVerify`: `now >= expiresAtMs` invalidates the generation.
- Delivery gating: a solve finishing before `minSubmitAtMs` is held
  (cancellably) until the floor; `minSubmitAtMs >= expiresAtMs`
  is treated as expired.
- Only the newest generation may emit; results from superseded
  generations are discarded.
- `KiwiLifecycle.deliveryDecision(receivedAtMs, ttlSecs,
  minDurationMs, solveFinishedAtMs, nowMs)` is the pure decision
  helper every client shares, with reasons `deliver | defer |
  expired` (plus `cancelled` when the caller passes the flag). The
  JVM tests run every scenario from
  `protocol/interactive-client-v1/lifecycle-vectors.json` against it.

### Cancellation

`KiwiSolver.solve(challenge, isCancelled = { ... })` accepts a cheap,
non-blocking probe. It is checked on entry — a cancelled generation
spends no work at all — and then at a bounded cadence; when it fires,
the typed `KiwiSolveError.Cancelled` is raised and no further CPU work
is scheduled:

| Workload | Checkpoint cadence            | Stale-work ceiling      |
|----------|-------------------------------|-------------------------|
| sha256   | every 2048 candidates         | 2048 hashes             |
| argon2id | between candidate derivations | one derivation          |
| rsw      | every 256 modular squarings   | 256 squarings           |

The view's probe is generation-based: it fires when the job is
cancelled, a newer generation started, or the parse-time deadline has
passed. The probe is optional (`null` default), so existing call
sites keep compiling unchanged.

### Execution capability header

`KiwiClient.fetchChallenge` sends `Kiwi-Execution-Max-Version: 0` on
the challenge POST. Native clients cannot execute the execution
dimension, and a *missing* header would read as the v1 compatibility
floor rather than "cannot execute" — so the declaration is explicit.

Widget notes: the status color comes from the theme's
`android.R.attr.textColorPrimary` (dark-quirk-safe fallback), text
sizes are in sp, state changes are announced through
contentDescription/stateDescription for TalkBack, and Retry stays an
independently focusable control.

## Tests

`src/test` holds the JVM unit tests: the BLAKE2b/Argon2id shared
vectors (`Argon2idTest`, the same pins the JVM SDK carries), the
solver-level argon tests (a known winning counter, the wire token
pack, the exhaustion branch, the caps refusals, and a solve at the
64 MiB memory ceiling), the SHA-256 vectors, the known search counter
for a fixed challenge, the token grammar bytes, the rsw external
vector, the validation refusals, the JSON reader, the siteverify body,
the base64 round trip, the Interactive-Client Lifecycle v1 delivery
gate against every shared vector (`KiwiLifecycleTest`), the solver
cancellation checkpoints (`KiwiSolverTest`), the expiry suppression
seam (`KiwiExpirySuppressionTest`), and the challenge POST shape
including the `Kiwi-Execution-Max-Version` capability header
(`KiwiClientTest`).

Run them with the pinned wrapper (AGP 8.13 needs Gradle up to 9.5):

```sh
./gradlew testDebugUnitTest
```

The Android widget layer (View, Compose) compiles with the module; the
solver tests run on the local JVM with no device or emulator.
