# @kiwicaptcha/react-native

React Native KiwiCaptcha client: the proof of work runs on a NATIVE
thread through the platform solver module — no WebView, no
JavaScript-thread search above the low-difficulty ceiling. The package
ships the JS orchestration (challenge fetch, validation, dispatch,
token assembly) and the native-module bridge contract
(docs/NATIVE.md). Expo works through a development build; Expo Go
sessions run fail-closed (low-difficulty sha256 only, with the missing
module named honestly in the error).

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

- sha256 at 8 bits or fewer runs on the JS thread through the
  optional `react-native-quick-crypto` peer (or the bundled pure-TS
  SHA-256); a missed window fails CLOSED to the native module, never
  to a weaker profile.
- Everything harder, and all argon2id and rsw challenges, go to
  `NativeModules.KiwiCaptchaSolver`: one async method, JSON in, JSON
  out (docs/NATIVE.md is the authoritative interface, the caps the
  module must enforce included).
- An absent module is a fail-closed condition: `KiwiSolveError` with
  `refusal: "solver-unavailable"` names what is missing.
- Execution-armed challenges are refused outright (the browser
  interpreter is outside the native path).

`acquireToken` POSTs the challenge request, validates the document
with the exact caps the browser driver enforces, dispatches, and packs
the wire token (base64 of nonce.counter.duration.telemetry, rsw proof
as the final 512-hex segment). Verification stays server-to-server.

## Tests

`npm test` runs the Jest suite (ts-jest, `react-native` mapped onto a
controllable mock): the SHA-256 vectors, the token grammar, the
validation refusals, the low-difficulty solve against a pinned
counter, native dispatch and malformed-answer handling, the full
acquireToken flow against a mocked fetch, and the siteverify body.
`npm run typecheck` runs the strict `tsc --noEmit`.
