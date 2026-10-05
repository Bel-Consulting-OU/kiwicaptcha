# KiwiCaptcha for Zitadel (Actions v2)

Native Zitadel extension: an Actions v2 script that guards user
creation. The `guardPreCreation` action verifies the kiwi
proof-of-work token server-to-server against the deployment and
aborts the creation when the challenge is missing or failed; an
unreachable deployment fails closed.

## Mechanism

- `scripts/kiwi-signup-guard.js` is the whole script: the pure core
  (`buildRequest`, `decide`, `verify`) and the action entry point
  (`guardPreCreation(ctx, api)`), which reads the token from the
  execution payload (`kiwiToken`, the shim widget's hidden field or
  the `X-Kiwi-Token` header carried by the caller) and calls the
  deployment's verify endpoint with fetch.
- The API-flow contract: clients solve the challenge before
  registering (the shim script loaded by the login UI or the app),
  then carry the solved token in the registration payload's
  `kiwiToken` field or the `X-Kiwi-Token` header; the action verifies
  it at PreCreation, so no user row exists before the proof.

## Deployment steps

1. Zitadel Console: Actions, add the script
   (`scripts/kiwi-signup-guard.js`); Actions v2 must be enabled on
   the instance.
2. Flows: create or edit the flow covering registration, add the
   action on the PreCreation trigger.
3. Edit the script's constants for the deployment: `KIWI_VERIFY_URL`,
   `KIWI_BEARER`, `KIWI_SCOPE`.
4. Serve the shim on the sign-up surface (the login UI theme or the
   app) so users solve the challenge before registering.

## Test status

`tests/kiwi-signup-guard.test.mjs` (12 checks, plain `node`) covers
the wire request, the decision table, `verify()` against a stubbed
fetch (success, failure, transport fault, missing token) and the
guard flow (abort on failure and on a missing token, continue on
success). The `guardPreCreation` context and api surface are
documented defensively in the script (payload shapes vary by
trigger); a live Zitadel instance remains the place where the flow
binding gets its final verification.
