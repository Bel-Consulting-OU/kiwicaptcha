# KiwiCaptcha for Authentik (custom flow stage)

Native authentik extension: a ChallengeStageView that renders the kiwi
widget into any flow and verifies the solved token server-to-server
against the kiwi deployment before the flow continues.

## Mechanism

- `kiwi_verify.py` is the framework-free verify module (extraction,
  wire request, decision table, an injected transport plus a requests
  transport).
- `stages/kiwi/stage.py` is the flow stage: `get_challenge()` carries
  the shim URL and the field name to the flow shell;
  `challenge_valid()` extracts the token (header, response field,
  cookie), calls the verify endpoint through the stage's config, and
  continues the flow only on success. Component id:
  `ak-stage-kiwi-captcha`.

## Deployment steps

1. Mount the two modules into the authentik server and worker images
   (authentik carries custom stages inside its own image; the
   documented path is a bind mount or a small derived image), so
   `authentik.lib.kiwi.kiwi_verify` and the stage module import.
2. Create the stage through the API (or after a restart it appears in
   the stage list) and set its config keys: `kiwi_verify_url`
   (default `http://127.0.0.1:7371/verify`), `kiwi_bearer`,
   `kiwi_scope`, `kiwi_trusted_proxies` (comma-separated trusted-proxy CIDRs; the default empty list never trusts a forwarded header), `kiwi_shim_url` (the
   deployment's compat loader URL, loaded by the flow shell).
3. Add the stage to a flow (registration or login) at the position
   where the protection belongs.
4. The flow shell needs a small component mapping for
   `ak-stage-kiwi-captcha` (render the shim script tag plus the
   hidden token field into the challenge form); brand-level custom
   CSS/JS covers it without forking the web UI.

## Test status

`tests/test_kiwi_verify.py` (18 checks, plain `python3`) runs here
and covers extraction, ip binding, the wire request, the decision
table and `verify()` over a stubbed transport, including the
transport-failure fault path. The stage module itself subclasses
authentik's framework classes (ChallengeStageView), which need an
authentik install to import; exercising it end to end needs a running
authentik, which this repository does not ship.
