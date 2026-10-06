# KiwiCaptcha for Authentik (stock Captcha stage)

Native integration: Authentik's **built-in Captcha stage**
(`ak-stage-captcha`) pointed at this deployment's two compatibility
endpoints. This works on a stock Authentik — no custom stage, no
custom frontend component, no image rebuild.

## Why not a custom stage

A custom ChallengeStageView cannot render on stock Authentik: the
component id (`ak-stage-kiwi-captcha`) is not in Authentik's frontend
bundle, and the Stage model carries no `custom_config` field for
stage settings. The previous custom-stage module was therefore
unusable as shipped; it is replaced by the stock-stage configuration
below.

## Mechanism

Authentik's Captcha stage carries four fields. Point them at the
deployment like this:

| CaptchaStage field | value |
| --- | --- |
| `js_url` | `{base}{prefix}/api.js?compat=recaptcha` — the incumbent-compatibility loader; the compat tier must match the captcha global the Authentik web UI drives (grecaptcha-shaped by default; `hcaptcha` / `turnstile` also available) |
| `api_url` | `{base}{prefix}/siteverify` — the provider-shaped siteverify endpoint; it accepts the `response` / `secret` / `remoteip` envelope the stock stage posts and answers the provider JSON (`success`, `challenge_ts`, …) the stock stage parses |
| `public_key` | the kiwi sitekey (public; goes to the browser) |
| `private_key` | the siteverify secret (server-to-server; the stage posts it as `secret`, the browser never sees it) |

`stages/kiwi/stage.py` is the framework-free helper that derives and
validates those four values (`build_stage_settings(...)`) and emits
the admin-API body (`admin_api_payload()`) that creates the stage:

```python
from stages.kiwi.stage import build_stage_settings

settings = build_stage_settings(
    base_url="https://captcha.example.com",
    sitekey="your-sitekey",
    siteverify_secret="your-siteverify-secret",
)
# POST to /api/v3/stages/captcha/ on the Authentik admin API:
body = settings.admin_api_payload("KiwiCaptcha")
```

Then add the stage to a flow (registration or login) at the position
where the protection belongs. The stock frontend renders it and the
stock backend verifies the solved token against `api_url` before the
flow continues.

## Requirements on the deployment

- `public_base_url` and the route prefix configured on the kiwi side
  (the URLs above are derived from them).
- `siteverify_secrets` configured with the secret that `private_key`
  carries; the endpoint is disabled without one.

## Server-side helper (forked Authentik only)

`kiwi_verify.py` remains available for deployments that fork Authentik
and write their own stage: token extraction, the trusted-proxy IP
walk, the sidecar-style `/verify` request and the decision table, all
framework-free and unit-tested. Stock Authentik needs no custom code.

## Test status

Both suites are plain `python3` and run here:

- `tests/test_captcha_stage.py` (14 checks): the stock-stage field
  derivation and fail-closed refusal of ambiguous inputs.
- `tests/test_kiwi_verify.py` (24 checks): extraction, ip binding, the
  wire request, the decision table and `verify()` over a stubbed
  transport.

Exercising the stage inside a running Authentik (flow editor, admin
API) needs a server, which this repository does not ship.
