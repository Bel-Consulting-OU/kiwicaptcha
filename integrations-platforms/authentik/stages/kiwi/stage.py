"""
The Authentik integration for KiwiCaptcha — the STOCK Captcha stage.

There is deliberately no custom ChallengeStageView here. A custom
stage component (`ak-stage-kiwi-captcha`) does not exist in
Authentik's frontend bundle, so a custom stage cannot render on a
stock install, and the Stage model carries no `custom_config` field
to hang settings on. The integration that actually works on stock
Authentik is Authentik's own **Captcha stage** (`ak-stage-captcha`)
pointed at this deployment's two compatibility endpoints:

  js_url   -> {base}{prefix}/api.js?compat=recaptcha
              (the incumbent-compatibility loader; the compat tier
              must match the captcha global the Authentik web UI
              drives — grecaptcha-shaped for the default build)

  api_url  -> {base}{prefix}/siteverify
              (the provider-shaped siteverify endpoint: it accepts
              the `response` / `secret` / `remoteip` envelope the
              stock stage posts and answers the provider JSON the
              stock stage parses — `success` and friends)

  public_key  -> the kiwi sitekey (the widget's public identifier)
  private_key -> the siteverify secret (server-to-server credential,
                 never exposed to the browser)

This module is the framework-free half of that integration: it
derives and validates those four field values from the deployment
description and can emit the Authentik admin-API payload that creates
the stage. It imports nothing from authentik, so it unit-tests with a
plain python3 interpreter (see tests/test_captcha_stage.py).

Server-side note: deployments that fork Authentik and write their own
stage may still use `kiwi_verify.py` (the framework-free verify
helper with the trusted-proxy IP walk) against the sidecar-style
`/verify` contract; stock Authentik needs no custom code at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

DEFAULT_ROUTE_PREFIX = "/kiwi-captcha"
DEFAULT_COMPAT = "recaptcha"

# The compat tiers the deployment's api.js loader speaks. The tier
# must match the captcha global the Authentik web UI calls into.
COMPAT_TIERS = ("recaptcha", "hcaptcha", "turnstile")

_ORIGIN_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]+)?$")
_PREFIX_RE = re.compile(r"^/[A-Za-z0-9._~/-]*[A-Za-z0-9._~/]$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+=:/-]{1,256}$")


class StageConfigError(ValueError):
    """A deployment description that cannot produce a safe stage: the
    caller must fail closed, never fall back to a guessed origin."""


@dataclass(frozen=True)
class CaptchaStageSettings:
    """The four fields of Authentik's stock Captcha stage."""

    public_key: str
    private_key: str
    js_url: str
    api_url: str

    def stage_fields(self) -> Dict[str, str]:
        """Exactly the field names the CaptchaStage model carries."""
        return {
            "public_key": self.public_key,
            "private_key": self.private_key,
            "js_url": self.js_url,
            "api_url": self.api_url,
        }

    def admin_api_payload(self, name: str = "KiwiCaptcha") -> Dict[str, Any]:
        """The Authentik admin-API body that creates this stage
        (POST /api/v3/stages/captcha/)."""
        if not isinstance(name, str) or name.strip() == "":
            raise StageConfigError("the stage name must be a non-empty string")
        return {"name": name.strip(), **self.stage_fields()}


def build_stage_settings(
    base_url: str,
    sitekey: str,
    siteverify_secret: str,
    route_prefix: str = DEFAULT_ROUTE_PREFIX,
    compat: str = DEFAULT_COMPAT,
) -> CaptchaStageSettings:
    """Derive the stock Captcha stage fields from the deployment.

    Fails closed on anything that would point the stage at an
    ambiguous origin, a foreign route, or an empty credential: a
    misconfigured stage must refuse to build, never fall back.
    """
    if not isinstance(base_url, str) or _ORIGIN_RE.match(base_url.strip().rstrip("/")) is None:
        raise StageConfigError(
            "the deployment base url must be an absolute origin like https://captcha.example.com"
        )
    base = base_url.strip().rstrip("/")
    if not isinstance(route_prefix, str) or _PREFIX_RE.match(route_prefix) is None:
        raise StageConfigError(
            "the route prefix must be an absolute path like /kiwi-captcha (no query, no fragment, no trailing slash)"
        )
    if not isinstance(compat, str) or compat not in COMPAT_TIERS:
        raise StageConfigError(
            "the compat tier must be one of " + ", ".join(COMPAT_TIERS)
        )
    if not isinstance(sitekey, str) or _TOKEN_RE.match(sitekey) is None:
        raise StageConfigError("the sitekey must be a non-empty bounded token")
    if not isinstance(siteverify_secret, str) or _TOKEN_RE.match(siteverify_secret) is None:
        raise StageConfigError("the siteverify secret must be a non-empty bounded token")

    return CaptchaStageSettings(
        public_key=sitekey,
        private_key=siteverify_secret,
        js_url=f"{base}{route_prefix}/api.js?compat={compat}",
        api_url=f"{base}{route_prefix}/siteverify",
    )
