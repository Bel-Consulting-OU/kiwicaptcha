"""
The authentik custom flow stage: a ChallengeStageView that renders
the kiwi widget into the flow and validates the submitted token
server-to-server against the kiwi deployment before the flow
continues.

Deployment (documented in the repository README): authentik carries
custom stages only inside its own image, so this module plus
kiwi_verify.py mount into the authentik server and worker containers
(a bind mount plus PYTHONPATH, or a small derived image), and a stage
instance is created through the API. The stage needs the settings
stored as the stage's config (the `kiwi_verify_url` and friends on
the Stage model's `custom_config`), or the environment variables
below.

Fields consumed from the stage instance config:
  kiwi_verify_url   default http://127.0.0.1:7371/verify
  kiwi_bearer       optional bearer credential
  kiwi_scope        default "login"
  kiwi_trust_proxy  honor X-Forwarded-For
  kiwi_shim_url     the deployment's shim script url, rendered into
                    the challenge so the flow shell loads it
"""

from __future__ import annotations

from typing import Optional

from django.http import HttpResponse
from rest_framework.fields import CharField

from authentik.flows.challenge import (
    Challenge,
    ChallengeResponse,
    ChallengeTypes,
    WithUserInfoChallenge,
)
from authentik.flows.stage import ChallengeStageView
from authentik.lib.kiwi import kiwi_verify  # mounted next to the authentik lib


class KiwiCaptchaChallenge(WithUserInfoChallenge):
    """The challenge payload: the shim url the flow shell loads and
    the field name the widget writes the token into."""

    component = CharField(default="ak-stage-kiwi-captcha")
    kiwi_shim_url = CharField(required=False, allow_blank=True)
    kiwi_field = CharField(default="kiwi__token")


class KiwiCaptchaChallengeResponse(ChallengeResponse):
    """The response carries the solved token."""

    kiwi__token = CharField(required=False, allow_blank=True)
    component = CharField(default="ak-stage-kiwi-captcha")


class KiwiCaptchaStageView(ChallengeStageView):
    """The kiwi proof-of-work stage."""

    response_class = KiwiCaptchaChallengeResponse

    def get_challenge(self, *args, **kwargs) -> Challenge:
        config = self.executor.current_stage.custom_config or {}
        return KiwiCaptchaChallenge(
            data={
                "type": ChallengeTypes.native.value,
                "component": "ak-stage-kiwi-captcha",
                "kiwi_shim_url": str(config.get("kiwi_shim_url") or ""),
                "kiwi_field": "kiwi__token",
            }
        )

    def challenge_valid(self, response: KiwiCaptchaChallengeResponse) -> HttpResponse:
        config = self.executor.current_stage.custom_config or {}
        request = self.request
        header_token = request.headers.get("X-Kiwi-Token")
        form_token: Optional[str] = response.validated_data.get("kiwi__token")
        token = kiwi_verify.extract_token(header_token, {}, request.COOKIES) or (
            form_token.strip() if form_token and form_token.strip() else None
        )
        if token is None:
            return self.challenge_invalid(response)

        remote_addr = request.META.get("REMOTE_ADDR")
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        result = kiwi_verify.verify(
            settings={
                "verify_url": config.get("kiwi_verify_url"),
                "bearer": config.get("kiwi_bearer", ""),
                "scope": str(config.get("kiwi_scope") or "login"),
                "trust_proxy": bool(config.get("kiwi_trust_proxy")),
            },
            token=token,
            scope=str(config.get("kiwi_scope") or "login"),
            remote_addr=remote_addr,
            forwarded_for=forwarded,
            transport=kiwi_verify.requests_transport,
        )
        if result["ok"]:
            return self.executor.stage_ok()
        return self.challenge_invalid(response)
