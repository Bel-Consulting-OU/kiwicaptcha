"""The plain-python test of the authentik stock-Captcha-stage
settings builder: field derivation, URL shapes, and fail-closed
refusal of ambiguous inputs. Run: python3 tests/test_captcha_stage.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from stages.kiwi.stage import (  # noqa: E402
    CaptchaStageSettings,
    StageConfigError,
    build_stage_settings,
)

failures = 0
checks = 0


def check(name, condition):
    global failures, checks
    checks += 1
    if not condition:
        failures += 1
        print(f"FAIL: {name}", file=sys.stderr)


def must_refuse(name, fn):
    try:
        fn()
    except StageConfigError:
        check(name, True)
        return
    check(name, False)


settings = build_stage_settings(
    "https://captcha.example.com", "site-key-1", "siteverify-secret-1"
)
check(
    "js url targets the compat loader",
    settings.js_url == "https://captcha.example.com/kiwi-captcha/api.js?compat=recaptcha",
)
check(
    "api url targets siteverify",
    settings.api_url == "https://captcha.example.com/kiwi-captcha/siteverify",
)
check("public key is the sitekey", settings.public_key == "site-key-1")
check("private key is the siteverify secret", settings.private_key == "siteverify-secret-1")
check(
    "stage field names match the CaptchaStage model",
    sorted(settings.stage_fields()) == ["api_url", "js_url", "private_key", "public_key"],
)
payload = settings.admin_api_payload("Kiwi")
check("admin payload carries the name and four fields", payload["name"] == "Kiwi" and len(payload) == 5)

custom = build_stage_settings(
    "https://captcha.example.com:8443/",
    "k",
    "s",
    route_prefix="/custom/kiwi",
    compat="hcaptcha",
)
check(
    "custom prefix and compat tier",
    custom.js_url == "https://captcha.example.com:8443/custom/kiwi/api.js?compat=hcaptcha",
)

must_refuse("relative base refused", lambda: build_stage_settings("/kiwi", "k", "s"))
must_refuse("missing scheme refused", lambda: build_stage_settings("captcha.example.com", "k", "s"))
must_refuse("empty sitekey refused", lambda: build_stage_settings("https://c.example", "", "s"))
must_refuse("empty secret refused", lambda: build_stage_settings("https://c.example", "k", ""))
must_refuse(
    "query in prefix refused",
    lambda: build_stage_settings("https://c.example", "k", "s", route_prefix="/kiwi?x=1"),
)
must_refuse(
    "unknown compat tier refused",
    lambda: build_stage_settings("https://c.example", "k", "s", compat="paypal"),
)
must_refuse("empty stage name refused", lambda: settings.admin_api_payload("  "))

print(f"{checks} checks, {failures} failures")
sys.exit(0 if failures == 0 else 1)
