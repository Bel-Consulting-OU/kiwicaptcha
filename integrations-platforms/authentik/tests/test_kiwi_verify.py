"""The plain-python test of the authentik stage's verify module:
extraction, ip binding, the wire request, the decision table, and one
verify() call over a stubbed transport. Run: python3
tests/test_kiwi_verify.py"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kiwi_verify import (  # noqa: E402
    build_request,
    client_ip,
    decide,
    extract_token,
    verify,
)

failures = 0
checks = 0


def check(name, condition):
    global failures, checks
    checks += 1
    if not condition:
        failures += 1
        print(f"FAIL: {name}", file=sys.stderr)


# Token extraction.
check("header token", extract_token(" hdr ", {}, {}) == "hdr")
check("native form token", extract_token(None, {"kiwi__token": "n"}, {}) == "n")
check("incumbent form token", extract_token(None, {"cf-turnstile-response": "cf"}, {}) == "cf")
check("json body token", extract_token(None, {}, {}, '{"token":"jt"}') == "jt")
check("cookie token", extract_token(None, {}, {"kiwi_token": "ck"}) == "ck")
check("missing token is None", extract_token(None, {}, {}) is None)

# Ip binding.
check("peer ip untrusted", client_ip("10.9.9.9", "1.2.3.4, 10.0.0.1", False) == "10.9.9.9")
check("forwarded ip trusted", client_ip("10.9.9.9", "1.2.3.4, 10.0.0.1", True) == "1.2.3.4")
check("loopback fallback", client_ip(None, None, False) == "127.0.0.1")

# The wire request.
request = build_request("http://127.0.0.1:7371/verify", "t", "signup", "192.0.2.4", bearer="b")
body = json.loads(request["body"])
check(
    "request shape",
    request["url"] == "http://127.0.0.1:7371/verify"
    and body["token"] == "t"
    and body["scope"] == "signup"
    and body["remoteip"] == "192.0.2.4",
)
check("bearer header", request["headers"]["Authorization"] == "Bearer b")

# The decision table.
check("success verifies", decide(200, '{"success":true}') == {"ok": True, "code": "verified"})
check("failure denies", decide(200, '{"success":false}') == {"ok": False, "code": "challenge_failed"})
check("5xx is a fault", decide(502, "") == {"ok": False, "code": "verify_unavailable"})
check("garbage body is unreadable", decide(200, "<html>") == {"ok": False, "code": "verify_unreadable"})

# verify() over a stubbed transport.
settings = {"verify_url": "http://127.0.0.1:7371/verify", "bearer": "b", "scope": "login"}
check(
    "verify success",
    verify(settings, "t", "login", "192.0.2.4", None, lambda u, b, h: {"status": 200, "body": '{"success":true}'})
    == {"ok": True, "code": "verified"},
)
check(
    "verify failure",
    verify(settings, "t", "login", "192.0.2.4", None, lambda u, b, h: {"status": 200, "body": '{"success":false}'})
    == {"ok": False, "code": "challenge_failed"},
)


def boom(url, body, headers):
    raise ConnectionError("down")


check("transport failure is a fault", verify(settings, "t", "login", "192.0.2.4", None, boom) == {"ok": False, "code": "verify_unavailable"})

print(f"{checks} checks, {failures} failures")
sys.exit(0 if failures == 0 else 1)
