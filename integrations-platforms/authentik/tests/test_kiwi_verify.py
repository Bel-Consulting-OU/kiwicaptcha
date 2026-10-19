"""The plain-python test of the authentik stage's verify module:
extraction, ip binding, the wire request, the decision table, and one
verify() call over a stubbed transport. Run: python3
tests/test_kiwi_verify.py"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kiwi_verify import (  # noqa: E402
    MALFORMED_TOKEN,
    TOKEN_SOURCE_CONFLICT,
    build_request,
    client_ip,
    decide,
    resolve_token,
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


# Token resolution: the collect/distinct/conflict authority rule.
check("header token", resolve_token(" hdr ", {}, {}) == {"token": "hdr"})
check("native form token", resolve_token(None, {"kiwi__token": "n"}, {}) == {"token": "n"})
check("incumbent form token", resolve_token(None, {"cf-turnstile-response": "cf"}, {}) == {"token": "cf"})
check("json body namespaced token", resolve_token(None, {}, {}, '{"kiwi_token":"jt"}') == {"token": "jt"})
check("json body captcha_response token", resolve_token(None, {}, {}, '{"captcha_response":"cr"}') == {"token": "cr"})
check(
    "json body bare token field is ignored",
    resolve_token(None, {}, {}, '{"token":"app-secret"}') == {"code": MALFORMED_TOKEN},
)
check("cookie token", resolve_token(None, {}, {"kiwi_token": "ck"}) == {"token": "ck"})
check("missing token is malformed_token", resolve_token(None, {}, {}) == {"code": MALFORMED_TOKEN})
check("blank values are no token", resolve_token("  ", {"kiwi__token": ""}, {"kiwi_token": ""}) == {"code": MALFORMED_TOKEN})

# The ambiguity matrix: zero distinct values pass nothing, one distinct
# value verifies however many sources carry it, two or more distinct
# values refuse with the typed token_source_conflict code before any
# verification.
check("header a form b conflicts", resolve_token("a", {"kiwi__token": "b"}, {}) == {"code": TOKEN_SOURCE_CONFLICT})
check("header a cookie b conflicts", resolve_token("a", {}, {"kiwi_token": "b"}) == {"code": TOKEN_SOURCE_CONFLICT})
check(
    "form a json b conflicts",
    resolve_token(None, {"kiwi__token": "a"}, {}, '{"kiwi_token":"b"}') == {"code": TOKEN_SOURCE_CONFLICT},
)
check(
    "json a cookie b conflicts",
    resolve_token(None, {}, {"kiwi_token": "b"}, '{"kiwi_token":"a"}') == {"code": TOKEN_SOURCE_CONFLICT},
)
check(
    "two distinct repeated header lines conflict",
    resolve_token(["a", "b"], {}, {}) == {"code": TOKEN_SOURCE_CONFLICT},
)
check(
    "a comma-joined header line splits into values",
    resolve_token("a, b", {}, {}) == {"code": TOKEN_SOURCE_CONFLICT},
)
check(
    "an array-valued form param with distinct values conflicts",
    resolve_token(None, {"kiwi__token": ["a", "b"]}, {}) == {"code": TOKEN_SOURCE_CONFLICT},
)
check(
    "same token in every source verifies",
    resolve_token("a", {"kiwi__token": "a"}, {"kiwi_token": "a"}) == {"token": "a"},
)
check(
    "same value twice in the header verifies",
    resolve_token(["a", "a"], {}, {}) == {"token": "a"},
)
check(
    "same value as a repeated form array verifies",
    resolve_token(None, {"kiwi__token": ["a", "a"]}, {}) == {"token": "a"},
)
check(
    "whitespace-padded equal values are one distinct value",
    resolve_token(" a ", {"kiwi__token": "a "}, {"kiwi_token": " a"}) == {"token": "a"},
)

# Ip binding.
check("peer ip untrusted", client_ip("10.9.9.9", "1.2.3.4, 10.0.0.1") == "10.9.9.9")
check("peer ip trust list empty", client_ip("10.9.9.9", "1.2.3.4, 10.0.0.1", "") == "10.9.9.9")
check("forwarded ip trusted", client_ip("10.0.0.1", "1.2.3.4, 10.0.0.1", "10.0.0.0/8") == "1.2.3.4")
check("client-supplied leftmost entry is ignored", client_ip("10.0.0.1", "6.6.6.6, 1.2.3.4, 10.0.0.1", "10.0.0.0/8") == "1.2.3.4")
check("garbage hop fails closed", client_ip("10.0.0.1", "1.2.3.4, garbage!!, 10.0.0.1", "10.0.0.0/8") == "10.0.0.1")
check("real ip when trusted and no xff", client_ip("10.0.0.1", None, "10.0.0.0/8", "198.51.100.7") == "198.51.100.7")
check("missing peer fails closed (never invents loopback)", client_ip(None, None) == "")
check("empty peer fails closed", client_ip("", "") == "")
check("garbage peer fails closed", client_ip("not-an-ip", None) == "")
check("unicode peer fails closed", client_ip("２０３.０.１１３.７", None) == "")
check("mapped peer canonicalizes to ipv4", client_ip("::ffff:10.0.0.9", None) == "10.0.0.9")
check("peer with port canonicalizes", client_ip("10.0.0.9:8080", None) == "10.0.0.9")
check("mapped-ipv6 hop resolves to its ipv4 form", client_ip("10.0.0.1", "::ffff:198.51.100.4, 10.0.0.1", "10.0.0.0/8") == "198.51.100.4")
check("star hop fails closed to the peer", client_ip("10.0.0.1", "*, 10.0.0.1", "10.0.0.0/8") == "10.0.0.1")
check("zone hop terminates the chain", client_ip("10.0.0.1", "fe80::1%eth0, 10.0.0.1", "10.0.0.0/8") == "10.0.0.1")

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
check("302 with success body fails closed", decide(302, '{"success":true}') == {"ok": False, "code": "challenge_failed"})
check("301 with success body fails closed", decide(301, '{"success":true}') == {"ok": False, "code": "challenge_failed"})
check("403 with success body fails closed", decide(403, '{"success":true}') == {"ok": False, "code": "challenge_failed"})
check("429 with success body fails closed", decide(429, '{"success":true}') == {"ok": False, "code": "challenge_failed"})
check("199 with success body fails closed", decide(199, '{"success":true}') == {"ok": False, "code": "challenge_failed"})
check("204 with success body passes", decide(204, '{"success":true}') == {"ok": True, "code": "verified"})

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
