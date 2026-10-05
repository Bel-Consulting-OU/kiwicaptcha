"""
The framework-free kiwi verify module for the authentik stage:
token extraction, the wire request, the decision table. The transport
is an injected callable so the whole module unit-tests without a
network.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

TOKEN_FIELDS: List[str] = [
    "kiwi__token",
    "g-recaptcha-response",
    "h-captcha-response",
    "cf-turnstile-response",
    "frc-captcha-solution",
    "altcha",
]

VERIFY_URL_DEFAULT = "http://127.0.0.1:7371/verify"

Transport = Callable[[str, str, Dict[str, str]], Dict[str, Any]]


def extract_token(
    header_token: Optional[str],
    form: Dict[str, Any],
    cookies: Dict[str, str],
    raw_json_body: Optional[str] = None,
) -> Optional[str]:
    """The first present token: header, form fields, JSON body, cookie."""
    if header_token and header_token.strip():
        return header_token.strip()
    for field in TOKEN_FIELDS:
        value = form.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if raw_json_body and raw_json_body.strip():
        try:
            parsed = json.loads(raw_json_body)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            value = parsed.get("token")
            if isinstance(value, str) and value.strip():
                return value.strip()
    cookie = cookies.get("kiwi_token")
    if isinstance(cookie, str) and cookie.strip():
        return cookie.strip()
    return None


def client_ip(remote_addr: Optional[str], forwarded_for: Optional[str], trust_proxy: bool) -> str:
    """The client ip bound into the verify call."""
    if trust_proxy and forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        if first:
            return first
    return (remote_addr or "127.0.0.1").strip() or "127.0.0.1"


def build_request(
    verify_url: str,
    token: str,
    scope: str,
    ip: str,
    bearer: str = "",
) -> Dict[str, Any]:
    """The sidecar json contract: {token, scope, remoteip} + bearer."""
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return {
        "url": verify_url or VERIFY_URL_DEFAULT,
        "headers": headers,
        "body": json.dumps({"token": token, "scope": scope, "remoteip": ip}),
    }


def decide(status: int, body: str) -> Dict[str, Any]:
    """The decision table: a transport failure, 5xx or 401/404 is a
    gate fault; the rest answer the challenge verdict."""
    if status == 0 or status >= 500 or status in (401, 404):
        return {"ok": False, "code": "verify_unavailable"}
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return {"ok": False, "code": "verify_unreadable"}
    if not isinstance(parsed, dict):
        return {"ok": False, "code": "verify_unreadable"}
    if parsed.get("success") is True:
        return {"ok": True, "code": "verified"}
    return {"ok": False, "code": "challenge_failed"}


def verify(
    settings: Dict[str, Any],
    token: str,
    scope: str,
    remote_addr: Optional[str],
    forwarded_for: Optional[str],
    transport: Transport,
) -> Dict[str, Any]:
    """One verify call end to end. The transport answers
    {status: int, body: str} and may raise for a connection failure
    (mapped to the gate fault)."""
    request = build_request(
        verify_url=str(settings.get("verify_url") or VERIFY_URL_DEFAULT),
        token=token,
        scope=scope,
        ip=client_ip(remote_addr, forwarded_for, bool(settings.get("trust_proxy"))),
        bearer=str(settings.get("bearer") or ""),
    )
    try:
        answer = transport(request["url"], request["body"], request["headers"])
    except Exception:  # noqa: BLE001 - any transport failure is a fault
        return {"ok": False, "code": "verify_unavailable"}
    return decide(int(answer.get("status", 0)), str(answer.get("body", "")))


def requests_transport(url: str, body: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """The production transport: authentik ships requests. A non-2xx
    answer still returns, so the decision table sees the status."""
    import requests  # local import: only needed in production

    response = requests.post(url, data=body, headers=headers, timeout=5)
    return {"status": response.status_code, "body": response.text}
