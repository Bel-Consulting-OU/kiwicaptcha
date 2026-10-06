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


def client_ip(
    remote_addr: Optional[str],
    forwarded_for: Optional[str],
    trusted_proxies: str = "",
    real_ip: Optional[str] = None,
) -> str:
    """The client ip bound into the verify call, resolved through the
    shared trusted-proxy walk: the socket peer wins unless the peer
    sits inside the trusted proxy CIDR list (the default empty list
    trusts nobody, so a forged X-Forwarded-For never moves the
    binding). The chain is walked right to left through the trusted
    hops and X-Real-IP is honored when no chain exists."""
    import ipaddress
    import re

    peer = (remote_addr or "127.0.0.1").strip() or "127.0.0.1"
    cidrs = [c.strip() for c in (trusted_proxies or "").split(",") if c.strip()]
    if not cidrs:
        return peer

    control = re.compile(r"[\x00-\x1F\x7F]")

    def canonical(text: str) -> Optional[str]:
        value = text.strip()
        if value == "" or value == "unknown" or value.startswith("_"):
            return None
        candidate = value
        if candidate.startswith("["):
            closing = candidate.find("]")
            if closing == -1:
                return None
            suffix = candidate[closing + 1:]
            if suffix != "" and not _valid_port(suffix):
                return None
            candidate = candidate[1:closing]
        elif candidate.count(":") == 1:
            left, _, right = candidate.partition(":")
            if _strict_ipv4(left) and _valid_port(":" + right):
                candidate = left
        if ":" in candidate and candidate.count(":") < 2:
            parts = candidate.split(":")
            if _strict_ipv4(parts[-1]):
                candidate = ":".join(parts[:-1])
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            return None
        mapped = getattr(addr, "ipv4_mapped", None)
        return str(mapped) if mapped is not None else str(addr)

    def in_trusted(ip_text: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            addr = mapped
        for cidr in cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if network.version == addr.version and addr in network:
                return True
        return False

    peer_canonical = canonical(peer)
    peer_trusted = peer_canonical is not None and in_trusted(peer_canonical)
    forwarded = (forwarded_for or "").strip()
    if forwarded == "":
        if not peer_trusted:
            return peer
        candidate = (real_ip or "").strip()
        if candidate == "" or control.search(candidate):
            return peer
        return canonical(candidate) or peer
    if control.search(forwarded) or not peer_trusted:
        return peer
    for hop in reversed([part.strip() for part in forwarded.split(",")]):
        canonical_text = canonical(hop)
        if canonical_text is None:
            # An unparsable hop terminates the trust chain: who lies
            # beyond it cannot be established, so the peer falls back.
            return peer
        if not in_trusted(canonical_text):
            return canonical_text
    return peer


def _valid_port(suffix: str) -> bool:
    if not suffix.startswith(":"):
        return False
    digits = suffix[1:]
    return digits.isdigit() and len(digits) <= 5 and 1 <= int(digits) <= 65535


def _strict_ipv4(text: str) -> bool:
    import re

    return (
        re.match(
            r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$",
            text or "",
        )
        is not None
    )


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
    real_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """One verify call end to end. The transport answers
    {status: int, body: str} and may raise for a connection failure
    (mapped to the gate fault)."""
    request = build_request(
        verify_url=str(settings.get("verify_url") or VERIFY_URL_DEFAULT),
        token=token,
        scope=scope,
        ip=client_ip(
            remote_addr,
            forwarded_for,
            str(settings.get("trusted_proxies") or ""),
            real_ip,
        ),
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
