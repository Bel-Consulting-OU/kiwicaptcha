"""The execution delegation plane of the python SDK.

An execution-armed record demands the browser-trace walker, an oracle
this SDK does not carry: the default policy fails every armed record
closed (``execution_mismatch``, documented). The sidecar policy
delegates that single verification to a co-located
kiwicaptcha-verifier sidecar over HTTP: the sidecar carries the full
Rust core with the real execution verifier, consumes the record
(single-use semantics preserved: the sidecar consumes, this SDK never
double-consumes) and answers the provider-shaped verdict mapped back
into this SDK's vocabulary.

Trust boundary: the sidecar decides acceptances, so it must be
co-located and trusted to the same standard as the verifier itself.
The bearer credential is sent per request, and a refused credential
denies instead of retrying into an untrusted verifier.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional


@dataclass
class ExecutionPolicy:
    """The execution-armed dimension policy of one verify call.

    The default (``None`` on the verify options) is the fail-closed
    behavior. A policy with a ``sidecar_url`` delegates.
    """

    sidecar_url: str = ""
    bearer_token: str = ""
    timeout_ms: int = 5000

    def enabled(self) -> bool:
        return bool(self.sidecar_url and self.sidecar_url.strip())


def delegation_enabled(record, policy: Optional[ExecutionPolicy]) -> bool:
    """Whether the record and the policy select the delegation path."""
    return record.execution_program is not None and policy is not None and policy.enabled()


def delegate_to_sidecar(
    raw_token: str,
    scope: str,
    client_ip: Optional[str],
    policy: ExecutionPolicy,
) -> tuple[bool, str]:
    """Hand one execution-armed verification to the sidecar.

    Returns ``(ok, code)``: ``ok`` means the sidecar's full-core pass
    accepted; a failure maps the sidecar's ``kiwi-code`` (the shared
    wire vocabulary) through verbatim, with the transport failures
    fail-closed (``storage_unavailable`` keeps the retry disposition
    with the record intact).
    """
    base = policy.sidecar_url.strip().rstrip("/")
    body = json.dumps({"token": raw_token, "scope": scope, "remoteip": client_ip}).encode()
    request = urllib.request.Request(
        f"{base}/verify",
        data=body,
        headers={
            "content-type": "application/json",
            **({"authorization": f"Bearer {policy.bearer_token}"} if policy.bearer_token else {}),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=max(1, policy.timeout_ms) / 1000) as response:
            status = response.status
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            # The sidecar refused the credential: never retry into an
            # untrusted verifier, fail closed with a deny.
            return False, "execution_mismatch"
        if exc.code >= 500:
            return False, "storage_unavailable"
        return False, "execution_mismatch"
    except Exception:
        return False, "storage_unavailable"
    if status != 200:
        return False, "execution_mismatch"
    if payload.get("success"):
        return True, "ok"
    return False, payload.get("kiwi-code") or "execution_mismatch"
