"""The shared python client of the red-team campaigns.

stdlib only: urllib for the wire, subprocess for the native solver.
Every campaign drives the REAL deployment surfaces through this client
so a campaign failure is a deployment failure, never a fixture artifact.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

REPO_ROOT = os.environ.get(
    "KIWI_RT_REPO_ROOT",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")),
)
SOLVER = os.path.join(REPO_ROOT, "target", "debug", "kiwicaptcha-solver")


class Response:
    """One HTTP round trip: status, parsed body (best effort), raw body."""

    def __init__(self, status: int, raw: bytes):
        self.status = status
        self.raw = raw
        try:
            self.body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.body = None

    @property
    def ok(self) -> bool:
        return bool(self.body.get("ok")) if isinstance(self.body, dict) else False

    @property
    def code(self) -> str:
        if isinstance(self.body, dict):
            if isinstance(self.body.get("error"), dict):
                return str(self.body["error"].get("code", ""))
            return str(self.body.get("code", ""))
        return ""

    @property
    def error_code(self) -> str:
        if isinstance(self.body, dict) and isinstance(self.body.get("error"), dict):
            return str(self.body["error"].get("code", ""))
        return ""


def post_json(url: str, payload, headers: dict | None = None,
              raw_body: bytes | None = None, timeout: float = 30.0) -> Response:
    """POST a JSON document (or raw bytes) and return the Response."""
    data = raw_body if raw_body is not None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("content-type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return Response(resp.status, resp.read(1 << 20))
    except urllib.error.HTTPError as err:
        return Response(err.code, err.read(1 << 20))
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return Response(0, b"")


def get(url: str, headers: dict | None = None, timeout: float = 30.0) -> Response:
    req = urllib.request.Request(url)
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return Response(resp.status, resp.read(1 << 20))
    except urllib.error.HTTPError as err:
        return Response(err.code, err.read(1 << 20))
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return Response(0, b"")


def challenge(base: str, scope: str = "login", binding: str | None = None,
              extra: dict | None = None) -> Response:
    """Issue one challenge through the deployment's real issuer."""
    payload = {"scope": scope}
    if binding is not None:
        payload["request_binding"] = binding
    if extra:
        payload.update(extra)
    return post_json(base + "/challenge", payload)


def solve(base: str, scope: str = "login", binding: str | None = None) -> dict:
    """The honest attacker path: fetch a challenge, pay the PoW, carry
    the token. Returns the solver's result document (token, hashes,
    duration_ms)."""
    cmd = [SOLVER, "solve", "--endpoint", base + "/challenge", "--scope", scope]
    if binding is not None:
        # The solver CLI carries no binding flag; solve unbound and let
        # the caller bind at the verify surface.
        cmd = [SOLVER, "solve", "--endpoint", base + "/challenge", "--scope", scope]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        return {"solved": False, "error": proc.stderr.strip()[-400:]}
    return json.loads(proc.stdout)


def solve_token(base: str, scope: str = "login") -> str:
    doc = solve(base, scope)
    return str(doc.get("token", "")) if doc.get("solved") else ""


def verify(base: str, token: str, scope: str = "login",
           binding: str | None = None, omit_token: bool = False,
           raw_body: bytes | None = None) -> Response:
    payload: dict = {"scope": scope}
    if not omit_token:
        payload["token"] = token
    if binding is not None:
        payload["request_binding"] = binding
    if raw_body is not None:
        return post_json(base + "/verify", None, raw_body=raw_body)
    return post_json(base + "/verify", payload)


def forge_token(nonce_b64: str, counter: int = 1, duration_ms: int = 5,
                tail: str = "{}") -> str:
    """Mint a structurally valid token around a nonce the attacker
    knows, without paying the proof of work."""
    inner = f"{nonce_b64}.{counter}.{duration_ms}.{tail}"
    return base64.b64encode(inner.encode("utf-8")).decode("ascii")


def pow_solve(challenge_doc: dict) -> int:
    """The honest proof of work for one challenge document, in the
    browser's price band: sha256(prefix || decimal(counter) || salt),
    first counter whose digest carries the target leading zero bits.
    Mirrors the shared preimage contract of the solver crate."""
    import hashlib

    prefix = str(challenge_doc["prefix"])
    salt = base64.b64decode(str(challenge_doc["salt"]))
    target_bits = int(challenge_doc.get("targetBits", 16))
    threshold = 1 << (256 - target_bits)
    counter = 0
    while True:
        digest = hashlib.sha256(
            prefix.encode() + str(counter).encode() + salt
        ).digest()
        if int.from_bytes(digest, "big") < threshold:
            return counter
        counter += 1


def mint_token(nonce_b64: str, counter: int, duration_ms: int = 5) -> str:
    """The wire token of a paid proof: base64(nonce.counter.duration.{})."""
    return forge_token(nonce_b64, counter, duration_ms, "{}")


def mutate_token(token: str, offset: int, replacement: str = "A") -> str:
    """Flip one character of a real token at a bounded offset."""
    if not token:
        return token
    pos = offset % len(token)
    return token[:pos] + replacement + token[pos + 1:]


def bench_rung_usd_per_thousand(rungs: str = "sha16", samples: int = 3) -> dict:
    """The measured attacker economics from the bench tool. Parses the
    solver's per-rung wall time table; the dollar table comes from the
    reference-costs file the bench itself prints."""
    proc = subprocess.run(
        [SOLVER, "bench", "--samples", str(samples), "--rungs", rungs],
        capture_output=True, text=True, timeout=600,
    )
    if proc.returncode != 0:
        return {}
    measurements: dict = {}
    in_table = False
    for line in proc.stdout.splitlines():
        # The measurement table starts at its own header row; the
        # output carries further sections whose rows also begin with
        # a rung name, so collection stops at the next blank line.
        if line.startswith("rung algorithm mean_us"):
            in_table = True
            continue
        if in_table:
            if not line.strip():
                in_table = False
                continue
            parts = line.split()
            if len(parts) >= 3:
                try:
                    measurements[parts[0]] = float(parts[2])
                except ValueError:
                    continue
    return measurements


def sha16_mean_us(samples: int = 3) -> float:
    data = bench_rung_usd_per_thousand("sha16", samples)
    return float(data.get("sha16", 0.0))


def monotonic_ms() -> float:
    return time.monotonic() * 1000.0
