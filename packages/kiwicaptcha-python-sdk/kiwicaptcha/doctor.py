"""The doctor command: one command that validates a deployment.

``python -m kiwicaptcha.doctor`` runs four checks against a
deployment description given on the command line: the settings shape,
the secret length, a full store roundtrip (store, find, consume,
commit, delete) and the proof budget of the configured profile. Each
check reports ok or failed with a reason; the exit code is 0 when every
check passes and 1 otherwise.

    python -m kiwicaptcha.doctor --secret <32+ bytes> --store memory:// \\
        --scopes login,comment --profile standard
"""

import argparse
import base64
import hashlib
import sys
import time
from typing import List, Optional, Tuple

from . import argon2 as argon2_backend
from .argon2 import derive as argon2id_derive
from .canonical import canonical_payload, sign_payload_v2
from .constants import NONCE_B64_BYTES, SALT_B64_BYTES
from .records import ChallengeRecord, is_valid_identifier
from .stores import open_store
from .verify import Verifier, VerifierConfig

#: The profile to proof-budget mapping the doctor reports: the
#: algorithm a standard issuance mints and its difficulty rung.
PROFILE_BUDGETS = {
    "standard": ("sha256", 12),
    "argon16": ("argon2id", 8),
    "argon32": ("argon2id", 6),
    "argon64": ("argon2id", 4),
}


class CheckResult:
    __slots__ = ("name", "ok", "detail")

    def __init__(self, name: str, ok: bool, detail: str) -> None:
        self.name = name
        self.ok = ok
        self.detail = detail


def check_settings(secret: str, profile: str) -> CheckResult:
    from .config import MIN_SECRET_BYTES, PROFILES, PROFILE_ARGON_PARAMS, argon_rung_verifiable

    if len(secret) < MIN_SECRET_BYTES:
        return CheckResult(
            "settings",
            False,
            f"the secret must be at least {MIN_SECRET_BYTES} bytes",
        )
    if profile not in PROFILES:
        return CheckResult(
            "settings",
            False,
            f"the profile must be one of {', '.join(PROFILES)}",
        )
    rung = PROFILE_ARGON_PARAMS.get(profile)
    if rung is not None and not argon_rung_verifiable(*rung):
        return CheckResult(
            "settings",
            False,
            f"the profile {profile!r} issues an argon2id rung this"
            f" runtime cannot verify (backend"
            f" {argon2_backend.backend_name()}); install argon2-cffi or"
            " choose the standard profile",
        )
    return CheckResult("settings", True, "the settings shape is valid")


def check_store(store_url: str) -> CheckResult:
    try:
        storage = open_store(store_url)
    except Exception as exc:
        return CheckResult("store", False, f"the store did not open: {exc}")
    config = VerifierConfig()
    verifier = Verifier(storage, config)
    record = _self_check_record()
    try:
        storage.store(record)
        found = storage.find(record.nonce)
        consumed = storage.consume(record.nonce)
        committed = storage.commit_result(record.nonce, True, None)
        deleted = storage.delete(record.nonce)
    except Exception as exc:
        return CheckResult("store", False, f"the store roundtrip failed: {exc}")
    if found is None or consumed is None or not consumed.consumed_now:
        return (
            CheckResult("store", False, "the consume transition did not win"),
        )
    if not committed or not deleted:
        return CheckResult("store", False, "the commit or the delete refused")
    del verifier
    return CheckResult("store", True, "the store roundtrip is one-shot and clean")


def _self_check_record() -> ChallengeRecord:
    """A locally minted self-check record that never leaves the store."""
    import hmac as hmac_module

    secret = b"kiwicaptcha-doctor-self-check-secret-0000"
    nonce = base64.b64encode(bytes(NONCE_B64_BYTES)).decode("ascii")
    salt = base64.b64encode(bytes(SALT_B64_BYTES)).decode("ascii")
    now = int(time.time())
    expires = now + 60
    canonical = canonical_payload(
        2,
        nonce,
        "doctor",
        "",
        now,
        expires,
        "sha256",
        1,
        1,
        1,
        1,
        salt,
        0,
        region=None,
        policy_version=1,
        request_binding=None,
        issuer=None,
        kid=1,
    )
    signature = sign_payload_v2(canonical, secret.decode("ascii"), None)
    challenge = canonical + "." + signature
    prefix = challenge + "|" + salt + "|"
    return ChallengeRecord(
        nonce=nonce,
        scope="doctor",
        binding_tag="",
        issued_at=now,
        expires_at=expires,
        algorithm="sha256",
        m_kib=1,
        t=1,
        p=1,
        target_bits=1,
        salt=salt,
        prefix=prefix,
        challenge=challenge,
        min_duration_ms=0,
        issued_at_ns=0,
        protocol_version=2,
        policy_version=1,
        kid=1,
    )


def leading_zero_count(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
        else:
            count += 8 - byte.bit_length()
            break
    return count


def check_proof_budget(profile: str) -> CheckResult:
    algorithm, bits = PROFILE_BUDGETS[profile]
    if algorithm == "sha256":
        start = time.perf_counter()
        counter = 0
        prefix = "doctor|"
        while counter <= 2_000_000:
            digest = hashlib.sha256(
                prefix.encode() + str(counter).encode() + bytes(SALT_B64_BYTES)
            ).digest()
            if leading_zero_count(digest) >= bits:
                break
            counter += 1
        else:
            return CheckResult(
                "proof_budget", False, "the sha256 budget search ran away"
            )
        elapsed = time.perf_counter() - start
        return CheckResult(
            "proof_budget",
            True,
            f"{algorithm} at {bits} bits solved in {elapsed * 1000:.0f} ms"
            f" ({counter} iterations)",
        )
    start = time.perf_counter()
    argon2id_derive(b"doctor", bytes(SALT_B64_BYTES), 3, 16, lanes=1, out_len=32)
    elapsed = time.perf_counter() - start
    return CheckResult(
        "proof_budget",
        True,
        f"argon2id m=16 t=3 derived in {elapsed * 1000:.0f} ms"
        f" ({argon2_backend.backend_name()});"
        f" the {profile} rung accepts {bits} target bits",
    )


def check_scopes(scopes: Tuple[str, ...]) -> CheckResult:
    for scope in scopes:
        if not is_valid_identifier(scope, 128):
            return CheckResult(
                "scopes", False, f"the scope {scope!r} is not a valid identifier"
            )
    detail = (
        "every scope is a valid identifier: " + ", ".join(scopes)
        if scopes
        else "no scopes configured (every scope is accepted)"
    )
    return CheckResult("scopes", True, detail)


def run_checks(
    secret: str, store_url: str, scopes: Tuple[str, ...], profile: str
) -> List[CheckResult]:
    return [
        check_settings(secret, profile),
        check_store(store_url),
        check_scopes(scopes),
        check_proof_budget(profile),
    ]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m kiwicaptcha.doctor",
        description="Validate a kiwicaptcha deployment.",
    )
    parser.add_argument("--secret", required=True, help="the HMAC master secret")
    parser.add_argument("--store", default="memory://", help="the store URL")
    parser.add_argument(
        "--scopes", default="", help="comma separated accepted scopes"
    )
    parser.add_argument(
        "--profile", default="standard", help="the deployment's challenge profile"
    )
    args = parser.parse_args(argv)
    scopes = tuple(s for s in args.scopes.split(",") if s)
    results = run_checks(args.secret, args.store, scopes, args.profile)
    failed = False
    for result in results:
        marker = "ok  " if result.ok else "FAIL"
        if not result.ok:
            failed = True
        print(f"{marker} {result.name}: {result.detail}")
    if failed:
        print("doctor: the deployment needs attention")
        return 1
    print("doctor: every check passed")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    sys.exit(main())
