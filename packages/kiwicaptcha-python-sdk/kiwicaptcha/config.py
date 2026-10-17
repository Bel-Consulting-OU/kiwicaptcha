"""Deployment settings: the four-setting quickstart and the verifier
factory.

``Settings`` carries the deployment inputs the SDK needs at boot:
the signing ``secret``, the ``store`` URL, the accepted ``scopes`` and
the ``profile`` naming the challenge budget the deployment issues.
Everything else stays optional. ``build_verifier`` wires them into a
:class:`~kiwicaptcha.verify.Verifier` over the store adapter chosen by
``open_store``.

Issuer guard: a profile is an issuance promise. Constructing settings
for a rung this runtime cannot verify raises a loud configuration
error — a deployment that would mint argon32 challenges against a
verifier that refuses them must never boot into a silent downgrade.
"""

from dataclasses import dataclass
from typing import Optional, Tuple

from . import argon2 as argon2_backend
from .stores import open_store
from .verify import (
    MAX_ARGON_MEMORY_KIB,
    MIN_ARGON_MEMORY_KIB,
    ArgonAdmissionGate,
    Verifier,
    VerifierConfig,
)

MIN_SECRET_BYTES = 32

#: The named challenge budgets, mirroring the issuance-side profiles:
#: the sha256 standard rung and the three Argon2id memory rungs.
PROFILES = ("standard", "argon16", "argon32", "argon64")

#: The Argon2id parameters (m_kib, t) each argon profile issues.
PROFILE_ARGON_PARAMS = {
    "argon16": (16 * 1024, 3),
    "argon32": (32 * 1024, 3),
    "argon64": (64 * 1024, 3),
}


def valid_argon_memory_kib(m_kib: int) -> bool:
    """The protocol Argon2id memory profile space.

    A power of two within 8..=65536 KiB, so every verifier — including
    log2-only bindings — can rederive what any profile mints. Budgets
    outside it are refused at configuration time, never per request.
    """
    return (
        isinstance(m_kib, int)
        and not isinstance(m_kib, bool)
        and MIN_ARGON_MEMORY_KIB <= m_kib <= MAX_ARGON_MEMORY_KIB
        and (m_kib & (m_kib - 1)) == 0
    )


def argon_rung_verifiable(m_kib: int, t_cost: int,
                          gate: Optional[ArgonAdmissionGate] = None) -> bool:
    """Whether this runtime can verify the argon2id rung (m_kib, t).

    The rung must sit in the protocol power-of-two profile space AND
    inside this runtime's admission budget. Without an explicit gate
    the default gate answers; it requires the native binding or a
    sidecar-admitted construction, so a runtime with neither simply
    answers False (the caller refuses the rung loudly at configuration
    time, never per request).
    """
    if not valid_argon_memory_kib(m_kib):
        return False
    if gate is None:
        if not argon2_backend.native_available():
            return False
        gate = ArgonAdmissionGate()
    return gate.admits_params(m_kib, t_cost)


@dataclass
class Settings:
    """The four-setting quickstart plus the optional expectation knobs.

    ``secret`` is the HMAC master secret, at least 32 bytes. ``store``
    is a store URL (``memory://``, ``sqlite:///path/db`` or
    ``redis://host:port``). ``scopes`` lists the accepted challenge
    scopes; an empty tuple accepts any scope. ``profile`` names the
    deployment's issuance budget for the doctor's report.
    """

    secret: str
    store: str = "memory://"
    scopes: Tuple[str, ...] = ()
    profile: str = "standard"
    region: Optional[str] = None
    expected_policy_version: Optional[int] = None
    policy_version_floor: Optional[int] = None
    expected_issuer: Optional[str] = None
    tenant_id: Optional[str] = None
    accept_legacy_v1: bool = False
    argon_sidecar_url: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.secret, str) or len(self.secret) < MIN_SECRET_BYTES:
            raise ValueError(
                f"secret must be at least {MIN_SECRET_BYTES} bytes"
            )
        if self.profile not in PROFILES:
            raise ValueError(
                f"profile must be one of {', '.join(PROFILES)} (got"
                f" {self.profile!r})"
            )
        if not isinstance(self.scopes, tuple):
            self.scopes = tuple(self.scopes)
        if self.argon_sidecar_url is not None and not self.argon_sidecar_url.strip():
            raise ValueError(
                "argon_sidecar_url must be a non-empty URL when set"
            )
        rung = PROFILE_ARGON_PARAMS.get(self.profile)
        if rung is not None and not valid_argon_memory_kib(rung[0]):
            raise ValueError(
                f"profile {self.profile!r} issues argon2id memory"
                f" m_kib={rung[0]}, outside the protocol profile space"
                " (powers of two within 8..=65536 KiB): refused at"
                " configuration time, never per request"
            )
        sidecar_admitted = bool(
            self.argon_sidecar_url and self.argon_sidecar_url.strip()
        )
        if rung is not None and not sidecar_admitted and not argon_rung_verifiable(*rung):
            raise ValueError(
                f"profile {self.profile!r} issues an argon2id rung"
                f" (m_kib={rung[0]}, t={rung[1]}) this runtime cannot"
                " verify within its admission budget"
                f" (backend {argon2_backend.backend_name()});"
                f" {argon2_backend.BACKEND_REQUIRED_MESSAGE} Or choose"
                " the standard profile — the rung is never silently"
                " downgraded"
            )

    def build_verifier(self) -> Verifier:
        """Build the verifier over the configured store adapter.

        The deployment secret is validated again here: ``Settings`` is
        mutable, so a value edited after construction must not reach a
        verifier silently. The per-call ``secret_key`` option keeps its
        own behavior in :meth:`Verifier.verify`.
        """
        if self.secret and len(self.secret) < MIN_SECRET_BYTES:
            raise ValueError(
                f"secret must be at least {MIN_SECRET_BYTES} bytes"
            )
        config = VerifierConfig(
            accept_legacy_v1=self.accept_legacy_v1,
            region=self.region,
            scopes=self.scopes,
            expected_policy_version=self.expected_policy_version,
            expected_issuer=self.expected_issuer,
            tenant_id=self.tenant_id,
            policy_version_floor=self.policy_version_floor,
            argon_sidecar_url=self.argon_sidecar_url,
        )
        storage = open_store(self.store)
        return Verifier(storage, config)


__all__ = [
    "MIN_SECRET_BYTES",
    "PROFILES",
    "PROFILE_ARGON_PARAMS",
    "ArgonAdmissionGate",
    "Settings",
    "VerifierConfig",
    "argon_rung_verifiable",
    "valid_argon_memory_kib",
]
