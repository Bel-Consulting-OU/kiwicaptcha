"""Deployment settings: the four-setting quickstart and the verifier
factory.

``Settings`` carries the deployment inputs the SDK needs at boot:
the signing ``secret``, the ``store`` URL, the accepted ``scopes`` and
the ``profile`` naming the challenge budget the deployment issues.
Everything else stays optional. ``build_verifier`` wires them into a
:class:`~kiwicaptcha.verify.Verifier` over the store adapter chosen by
``open_store``.
"""

from dataclasses import dataclass
from typing import Optional, Tuple

from .stores import open_store
from .verify import Verifier, VerifierConfig

MIN_SECRET_BYTES = 32

#: The named challenge budgets, mirroring the issuance-side profiles:
#: the sha256 standard rung and the three Argon2id memory rungs.
PROFILES = ("standard", "argon16", "argon32", "argon64")


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

    def build_verifier(self) -> Verifier:
        """Build the verifier over the configured store adapter."""
        config = VerifierConfig(
            accept_legacy_v1=self.accept_legacy_v1,
            region=self.region,
            expected_policy_version=self.expected_policy_version,
            expected_issuer=self.expected_issuer,
            tenant_id=self.tenant_id,
            policy_version_floor=self.policy_version_floor,
        )
        storage = open_store(self.store)
        return Verifier(storage, config)


__all__ = [
    "MIN_SECRET_BYTES",
    "PROFILES",
    "Settings",
    "VerifierConfig",
]
