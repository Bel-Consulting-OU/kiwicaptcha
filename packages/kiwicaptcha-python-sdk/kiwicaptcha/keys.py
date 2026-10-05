"""Purpose key separation, byte-identical with the PHP DerivedKeys.

Every cryptographic purpose derives its own key from the single master
secret, so a compromise in one purpose never leaks the others. The
construction is RFC 5869 extract-then-expand over sha256:

    prk         = hmac-sha256(salt, master)
    k_x         = hmac-sha256(prk, info + 0x01)

with the deployment salt ``kiwicaptcha/deploy-salt/v1``. A tenant id
derives the purpose keys under a per-tenant root, so tenants sharing a
master secret cannot forge each other's challenges or binding tags.
"""

from __future__ import annotations

import hmac
from typing import Optional

from . import constants as c


def hkdf_sha256(ikm: bytes, info: bytes, salt: bytes, length: int = 32) -> bytes:
    """One extract-then-expand step of RFC 5869 with sha256."""
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, "sha256").digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), "sha256").digest()
        out += t
        counter += 1
    return out[:length]


class DerivedKeys:
    """The four purpose keys derived from one master secret.

    Construct through :func:`from_master`; the class memoizes derived
    sets per distinct master and tenant pair for the process lifetime,
    mirroring the PHP memo. The memo is tiny: a deployment holds a
    handful of immutable secrets.
    """

    _cache: dict[tuple[bytes, bool, str], "DerivedKeys"] = {}
    _cache_limit = 64

    __slots__ = ("challenge_key", "ip_bind_key", "result_key", "server_state_key")

    def __init__(
        self,
        challenge_key: bytes,
        ip_bind_key: bytes,
        result_key: bytes,
        server_state_key: bytes,
    ) -> None:
        self.challenge_key = challenge_key
        self.ip_bind_key = ip_bind_key
        self.result_key = result_key
        self.server_state_key = server_state_key

    @classmethod
    def from_master(cls, master: str, tenant_id: Optional[str] = None) -> "DerivedKeys":
        """Derive the purpose keys, memoized per master and tenant.

        A master secret shorter than the 32-byte floor raises
        ValueError: the derivation boundary carries the entropy
        invariant. A tenant id scopes the keys under the per-tenant
        root ``kiwi/v2/tenant/<tenant>``.
        """
        if not isinstance(master, str):
            raise TypeError("the master secret must be a str")
        if len(master.encode("utf-8", "surrogatepass")) < c.MIN_SECRET_BYTES:
            raise ValueError(
                f"the master secret must be at least {c.MIN_SECRET_BYTES} bytes"
                f" (got {len(master)})"
            )
        salt = c.HKDF_DEPLOY_SALT.encode()
        material = master.encode("utf-8", "surrogatepass")
        if tenant_id is not None:
            material = cls._hkdf(material, c.INFO_TENANT_ROOT_PREFIX + tenant_id, salt)
            salt = b""
        key = (material, tenant_id is not None, tenant_id or "")
        cached = cls._cache.get(key)
        if cached is not None:
            return cached
        derived = cls(
            challenge_key=cls._hkdf(material, c.INFO_CHALLENGE_SIGN, salt),
            ip_bind_key=cls._hkdf(material, c.INFO_IP_BIND, salt),
            result_key=cls._hkdf(material, c.INFO_RESULT_TOKEN, salt),
            server_state_key=cls._hkdf(material, c.INFO_SERVER_STATE, salt),
        )
        if len(cls._cache) >= cls._cache_limit:
            cls._cache.clear()
        cls._cache[key] = derived
        return derived

    @staticmethod
    def _hkdf(ikm: bytes, info: str, salt: bytes) -> bytes:
        return hkdf_sha256(ikm, info.encode(), salt, 32)
