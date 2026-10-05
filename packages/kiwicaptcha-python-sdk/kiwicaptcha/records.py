"""Server side challenge state and its strict wire parser.

Port of packages/kiwicaptcha-php/src/ChallengeRecord.php. The JSON
keys mirror the Rust serde schema one to one, and ``from_array``
accepts exactly what the Rust parser accepts: whitelisted keys, exact
algorithm values, strict integer types and ranges, bounded strings,
and nulls only where the schema allows them. Anything else raises
:class:`MalformedRecordError`.

The protocol grammar is total: v1 and v2 carry neither extension, v3
requires the decoy and carries no execution, v4 requires the execution
triplet and may carry the decoy, and v5 requires the rsw identity.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Optional

from . import constants as c
from . import execution

WIRE_KEYS = (
    "nonce", "scope", "binding_tag", "issued_at", "expires_at",
    "algorithm", "m_kib", "t", "p", "target_bits", "salt", "prefix",
    "challenge", "min_duration_ms", "issued_at_ns", "protocol_version",
    "attempts_used", "region", "policy_version", "request_binding",
    "issuer", "kid", "hostname", "decoy_field", "execution_program",
    "execution_version", "execution_commitment", "rsw_modulus_sha256",
    "server_mac",
)
_REQUIRED_KEYS = (
    "nonce", "scope", "binding_tag", "issued_at", "expires_at",
    "algorithm", "m_kib", "t", "p", "target_bits", "salt", "prefix",
    "challenge", "min_duration_ms",
)
_WIRE_KEY_SET = frozenset(WIRE_KEYS)

_ALGORITHMS = ("sha256", "argon2id", "rsw")
_U32_MAX = 4_294_967_295
_U64_MAX = 9_223_372_036_854_775_807

_HEX64_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
_HOSTNAME_CONTROL = re.compile(r"[\x00-\x20\x7f]")


class MalformedRecordError(ValueError):
    """A stored record violated the strict wire schema."""


def is_valid_identifier(value: str, max_bytes: int) -> bool:
    """The narrow security identifier alphabet with a length cap.

    Deployment bound identifiers must match ``[A-Za-z0-9._:-]+`` so no
    identifier can smuggle canonical separators, whitespace, or
    multibyte text into a signed payload segment.
    """
    length = len(value.encode("utf-8", "surrogatepass"))
    return 1 <= length <= max_bytes and re.match(r"\A[A-Za-z0-9._:-]+\Z", value) is not None


def is_valid_decoy_field_name(value: str) -> bool:
    """The honeypot field name alphabet: 1 to 64 bytes of ``[A-Za-z0-9_-]``.

    The alphabet excludes the canonical separators, so a stored name
    can never alter the structure of the signed payload.
    """
    length = len(value.encode("utf-8", "surrogatepass"))
    return 1 <= length <= 64 and re.match(r"\A[A-Za-z0-9_-]+\Z", value) is not None


def protocol_extension_grammar_ok(
    protocol_version: int,
    decoy_present: bool,
    execution_present: bool,
    rsw_identity_present: bool = False,
) -> bool:
    """The one protocol versus extension matrix every boundary applies.

    The legacy v1 signature covers no extension segment at all. v2 is
    the plain base canonical. v3 requires the decoy. v4 requires the
    execution triplet. v5 requires the rsw identity, and the decoy and
    execution segments there stay governed by their own signed shape.
    """
    if protocol_version == 1:
        return not decoy_present and not execution_present and not rsw_identity_present
    if protocol_version == c.BASE_PROTOCOL_VERSION:
        return not decoy_present and not execution_present
    if protocol_version == c.DECOY_PROTOCOL_VERSION:
        return decoy_present and not execution_present
    if protocol_version == c.EXECUTION_PROTOCOL_VERSION:
        return execution_present
    if protocol_version == c.RSW_IDENTITY_PROTOCOL_VERSION:
        return rsw_identity_present
    return False


def _require_string(data: Mapping[str, Any], field: str) -> str:
    value = data[field]
    if not isinstance(value, str):
        raise MalformedRecordError(f"{field} must be a string")
    if len(value.encode("utf-8", "surrogatepass")) > c.MAX_STRING_BYTES:
        raise MalformedRecordError(f"{field} exceeds the {c.MAX_STRING_BYTES} byte wire cap")
    return value


def _require_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedRecordError(f"{field} must be an integer within {minimum}..{maximum}")
    if value < minimum or value > maximum:
        raise MalformedRecordError(f"{field} must be an integer within {minimum}..{maximum}")
    return value


def _optional_identifier(data: Mapping[str, Any], field: str) -> Optional[str]:
    if field not in data or data[field] is None:
        return None
    value = _require_string(data, field)
    cap = 64 if field == "region" else 128
    if not is_valid_identifier(value, cap):
        raise MalformedRecordError(f"{field} must match the narrow identifier alphabet")
    return value


def _validate_hostname(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or value == "":
        raise MalformedRecordError("hostname must be a non-empty string or null")
    if len(value.encode("utf-8", "surrogatepass")) > c.MAX_STRING_BYTES:
        raise MalformedRecordError("hostname exceeds the wire string cap")
    if _HOSTNAME_CONTROL.search(value):
        raise MalformedRecordError("hostname must carry no whitespace or control characters")
    return value


class ChallengeRecord:
    """One persisted challenge with its signed canonical material.

    Field names mirror the PHP properties. ``server_mac`` authenticates
    the metadata the canonical does not cover; ``decoy_field`` and the
    execution triplet serialize only when present, so unarmed records
    keep the exact pre-extension byte format.
    """

    __slots__ = (
        "nonce", "scope", "binding_tag", "issued_at", "expires_at",
        "algorithm", "m_kib", "t", "p", "target_bits", "salt", "prefix",
        "challenge", "min_duration_ms", "issued_at_ns", "protocol_version",
        "region", "policy_version", "request_binding", "issuer", "kid",
        "hostname", "decoy_field", "execution_program", "execution_version",
        "execution_commitment", "rsw_modulus_sha256", "server_mac",
    )

    def __init__(
        self,
        nonce: str,
        scope: str,
        binding_tag: str,
        issued_at: int,
        expires_at: int,
        algorithm: str,
        m_kib: int,
        t: int,
        p: int,
        target_bits: int,
        salt: str,
        prefix: str,
        challenge: str,
        min_duration_ms: int,
        issued_at_ns: int = 0,
        protocol_version: int = 2,
        region: Optional[str] = None,
        policy_version: Optional[int] = 1,
        request_binding: Optional[str] = None,
        issuer: Optional[str] = None,
        kid: Optional[int] = 1,
        hostname: Optional[str] = None,
        decoy_field: Optional[str] = None,
        execution_program: Optional[str] = None,
        execution_version: Optional[int] = None,
        execution_commitment: Optional[str] = None,
        rsw_modulus_sha256: Optional[str] = None,
        server_mac: Optional[str] = None,
    ) -> None:
        self.nonce = nonce
        self.scope = scope
        self.binding_tag = binding_tag
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.algorithm = algorithm
        self.m_kib = m_kib
        self.t = t
        self.p = p
        self.target_bits = target_bits
        self.salt = salt
        self.prefix = prefix
        self.challenge = challenge
        self.min_duration_ms = min_duration_ms
        self.issued_at_ns = issued_at_ns
        self.protocol_version = protocol_version
        self.region = region
        self.policy_version = policy_version
        self.request_binding = request_binding
        self.issuer = issuer
        self.kid = kid
        self.hostname = hostname
        self.decoy_field = decoy_field
        self.execution_program = execution_program
        self.execution_version = execution_version
        self.execution_commitment = execution_commitment
        self.rsw_modulus_sha256 = rsw_modulus_sha256
        self.server_mac = server_mac

    @property
    def ip_hash(self) -> str:
        """The legacy v1 name of the binding tag.

        For v1 records the tag is exactly the legacy
        ``sha256(secret + ip)`` value, so v1 callers see the same bytes.
        """
        return self.binding_tag

    def to_array(self) -> Dict[str, Any]:
        """The canonical wire schema, mirroring the Rust serde struct.

        ``ip_hash`` is never emitted beside ``binding_tag``: a Rust
        reader rejects the duplicate field. The one optional key
        omitted when null keeps unarmed records byte identical to the
        pre-extension format.
        """
        data: Dict[str, Any] = {
            "nonce": self.nonce,
            "scope": self.scope,
            "binding_tag": self.binding_tag,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "algorithm": self.algorithm,
            "m_kib": self.m_kib,
            "t": self.t,
            "p": self.p,
            "target_bits": self.target_bits,
            "salt": self.salt,
            "prefix": self.prefix,
            "challenge": self.challenge,
            "min_duration_ms": self.min_duration_ms,
            "issued_at_ns": self.issued_at_ns,
            "protocol_version": self.protocol_version,
            "attempts_used": 0,
            "region": self.region,
            "policy_version": self.policy_version if self.policy_version is not None else 1,
            "request_binding": self.request_binding,
            "issuer": self.issuer,
            "kid": self.kid if self.kid is not None else 1,
            "hostname": self.hostname,
        }
        if self.decoy_field is not None:
            data["decoy_field"] = self.decoy_field
        if self.execution_program is not None:
            data["execution_program"] = self.execution_program
        if self.execution_version is not None:
            data["execution_version"] = self.execution_version
        if self.execution_commitment is not None:
            data["execution_commitment"] = self.execution_commitment
        if self.rsw_modulus_sha256 is not None:
            data["rsw_modulus_sha256"] = self.rsw_modulus_sha256
        if self.server_mac is not None:
            data["server_mac"] = self.server_mac
        return data

    @classmethod
    def from_array(cls, data: Mapping[str, Any]) -> "ChallengeRecord":
        """The strict serde mirror parser.

        Accepts exactly what the Rust ``ChallengeRecord`` parser
        accepts, including the legacy ``ip_hash`` alias, which must
        never appear beside ``binding_tag``. Unknown keys, partial
        execution triplets, forbidden protocol and extension
        combinations, and out-of-range integers all raise
        :class:`MalformedRecordError`.
        """
        if not isinstance(data, Mapping):
            raise MalformedRecordError("a record must decode from a JSON object")
        for key in data:
            if not isinstance(key, str) or (key != "ip_hash" and key not in _WIRE_KEY_SET):
                raise MalformedRecordError(f"unknown record key: {key}")

        if "ip_hash" in data:
            if "binding_tag" in data:
                raise MalformedRecordError("binding_tag and ip_hash are duplicate fields")
            merged = dict(data)
            merged["binding_tag"] = data["ip_hash"]
            data = merged

        for field in _REQUIRED_KEYS:
            if field not in data:
                raise MalformedRecordError(f"missing record field: {field}")

        for field in ("nonce", "scope", "binding_tag", "salt", "prefix", "challenge"):
            _require_string(data, field)
        for field in ("issued_at", "expires_at", "min_duration_ms"):
            _require_int(data.get(field), field, 0, _U64_MAX)
        _require_int(data.get("issued_at_ns", 0), "issued_at_ns", 0, _U64_MAX)
        for field in ("m_kib", "t", "p", "target_bits", "attempts_used"):
            _require_int(data.get(field, 0), field, 0, _U32_MAX)
        for field in ("policy_version", "kid"):
            _require_int(data.get(field, 1), field, 0, _U32_MAX)
        protocol_version = _require_int(
            data.get("protocol_version", 1),
            "protocol_version",
            1,
            c.MAX_PROTOCOL_VERSION,
        )

        algorithm = data["algorithm"]
        if algorithm not in _ALGORITHMS:
            raise MalformedRecordError(f"invalid algorithm: {algorithm}")

        for field in ("region", "request_binding", "issuer"):
            _optional_identifier(data, field)

        decoy_field: Optional[str] = None
        if data.get("decoy_field") is not None:
            decoy_field = _require_string(data, "decoy_field")
            if not is_valid_decoy_field_name(decoy_field):
                raise MalformedRecordError("invalid decoy field name")

        execution_program: Optional[str] = None
        if data.get("execution_program") is not None:
            execution_program = _require_string(data, "execution_program")
            if len(execution_program) > execution.MAX_PROGRAM_BASE64:
                raise MalformedRecordError("execution_program exceeds the wire cap")
            if not execution.is_valid_program(execution_program):
                raise MalformedRecordError("invalid execution program")

        has_version = data.get("execution_version") is not None
        has_commitment = data.get("execution_commitment") is not None
        if execution_program is not None or has_version or has_commitment:
            if execution_program is None or not has_version or not has_commitment:
                raise MalformedRecordError("incomplete execution fields")
            version = _require_int(data["execution_version"], "execution_version", 0, 255)
            if version < 1 or version > execution.MAX_EXECUTION_VERSION:
                raise MalformedRecordError(f"invalid execution version: {version}")
            commitment = _require_string(data, "execution_commitment")
            if not _HEX64_PATTERN.match(commitment):
                raise MalformedRecordError("invalid execution commitment")
            if execution.execution_commitment(execution_program) != commitment:
                raise MalformedRecordError("execution commitment mismatch")

        rsw_modulus_sha256 = cls._parse_rsw_identity(data)

        if not protocol_extension_grammar_ok(
            protocol_version,
            decoy_field is not None,
            execution_program is not None,
            rsw_modulus_sha256 is not None,
        ):
            raise MalformedRecordError(
                f"invalid protocol and extension combination: {protocol_version}"
            )

        server_mac: Optional[str] = None
        if data.get("server_mac") is not None:
            server_mac = _require_string(data, "server_mac")
            if not _HEX64_PATTERN.match(server_mac):
                raise MalformedRecordError("server_mac must be 64 lowercase hex characters")

        hostname = _validate_hostname(data.get("hostname"))

        return cls(
            nonce=data["nonce"],
            scope=data["scope"],
            binding_tag=data["binding_tag"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            algorithm=algorithm,
            m_kib=data["m_kib"],
            t=data["t"],
            p=data["p"],
            target_bits=data["target_bits"],
            salt=data["salt"],
            prefix=data["prefix"],
            challenge=data["challenge"],
            min_duration_ms=data["min_duration_ms"],
            issued_at_ns=data.get("issued_at_ns", 0),
            protocol_version=protocol_version,
            region=data.get("region"),
            policy_version=data.get("policy_version", 1),
            request_binding=data.get("request_binding"),
            issuer=data.get("issuer"),
            kid=data.get("kid", 1),
            hostname=hostname,
            decoy_field=decoy_field,
            execution_program=execution_program,
            execution_version=data["execution_version"] if has_version else None,
            execution_commitment=commitment if has_commitment else None,
            rsw_modulus_sha256=rsw_modulus_sha256,
            server_mac=server_mac,
        )

    @staticmethod
    def _parse_rsw_identity(data: Mapping[str, Any]) -> Optional[str]:
        value = data.get("rsw_modulus_sha256")
        if value is None:
            return None
        if not isinstance(value, str) or not _HEX64_PATTERN.match(value):
            raise MalformedRecordError("rsw_modulus_sha256 must be 64 lowercase hex characters")
        if data.get("algorithm") != "rsw":
            raise MalformedRecordError("rsw_modulus_sha256 may only ride an rsw record")
        if data.get("protocol_version", 1) == 1:
            raise MalformedRecordError(
                "rsw_modulus_sha256 may not ride the v1 canonical"
            )
        return value
