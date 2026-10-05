"""The signed canonical payload, its signature and the binding tags.

Port of the signing surfaces of packages/kiwicaptcha-php/src/Issuer.php
plus ServerStateMac.php. The canonical field order, the tagged
extension segments and the signature keys are the cross-language
contract: the bytes here are identical to the PHP and Rust cores.

Canonical layout, revision 4::

    v4|protocol_version|nonce|scope|binding_tag|issued_at|expires_at|
      algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|
      policy_version|request_binding|issuer|kid[|d=decoy][|e=v,hex]
      [|r=hex][|m=1]

Unset optional fields render as the empty segment. Every armed
extension is appended tagged in capability order, and the record
metadata mac marker ``m=1`` lands last, so stripping the mac breaks
the signature.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from typing import Any, List, Mapping, Optional, Sequence

from . import constants as c
from .keys import DerivedKeys

_HEX512 = re.compile(r"\A[0-9a-f]{512}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")

_SIGNATURE_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")


def canonical_payload(
    protocol_version: int,
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
    min_duration_ms: int,
    region: Optional[str] = None,
    policy_version: int = 1,
    request_binding: Optional[str] = None,
    issuer: Optional[str] = None,
    kid: int = 1,
    decoy_field: Optional[str] = None,
    execution_version: Optional[int] = None,
    execution_commitment: Optional[str] = None,
    rsw_modulus_sha256: Optional[str] = None,
    server_mac_committed: bool = False,
) -> str:
    """Assemble the signed canonical bytes for one record.

    The field order is the shared contract. The execution segments are
    appended only as the exact pair; a caller passing exactly one is a
    programming error and raises ValueError, so the canonical can never
    be ambiguous across languages.
    """
    base = "v4|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(
        protocol_version,
        nonce,
        scope,
        binding_tag,
        issued_at,
        expires_at,
        algorithm,
        m_kib,
        t,
        p,
        target_bits,
        salt,
        min_duration_ms,
        region if region is not None else "",
        policy_version,
        request_binding if request_binding is not None else "",
        issuer if issuer is not None else "",
        kid,
    )
    if decoy_field is not None:
        base += "|d=" + decoy_field
    if execution_version is not None or execution_commitment is not None:
        if execution_version is None or execution_commitment is None:
            raise ValueError(
                "execution_version and execution_commitment must be passed together"
            )
        base += "|e={},{}".format(execution_version, execution_commitment)
    if rsw_modulus_sha256 is not None:
        base += "|r=" + rsw_modulus_sha256
    if server_mac_committed:
        base += "|m=1"
    return base


def signed_canonical_commits_record_meta(challenge: str) -> bool:
    """True when the signed canonical carries the ``m=1`` marker.

    The marker is parsed from the challenge string itself, never
    inferred from the stored mac presence, so an ``m=1`` record must
    carry a valid mac regardless of any stored value.
    """
    pos = challenge.rfind(".")
    if pos < 0:
        return False
    try:
        canonical = _b64_decode_strict(challenge[:pos])
    except ValueError:
        return False
    return canonical.startswith("v4|") and canonical.endswith("|m=1")


def legacy_v1_payload(nonce: str, scope: str, ip_hash: str, issued_at: int) -> str:
    """The legacy v1 canonical: four untagged segments."""
    return "{}|{}|{}|{}".format(nonce, scope, ip_hash, issued_at)


def sign_payload_v1(canonical_payload_str: str, secret_key: str) -> str:
    """The legacy v1 signature: hmac under the master secret directly."""
    return hmac.new(
        secret_key.encode("utf-8", "surrogatepass"),
        canonical_payload_str.encode("utf-8", "surrogatepass"),
        "sha256",
    ).hexdigest()


def sign_payload_v2(canonical_payload_str: str, secret_key: str,
                    tenant_id: Optional[str] = None) -> str:
    """The v2 signature: hmac under the derived challenge purpose key."""
    key = DerivedKeys.from_master(secret_key, tenant_id).challenge_key
    return hmac.new(
        key,
        canonical_payload_str.encode("utf-8", "surrogatepass"),
        "sha256",
    ).hexdigest()


def signature_from_challenge(challenge: str) -> str:
    """The hex tag after the last dot of the challenge string."""
    pos = challenge.rfind(".")
    if pos < 0:
        return ""
    return challenge[pos + 1:]


def hash_ip_v1(ip: str, secret: str) -> str:
    """The legacy v1 binding value: sha256 hex of ``secret + ip``."""
    return hashlib.sha256(
        secret.encode("utf-8", "surrogatepass") + ip.encode("utf-8", "surrogatepass")
    ).hexdigest()


def canonical_ip_family(ip: str) -> bytes:
    """The family byte plus the packed bytes of one address.

    The reply is ``b"\\x04"`` plus the 4-byte ipv4 form, or ``b"\\x06"``
    plus the 16-byte ipv6 form. An ipv4-mapped or deprecated
    ipv4-compatible ipv6 form folds to its 4-byte ipv4 form, so two
    textual spellings of one address produce the same bytes. A
    non-address input raises ValueError, which the ip binding check
    resolves to the typed mismatch outcome.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("Invalid IP address") from None
    packed = addr.packed
    if len(packed) == 16:
        low = packed[12:]
        prefix = packed[:12]
        mapped = prefix == b"\x00" * 10 + b"\xff\xff"
        compatible = prefix == b"\x00" * 12 and low not in (
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x01",
        )
        if mapped or compatible:
            return b"\x04" + low
        return b"\x06" + packed
    return b"\x04" + packed


def binding_tag(nonce: str, ip: str, secret: str,
                tenant_id: Optional[str] = None) -> str:
    """The v2 binding tag: a nonce bound hmac over the canonical ip bytes.

    The tag is a nonce bound hmac, never a stable ip derived
    identifier. A client ip that cannot be canonicalized raises
    ValueError, which the verifier resolves to the typed mismatch.
    """
    family = canonical_ip_family(ip)
    message = b"kiwicaptcha/ip-bind/v2\x00" + nonce.encode("utf-8", "surrogatepass") + b"\x00" + family
    key = DerivedKeys.from_master(secret, tenant_id).ip_bind_key
    return hmac.new(key, message, "sha256").hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """Constant time string comparison."""
    return hmac.compare_digest(
        a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass")
    )


def leading_zero_bits(digest: bytes) -> int:
    """Count the leading zero bits of a hash, big-endian bit order."""
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        value = byte
        while value & 0x80 == 0:
            count += 1
            value = (value << 1) & 0xFF
        break
    return count


def _b64_decode_strict(raw: str) -> str:
    import base64
    import binascii

    try:
        plain = base64.b64decode(raw.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise ValueError("invalid base64") from None
    if base64.b64encode(plain).decode("ascii") != raw:
        raise ValueError("non-canonical base64")
    return plain.decode("utf-8", "surrogatepass")


class ServerStateMac:
    """Authentication of the server written state the signature skips.

    Two values live beside the signed record but outside the canonical:
    the record metadata ``issued_at_ns`` and ``hostname``, and the
    committed consumed result. Both are maced under the dedicated
    server state purpose key, so a storage writer without the master
    secret can neither backdate the issuance clock nor forge a stored
    success. The mac input binds the full challenge string and
    length-prefixes every variable field, so a mac can never be
    transplanted to another record.
    """

    RECORD_META_DOMAIN = c.RECORD_META_DOMAIN
    CONSUMED_RESULT_DOMAIN = c.CONSUMED_RESULT_DOMAIN
    PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")

    @staticmethod
    def key(secret: str, tenant_id: Optional[str] = None) -> bytes:
        return DerivedKeys.from_master(secret, tenant_id).server_state_key

    @staticmethod
    def record_meta(key: bytes, challenge: str, issued_at_ns: int,
                    hostname: Optional[str]) -> str:
        return hmac.new(
            key, ServerStateMac.record_meta_input(challenge, issued_at_ns, hostname).encode(
                "utf-8", "surrogatepass"
            ),
            "sha256",
        ).hexdigest()

    @staticmethod
    def consumed_result(key: bytes, challenge: str, valid: bool,
                        binding: Optional[str],
                        operation_identity: Optional[str]) -> str:
        return hmac.new(
            key,
            ServerStateMac.consumed_result_input(
                challenge, valid, binding, operation_identity
            ).encode("utf-8", "surrogatepass"),
            "sha256",
        ).hexdigest()

    @staticmethod
    def verify_record_meta(key: bytes, record: Any) -> bool:
        if record.server_mac is None:
            return False
        return hmac.compare_digest(
            ServerStateMac.record_meta(key, record.challenge, record.issued_at_ns,
                                       record.hostname).encode(),
            record.server_mac.encode(),
        )

    @staticmethod
    def verify_consumed_result(key: bytes, consumed: Any) -> bool:
        result = consumed.consumed_result
        if result is None or result.mac is None:
            return False
        return hmac.compare_digest(
            ServerStateMac.consumed_result(
                key, consumed.record.challenge, result.valid, result.binding,
                consumed.operation_identity,
            ).encode(),
            result.mac.encode(),
        )

    @staticmethod
    def record_meta_input(challenge: str, issued_at_ns: int,
                          hostname: Optional[str]) -> str:
        return "{}\n{}\n{}\n{}".format(
            ServerStateMac.RECORD_META_DOMAIN,
            ServerStateMac._lp(challenge),
            issued_at_ns,
            ServerStateMac._opt(hostname),
        )

    @staticmethod
    def consumed_result_input(challenge: str, valid: bool, binding: Optional[str],
                              operation_identity: Optional[str]) -> str:
        return "{}\n{}\n{}\n{}\n{}".format(
            ServerStateMac.CONSUMED_RESULT_DOMAIN,
            ServerStateMac._lp(challenge),
            "1" if valid else "0",
            ServerStateMac._opt(binding),
            ServerStateMac._opt(operation_identity),
        )

    @staticmethod
    def _lp(value: str) -> str:
        return "{}:{}".format(len(value.encode("utf-8", "surrogatepass")), value)

    @staticmethod
    def _opt(value: Optional[str]) -> str:
        if value is None:
            return "0"
        return "1:" + ServerStateMac._lp(value)


def verify_record_signature(record: Any, secret_key: str,
                            tenant_id: Optional[str] = None) -> bool:
    """Recompute the expected signature of a record and compare it.

    Protocol v1 uses the legacy canonical signed under the master
    secret; v2 and above use the full parameter canonical signed under
    the derived challenge key. The signed ``m=1`` marker requires a
    valid record metadata mac; a record signed without the marker
    accepts an absent mac and always verifies a present one.
    """
    from .records import ChallengeRecord

    assert isinstance(record, ChallengeRecord)
    commits_mac = signed_canonical_commits_record_meta(record.challenge)
    if record.protocol_version == 1:
        expected = sign_payload_v1(
            legacy_v1_payload(record.nonce, record.scope, record.binding_tag,
                              record.issued_at),
            secret_key,
        )
    else:
        expected = sign_payload_v2(
            canonical_payload(
                record.protocol_version,
                record.nonce,
                record.scope,
                record.binding_tag,
                record.issued_at,
                record.expires_at,
                record.algorithm,
                record.m_kib,
                record.t,
                record.p,
                record.target_bits,
                record.salt,
                record.min_duration_ms,
                record.region,
                record.policy_version if record.policy_version is not None else 1,
                record.request_binding,
                record.issuer,
                record.kid if record.kid is not None else 1,
                record.decoy_field,
                record.execution_version,
                record.execution_commitment,
                record.rsw_modulus_sha256,
                commits_mac,
            ),
            secret_key,
            tenant_id,
        )
    presented = signature_from_challenge(record.challenge)
    if not constant_time_equals(expected, presented):
        return False

    key = ServerStateMac.key(secret_key, tenant_id)
    if commits_mac:
        return record.server_mac is not None and ServerStateMac.verify_record_meta(key, record)
    return record.server_mac is None or ServerStateMac.verify_record_meta(key, record)
