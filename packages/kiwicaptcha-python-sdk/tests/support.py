"""Shared test support: the canonical vectors, the corpus paths and the
record and token builders every suite composes."""

import base64
import hashlib
import json
import os

from kiwicaptcha.canonical import canonical_payload, sign_payload_v2, sign_payload_v1
from kiwicaptcha.records import ChallengeRecord
from kiwicaptcha.tokens import SolutionToken

PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(os.path.dirname(PACKAGE_ROOT))
PROTOCOL_DIR = os.path.join(REPO_ROOT, "protocol")

SECRET = "0123456789abcdef0123456789abcdef"
CLIENT_IP = "203.0.113.7"
ISSUED_AT = 1_800_000_000
NOW = 1_800_000_100
IP_HASH = "9c50b8d493de847656a168d0408bd4455994df2fc0b1e94bab5a85d64850034b"

SHA_VECTOR = {
    "nonce": "2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=",
    "challenge": "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58"
                 "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
                 "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
                 "dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba",
    "salt": "phUfA189G9A5KMv3r+wzLA==",
    "prefix": "MmwwSVZoMXh1S05qemNDRHlWK1gwbHJjZU1IbEh2bXFDczVNZER3OHR3MD18bG9naW58"
              "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
              "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
              "dee1893de8e9f57e974af43ec5b6e7523f7d09cee038a8edd5df59ad2f9248ba"
              "|phUfA189G9A5KMv3r+wzLA==|",
    "algorithm": "sha256",
    "m_kib": 0,
    "t": 1,
    "p": 1,
    "target_bits": 8,
    "counter": 158,
    "outcome": "Valid",
}

ARGON2_VECTOR = {
    "nonce": "Sn89Ua2qPftlfNO2K9jZSWB52OpcuYwRD1kf2GDhAX4=",
    "challenge": "U244OVVhMnFQZnRsZk5PMks5alpTV0I1Mk9wY3VZd1JEMWtmMkdEaEFYND18bG9naW58"
                 "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
                 "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
                 "2757c7cdabe01a52d31cb91900d64eaaae881dd25353dd79267ce35298b3c239",
    "salt": "6HL5BOgvD4ryefTBPNhS8A==",
    "prefix": "U244OVVhMnFQZnRsZk5PMks5alpTV0I1Mk9wY3VZd1JEMWtmMkdEaEFYND18bG9naW58"
              "OWM1MGI4ZDQ5M2RlODQ3NjU2YTE2OGQwNDA4YmQ0NDU1OTk0ZGYyZmMwYjFlOTRiYWI1YTg1"
              "ZDY0ODUwMDM0YnwxODAwMDAwMDAw."
              "2757c7cdabe01a52d31cb91900d64eaaae881dd25353dd79267ce35298b3c239"
              "|6HL5BOgvD4ryefTBPNhS8A==|",
    "algorithm": "argon2id",
    "m_kib": 64,
    "t": 3,
    "p": 1,
    "target_bits": 4,
    "counter": 21,
    "outcome": "Valid",
}


def load_token_fixtures() -> dict:
    path = os.path.join(PROTOCOL_DIR, "solution-token-v1", "fixtures.json")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_outcome_vectors() -> dict:
    path = os.path.join(PROTOCOL_DIR, "risk-v1", "outcomes-vectors.json")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def record_from_vector(vector: dict) -> ChallengeRecord:
    """The PHP VerifyFixtureTrait assembly, byte-identical fields."""
    return ChallengeRecord(
        nonce=vector["nonce"],
        scope="login",
        binding_tag=IP_HASH,
        issued_at=ISSUED_AT,
        expires_at=ISSUED_AT + 120,
        algorithm=vector["algorithm"],
        m_kib=int(vector["m_kib"]),
        t=int(vector["t"]),
        p=int(vector["p"]),
        target_bits=int(vector["target_bits"]),
        salt=vector["salt"],
        prefix=vector["prefix"],
        challenge=vector["challenge"],
        min_duration_ms=0,
        issued_at_ns=ISSUED_AT * 1_000_000,
        protocol_version=1,
    )


def token_for(vector: dict, counter=None, duration_ms=5000) -> str:
    return SolutionToken.create(
        vector["nonce"],
        vector["counter"] if counter is None else counter,
        duration_ms,
        {"wd": False, "me": 3, "ke": 1, "et": [100, 250, 480]},
    ).encode()


def mint_v2_record(
    secret: str = SECRET,
    scope: str = "login",
    nonce_bytes: bytes = bytes(range(32)),
    salt_bytes: bytes = bytes(range(16)),
    issued_at: int = ISSUED_AT,
    ttl: int = 120,
    algorithm: str = "sha256",
    m_kib: int = 1,
    t: int = 1,
    p: int = 1,
    target_bits: int = 4,
    min_duration_ms: int = 0,
    region=None,
    policy_version: int = 1,
    request_binding=None,
    issuer=None,
    kid: int = 1,
    binding_ip: str = "",
    tenant_id=None,
    protocol_version: int = 2,
    decoy_field=None,
    hostname=None,
    mint_meta_mac: bool = False,
    execution_program: str = None,
) -> ChallengeRecord:
    """Mint one record the way the PHP Issuer does, for tests.

    The challenge rides the wire form: ``base64(payload) + "." + sig``.
    With ``mint_meta_mac`` the canonical commits the ``m=1`` marker and
    the record carries the server-state MAC over the challenge, the
    issuance clock and the hostname.
    """
    nonce = base64.b64encode(nonce_bytes).decode("ascii")
    salt = base64.b64encode(salt_bytes).decode("ascii")
    expires_at = issued_at + ttl
    issued_at_ns = issued_at * 1_000_000
    if protocol_version == 1:
        ip_hash = hashlib.sha256(
            (secret + (binding_ip or CLIENT_IP)).encode()
        ).hexdigest()
        legacy = "%s|%s|%s|%d" % (nonce, scope, ip_hash, issued_at)
        signature = sign_payload_v1(legacy, secret)
        challenge = base64.b64encode(legacy.encode("ascii")).decode("ascii") + "." + signature
        binding_tag_value = ip_hash
    else:
        binding_tag_value = ""
        if binding_ip:
            from kiwicaptcha.canonical import binding_tag as compute_binding_tag

            binding_tag_value = compute_binding_tag(
                nonce, binding_ip, secret, tenant_id
            )
        payload = canonical_payload(
            protocol_version,
            nonce,
            scope,
            binding_tag_value,
            issued_at,
            expires_at,
            algorithm,
            m_kib,
            t,
            p,
            target_bits,
            salt,
            min_duration_ms,
            region=region,
            policy_version=policy_version,
            request_binding=request_binding,
            issuer=issuer,
            kid=kid,
            decoy_field=decoy_field,
            execution_version=4 if execution_program else None,
            execution_commitment=(
                hashlib.sha256(execution_program.encode("utf-8")).hexdigest()
                if execution_program
                else None
            ),
            server_mac_committed=mint_meta_mac,
        )
        signature = sign_payload_v2(payload, secret, tenant_id)
        challenge = base64.b64encode(payload.encode("ascii")).decode("ascii") + "." + signature
    server_mac = None
    if mint_meta_mac and protocol_version != 1:
        from kiwicaptcha.canonical import ServerStateMac

        server_mac = ServerStateMac.record_meta(
            ServerStateMac.key(secret, tenant_id), challenge, issued_at_ns, hostname
        )
    return ChallengeRecord(
        nonce=nonce,
        scope=scope,
        binding_tag=binding_tag_value,
        issued_at=issued_at,
        expires_at=expires_at,
        algorithm=algorithm,
        m_kib=m_kib,
        t=t,
        p=p,
        target_bits=target_bits,
        salt=salt,
        prefix=challenge + "|" + salt + "|",
        challenge=challenge,
        min_duration_ms=min_duration_ms,
        issued_at_ns=issued_at_ns,
        protocol_version=protocol_version,
        region=region,
        policy_version=policy_version,
        request_binding=request_binding,
        issuer=issuer,
        kid=kid,
        hostname=hostname,
        decoy_field=decoy_field,
        execution_program=execution_program,
        execution_version=4 if execution_program else None,
        execution_commitment=(
            hashlib.sha256(execution_program.encode("utf-8")).hexdigest()
            if execution_program
            else None
        ),
        server_mac=server_mac,
    )


def minimal_program_b64(scope: str = "login", action: str = "submit") -> str:
    """A minimal well-formed v1 program blob: eight OP_ADD records."""
    body = bytearray()
    body.append(1)  # format version
    body.append(len(scope))
    body.extend(scope.encode("ascii"))
    body.append(len(action))
    body.extend(action.encode("ascii"))
    body.append(1)  # op version
    body.append(8)  # op count
    for i in range(8):
        body.append(0)  # OP_ADD
        body.extend(((i + 1).to_bytes(4, "little")))
        body.extend((1).to_bytes(4, "little"))
    return base64.b64encode(bytes(body)).decode("ascii")


def solve_sha(prefix: str, salt_b64: str, target_bits: int, start: int = 0):
    """Search the sha256 counter to the target difficulty."""
    salt_bytes = base64.b64decode(salt_b64)
    counter = start
    while True:
        digest = hashlib.sha256(
            prefix.encode("ascii") + str(counter).encode("ascii") + salt_bytes
        ).digest()
        if leading_zero_bits(digest) >= target_bits:
            return counter
        counter += 1


def leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
        else:
            count += 8 - byte.bit_length()
            break
    return count
