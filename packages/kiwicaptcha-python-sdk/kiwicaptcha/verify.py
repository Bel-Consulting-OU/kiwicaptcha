"""The solution verifier: the exact cheap-gate order and the consumed
resolution of the PHP Verifier, over the storage seam.

The gate order is normative and mirrors ``Verifier::verify()``:
nonce match, structure, protocol gate, kid revocation, kid resolution,
signature, Argon2id ceilings, rsw bounds, TTL, scope, request binding,
IP binding, region, policy epoch, issuer, execution binding and
minimum duration. The policy epoch carries the rollout-floor window.
Then comes the opt-in telemetry gate, the terminal-state resolution,
the admission gate, consume, proof, the post-derive final revalidation
and the result commit.

Verify is pure-local: it never calls out to any network service. The
only side effects are the storage transitions the one-shot model
requires. Execution-armed records (the signed ``e=`` commitment) are
refused deterministically with ``execution_mismatch``: the browser-trace
walker is a browser-behavior oracle this SDK does not carry, and an
armed record must never pass without it.
"""

import base64
import hashlib
import hmac
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

from . import argon2 as argon2_backend
from .argon2 import derive as argon2id_derive
from .canonical import (
    ServerStateMac,
    binding_tag,
    constant_time_equals,
    hash_ip_v1,
    leading_zero_bits,
    verify_record_signature,
)
from .constants import (
    MAX_ARGON_MEMORY_KIB,
    MAX_ARGON_TIME,
    MAX_DIFFICULTY,
    MAX_PROTOCOL_VERSION,
    MAX_TTL_SECS,
    MIN_DIFFICULTY,
    MIN_RSW_T,
    MAX_RSW_T,
)
from .errors import VerifyError, VerifyOutcome
from .execution import MAX_EXECUTION_VERSION, execution_commitment, is_valid_program
from .sidecar import ExecutionPolicy, delegate_to_sidecar, delegation_enabled
from .records import (
    ChallengeRecord,
    is_valid_decoy_field_name,
    is_valid_identifier,
    protocol_extension_grammar_ok,
)
from .rsw import Rsw
from .rsw import fingerprint as rsw_fingerprint
from .telemetry import score as score_telemetry
from .tokens import DecodeError, SolutionToken
from .stores.base import (
    AtomicDeleteIfPendingStorage,
    AuthenticatedResultCommitStorage,
    ChallengeRuntimeStateKind,
    ConsumedRecord,
    ConsumedResult,
    ConsumedStateReadableStorage,
    DeleteIfPendingResult,
    OperationIdentityAwareStorage,
    RuntimeStateReadableStorage,
    Storage,
)

SKEW_TOLERANCE_US = 5_000_000
MAX_CLOCK_SKEW = 60
MIN_ARGON_MEMORY_KIB = 8
MAX_ARGON_MEMORY_KIB = 65536
MIN_ARGON_TIME = 3
MAX_ARGON_TIME = 16
MIN_PARALLELISM = 1
MAX_PARALLELISM = 4

_FINGERPRINT_HEX_LEN = 64


def _is_hex64(value: str) -> bool:
    return len(value) == _FINGERPRINT_HEX_LEN and all(
        c in "0123456789abcdef" for c in value
    )


def rsw_modulus_fingerprint(modulus_b64: str) -> Optional[str]:
    """The canonical identity: SHA-256 of the decoded modulus bytes.

    None when the modulus is not canonical standard base64 of exactly
    256 bytes.
    """
    return rsw_fingerprint(modulus_b64)


def rsw_modulus_legacy_identity(modulus_b64: str) -> str:
    """The legacy pre-v5 identity: SHA-256 of the base64 text itself."""
    return hashlib.sha256(modulus_b64.encode("ascii")).hexdigest()


def rsw_modulus_identity_matches(
    identity: str, modulus_b64: str, allow_legacy_alias: bool
) -> bool:
    """Whether the identity is an accepted form of the modulus."""
    canonical = rsw_modulus_fingerprint(modulus_b64)
    if canonical is not None and constant_time_equals(canonical, identity):
        return True
    return allow_legacy_alias and constant_time_equals(
        rsw_modulus_legacy_identity(modulus_b64), identity
    )


class RequestBindingExpectation:
    """The explicit request-binding enforcement policy.

    ``exact`` is Option-equality: null equals an explicitly unbound
    record and a string equals the same bound transaction. ``legacy``
    reproduces the historical nullable behavior, where a null expected
    binding disables enforcement and a bound expectation compares only
    records that carry one. ``unenforced`` skips the check entirely.
    """

    __slots__ = ("enforced", "expected", "require_binding_presence")

    def __init__(
        self,
        enforced: bool,
        expected: Optional[str],
        require_binding_presence: bool,
    ) -> None:
        self.enforced = enforced
        self.expected = expected
        self.require_binding_presence = require_binding_presence

    @classmethod
    def unenforced(cls) -> "RequestBindingExpectation":
        return cls(False, None, False)

    @classmethod
    def exact(cls, binding: Optional[str]) -> "RequestBindingExpectation":
        return cls(True, binding, True)

    @classmethod
    def legacy(cls, binding: Optional[str]) -> "RequestBindingExpectation":
        return cls(binding is not None, binding, False)


class ExecutionEvidence:
    """The execution digest and trace a solution token carries."""

    __slots__ = ("digest", "trace")

    def __init__(self, digest: Optional[str], trace: Optional[str]) -> None:
        self.digest = digest
        self.trace = trace

    @classmethod
    def from_token(cls, token: SolutionToken) -> "ExecutionEvidence":
        return cls(token.execution_digest, token.execution_trace)

    def is_empty(self) -> bool:
        return self.digest is None and self.trace is None


class AdmissionGate:
    """The admission-gate seam, mirroring VerificationAdmissionGate.

    ``acquire`` returns a lease object when a slot was granted, or None
    on exhaustion. ``release`` returns the lease; a failing release must
    never break the verification (the challenge is already consumed).
    ``admits`` answers whether the gate's budget covers a record's
    signed parameters at all — the hard refuse for absurd profiles,
    checked before any slot is taken. Subclass or duck-type to bind a
    semaphore, a token bucket or any bounded pool.
    """

    def acquire(self) -> Optional[object]:  # pragma: no cover - seam
        return object()

    def release(self, lease: object) -> None:  # pragma: no cover - seam
        return None

    def admits(self, record: object) -> bool:  # pragma: no cover - seam
        return True


class ArgonAdmissionGate(AdmissionGate):
    """The shipped default: bounded concurrency plus a hard params budget.

    Pure-Python derivation of a 16-64 MiB rung costs seconds of CPU per
    request, so the default refuses any profile whose memory or time
    cost leaves the configured budget before a slot is handed out
    (``admits`` is False; the verifier answers
    ``unsupported_argon2_params``, never a silent downgrade). With the
    native binding the budget is the protocol's process ceiling; the
    pure last-resort backend gets a deliberately tight budget whose
    worst-case derivation stays under about a second. Exhaustion of the
    bounded pool answers ``capacity_exceeded`` and the record stays
    retryable.
    """

    #: Worst-case pure-Python admission budget (8 MiB, t=3): about a
    #: second of interpreted block compression on commodity hardware.
    PURE_MAX_MEMORY_KIB = 8_192
    PURE_MAX_TIME = 3

    def __init__(
        self,
        max_concurrent: int = 2,
        max_memory_kib: Optional[int] = None,
        max_time_cost: Optional[int] = None,
    ) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        if max_memory_kib is None or max_time_cost is None:
            if argon2_backend.native_available():
                budget_memory = MAX_ARGON_MEMORY_KIB
                budget_time = MAX_ARGON_TIME
            else:
                budget_memory = self.PURE_MAX_MEMORY_KIB
                budget_time = self.PURE_MAX_TIME
        else:
            budget_memory = max_memory_kib
            budget_time = max_time_cost
        if budget_memory < 1 or budget_time < 1:
            raise ValueError("the argon gate budget must be positive")
        self.max_concurrent = max_concurrent
        self.max_memory_kib = budget_memory
        self.max_time_cost = budget_time
        self._slots = threading.Semaphore(max_concurrent)

    def admits(self, record: object) -> bool:
        return self.admits_params(
            getattr(record, "m_kib", 0) or 0, getattr(record, "t", 0) or 0
        )

    def admits_params(self, m_kib: int, t_cost: int) -> bool:
        return m_kib <= self.max_memory_kib and t_cost <= self.max_time_cost

    def acquire(self) -> Optional[object]:
        if not self._slots.acquire(blocking=False):
            return None
        return object()

    def release(self, lease: object) -> None:
        try:
            self._slots.release()
        except ValueError:
            pass


def _gate_admits(gate: Any, record: Any) -> bool:
    """The additive params-admission check; a gate without the method
    admits everything (the pure acquire/release seam stays intact)."""
    admits = getattr(gate, "admits", None)
    if admits is None:
        return True
    return bool(admits(record))


class VerifierConfig:
    """The verifier construction options, mirroring the PHP constructor.

    ``argon_gate`` admits argon2id derivations; ``None`` installs the
    shipped :class:`ArgonAdmissionGate` (a hard params budget plus
    bounded concurrency — never an ungated derivation). ``now_provider``
    returns epoch seconds (float or int) and stands in
    for the wall clock in tests. ``secrets_by_kid`` maps positive integer
    kid values to secrets of at least 32 bytes; an empty map keeps the
    legacy single-secret path. ``rsw_modulus_n`` and ``rsw_lambda`` must
    be configured together or both left None.
    """

    def __init__(
        self,
        argon_gate: Optional[AdmissionGate] = None,
        now_provider: Optional[Callable[[], Any]] = None,
        accept_legacy_v1: bool = False,
        region: Optional[str] = None,
        expected_policy_version: Optional[int] = None,
        expected_issuer: Optional[str] = None,
        secrets_by_kid: Optional[Dict[int, str]] = None,
        revoked_kids: Optional[Tuple[int, ...]] = None,
        rsw_modulus_n: Optional[str] = None,
        rsw_lambda: Optional[str] = None,
        tenant_id: Optional[str] = None,
        rsw_verification_keys: Optional[Dict[str, Dict[str, str]]] = None,
        allow_legacy_rsw_identity: bool = False,
        policy_version_floor: Optional[int] = None,
    ) -> None:
        secrets_by_kid = dict(secrets_by_kid or {})
        for kid, secret in secrets_by_kid.items():
            if (
                not isinstance(kid, int)
                or isinstance(kid, bool)
                or kid < 1
                or not isinstance(secret, str)
                or len(secret) < 32
            ):
                raise ValueError(
                    "secrets_by_kid keys must be positive integers 1..N with"
                    " secrets of at least 32 bytes"
                )
        for kid in revoked_kids or ():
            if not isinstance(kid, int) or isinstance(kid, bool) or kid < 1:
                raise ValueError("revoked_kids values must be positive integers 1..N")
        if (rsw_modulus_n is None) != (rsw_lambda is None):
            raise ValueError(
                "rsw_modulus_n and rsw_lambda must be configured together"
                " (the rsw trapdoor pair)"
            )
        if tenant_id is not None and not is_valid_identifier(tenant_id, 64):
            raise ValueError(
                "tenant_id must be 1-64 characters of [A-Za-z0-9._:-] when set"
            )
        self.argon_gate: AdmissionGate = argon_gate if argon_gate is not None else ArgonAdmissionGate()
        self.now_provider = now_provider
        self.accept_legacy_v1 = accept_legacy_v1
        self.region = region
        self.expected_policy_version = expected_policy_version
        self.expected_issuer = expected_issuer
        self.secrets_by_kid = secrets_by_kid
        self.revoked_kids = tuple(revoked_kids or ())
        self.tenant_id = tenant_id
        self.allow_legacy_rsw_identity = allow_legacy_rsw_identity
        self.policy_version_floor = policy_version_floor
        self._newest_kid: Optional[int] = None
        if secrets_by_kid:
            self._newest_kid = max(secrets_by_kid)
        self.rsw: Optional[Rsw] = None
        if rsw_modulus_n is not None and rsw_lambda is not None:
            self.rsw = Rsw(rsw_modulus_n, rsw_lambda)
        self._rsw_by_hash: Dict[str, Rsw] = {}
        self._rsw_modulus_by_hash: Dict[str, str] = {}
        for key, pair in (rsw_verification_keys or {}).items():
            if not isinstance(key, str) or not _is_hex64(key):
                raise ValueError(
                    "rsw_verification_keys keys must be 64-hex modulus SHA-256"
                    " digests"
                )
            modulus_n = (pair or {}).get("modulus_n")
            lam = (pair or {}).get("lambda")
            if not isinstance(modulus_n, str) or modulus_n == "" or not isinstance(lam, str) or lam == "":
                raise ValueError(
                    "rsw_verification_keys values must map the digest to a"
                    " {modulus_n, lambda} pair of non-empty strings"
                )
            if not rsw_modulus_identity_matches(
                key, modulus_n, self.allow_legacy_rsw_identity
            ):
                raise ValueError(
                    "rsw_verification_keys keys must be the canonical SHA-256"
                    " of the decoded modulus_n (or its legacy base64-text"
                    " alias while allow_legacy_rsw_identity is enabled)"
                )
            trapdoor = Rsw(modulus_n, lam)
            identities = {key, rsw_modulus_fingerprint(modulus_n)}
            if self.allow_legacy_rsw_identity:
                identities.add(rsw_modulus_legacy_identity(modulus_n))
            for identity in identities:
                self._rsw_by_hash[identity] = trapdoor
                self._rsw_modulus_by_hash[identity] = modulus_n

    def rotate_deployment_expectations(
        self,
        policy_version: Optional[int],
        region: Optional[str],
        issuer: Optional[str],
    ) -> None:
        """Test seam: rotate the current expectations mid-verification."""
        self.expected_policy_version = policy_version
        self.region = region
        self.expected_issuer = issuer


class VerifyOptions:
    """One verify call's parameters, the keyword bundle of ``verify``."""

    __slots__ = (
        "secret_key",
        "expected_scope",
        "client_ip",
        "now_ns",
        "enforce_telemetry",
        "operation_identity",
        "expected_request_binding",
        "binding_expectation",
        "execution_policy",
    )

    def __init__(
        self,
        secret_key: str,
        expected_scope: str,
        client_ip: Optional[str] = None,
        now_ns: Optional[int] = None,
        enforce_telemetry: bool = False,
        operation_identity: Optional[str] = None,
        expected_request_binding: Optional[str] = None,
        binding_expectation: Optional[RequestBindingExpectation] = None,
        execution_policy: Optional["ExecutionPolicy"] = None,
    ) -> None:
        self.secret_key = secret_key
        self.expected_scope = expected_scope
        self.client_ip = client_ip
        self.now_ns = now_ns
        self.enforce_telemetry = enforce_telemetry
        self.operation_identity = operation_identity
        self.expected_request_binding = expected_request_binding
        self.binding_expectation = binding_expectation
        # The execution-armed dimension policy: None (the default)
        # fails every armed record closed; the sidecar policy delegates
        # that single verification to a co-located kiwicaptcha-verifier
        # sidecar (see kiwicaptcha.sidecar).
        self.execution_policy = execution_policy


class Verifier:
    """The one-shot solution verifier over a store adapter."""

    def __init__(self, storage: Storage, config: Optional[VerifierConfig] = None) -> None:
        self.storage = storage
        self.config = config if config is not None else VerifierConfig()

    # ---- clock helpers -------------------------------------------------

    def _now_secs(self) -> float:
        if self.config.now_provider is not None:
            return self.config.now_provider()
        return time.time()

    # ---- record validation ---------------------------------------------

    def validate_record(self, record: ChallengeRecord) -> bool:
        """The structural validation of ``Verifier::validateRecord``."""
        if record.protocol_version < 1 or record.protocol_version > MAX_PROTOCOL_VERSION:
            return False
        execution_present = record.execution_program is not None
        if not protocol_extension_grammar_ok(
            record.protocol_version,
            record.decoy_field is not None,
            execution_present,
            record.rsw_modulus_sha256 is not None,
        ):
            return False
        scope_len = len(record.scope)
        if scope_len < 1 or scope_len > 128 or not is_valid_identifier(record.scope, 128):
            return False
        if record.decoy_field is not None and not is_valid_decoy_field_name(
            record.decoy_field
        ):
            return False
        if execution_present:
            if (
                record.execution_version is None
                or record.execution_version < 1
                or record.execution_version > MAX_EXECUTION_VERSION
                or record.execution_commitment is None
            ):
                return False
            if not _is_hex64(record.execution_commitment):
                return False
            if not constant_time_equals(
                execution_commitment(record.execution_program),
                record.execution_commitment,
            ):
                return False
        elif record.execution_version is not None or record.execution_commitment is not None:
            return False
        if record.rsw_modulus_sha256 is not None:
            if record.algorithm != "rsw" or not _is_hex64(record.rsw_modulus_sha256):
                return False
        try:
            nonce_bytes = base64.b64decode(record.nonce, validate=True)
            salt_bytes = base64.b64decode(record.salt, validate=True)
        except Exception:
            return False
        if len(nonce_bytes) != 32 or len(salt_bytes) != 16:
            return False
        if (
            record.expires_at <= record.issued_at
            or record.expires_at - record.issued_at > MAX_TTL_SECS
        ):
            return False
        if not constant_time_equals(
            record.challenge + "|" + record.salt + "|", record.prefix
        ):
            return False
        if record.target_bits < MIN_DIFFICULTY or record.target_bits > MAX_DIFFICULTY:
            return False
        if record.execution_program is not None:
            if not is_valid_program(record.execution_program):
                return False
        return True

    # ---- cheap-phase pieces ---------------------------------------------

    def is_revoked_kid(self, kid: Optional[int]) -> bool:
        return kid is not None and kid in self.config.revoked_kids

    def secret_for_key(self, record: ChallengeRecord, legacy_secret: str) -> Optional[str]:
        secrets = self.config.secrets_by_kid
        if not secrets:
            return legacy_secret
        newest = self.config._newest_kid
        if newest is not None and record.kid is not None and record.kid > newest:
            return None
        if record.kid is None or record.kid not in secrets:
            return None
        return secrets[record.kid]

    def verify_signature(self, record: ChallengeRecord, secret_key: str) -> bool:
        return verify_record_signature(record, secret_key, self.config.tenant_id)

    def argon2_ceilings_ok(self, record: ChallengeRecord) -> bool:
        if record.algorithm != "argon2id":
            return True
        return (
            MIN_ARGON_MEMORY_KIB <= record.m_kib <= MAX_ARGON_MEMORY_KIB
            and MIN_ARGON_TIME <= record.t <= MAX_ARGON_TIME
            and MIN_PARALLELISM <= record.p <= MAX_PARALLELISM
        )

    def rsw_params_ok(self, record: ChallengeRecord) -> bool:
        if record.algorithm != "rsw":
            return True
        return MIN_RSW_T <= record.t <= MAX_RSW_T

    def check_authenticated_shape(
        self, record: ChallengeRecord, legacy_secret: str
    ) -> Optional[VerifyError]:
        if not self.validate_record(record):
            return VerifyError.MALFORMED_RECORD
        if record.protocol_version == 1 and not self.config.accept_legacy_v1:
            return VerifyError.MALFORMED_RECORD
        if self.is_revoked_kid(record.kid):
            return VerifyError.UNKNOWN_KID
        signing_secret = self.secret_for_key(record, legacy_secret)
        if signing_secret is None:
            return VerifyError.UNKNOWN_KID
        if not self.verify_signature(record, signing_secret):
            return VerifyError.BAD_SIGNATURE
        if not self.argon2_ceilings_ok(record):
            return VerifyError.UNSUPPORTED_ARGON2_PARAMS
        if not self.rsw_params_ok(record):
            return VerifyError.UNSUPPORTED_RSW_PARAMS
        return None

    def check_ttl(self, record: ChallengeRecord) -> Optional[VerifyError]:
        now = int(self._now_secs())
        if now >= record.expires_at:
            return VerifyError.EXPIRED
        if record.issued_at > now + MAX_CLOCK_SKEW:
            return VerifyError.EXPIRED
        return None

    def check_request_binding(
        self, record: ChallengeRecord, expectation: RequestBindingExpectation
    ) -> Optional[VerifyError]:
        if not expectation.enforced:
            return None
        if record.request_binding is None or expectation.expected is None:
            if record.request_binding is None and not expectation.require_binding_presence:
                return None
            if record.request_binding == expectation.expected:
                return None
            return VerifyError.REQUEST_BINDING_MISMATCH
        if constant_time_equals(record.request_binding, expectation.expected):
            return None
        return VerifyError.REQUEST_BINDING_MISMATCH

    def check_scope_and_binding(
        self,
        record: ChallengeRecord,
        expected_scope: Optional[str],
        expectation: RequestBindingExpectation,
    ) -> Optional[VerifyError]:
        # The scope option is required: an empty option refuses with
        # the typed code instead of accepting any scope.
        if not expected_scope:
            return VerifyError.REQUIRED_SCOPE
        if record.scope != expected_scope:
            return VerifyError.WRONG_SCOPE
        return self.check_request_binding(record, expectation)

    def check_ip_binding(
        self, record: ChallengeRecord, client_ip: Optional[str], signing_secret: str
    ) -> Optional[VerifyError]:
        if record.binding_tag != "":
            if client_ip is None:
                return VerifyError.MISSING_CLIENT_IP
            try:
                if record.protocol_version == 1:
                    expected_tag = hash_ip_v1(client_ip, signing_secret)
                else:
                    expected_tag = binding_tag(
                        record.nonce, client_ip, signing_secret, self.config.tenant_id
                    )
            except ValueError:
                return VerifyError.IP_MISMATCH
            if not constant_time_equals(expected_tag, record.binding_tag):
                return VerifyError.IP_MISMATCH
        return None

    def policy_version_accepted(self, record_version: Optional[int]) -> bool:
        if self.config.expected_policy_version is None:
            return True
        if self.config.policy_version_floor is None:
            return record_version == self.config.expected_policy_version
        return (
            self.config.policy_version_floor <= record_version
            and record_version <= self.config.expected_policy_version
        )

    def check_deployment_expectations(
        self, record: ChallengeRecord
    ) -> Optional[VerifyError]:
        if (
            self.config.region is not None
            and record.region != self.config.region
        ):
            return VerifyError.WRONG_REGION
        if not self.policy_version_accepted(record.policy_version if record.policy_version is not None else 1):
            return VerifyError.WRONG_POLICY_VERSION
        if (
            self.config.expected_issuer is not None
            and record.issuer != self.config.expected_issuer
        ):
            return VerifyError.WRONG_ISSUER
        return None

    def check_execution_binding(
        self, record: ChallengeRecord, evidence: ExecutionEvidence
    ) -> Optional[VerifyError]:
        if record.execution_program is None:
            return None if evidence.is_empty() else VerifyError.EXECUTION_MISMATCH
        # An armed record demands the browser-trace walker, a
        # browser-behavior oracle this SDK does not carry. The armed
        # dimension fails closed: the record's own authenticated
        # program and commitment still verify, but no submission can
        # satisfy the armed binding, matching the mandate that a
        # missing capability must never widen acceptance.
        _ = evidence
        return VerifyError.EXECUTION_MISMATCH

    def check_min_duration(
        self, record: ChallengeRecord, now_ns: Optional[int]
    ) -> Optional[VerifyError]:
        if record.issued_at_ns <= 0:
            return VerifyError.MALFORMED_RECORD
        floor = max(0, record.min_duration_ms)
        if floor > 0 and record.server_mac is None:
            return VerifyError.MALFORMED_RECORD
        if floor > 0:
            receipt_ns = now_ns if now_ns is not None else int(time.time() * 1_000_000)
            if receipt_ns >= record.issued_at_ns:
                if receipt_ns - record.issued_at_ns < floor * 1_000:
                    return VerifyError.TOO_FAST
            elif record.issued_at_ns - receipt_ns > SKEW_TOLERANCE_US:
                return VerifyError.TOO_FAST
        return None

    def measurable_solve_duration_ms(
        self, record: ChallengeRecord, receipt_ns: Optional[int]
    ) -> Optional[int]:
        if (
            record.server_mac is None
            or record.issued_at_ns <= 0
            or receipt_ns is None
            or receipt_ns < record.issued_at_ns
        ):
            return None
        return (receipt_ns - record.issued_at_ns) // 1_000

    def cheap_phase_check(
        self,
        record: ChallengeRecord,
        token_nonce: str,
        secret_key: str,
        expected_scope: Optional[str],
        client_ip: Optional[str],
        check_timing: bool,
        now_ns: Optional[int],
        expectation: RequestBindingExpectation,
        evidence: ExecutionEvidence,
        delegate_execution: bool = False,
    ) -> Optional[VerifyError]:
        if record.nonce != token_nonce:
            return VerifyError.MALFORMED_RECORD
        error = self.check_authenticated_shape(record, secret_key)
        if error is not None:
            return error
        signing_secret = self.secret_for_key(record, secret_key) or ""
        if check_timing:
            error = self.check_ttl(record)
            if error is not None:
                return error
        error = self.check_scope_and_binding(record, expected_scope, expectation)
        if error is not None:
            return error
        error = self.check_ip_binding(record, client_ip, signing_secret)
        if error is not None:
            return error
        error = self.check_deployment_expectations(record)
        if error is not None:
            return error
        if not delegate_execution:
            # The delegation path leaves the execution gate to the
            # sidecar's full-core pass; every other gate stays local.
            error = self.check_execution_binding(record, evidence)
            if error is not None:
                return error
        if check_timing:
            error = self.check_min_duration(record, now_ns)
            if error is not None:
                return error
        return None

    def replay_security_check(
        self,
        record: ChallengeRecord,
        secret_key: str,
        expected_scope: Optional[str],
        expectation: RequestBindingExpectation,
        evidence: ExecutionEvidence,
        receipt_ns: Optional[int],
    ) -> Optional[VerifyError]:
        error = self.check_authenticated_shape(record, secret_key)
        if error is not None:
            return error
        error = self.check_scope_and_binding(record, expected_scope, expectation)
        if error is not None:
            return error
        error = self.check_deployment_expectations(record)
        if error is not None:
            return error
        error = self.check_execution_binding(record, evidence)
        if error is not None:
            return error
        error = self.check_min_duration(record, receipt_ns)
        if error is not None:
            return error
        return None

    # ---- retained state --------------------------------------------------

    def retained_consumed_state(self, nonce: str) -> str:
        if not isinstance(self.storage, ConsumedStateReadableStorage):
            return "unknown"
        try:
            return "consumed" if self.storage.consumed_state(nonce) is not None else "pending"
        except Exception:
            return "unreadable"

    def best_effort_delete(self, nonce: str) -> None:
        try:
            self.storage.delete(nonce)
        except Exception:
            pass

    # ---- proof ------------------------------------------------------------

    def derive_hash(self, record: ChallengeRecord, counter: int) -> Optional[bytes]:
        try:
            salt_bytes = base64.b64decode(record.salt, validate=True)
        except Exception:
            return None
        password = record.prefix + str(counter)
        if record.algorithm == "sha256":
            return hashlib.sha256(password.encode("ascii") + salt_bytes).digest()
        if record.algorithm == "argon2id":
            return self._argon2id(password, salt_bytes, record)
        return None

    def _argon2id(
        self, password: str, salt_bytes: bytes, record: ChallengeRecord
    ) -> Optional[bytes]:
        # The protocol profile is p == 1 and t >= 3: parameters outside
        # it are authentic but unsupported, the libsodium split.
        if record.p != 1 or record.t < 3:
            return None
        mem_kib = record.m_kib
        if mem_kib * 1024 < 8192:
            return None
        try:
            return argon2id_derive(
                password.encode("utf-8"), salt_bytes, record.t, mem_kib, lanes=1, out_len=32
            )
        except ValueError:
            return None

    def recompute_valid_proof(
        self, record: ChallengeRecord, token: SolutionToken
    ) -> Optional[bool]:
        if record.algorithm == "rsw":
            rsw = self._resolve_rsw(record)
            if rsw is None:
                return None
            if token.counter != 0 or token.rsw_proof is None:
                return False
            expected = rsw.expected_proof_hex(record.prefix, record.nonce, record.t)
            return constant_time_equals(expected, token.rsw_proof)
        if token.rsw_proof is not None:
            return False
        digest = self.derive_hash(record, token.counter)
        if digest is None:
            return None
        return leading_zero_bits(digest) >= record.target_bits

    def _resolve_rsw(self, record: ChallengeRecord) -> Optional[Rsw]:
        if record.rsw_modulus_sha256 is not None:
            allow_alias = (
                self.config.allow_legacy_rsw_identity and record.protocol_version <= 4
            )
            identity = record.rsw_modulus_sha256
            modulus = self.config._rsw_modulus_by_hash.get(identity)
            if modulus is not None and rsw_modulus_identity_matches(
                identity, modulus, allow_alias
            ):
                return self.config._rsw_by_hash[identity]
            if self.config.rsw is not None and rsw_modulus_identity_matches(
                identity, self.config.rsw.modulus_b64, allow_alias
            ):
                return self.config.rsw
            return None
        return self.config.rsw

    # ---- commits -----------------------------------------------------------

    def commit_consumed_result(
        self,
        record: ChallengeRecord,
        valid: bool,
        operation_identity: Optional[str],
        secret: str,
    ) -> bool:
        binding = record.request_binding
        if isinstance(self.storage, AuthenticatedResultCommitStorage):
            mac_key = ServerStateMac.key(secret, self.config.tenant_id)
            mac = ServerStateMac.consumed_result(
                mac_key, record.challenge, valid, binding, operation_identity
            )
            result = ConsumedResult(valid, binding, mac)
            return self.storage.commit_authenticated_result(record.nonce, result)
        return self.storage.commit_result(record.nonce, valid, binding)

    def best_effort_commit(
        self,
        record: ChallengeRecord,
        valid: bool,
        operation_identity: Optional[str],
        secret: str,
    ) -> None:
        try:
            self.commit_consumed_result(record, valid, operation_identity, secret)
        except Exception:
            pass

    def stored_success_authentic(
        self, consumed: ConsumedRecord, secret_key: str
    ) -> bool:
        result = consumed.consumed_result
        if result is None or not result.valid:
            return False
        if result.mac is None:
            return not isinstance(self.storage, AuthenticatedResultCommitStorage)
        secret = self.secret_for_key(consumed.record, secret_key)
        if secret is None:
            return False
        key = ServerStateMac.key(secret, self.config.tenant_id)
        return ServerStateMac.verify_consumed_result(key, consumed)

    def authenticated_hostname(
        self, record: ChallengeRecord, secret_key: str
    ) -> Optional[str]:
        if record.server_mac is None:
            return None
        secret = self.secret_for_key(record, secret_key)
        if secret is None:
            return None
        key = ServerStateMac.key(secret, self.config.tenant_id)
        if not ServerStateMac.verify_record_meta(key, record):
            return None
        return record.hostname

    # ---- consumed resolution -------------------------------------------------

    def resolve_consumed_record(
        self,
        consumed: ConsumedRecord,
        token_nonce: str,
        operation_identity: Optional[str],
        secret_key: str,
    ) -> VerifyOutcome:
        if consumed.record.nonce != token_nonce:
            return VerifyOutcome.invalid(VerifyError.MALFORMED_RECORD)
        if consumed.consumed_result is None:
            return VerifyOutcome.invalid(VerifyError.CONSUME_INDETERMINATE)
        if not consumed.consumed_result.valid:
            return VerifyOutcome.invalid(VerifyError.INSUFFICIENT_WORK)
        if (
            operation_identity is not None
            and consumed.operation_identity is not None
            and constant_time_equals(consumed.operation_identity, operation_identity)
        ):
            if not self.stored_success_authentic(consumed, secret_key):
                return VerifyOutcome.invalid(VerifyError.MALFORMED_RECORD)
            return VerifyOutcome.valid_outcome(
                nonce=consumed.record.nonce,
                request_binding=consumed.consumed_result.binding,
                from_stored_result=True,
                solve_duration_ms=None,
                decoy_field=consumed.record.decoy_field,
            )
        return VerifyOutcome.invalid(VerifyError.ALREADY_CONSUMED)

    # ---- the main entry --------------------------------------------------------

    def verify(self, raw_token: str, options: VerifyOptions) -> VerifyOutcome:
        """Verify one solution token against this verifier's store."""
        expectation = (
            options.binding_expectation
            if options.binding_expectation is not None
            else RequestBindingExpectation.exact(options.expected_request_binding)
        )
        secret_key = options.secret_key
        try:
            token = SolutionToken.decode(raw_token)
        except DecodeError as exc:
            return VerifyOutcome.malformed_token(str(exc))

        receipt_ns = (
            options.now_ns if options.now_ns is not None else int(time.time() * 1_000_000)
        )
        evidence = ExecutionEvidence.from_token(token)

        runtime = None
        peek: Optional[ChallengeRecord] = None
        if isinstance(self.storage, RuntimeStateReadableStorage):
            try:
                runtime = self.storage.runtime_state(token.nonce)
            except Exception:
                return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE)
            if runtime.kind == ChallengeRuntimeStateKind.MISSING:
                return VerifyOutcome.invalid(VerifyError.RECORD_NOT_FOUND)
            peek = runtime.record
        if peek is None:
            try:
                peek = self.storage.find(token.nonce)
            except Exception:
                return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE)
            if peek is None:
                return VerifyOutcome.invalid(VerifyError.RECORD_NOT_FOUND)

        # The execution delegation plane: an armed record under a
        # sidecar policy delegates the execution dimension after the
        # cheap phase proved everything the SDK checks locally.
        delegate_execution = delegation_enabled(peek, options.execution_policy)
        failure = self.cheap_phase_check(
            peek,
            token.nonce,
            secret_key,
            options.expected_scope,
            options.client_ip,
            True,
            receipt_ns,
            expectation,
            evidence,
            delegate_execution,
        )
        if failure is None and delegate_execution:
            ok, code = delegate_to_sidecar(
                raw_token, options.expected_scope, options.client_ip, options.execution_policy
            )
            if ok:
                return VerifyOutcome.valid_outcome(
                    nonce=token.nonce,
                    request_binding=peek.request_binding,
                    from_stored_result=True,
                    solve_duration_ms=None,
                    decoy_field=peek.decoy_field,
                )
            # The sidecar's kiwi-code is the shared wire vocabulary: a
            # known code maps onto the enum, an unknown one stays the
            # deterministic execution_mismatch deny (never widened).
            try:
                mapped = VerifyError(code)
            except ValueError:
                mapped = VerifyError.EXECUTION_MISMATCH
            return VerifyOutcome.invalid(mapped)
        if failure is not None:
            if isinstance(self.storage, AtomicDeleteIfPendingStorage) and failure != VerifyError.MISSING_CLIENT_IP:
                try:
                    cleanup: DeleteIfPendingResult = self.storage.delete_if_pending(token.nonce)
                except Exception:
                    return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE)
                if not cleanup.was_consumed():
                    return VerifyOutcome.invalid(failure)
                if not failure.is_replay_exempt():
                    return VerifyOutcome.invalid(failure)
                hard = self.replay_security_check(
                    peek, secret_key, options.expected_scope, expectation, evidence, receipt_ns
                )
                if hard is not None:
                    return VerifyOutcome.invalid(hard)
            else:
                if runtime is not None:
                    retained = (
                        "consumed"
                        if runtime.kind == ChallengeRuntimeStateKind.CONSUMED
                        else "pending"
                    )
                else:
                    retained = self.retained_consumed_state(token.nonce)
                if retained == "unreadable":
                    return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE)
                if retained == "consumed" and not failure.is_replay_exempt():
                    return VerifyOutcome.invalid(failure)
                if retained == "consumed":
                    hard = self.replay_security_check(
                        peek, secret_key, options.expected_scope, expectation, evidence, receipt_ns
                    )
                    if hard is not None:
                        return VerifyOutcome.invalid(hard)
                else:
                    if failure != VerifyError.MISSING_CLIENT_IP:
                        self.best_effort_delete(token.nonce)
                    return VerifyOutcome.invalid(failure)

        if (
            options.enforce_telemetry
            and (not token.telemetry or score_telemetry(token.telemetry, token.duration_ms))
            and not (runtime is not None and runtime.kind == ChallengeRuntimeStateKind.CONSUMED)
        ):
            if isinstance(self.storage, AtomicDeleteIfPendingStorage):
                try:
                    cleanup = self.storage.delete_if_pending(token.nonce)
                except Exception:
                    return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE)
                if not cleanup.was_consumed():
                    return VerifyOutcome.invalid(VerifyError.TELEMETRY_REJECTED)
            else:
                if runtime is not None:
                    retained = (
                        "consumed"
                        if runtime.kind == ChallengeRuntimeStateKind.CONSUMED
                        else "pending"
                    )
                else:
                    retained = self.retained_consumed_state(token.nonce)
                if retained == "unreadable":
                    return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE)
                if retained != "consumed":
                    self.best_effort_delete(token.nonce)
                    return VerifyOutcome.invalid(VerifyError.TELEMETRY_REJECTED)

        if runtime is not None:
            if runtime.kind == ChallengeRuntimeStateKind.CANCELLED:
                return VerifyOutcome.invalid(VerifyError.RECORD_NOT_FOUND)
            if runtime.kind == ChallengeRuntimeStateKind.CONSUMED:
                if runtime.consumed is not None:
                    return self.resolve_consumed_record(
                        runtime.consumed, token.nonce, options.operation_identity, secret_key
                    )
                if isinstance(self.storage, ConsumedStateReadableStorage):
                    try:
                        retained = self.storage.consumed_state(token.nonce)
                    except Exception:
                        return VerifyOutcome.invalid(VerifyError.STORAGE_UNAVAILABLE)
                    if retained is not None:
                        return self.resolve_consumed_record(
                            retained, token.nonce, options.operation_identity, secret_key
                        )

        lease = None
        if peek.algorithm == "argon2id":
            if not _gate_admits(self.config.argon_gate, peek):
                # The record's signed parameters leave the gate's
                # budget: refuse loudly, never derive and never
                # silently downgrade the rung.
                return VerifyOutcome.invalid(VerifyError.UNSUPPORTED_ARGON2_PARAMS)
            try:
                lease = self.config.argon_gate.acquire()
            except Exception:
                return VerifyOutcome.invalid(VerifyError.ADMISSION_UNAVAILABLE)
            if lease is None:
                return VerifyOutcome.invalid(VerifyError.CAPACITY_EXCEEDED)

        try:
            try:
                if (
                    options.operation_identity is not None
                    and isinstance(self.storage, OperationIdentityAwareStorage)
                ):
                    consumed = self.storage.consume_with_operation_identity(
                        token.nonce, options.operation_identity
                    )
                else:
                    consumed = self.storage.consume(token.nonce)
            except Exception:
                return VerifyOutcome.invalid(VerifyError.CONSUME_INDETERMINATE)
            if consumed is None:
                return VerifyOutcome.invalid(VerifyError.RECORD_NOT_FOUND)

            if consumed.consumed_before:
                return self.resolve_consumed_record(
                    consumed, token.nonce, options.operation_identity, secret_key
                )
            record = consumed.record

            consumed_secret = self.secret_for_key(record, secret_key)
            if (
                not constant_time_equals(peek.challenge, record.challenge)
                or self.is_revoked_kid(record.kid)
                or consumed_secret is None
                or not self.validate_record(record)
                or not self.verify_signature(record, consumed_secret)
            ):
                return VerifyOutcome.invalid(VerifyError.MALFORMED_RECORD)

            if not self.argon2_ceilings_ok(record):
                return VerifyOutcome.invalid(VerifyError.UNSUPPORTED_ARGON2_PARAMS)
            if not self.rsw_params_ok(record):
                return VerifyOutcome.invalid(VerifyError.UNSUPPORTED_RSW_PARAMS)

            if not self.policy_version_accepted(
                record.policy_version if record.policy_version is not None else 1
            ):
                return VerifyOutcome.invalid(VerifyError.WRONG_POLICY_VERSION)

            if (
                self.config.expected_issuer is not None
                and record.issuer != self.config.expected_issuer
            ):
                return VerifyOutcome.invalid(VerifyError.WRONG_ISSUER)

            valid = self.recompute_valid_proof(record, token)
            if valid is None:
                if record.algorithm == "rsw":
                    return VerifyOutcome.invalid(VerifyError.UNSUPPORTED_RSW_PARAMS)
                if record.algorithm == "argon2id":
                    return VerifyOutcome.invalid(VerifyError.UNSUPPORTED_ARGON2_PARAMS)
                return VerifyOutcome.invalid(VerifyError.MALFORMED_RECORD)

            now = int(self._now_secs())
            if now >= record.expires_at:
                return VerifyOutcome.invalid(VerifyError.EXPIRED)
            if not self.policy_version_accepted(
                record.policy_version if record.policy_version is not None else 1
            ):
                return VerifyOutcome.invalid(VerifyError.WRONG_POLICY_VERSION)
            if self.config.region is not None and record.region != self.config.region:
                return VerifyOutcome.invalid(VerifyError.WRONG_REGION)
            if (
                self.config.expected_issuer is not None
                and record.issuer != self.config.expected_issuer
            ):
                return VerifyOutcome.invalid(VerifyError.WRONG_ISSUER)

            if not valid:
                self.best_effort_commit(
                    record, False, consumed.operation_identity, consumed_secret
                )
                return VerifyOutcome.invalid(VerifyError.INSUFFICIENT_WORK)

            self.best_effort_commit(
                record, True, consumed.operation_identity, consumed_secret
            )
            return VerifyOutcome.valid_outcome(
                nonce=record.nonce,
                request_binding=record.request_binding,
                solve_duration_ms=self.measurable_solve_duration_ms(record, receipt_ns),
                decoy_field=record.decoy_field,
            )
        finally:
            if lease is not None:
                try:
                    self.config.argon_gate.release(lease)
                except Exception:
                    pass
