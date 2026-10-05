"""The store adapter seam: record envelopes, runtime states and the
capability protocols the verifier composes.

Every backend implements :class:`Storage`. The narrower capabilities
are optional: the verifier probes them with ``isinstance`` against
these runtime-checkable protocols and follows the same fallbacks as the
PHP verifier. The fallbacks cover the plain consume without an
identity, the one-shot delete on a cheap failure, and the legacy commit
without a server-state MAC. The shipped memory, SQLite and Redis
backends implement every capability here.
"""

from enum import Enum
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from ..records import ChallengeRecord

MIN_SECRET_BYTES = 32


class ChallengeRuntimeStateKind(Enum):
    """The terminal-aware runtime classification of one storage key."""

    MISSING = "missing"
    PENDING = "pending"
    CONSUMED = "consumed"
    CANCELLED = "cancelled"


class ChallengeRuntimeState:
    """One runtime-state snapshot: the kind plus the decoded payloads.

    ``record`` is set for every non-Missing kind. ``consumed`` carries
    the retained consumed envelope exactly when the kind is the
    consumed one.
    """

    __slots__ = ("kind", "record", "consumed")

    def __init__(
        self,
        kind: ChallengeRuntimeStateKind,
        record: Optional[ChallengeRecord] = None,
        consumed: Optional["ConsumedRecord"] = None,
    ) -> None:
        self.kind = kind
        self.record = record
        self.consumed = consumed


class ConsumedResult:
    """The committed deterministic outcome of one consumed challenge.

    ``mac`` is the server-state MAC over the record's challenge, the
    verdict, the binding and the operation identity, or None on a
    legacy commit from a backend that cannot carry one.
    """

    __slots__ = ("valid", "binding", "mac")

    def __init__(
        self,
        valid: bool,
        binding: Optional[str],
        mac: Optional[str] = None,
    ) -> None:
        self.valid = valid
        self.binding = binding
        self.mac = mac

    def to_array(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"valid": bool(self.valid), "binding": self.binding}
        if self.mac is not None:
            data["mac"] = self.mac
        return data

    @classmethod
    def from_array(cls, data: Dict[str, Any]) -> "ConsumedResult":
        """The strict rebuild: only the exact supported key set, a real
        boolean ``valid`` (the production Lua also accepts the legacy
        1/0 form), a string or null binding, and a 64-hex mac."""
        unknown = set(data) - {"valid", "binding", "mac"}
        if unknown:
            raise ValueError(
                "consumed_result carries unsupported keys: "
                + ",".join(sorted(str(k) for k in unknown))
            )
        valid = data.get("valid")
        if valid in (0, 1):
            valid = bool(valid)
        if not isinstance(valid, bool):
            raise ValueError("consumed_result.valid must be a boolean")
        binding = data.get("binding")
        if binding is not None and not isinstance(binding, str):
            raise ValueError("consumed_result.binding must be a string or null")
        mac = data.get("mac")
        if mac is not None:
            if not isinstance(mac, str):
                raise ValueError("consumed_result.mac must be a string or null")
            if (
                len(mac) != 64
                or any(c not in "0123456789abcdef" for c in mac)
            ):
                raise ValueError(
                    "consumed_result.mac must be 64 lowercase hex characters"
                )
        return cls(valid, binding, mac)


class ConsumedRecord:
    """The consume transition's return: the record plus its new state.

    ``consumed_now`` marks the call that won the pending-to-consumed
    flip; ``consumed_before`` marks a retry against an already
    consumed record.
    """

    __slots__ = (
        "record",
        "consumed_now",
        "consumed_before",
        "consumed_result",
        "operation_identity",
    )

    def __init__(
        self,
        record: ChallengeRecord,
        consumed_now: bool = False,
        consumed_before: bool = False,
        consumed_result: Optional[ConsumedResult] = None,
        operation_identity: Optional[str] = None,
    ) -> None:
        self.record = record
        self.consumed_now = consumed_now
        self.consumed_before = consumed_before
        self.consumed_result = consumed_result
        self.operation_identity = operation_identity


class DeleteIfPendingResult:
    """The fused cheap-failure cleanup outcome.

    ``status`` is one of ``missing``, ``deleted-pending``, ``consumed``
    or ``cancelled``, mirroring the tri-state contract of the Redis Lua
    script. ``consumed`` carries the retained envelope on the consumed
    status.
    """

    __slots__ = ("status", "consumed")

    def __init__(
        self,
        status: str,
        consumed: Optional[ConsumedRecord] = None,
    ) -> None:
        self.status = status
        self.consumed = consumed

    def was_consumed(self) -> bool:
        return self.status == "consumed"


class CancellationResult:
    """The cancel transition's outcome: ``cancelled-now`` on a fresh
    flip, ``cancelled`` when already cancelled, ``consumed`` when the
    record was already finalized."""

    __slots__ = ("status",)

    def __init__(self, status: str) -> None:
        self.status = status


_OPERATION_IDENTITY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_-"
)


def validate_operation_identity(operation_identity: Optional[str]) -> Optional[str]:
    """Validate one logical-operation identity, or pass None through.

    A non-null identity must be 1..128 bytes of ``[A-Za-z0-9_-]``;
    anything else raises ``ValueError`` before the transition.
    """
    if operation_identity is None:
        return None
    if (
        not isinstance(operation_identity, str)
        or not 1 <= len(operation_identity) <= 128
        or not all(c in _OPERATION_IDENTITY_CHARS for c in operation_identity)
    ):
        raise ValueError(
            "operation identity must be 1..128 bytes of [A-Za-z0-9_-]"
        )
    return operation_identity


@runtime_checkable
class Storage(Protocol):
    """The mandatory store adapter surface."""

    def find(self, nonce: str) -> Optional[ChallengeRecord]:
        ...

    def delete(self, nonce: str) -> bool:
        ...

    def consume(self, nonce: str) -> Optional[ConsumedRecord]:
        ...

    def commit_result(self, nonce: str, valid: bool, binding: Optional[str]) -> bool:
        ...


@runtime_checkable
class ConsumedStateReadableStorage(Protocol):
    """The retained consumed-envelope read."""

    def consumed_state(self, nonce: str) -> Optional[ConsumedRecord]:
        ...


@runtime_checkable
class RuntimeStateReadableStorage(Protocol):
    """The single-GET runtime-state snapshot read."""

    def runtime_state(self, nonce: str) -> ChallengeRuntimeState:
        ...


@runtime_checkable
class AtomicDeleteIfPendingStorage(Protocol):
    """The fused read-and-delete-on-pending transition."""

    def delete_if_pending(self, nonce: str) -> DeleteIfPendingResult:
        ...


@runtime_checkable
class OperationIdentityAwareStorage(Protocol):
    """The identity-bearing consume transition."""

    def consume_with_operation_identity(
        self, nonce: str, operation_identity: str
    ) -> Optional[ConsumedRecord]:
        ...


@runtime_checkable
class AuthenticatedResultCommitStorage(Protocol):
    """The server-state-MAC commit for a consumed result."""

    def commit_authenticated_result(
        self, nonce: str, result: ConsumedResult
    ) -> bool:
        ...


@runtime_checkable
class CancellableStorage(Protocol):
    """The terminal cancellation marker transition."""

    def cancel(self, nonce: str) -> Optional[CancellationResult]:
        ...
