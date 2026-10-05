"""The versioned outcomes mapping and its reporting client.

Port of packages/kiwicaptcha-risk-php/src/Outcomes (OutcomeMap,
OutcomeMapping, OutcomeHandle, OutcomeReceipt, KiwiOutcomes). The one
mapping table resolves each of the eight typed outcomes onto the
risk-v1 event channels, the always-on outcome ledger and the long-memory
marks. The trust polarity is a table property: exactly the three
server-confirmed trust outcomes may subtract risk, and exactly the four
abuse outcomes write marks; the two classes are disjoint. The vectors at
protocol/risk-v1/outcomes-vectors.json pin the table contents across
the languages, and the conformance tests replay them against this
module.

The reporting client is storage-agnostic: it resolves the mapping and
dispatches to an injectable sink. The shipped
:class:`MemoryOutcomeSink` keeps marks and ledger actions in-process;
binding the sink to a Redis deployment is a deployment composition, not
a protocol concern.
"""

from dataclasses import dataclass, field
from enum import Enum
import re
import time
from typing import Any, Dict, List, Optional, Tuple

VERSION = 1

_MARK_KEY = "mark:{kiwi:%s}:%s:%s"


class Outcome(Enum):
    """The eight typed outcome wire names, in vocabulary order."""

    CONFIRMED_LEGITIMATE = "confirmedLegitimate"
    STEP_UP_COMPLETED = "stepUpCompleted"
    AUTHENTICATION_SUCCESS = "authenticationSuccess"
    AUTHENTICATION_FAILURE = "authenticationFailure"
    SPAM_REPORTED = "spamReported"
    CHARGEBACK = "chargeback"
    ACCOUNT_BANNED = "accountBanned"
    FRAUD_CONFIRMED = "fraudConfirmed"


class OutcomeHandleDimension(Enum):
    """The six subject-address dimensions with their key roles."""

    NONCE = "nonce"
    DECISION_ID = "decisionId"
    PRINCIPAL = "principal"
    TARGET = "target"
    SESSION = "session"
    AGENT = "agent"

    def is_ledger(self) -> bool:
        return self in (OutcomeHandleDimension.NONCE, OutcomeHandleDimension.DECISION_ID)

    def is_identity(self) -> bool:
        return not self.is_ledger()

    def mark_dimension(self) -> Optional[str]:
        if self.is_ledger():
            return None
        return self.value


# The risk-v1 event channel values (RiskEventKind wire numbers).
CHANNEL_CONFIRMED_LEGITIMATE = 12
CHANNEL_PROTECTED_ACTION_SUCCESS = 8
CHANNEL_AUTHENTICATION_SUCCESS = 10
CHANNEL_AUTHENTICATION_FAILURE = 11
CHANNEL_PROTECTED_ACTION_FAILURE = 9
CHANNEL_CONFIRMED_ABUSE = 13

_PSEUDONYM = re.compile(r"^[0-9a-f]{32}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f:}]|\xc2[\x80-\x9f]|\xe2\x80[\xa8\xa9]")


def assert_key_safe_identifier(name: str, value: str) -> None:
    """The shared key-safety rule for caller-supplied identifiers.

    A 32-char lowercase hex id always passes; otherwise the value must
    be a non-empty string free of control characters, ``:`` and ``}``,
    the key separator and the hash-tag closing byte.
    """
    if _PSEUDONYM.match(value):
        return
    if value == "" or _CONTROL_CHARS.search(value):
        raise ValueError(
            f"{name} must be a 32-char lowercase hex id or a non-empty"
            f" value free of control characters, ':' and '}}' (got"
            f" {value!r})"
        )


class OutcomeHandle:
    """One subject address of a typed outcome report.

    The identity dimensions carry pseudonyms, never raw identifiers:
    principal, target and session values must already be the 32-char
    lowercase hex pseudonyms. A raw-looking value is rejected at
    construction, fail-closed.
    """

    __slots__ = ("dimension", "id")

    def __init__(self, dimension: OutcomeHandleDimension, identifier: str) -> None:
        self.dimension = dimension
        self.id = identifier

    @classmethod
    def nonce(cls, nonce: str) -> "OutcomeHandle":
        assert_key_safe_identifier("nonce", nonce)
        return cls(OutcomeHandleDimension.NONCE, nonce)

    @classmethod
    def decision_id(cls, decision_id: str) -> "OutcomeHandle":
        assert_key_safe_identifier("decisionId", decision_id)
        return cls(OutcomeHandleDimension.DECISION_ID, decision_id)

    @classmethod
    def principal(cls, pseudonym: str) -> "OutcomeHandle":
        cls._require_pseudonym("principal", pseudonym)
        return cls(OutcomeHandleDimension.PRINCIPAL, pseudonym)

    @classmethod
    def target(cls, pseudonym: str) -> "OutcomeHandle":
        cls._require_pseudonym("target", pseudonym)
        return cls(OutcomeHandleDimension.TARGET, pseudonym)

    @classmethod
    def session(cls, pseudonym: str) -> "OutcomeHandle":
        cls._require_pseudonym("session", pseudonym)
        return cls(OutcomeHandleDimension.SESSION, pseudonym)

    @classmethod
    def agent(cls, agent_id: str) -> "OutcomeHandle":
        assert_key_safe_identifier("agent", agent_id)
        return cls(OutcomeHandleDimension.AGENT, agent_id)

    @staticmethod
    def _require_pseudonym(name: str, value: str) -> None:
        if not _PSEUDONYM.match(value):
            raise ValueError(
                f"{name} handle must carry the 32-char lowercase hex"
                f" pseudonym, never a raw identifier (got {value!r})"
            )

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, OutcomeHandle)
            and self.dimension == other.dimension
            and self.id == other.id
        )

    def __hash__(self) -> int:
        return hash((self.dimension, self.id))


@dataclass(frozen=True)
class OutcomeMapping:
    """One immutable table row: channel, ledger and mark behavior."""

    outcome: Outcome
    channel: int
    ledger_legitimate: Optional[bool]
    writes_abuse_mark: bool
    server_confirmed: bool
    may_subtract_risk: bool
    accepted_handles: Tuple[OutcomeHandleDimension, ...] = field(default=())

    def accepts(self, dimension: OutcomeHandleDimension) -> bool:
        return dimension in self.accepted_handles

    def mark_kind(self) -> Optional[str]:
        if self.writes_abuse_mark:
            return self.outcome.value
        return None

    def has_ledger_action(self) -> bool:
        return self.ledger_legitimate is not None


_EVERY = (
    OutcomeHandleDimension.NONCE,
    OutcomeHandleDimension.DECISION_ID,
    OutcomeHandleDimension.PRINCIPAL,
    OutcomeHandleDimension.TARGET,
    OutcomeHandleDimension.SESSION,
    OutcomeHandleDimension.AGENT,
)

_IDENTITY = (
    OutcomeHandleDimension.PRINCIPAL,
    OutcomeHandleDimension.TARGET,
    OutcomeHandleDimension.SESSION,
    OutcomeHandleDimension.AGENT,
)

_TABLE: Dict[str, OutcomeMapping] = {
    "confirmedLegitimate": OutcomeMapping(
        Outcome.CONFIRMED_LEGITIMATE,
        CHANNEL_CONFIRMED_LEGITIMATE,
        True,
        False,
        True,
        True,
        _EVERY,
    ),
    "stepUpCompleted": OutcomeMapping(
        Outcome.STEP_UP_COMPLETED,
        CHANNEL_PROTECTED_ACTION_SUCCESS,
        None,
        False,
        True,
        True,
        _IDENTITY,
    ),
    "authenticationSuccess": OutcomeMapping(
        Outcome.AUTHENTICATION_SUCCESS,
        CHANNEL_AUTHENTICATION_SUCCESS,
        None,
        False,
        True,
        True,
        _IDENTITY,
    ),
    "authenticationFailure": OutcomeMapping(
        Outcome.AUTHENTICATION_FAILURE,
        CHANNEL_AUTHENTICATION_FAILURE,
        None,
        False,
        False,
        False,
        _IDENTITY,
    ),
    "spamReported": OutcomeMapping(
        Outcome.SPAM_REPORTED,
        CHANNEL_PROTECTED_ACTION_FAILURE,
        None,
        True,
        True,
        False,
        _IDENTITY,
    ),
    "chargeback": OutcomeMapping(
        Outcome.CHARGEBACK,
        CHANNEL_CONFIRMED_ABUSE,
        False,
        True,
        True,
        False,
        _EVERY,
    ),
    "accountBanned": OutcomeMapping(
        Outcome.ACCOUNT_BANNED,
        CHANNEL_CONFIRMED_ABUSE,
        False,
        True,
        True,
        False,
        _EVERY,
    ),
    "fraudConfirmed": OutcomeMapping(
        Outcome.FRAUD_CONFIRMED,
        CHANNEL_CONFIRMED_ABUSE,
        False,
        True,
        True,
        False,
        _EVERY,
    ),
}

_LEDGER_DIMENSIONS = (
    OutcomeHandleDimension.NONCE,
    OutcomeHandleDimension.DECISION_ID,
)


class OutcomeMap:
    """The one versioned mapping table, total over the vocabulary."""

    @staticmethod
    def for_outcome(outcome: Outcome) -> OutcomeMapping:
        row = _TABLE.get(outcome.value)
        if row is None:
            raise ValueError(f"No outcome mapping row for {outcome.value}")
        return row

    @staticmethod
    def all() -> List[OutcomeMapping]:
        return list(_TABLE.values())

    @staticmethod
    def ledger_dimensions() -> Tuple[OutcomeHandleDimension, ...]:
        return _LEDGER_DIMENSIONS

    @staticmethod
    def identity_dimensions() -> Tuple[OutcomeHandleDimension, ...]:
        return _IDENTITY


@dataclass(frozen=True)
class OutcomeReceipt:
    """The outcome of one report: what was booked where."""

    outcome: Outcome
    handle_dimension: OutcomeHandleDimension
    status: int
    channel_booked: bool
    marks_written: int
    mark_count: int
    event_id: Optional[str]


class MemoryOutcomeSink:
    """The in-process sink: ledger actions and marks in plain dicts.

    ``status`` follows the ledger confirm contract: 1 confirmed as
    legitimate, minus 1 confirmed as abusive, 0 when no ledger entry
    existed. Marks accumulate ``(kind, at_ms)`` tuples per key and
    ``forget`` clears them.
    """

    def __init__(self, namespace: str = "test") -> None:
        self.namespace = namespace
        self.ledger: Dict[str, List[Tuple[bool, int]]] = {}
        self.marks: Dict[str, List[Tuple[str, int]]] = {}
        self.events: List[Tuple[int, Optional[str], Optional[str], Optional[str]]] = []

    def mark_key(self, dimension: str, identifier: str) -> str:
        return _MARK_KEY % (self.namespace, dimension, identifier)

    def confirm_outcome(self, decision_id: str, legitimate: bool) -> int:
        entries = self.ledger.get(decision_id)
        if not entries:
            return 0
        self.ledger[decision_id].append((legitimate, entries[-1][1]))
        return 1 if legitimate else -1

    def register_outcome(self, decision_id: str, at_ms: Optional[int] = None) -> None:
        self.ledger.setdefault(decision_id, []).append((False, at_ms or 0))

    def write_mark(
        self, dimension: str, identifier: str, kind: str, at_ms: int
    ) -> int:
        key = self.mark_key(dimension, identifier)
        self.marks.setdefault(key, []).append((kind, at_ms))
        return 1

    def forget_marks(self, dimension: str, identifier: str) -> int:
        key = self.mark_key(dimension, identifier)
        removed = len(self.marks.get(key, ()))
        self.marks.pop(key, None)
        return removed

    def record_outcome_feedback(
        self,
        channel: int,
        idempotency_key: Optional[str] = None,
        session_pseudonym: Optional[str] = None,
        principal_pseudonym: Optional[str] = None,
    ) -> Optional[str]:
        self.events.append((channel, idempotency_key, session_pseudonym, principal_pseudonym))
        return idempotency_key


class OutcomesClient:
    """The typed outcome reporter, mirroring the PHP KiwiOutcomes."""

    def __init__(self, sink: MemoryOutcomeSink) -> None:
        self.sink = sink

    def report(
        self,
        outcome: Outcome,
        handle: OutcomeHandle,
        idempotency_key: Optional[str] = None,
        at_ms: Optional[int] = None,
    ) -> OutcomeReceipt:
        mapping = OutcomeMap.for_outcome(outcome)
        if not mapping.accepts(handle.dimension):
            accepted = ", ".join(d.value for d in mapping.accepted_handles)
            raise ValueError(
                f"Outcome {outcome.value} cannot be reported on a"
                f" {handle.dimension.value} handle (accepted: {accepted})"
            )
        if at_ms is None:
            at_ms = int(time.time() * 1000)
        status = 0
        channel_booked = False
        marks_written = 0
        mark_count = 0
        event_id: Optional[str] = None
        if handle.dimension.is_ledger():
            if mapping.has_ledger_action():
                status = self.sink.confirm_outcome(
                    handle.id, mapping.ledger_legitimate is True
                )
            if status != 0:
                event_id = self.sink.record_outcome_feedback(
                    mapping.channel, idempotency_key
                )
                channel_booked = True
        else:
            if mapping.writes_abuse_mark:
                dimension = handle.dimension.mark_dimension()
                assert dimension is not None
                kind = mapping.mark_kind()
                assert kind is not None
                mark_count = self.sink.write_mark(
                    dimension, handle.id, kind, at_ms
                )
                marks_written = 1
            event_id = self.sink.record_outcome_feedback(
                mapping.channel, idempotency_key
            )
            channel_booked = True
        return OutcomeReceipt(
            outcome=outcome,
            handle_dimension=handle.dimension,
            status=status,
            channel_booked=channel_booked,
            marks_written=marks_written,
            mark_count=mark_count,
            event_id=event_id,
        )

    def forget(self, handle: OutcomeHandle) -> int:
        dimension = handle.dimension.mark_dimension()
        if dimension is None:
            return 0
        return self.sink.forget_marks(dimension, handle.id)
