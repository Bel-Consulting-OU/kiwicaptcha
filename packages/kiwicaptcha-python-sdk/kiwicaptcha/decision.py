"""The shared server SDK decision shape: ok, disposition, handle, price."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .errors import VerifyOutcome

DISPOSITION_ALLOW = "allow"
DISPOSITION_DENY = "deny"
DISPOSITION_RETRY = "retry"

_RETRY_CODES = frozenset(
    (
        "storage_unavailable",
        "capacity_exceeded",
        "admission_unavailable",
        "consume_indeterminate",
    )
)


@dataclass(frozen=True)
class VerifyDecision:
    """The contract level answer of ``Verifier.verify``.

    ``disposition`` is one of the decision plane verbs: ``allow`` when
    the proof verified, ``deny`` for a definitive rejection, and
    ``retry`` for a transient condition where the same token may
    legitimately be resubmitted once the backend recovers.
    ``decision_handle`` is the verified nonce, the canonical replay id
    the outcomes ledger addresses. ``price`` is the work ladder rung
    the challenge carried, derived from its authenticated parameters.
    """

    ok: bool
    disposition: str
    decision_handle: Optional[str] = None
    price: Optional[str] = None
    error: Optional[str] = None
    outcome: Optional[VerifyOutcome] = None

    @classmethod
    def from_outcome(cls, outcome: VerifyOutcome, price: Optional[str] = None) -> "VerifyDecision":
        if outcome.valid:
            return cls(
                ok=True,
                disposition=DISPOSITION_ALLOW,
                decision_handle=outcome.nonce,
                price=price,
                error=None,
                outcome=outcome,
            )
        code = outcome.code
        disposition = DISPOSITION_RETRY if code in _RETRY_CODES else DISPOSITION_DENY
        return cls(
            ok=False,
            disposition=disposition,
            decision_handle=None,
            price=None,
            error=code,
            outcome=outcome,
        )


def price_rung(algorithm: str, target_bits: int, m_kib: int) -> str:
    """The work ladder name of one record's authenticated parameters.

    Mirrors the ladder alphabet of the decision plane: sha rungs carry
    their difficulty, argon rungs their memory, and the sequential
    time-lock rung is ``rsw``.
    """
    if algorithm == "sha256":
        return "sha{}".format(target_bits)
    if algorithm == "argon2id":
        return "argon{}".format(m_kib)
    return "rsw"
