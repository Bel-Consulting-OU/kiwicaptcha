"""Verification error codes and outcomes.

Port of VerifyError.php and VerifyOutcome.php. Every case value is a
machine readable snake_case code, the stable wire vocabulary shared
with the PHP enum and the Rust code mapping; logs, metrics and
cross-service consumers switch on it without parsing prose.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


class VerifyError(str, Enum):
    """The machine readable failure vocabulary of the verify path."""

    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    WRONG_SCOPE = "wrong_scope"
    REQUIRED_SCOPE = "required_scope"
    IP_MISMATCH = "ip_mismatch"
    MISSING_CLIENT_IP = "missing_client_ip"
    WRONG_REGION = "wrong_region"
    WRONG_ISSUER = "wrong_issuer"
    WRONG_POLICY_VERSION = "wrong_policy_version"
    UNKNOWN_KID = "unknown_kid"
    TOO_FAST = "too_fast"
    INSUFFICIENT_WORK = "insufficient_work"
    MALFORMED_RECORD = "malformed_record"
    RECORD_NOT_FOUND = "record_not_found"
    MALFORMED_TOKEN = "malformed_token"
    UNSUPPORTED_ARGON2_PARAMS = "unsupported_argon2_params"
    TOO_MANY_ATTEMPTS = "too_many_attempts"
    TELEMETRY_REJECTED = "telemetry_rejected"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    ADMISSION_UNAVAILABLE = "admission_unavailable"
    STORAGE_UNAVAILABLE = "storage_unavailable"
    CONSUME_INDETERMINATE = "consume_indeterminate"
    ALREADY_CONSUMED = "already_consumed"
    REQUEST_BINDING_MISMATCH = "request_binding_mismatch"
    EXECUTION_MISMATCH = "execution_mismatch"
    UNSUPPORTED_RSW_PARAMS = "unsupported_rsw_params"

    @property
    def code(self) -> str:
        """The wire code of this failure."""
        return self.value

    @property
    def description(self) -> str:
        """The operator facing explanation; switch on the case, not this."""
        return _DESCRIPTIONS[self]

    def is_replay_exempt(self) -> bool:
        """Whether this failure is exempt from the one-shot policy.

        The exempt set describes the original redemption's
        circumstances: the signed expiry, the network binding, the
        missing client ip, and the client side telemetry evidence. A
        consumed record failing one of them may still resolve through
        the consumed branch. Every security verdict stands regardless
        of a matching operation identity.
        """
        return self in (
            VerifyError.EXPIRED,
            VerifyError.IP_MISMATCH,
            VerifyError.MISSING_CLIENT_IP,
            VerifyError.TELEMETRY_REJECTED,
        )


_DESCRIPTIONS = {
    VerifyError.BAD_SIGNATURE: "challenge signature is invalid",
    VerifyError.EXPIRED: "challenge has expired",
    VerifyError.WRONG_SCOPE: "challenge was issued for a different scope",
    VerifyError.REQUIRED_SCOPE: "the scope option is required: verify refuses to accept a token for any scope",
    VerifyError.IP_MISMATCH: "challenge was issued to a different client ip",
    VerifyError.MISSING_CLIENT_IP: "challenge is ip-bound but no client ip was supplied",
    VerifyError.WRONG_REGION: "challenge was issued for a different region",
    VerifyError.WRONG_ISSUER: "challenge was issued by a different deployment",
    VerifyError.WRONG_POLICY_VERSION:
        "challenge was issued under a different security-policy epoch",
    VerifyError.UNKNOWN_KID: "unknown signing key id",
    VerifyError.TOO_FAST:
        "solution arrived faster than the theoretical minimum, server measured",
    VerifyError.INSUFFICIENT_WORK: "solution does not meet the difficulty target",
    VerifyError.MALFORMED_RECORD: "stored challenge record is malformed",
    VerifyError.RECORD_NOT_FOUND:
        "challenge record not found, unknown or already deleted",
    VerifyError.MALFORMED_TOKEN: "solution token is malformed",
    VerifyError.UNSUPPORTED_ARGON2_PARAMS:
        "argon2id parameters exceed the supported process ceilings",
    VerifyError.TOO_MANY_ATTEMPTS: "too many verification attempts",
    VerifyError.TELEMETRY_REJECTED: "bot-signal telemetry rejected the solution",
    VerifyError.CAPACITY_EXCEEDED: "verification capacity exceeded, try again shortly",
    VerifyError.ADMISSION_UNAVAILABLE:
        "verification admission backend unavailable, try again shortly",
    VerifyError.STORAGE_UNAVAILABLE:
        "verification storage backend unavailable, try again shortly",
    VerifyError.CONSUME_INDETERMINATE:
        "verification storage response indeterminate, the challenge may or may not have been consumed",
    VerifyError.ALREADY_CONSUMED:
        "the challenge was already consumed by a different logical operation",
    VerifyError.REQUEST_BINDING_MISMATCH:
        "the challenge is not bound to the expected application transaction",
    VerifyError.EXECUTION_MISMATCH:
        "the execution digest does not match the expected program trace of the challenge",
    VerifyError.UNSUPPORTED_RSW_PARAMS:
        "the rsw challenge cannot be verified: this verifier is not configured with the"
        " matching rsw trapdoor, or the signed sequential cost is outside the supported bounds",
}


class VerifyOutcome:
    """The result of one solution verification.

    A valid outcome exposes the nonce, the canonical replay id, the
    consumed record's application transaction binding, the
    server-measured solve duration, and the authenticated honeypot
    field name. Every field is null on a non-valid outcome; the solve
    duration is also null on a stored-result replay, whose receipt is
    not the solve's endpoint.
    """

    __slots__ = ("valid", "error", "detail", "nonce", "request_binding",
                 "from_stored_result", "solve_duration_ms", "decoy_field")

    def __init__(
        self,
        valid: bool,
        error: Optional[VerifyError] = None,
        detail: Optional[str] = None,
        nonce: Optional[str] = None,
        request_binding: Optional[str] = None,
        from_stored_result: bool = False,
        solve_duration_ms: Optional[int] = None,
        decoy_field: Optional[str] = None,
    ) -> None:
        self.valid = valid
        self.error = error
        self.detail = detail
        self.nonce = nonce
        self.request_binding = request_binding
        self.from_stored_result = from_stored_result
        self.solve_duration_ms = solve_duration_ms
        self.decoy_field = decoy_field

    @classmethod
    def valid_outcome(
        cls,
        nonce: Optional[str] = None,
        request_binding: Optional[str] = None,
        from_stored_result: bool = False,
        solve_duration_ms: Optional[int] = None,
        decoy_field: Optional[str] = None,
    ) -> "VerifyOutcome":
        return cls(True, None, None, nonce, request_binding, from_stored_result,
                   solve_duration_ms, decoy_field)

    @classmethod
    def invalid(cls, error: VerifyError) -> "VerifyOutcome":
        return cls(False, error, None, None, None)

    @classmethod
    def malformed_token(cls, detail: str) -> "VerifyOutcome":
        return cls(False, VerifyError.MALFORMED_TOKEN, detail, None, None)

    def is_ok(self) -> bool:
        return self.valid

    @property
    def code(self) -> str:
        """The machine readable error code, empty when valid."""
        return self.error.value if self.error is not None else ""

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return (
            f"VerifyOutcome(valid={self.valid}, error={self.error},"
            f" nonce={self.nonce!r})"
        )
