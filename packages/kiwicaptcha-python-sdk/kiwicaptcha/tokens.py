"""The client submitted solution token and its wire grammar.

Port of packages/kiwicaptcha-php/src/SolutionToken.php. The wire
format is ``base64(nonce "." counter "." duration_ms "." telemetry_json
["." execution_digest[":" execution_trace]] ["." rsw_proof])``. The
telemetry segment may contain dots, so decoding splits on all dots and
peels the optional suffix segments right to left, independently. The
rsw final value peels first, exactly when the last segment is 512
lowercase hex. The execution evidence segment that precedes it peels
next. The unarmed token keeps the exact four segment shape.

Numeric segments are canonical decimal: digits only, a leading zero
rejected unless the whole segment is exactly "0", so each value has
exactly one wire spelling in every implementation.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Dict, Optional

from . import constants as c

NONCE_PATTERN = re.compile(r"\A[A-Za-z0-9+/]{43}=\Z")
HEX512_PATTERN = re.compile(r"\A[0-9a-f]{512}\Z")
HEX64_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")

MAX_TOKEN_BYTES = 32_768
"""Early size cap: larger inputs are abuse probes, not solutions."""

MAX_TRACE_B64_LENGTH = 10_924
"""Ceiling for the base64url execution trace segment."""


class DecodeError(Exception):
    """A solution token failed the wire grammar.

    The ``code`` is the machine readable reason carried as the
    malformed_token outcome detail, identical to the PHP codes.
    """

    INVALID_BASE64 = "invalid_base64"
    INVALID_UTF8 = "invalid_utf8"
    MALFORMED = "malformed"
    INVALID_COUNTER = "invalid_counter"
    COUNTER_EXCEEDS_SOLVER_MAXIMUM = "counter exceeds solver maximum"
    INVALID_DURATION = "invalid_duration"

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    @classmethod
    def invalid_base64(cls) -> "DecodeError":
        return cls(cls.INVALID_BASE64)

    @classmethod
    def invalid_utf8(cls) -> "DecodeError":
        return cls(cls.INVALID_UTF8)

    @classmethod
    def malformed(cls) -> "DecodeError":
        return cls(cls.MALFORMED)

    @classmethod
    def invalid_counter(cls) -> "DecodeError":
        return cls(cls.INVALID_COUNTER)

    @classmethod
    def counter_exceeds_solver_maximum(cls) -> "DecodeError":
        return cls(cls.COUNTER_EXCEEDS_SOLVER_MAXIMUM)

    @classmethod
    def invalid_duration(cls) -> "DecodeError":
        return cls(cls.INVALID_DURATION)


def _canonical_b64_decode(raw: str) -> Optional[bytes]:
    """Strict canonical base64: one spelling per byte string.

    Rejects every character outside the standard alphabet, including
    the base64url alphabet and whitespace, and the canonical re-encode
    check rejects non-canonical padding and non-zero trailing bits.
    """
    try:
        plain = base64.b64decode(raw.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None
    if base64.b64encode(plain).decode("ascii") != raw:
        return None
    return plain


def _b64url_to_standard(trace: str) -> str:
    standard = trace.replace("-", "+").replace("_", "/")
    pad = (-len(standard)) % 4
    return standard + "=" * pad


def _canonical_b64url_check(trace: str) -> bool:
    """The driver emits unpadded base64url; require one canonical form."""
    if trace == "" or len(trace) > MAX_TRACE_B64_LENGTH:
        return False
    try:
        decoded = base64.urlsafe_b64decode(_b64url_to_standard(trace) + "")
    except (binascii.Error, ValueError):
        return False
    reencoded = (
        base64.b64encode(decoded).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")
    )
    return reencoded == trace


class SolutionToken:
    """A decoded solution token, peelable in both directions.

    Create with :meth:`create` or decode wire bytes with
    :meth:`decode`. ``telemetry`` is always a dict: the wire grammar
    requires a JSON object, so an array or scalar fails closed.
    """

    __slots__ = ("nonce", "counter", "duration_ms", "telemetry", "execution_digest",
                 "execution_trace", "rsw_proof")

    def __init__(
        self,
        nonce: str,
        counter: int,
        duration_ms: int,
        telemetry: Dict[str, Any],
        execution_digest: Optional[str] = None,
        execution_trace: Optional[str] = None,
        rsw_proof: Optional[str] = None,
    ) -> None:
        self.nonce = nonce
        self.counter = counter
        self.duration_ms = duration_ms
        self.telemetry = telemetry
        self.execution_digest = execution_digest
        self.execution_trace = execution_trace
        self.rsw_proof = rsw_proof

    @classmethod
    def create(
        cls,
        nonce: str,
        counter: int,
        duration_ms: int,
        telemetry: Dict[str, Any],
        execution_digest: Optional[str] = None,
        execution_trace: Optional[str] = None,
        rsw_proof: Optional[str] = None,
    ) -> "SolutionToken":
        return cls(nonce, counter, duration_ms, telemetry,
                   execution_digest, execution_trace, rsw_proof)

    @staticmethod
    def max_solver_counter() -> int:
        """The solver cap ceiling exposed for tests."""
        return c.MAX_SOLVER_COUNTER

    def encode(self) -> str:
        """Assemble the canonical wire bytes.

        The telemetry segment is always a JSON object, so an empty dict
        encodes as ``{}`` and never ``[]``. The execution trace travels
        as unpadded base64url; a standard base64 trace is translated,
        never double encoded. An unarmed token stays byte identical to
        the four segment shape.
        """
        plain = "{}.{}.{}.{}".format(
            self.nonce,
            self.counter,
            self.duration_ms,
            json.dumps(self.telemetry, separators=(",", ":"), ensure_ascii=True),
        )
        if self.execution_digest is not None:
            plain += "." + self.execution_digest
            if self.execution_trace is not None:
                # The trace field already holds the standard base64 of
                # the plain trace (the driver's format), so only the
                # alphabet and padding translation applies, never a
                # second encode.
                b64url = (
                    self.execution_trace.replace("+", "-")
                    .replace("/", "_")
                    .rstrip("=")
                )
                plain += ":" + b64url
        if self.rsw_proof is not None:
            plain += "." + self.rsw_proof
        return base64.b64encode(plain.encode("utf-8", "surrogatepass")).decode("ascii")

    @classmethod
    def decode(cls, raw: str) -> "SolutionToken":
        """Parse wire bytes; raise :class:`DecodeError` on any violation."""
        if not isinstance(raw, str) or len(raw.encode("utf-8", "surrogatepass")) > MAX_TOKEN_BYTES:
            raise DecodeError.malformed()
        plain_bytes = _canonical_b64_decode(raw)
        if plain_bytes is None:
            raise DecodeError.invalid_base64()
        try:
            plain = plain_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise DecodeError.invalid_utf8() from None

        parts = plain.split(".")
        if len(parts) < 4:
            raise DecodeError.malformed()
        end = len(parts)
        rsw_proof: Optional[str] = None
        execution_digest: Optional[str] = None
        execution_trace: Optional[str] = None

        if end >= 5 and HEX512_PATTERN.match(parts[end - 1]):
            rsw_proof = parts[end - 1]
            end -= 1
        if end >= 5:
            segment = parts[end - 1]
            colon = segment.find(":")
            digest_part = segment if colon < 0 else segment[:colon]
            if HEX64_PATTERN.match(digest_part):
                execution_digest = digest_part
                if colon >= 0:
                    execution_trace = segment[colon + 1:]
                    if not _canonical_b64url_check(execution_trace):
                        raise DecodeError.malformed()
                end -= 1

        telemetry_str = ".".join(parts[3:end])
        nonce, counter_str, duration_str = parts[0], parts[1], parts[2]

        # The nonce is base64 of 32 random bytes: exactly 44 chars with
        # one padding character. The shape check alone is not enough, so
        # the canonical re-encode check pins exactly one wire spelling.
        if len(nonce) != 44 or not NONCE_PATTERN.match(nonce):
            raise DecodeError.malformed()
        nonce_bytes = _canonical_b64_decode(nonce)
        if nonce_bytes is None or len(nonce_bytes) != c.NONCE_B64_BYTES:
            raise DecodeError.malformed()

        if counter_str == "" or not counter_str.isdigit() or not counter_str.isascii():
            raise DecodeError.invalid_counter()
        if len(counter_str) > 1 and counter_str[0] == "0":
            raise DecodeError.invalid_counter()
        if len(counter_str) > 8 or int(counter_str) >= c.MAX_SOLVER_COUNTER:
            raise DecodeError.counter_exceeds_solver_maximum()
        counter = int(counter_str)

        if duration_str == "" or not duration_str.isdigit() or not duration_str.isascii():
            raise DecodeError.invalid_duration()
        if len(duration_str) > 1 and duration_str[0] == "0":
            raise DecodeError.invalid_duration()
        if int(duration_str) > c.MAX_DURATION_MS:
            raise DecodeError.invalid_duration()
        duration_ms = int(duration_str)

        try:
            telemetry = json.loads(telemetry_str)
        except ValueError:
            raise DecodeError.malformed() from None
        if not isinstance(telemetry, dict):
            raise DecodeError.malformed()

        if execution_digest is not None and not HEX64_PATTERN.match(execution_digest):
            raise DecodeError.malformed()

        return cls(nonce, counter, duration_ms, telemetry,
                   execution_digest, execution_trace, rsw_proof)
