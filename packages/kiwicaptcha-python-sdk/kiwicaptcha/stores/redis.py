"""Redis storage: the shared-backend store adapter.

Port of packages/kiwicaptcha-php/src/Storage/RedisStorage.php. The
stored envelope is one JSON document per nonce key: the flattened
record fields plus the ``state``, ``consumed_result`` and
``operation_identity`` runtime markers. The consume, delete-if-pending,
cancel and commit transitions run the exact Lua scripts of the PHP
adapter (see :mod:`.stores._lua_scripts`), so envelopes written by
either SDK are interchangeable, byte for byte.

The adapter binds to a narrow client surface instead of a concrete
driver: ``get``, ``set`` (with an ``ex`` seconds or ``px`` milliseconds
lifetime), ``pttl``, ``delete``, and script execution via ``eval`` with
optional ``script_load``/``evalsha`` caching. The official ``redis``
client (the optional ``[redis]`` extra) matches it directly, and the
test suite drives the same surface with a standard-library RESP client.
"""

import json
import time
from typing import Any, List, Optional, Sequence

from ..records import ChallengeRecord, MalformedRecordError
from .base import (
    ChallengeRuntimeState,
    ChallengeRuntimeStateKind,
    ConsumedRecord,
    ConsumedResult,
    CancellationResult,
    DeleteIfPendingResult,
    validate_operation_identity,
)
from ._lua_scripts import (
    CANCEL_SCRIPT,
    COMMIT_SCRIPT,
    CONSUME_SCRIPT,
    DELETE_IF_PENDING_SCRIPT,
)

ENVELOPE_MAX_BYTES = 131072

DEFAULT_PREFIX = "kiwicaptcha:"


class RedisStorageError(Exception):
    """The typed fail-closed storage failure the verifier resolves as
    an unavailable store."""


def _reject_duplicate_keys(pairs: List[Any]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def decode_envelope(raw: "bytes | str") -> Optional[dict]:
    """Decode one stored envelope: the record, its runtime state, the
    committed result and the operation identity, all from the same
    bytes.

    Returns None for an oversized, malformed, ambiguous or
    unparseable document, mirroring the PHP StrictJson gate: an
    unusable envelope is an absent record, never a partially trusted
    one.
    """
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    elif isinstance(raw, str):
        text = raw
    else:
        return None
    if len(text.encode("utf-8")) > ENVELOPE_MAX_BYTES:
        return None
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    state = data.get("state")
    identity = data.get("operation_identity")
    result = None
    raw_result = data.get("consumed_result")
    if isinstance(raw_result, dict):
        try:
            result = ConsumedResult.from_array(raw_result)
        except (TypeError, ValueError):
            result = None
    record_data = {
        key: value
        for key, value in data.items()
        if key
        not in (
            "state",
            "consumed_result",
            "operation_identity",
            "resume_owner",
            "resume_until",
        )
    }
    try:
        record = ChallengeRecord.from_array(record_data)
    except MalformedRecordError:
        return None
    return {
        "record": record,
        "state": state if isinstance(state, str) else None,
        "identity": identity if isinstance(identity, str) else None,
        "result": result,
    }


class RedisStorage:
    """The Redis store adapter over the narrow client surface."""

    def __init__(
        self,
        client: Any,
        prefix: str = DEFAULT_PREFIX,
        ttl_margin_secs: int = 60,
    ) -> None:
        if ttl_margin_secs < 0:
            raise ValueError("ttl_margin_secs must be at least 0")
        self.client = client
        self.prefix = prefix
        self.ttl_margin_secs = ttl_margin_secs
        self._sha_cache: dict = {}

    # ---- script execution ------------------------------------------------

    def _eval(self, script: str, keys: Sequence[str], args: Sequence[str]) -> Any:
        sha = self._sha_cache.get(script)
        try:
            if sha is None:
                try:
                    sha = self.client.script_load(script)
                    if isinstance(sha, bytes):
                        sha = sha.decode("ascii")
                    self._sha_cache[script] = sha
                except Exception:
                    sha = None
            if sha is not None:
                return self.client.evalsha(sha, len(keys), *keys, *args)
        except Exception as exc:
            message = str(exc).lower()
            if "noscript" not in message:
                raise RedisStorageError(f"redis storage failure: {exc}") from exc
        try:
            return self.client.eval(script, len(keys), *keys, *args)
        except Exception as exc:
            raise RedisStorageError(f"redis storage failure: {exc}") from exc

    @staticmethod
    def _text(value: Any) -> Optional[str]:
        if isinstance(value, bytes):
            return value.decode("utf-8")
        if isinstance(value, str):
            return value
        return None

    # ---- public transitions -------------------------------------------------

    def store(self, record: ChallengeRecord) -> None:
        """Persist one pending record with a Redis TTL of the signed
        lifetime plus the retention margin."""
        envelope = dict(record.to_array())
        envelope["state"] = "pending"
        envelope["consumed_result"] = None
        envelope["operation_identity"] = None
        value = json.dumps(envelope, separators=(",", ":"), ensure_ascii=True)
        ttl = max(1, record.expires_at - int(time.time()) + self.ttl_margin_secs)
        try:
            self.client.set(self.prefix + record.nonce, value, ex=ttl)
        except Exception as exc:
            raise RedisStorageError(f"redis storage failure: {exc}") from exc

    def find(self, nonce: str) -> Optional[ChallengeRecord]:
        try:
            raw = self.client.get(self.prefix + nonce)
        except Exception as exc:
            raise RedisStorageError(f"redis storage failure: {exc}") from exc
        if raw is None or raw is False or raw == "":
            return None
        envelope = decode_envelope(raw)
        if envelope is None:
            return None
        return envelope["record"]

    def _consume(self, nonce: str, identity_json: str) -> Optional[ConsumedRecord]:
        key = self.prefix + nonce
        raw = self._eval(CONSUME_SCRIPT, [key], [identity_json])
        if not isinstance(raw, (list, tuple)) or len(raw) < 3:
            return None
        json_bytes = self._text(raw[0])
        consumed_now = bool(raw[1])
        consumed_before = bool(raw[2])
        if json_bytes is None:
            return None
        envelope = decode_envelope(json_bytes)
        if envelope is None:
            return None
        return ConsumedRecord(
            envelope["record"],
            consumed_now,
            consumed_before,
            envelope["result"],
            envelope["identity"],
        )

    def consume(self, nonce: str) -> Optional[ConsumedRecord]:
        return self._consume(nonce, "")

    def consume_with_operation_identity(
        self, nonce: str, operation_identity: str
    ) -> Optional[ConsumedRecord]:
        validated = validate_operation_identity(operation_identity)
        identity_json = (
            json.dumps(validated, separators=(",", ":"), ensure_ascii=True)
            if validated is not None
            else ""
        )
        return self._consume(nonce, identity_json)

    def consumed_state(self, nonce: str) -> Optional[ConsumedRecord]:
        try:
            raw = self.client.get(self.prefix + nonce)
        except Exception as exc:
            raise RedisStorageError(f"redis storage failure: {exc}") from exc
        text = self._text(raw)
        if text is None or text == "":
            return None
        envelope = decode_envelope(text)
        if envelope is None or envelope["state"] != "consumed":
            return None
        return ConsumedRecord(
            envelope["record"], False, True, envelope["result"], envelope["identity"]
        )

    def delete_if_pending(self, nonce: str) -> DeleteIfPendingResult:
        key = self.prefix + nonce
        raw = self._eval(DELETE_IF_PENDING_SCRIPT, [key], [])
        if not isinstance(raw, (list, tuple)) or not raw:
            raise RedisStorageError("delete-if-pending: unexpected storage reply")
        state = self._text(raw[0])
        if state == "consumed":
            envelope = decode_envelope(self._text(raw[1]) or "")
            if envelope is None:
                raise RedisStorageError(
                    "delete-if-pending: undecodable consumed envelope"
                )
            return DeleteIfPendingResult(
                "consumed",
                ConsumedRecord(
                    envelope["record"],
                    False,
                    True,
                    envelope["result"],
                    envelope["identity"],
                ),
            )
        return DeleteIfPendingResult(state or "corrupt")

    def runtime_state(self, nonce: str) -> ChallengeRuntimeState:
        try:
            raw = self.client.get(self.prefix + nonce)
        except Exception as exc:
            raise RedisStorageError(f"redis storage failure: {exc}") from exc
        text = self._text(raw)
        if text is None or text == "":
            return ChallengeRuntimeState(ChallengeRuntimeStateKind.MISSING)
        envelope = decode_envelope(text)
        if envelope is None:
            return ChallengeRuntimeState(ChallengeRuntimeStateKind.MISSING)
        state = envelope["state"]
        if state == "cancelled":
            return ChallengeRuntimeState(
                ChallengeRuntimeStateKind.CANCELLED, envelope["record"]
            )
        if state == "consumed":
            consumed = ConsumedRecord(
                envelope["record"],
                False,
                True,
                envelope["result"],
                envelope["identity"],
            )
            return ChallengeRuntimeState(
                ChallengeRuntimeStateKind.CONSUMED, consumed.record, consumed
            )
        if state == "pending":
            return ChallengeRuntimeState(
                ChallengeRuntimeStateKind.PENDING, envelope["record"]
            )
        return ChallengeRuntimeState(ChallengeRuntimeStateKind.MISSING)

    def cancel(self, nonce: str) -> Optional[CancellationResult]:
        key = self.prefix + nonce
        raw = self._eval(CANCEL_SCRIPT, [key], [])
        if not isinstance(raw, (list, tuple)) or not raw:
            return None
        state = self._text(raw[0])
        if state is None:
            return None
        return CancellationResult(state)

    def delete(self, nonce: str) -> bool:
        try:
            removed = self.client.delete(self.prefix + nonce)
        except Exception as exc:
            raise RedisStorageError(f"redis storage failure: {exc}") from exc
        return bool(removed)

    def commit_result(self, nonce: str, valid: bool, binding: Optional[str]) -> bool:
        return self.commit_authenticated_result(
            nonce, ConsumedResult(valid, binding)
        )

    def commit_authenticated_result(
        self, nonce: str, result: ConsumedResult
    ) -> bool:
        key = self.prefix + nonce
        raw = self._eval(
            COMMIT_SCRIPT,
            [key],
            [
                "1" if result.valid else "0",
                result.binding if result.binding is not None else "",
                "0" if result.binding is None else "1",
                "",
                result.mac if result.mac is not None else "",
            ],
        )
        return raw in (1, "1", True)
