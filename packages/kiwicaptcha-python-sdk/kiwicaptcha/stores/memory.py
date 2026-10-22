"""In-memory storage: single-process, non-persistent.

Port of packages/kiwicaptcha-php/src/Storage/ArrayStorage.php. The
read-modify-write transitions are atomic because the dict is unshared
within the process. Consume is the one-shot transition: the record is
marked consumed and kept until deletion, so replay protection is the
consumed marker, never absence. Expiry follows the Redis TTL semantics:
an entry whose ``expires_at + retention_margin`` has passed is absent
from every read and transition, and is evicted lazily on first
observation. ``store`` prunes expired entries and evicts the
earliest-expiring entries at the hard cap, so a long-lived process
never accumulates unbounded state. The per-store sweep is gated on the
earliest known expiry so a store call before that horizon is a cheap
comparison; cap eviction walks a heap ordered by (expiry, nonce)
instead of re-sorting every key.
"""

import heapq
import time
from typing import Callable, Dict, List, Optional, Tuple

from ..records import ChallengeRecord
from .base import (
    ChallengeRuntimeState,
    ChallengeRuntimeStateKind,
    ConsumedRecord,
    ConsumedResult,
    CancellationResult,
    DeleteIfPendingResult,
    validate_operation_identity,
)

DEFAULT_MAX_ENTRIES = 10_000

# The sweep gate's "no known expiry" sentinel.
_NO_EXPIRY = 2**63 - 1


class _Entry:
    __slots__ = (
        "record",
        "consumed",
        "cancelled",
        "result",
        "operation_identity",
    )

    def __init__(self, record: ChallengeRecord) -> None:
        self.record = record
        self.consumed = False
        self.cancelled = False
        self.result: Optional[ConsumedResult] = None
        self.operation_identity: Optional[str] = None


class MemoryStorage:
    """The in-process store adapter, mirroring the PHP ArrayStorage."""

    def __init__(
        self,
        now: Optional[Callable[[], float]] = None,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        retention_margin_secs: int = 0,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        if retention_margin_secs < 0:
            raise ValueError("retention_margin_secs must be at least 0")
        self._now = now
        self._max_entries = max_entries
        self._retention_margin = retention_margin_secs
        self._records: Dict[str, _Entry] = {}
        # The earliest effective expiry among live entries; the
        # per-store sweep only runs once now has reached it.
        self._next_expiry: int = _NO_EXPIRY
        self._by_expiry: List[Tuple[int, str]] = []

    def _now_secs(self) -> int:
        if self._now is not None:
            return int(self._now())
        return int(time.time())

    def _effective_expiry(self, entry: _Entry) -> int:
        return entry.record.expires_at + self._retention_margin

    def _entry(self, nonce: str) -> Optional[_Entry]:
        entry = self._records.get(nonce)
        if entry is None:
            return None
        if self._now_secs() >= entry.record.expires_at + self._retention_margin:
            del self._records[nonce]
            return None
        return entry

    def _prune_expired(self) -> None:
        now = self._now_secs()
        if now < self._next_expiry:
            return
        dead = [
            nonce
            for nonce, entry in self._records.items()
            if now >= entry.record.expires_at + self._retention_margin
        ]
        for nonce in dead:
            del self._records[nonce]
        self._rebuild_horizon()

    def _rebuild_horizon(self) -> None:
        """Rescan the live rows: the next sweep gate and the heap refresh from scratch."""
        self._next_expiry = _NO_EXPIRY
        self._by_expiry = []
        for nonce, entry in self._records.items():
            expires = self._effective_expiry(entry)
            if expires < self._next_expiry:
                self._next_expiry = expires
            self._by_expiry.append((expires, nonce))
        heapq.heapify(self._by_expiry)

    def _evict_to_cap(self) -> None:
        """Drop the earliest-expiring live entries until one slot is free for the incoming record."""
        while len(self._records) >= self._max_entries and self._by_expiry:
            expires, nonce = heapq.heappop(self._by_expiry)
            entry = self._records.get(nonce)
            if entry is None or self._effective_expiry(entry) != expires:
                continue  # stale heap item
            del self._records[nonce]

    def store(self, record: ChallengeRecord) -> None:
        """Persist one pending record (single-use bounded retention)."""
        self._prune_expired()
        if record.nonce not in self._records:
            if len(self._records) + 1 > self._max_entries:
                self._evict_to_cap()
        self._records[record.nonce] = _Entry(record)
        expires = record.expires_at + self._retention_margin
        heapq.heappush(self._by_expiry, (expires, record.nonce))
        if expires < self._next_expiry:
            self._next_expiry = expires
        # Compaction: deletes leave stale heap items; rescan once they
        # dominate, so amortized cost stays O(1) per store.
        if len(self._by_expiry) > 4 * len(self._records) + 64:
            self._rebuild_horizon()

    def find(self, nonce: str) -> Optional[ChallengeRecord]:
        entry = self._entry(nonce)
        return entry.record if entry is not None else None

    def _classify(self, nonce: str) -> Optional[_Entry]:
        entry = self._entry(nonce)
        if entry is None or entry.cancelled:
            return None
        return entry

    def consume(self, nonce: str) -> Optional[ConsumedRecord]:
        entry = self._classify(nonce)
        if entry is None:
            return None
        if entry.consumed:
            return ConsumedRecord(
                entry.record,
                False,
                True,
                entry.result,
                entry.operation_identity,
            )
        if entry.result is not None or entry.operation_identity is not None:
            return None
        entry.consumed = True
        return ConsumedRecord(entry.record, True, False, None, None)

    def consume_with_operation_identity(
        self, nonce: str, operation_identity: str
    ) -> Optional[ConsumedRecord]:
        validated = validate_operation_identity(operation_identity)
        entry = self._classify(nonce)
        if entry is None:
            return None
        if entry.consumed:
            return ConsumedRecord(
                entry.record,
                False,
                True,
                entry.result,
                entry.operation_identity,
            )
        if entry.result is not None or entry.operation_identity is not None:
            return None
        entry.consumed = True
        if validated is not None:
            entry.operation_identity = validated
        return ConsumedRecord(
            entry.record, True, False, None, entry.operation_identity
        )

    def consumed_state(self, nonce: str) -> Optional[ConsumedRecord]:
        entry = self._entry(nonce)
        if entry is None or not entry.consumed:
            return None
        return ConsumedRecord(
            entry.record, False, True, entry.result, entry.operation_identity
        )

    def commit_result(self, nonce: str, valid: bool, binding: Optional[str]) -> bool:
        return self.commit_authenticated_result(
            nonce, ConsumedResult(valid, binding)
        )

    def commit_authenticated_result(
        self, nonce: str, result: ConsumedResult
    ) -> bool:
        entry = self._entry(nonce)
        if entry is None or not entry.consumed or entry.result is not None:
            return False
        entry.result = result
        return True

    def delete(self, nonce: str) -> bool:
        return self._records.pop(nonce, None) is not None

    def delete_if_pending(self, nonce: str) -> DeleteIfPendingResult:
        entry = self._entry(nonce)
        if entry is None:
            return DeleteIfPendingResult("missing")
        if entry.consumed:
            return DeleteIfPendingResult(
                "consumed",
                ConsumedRecord(
                    entry.record, False, True, entry.result, entry.operation_identity
                ),
            )
        if entry.cancelled:
            return DeleteIfPendingResult("cancelled")
        del self._records[nonce]
        return DeleteIfPendingResult("deleted-pending")

    def runtime_state(self, nonce: str) -> ChallengeRuntimeState:
        entry = self._entry(nonce)
        if entry is None:
            return ChallengeRuntimeState(ChallengeRuntimeStateKind.MISSING)
        if entry.cancelled:
            return ChallengeRuntimeState(
                ChallengeRuntimeStateKind.CANCELLED, entry.record
            )
        if entry.consumed:
            return ChallengeRuntimeState(
                ChallengeRuntimeStateKind.CONSUMED,
                entry.record,
                ConsumedRecord(
                    entry.record, False, True, entry.result, entry.operation_identity
                ),
            )
        return ChallengeRuntimeState(
            ChallengeRuntimeStateKind.PENDING, entry.record
        )

    def cancel(self, nonce: str) -> Optional[CancellationResult]:
        entry = self._entry(nonce)
        if entry is None:
            return None
        if entry.consumed:
            return CancellationResult("consumed")
        if entry.cancelled:
            return CancellationResult("cancelled")
        entry.cancelled = True
        return CancellationResult("cancelled-now")
