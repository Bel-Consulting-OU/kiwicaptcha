"""SQLite storage: the file-backed store adapter.

Port of packages/kiwicaptcha-php/src/Storage/SqliteStorage.php onto the
standard library's sqlite3 module. Every write runs inside one
``BEGIN IMMEDIATE`` transaction, so the read-decide-write sequence is
serialized against every other writer on the file and the commit is the
durability point. The schema is byte-compatible with the PHP adapter:
the same table, the same ``user_version`` stamp, and the same
``retained_until`` expiry boundary (``now >= retained_until``), so both
adapters can share one database file.
"""

import json
import sqlite3
import time
from typing import Any, Callable, Optional

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

SCHEMA_VERSION = 1

_SELECT_ROW = (
    "SELECT record_json, state, consumed_result_json, operation_identity,"
    " resume_owner, resume_until, retained_until"
    " FROM kiwicaptcha_challenge_records WHERE nonce = ?"
)

_CREATE_TABLE = (
    "CREATE TABLE IF NOT EXISTS kiwicaptcha_challenge_records ("
    "nonce TEXT PRIMARY KEY, "
    "record_json TEXT NOT NULL, "
    "state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')), "
    "consumed_result_json TEXT, "
    "operation_identity TEXT, "
    "resume_owner TEXT, "
    "resume_until INTEGER, "
    "retained_until INTEGER NOT NULL)"
)

_CREATE_INDEX = (
    "CREATE INDEX IF NOT EXISTS kiwicaptcha_challenge_records_retained_until_idx"
    " ON kiwicaptcha_challenge_records (retained_until)"
)


class SqliteStorageError(Exception):
    """The typed fail-closed storage failure, mirroring
    SqliteStorageException; the verifier resolves it as an
    unavailable store."""


class SqliteStorage:
    """The SQLite store adapter, mirroring the PHP SqliteStorage."""

    def __init__(
        self,
        connection_or_path: "sqlite3.Connection | str",
        busy_timeout_ms: int = 5000,
        ttl_margin_secs: int = 60,
        now: Optional[Callable[[], float]] = None,
    ) -> None:
        if busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be >= 0")
        if ttl_margin_secs < 0:
            raise ValueError("ttl_margin_secs must be >= 0")
        self._ttl_margin = ttl_margin_secs
        self._now = now
        if isinstance(connection_or_path, str):
            self._owns_connection = True
            self.conn = sqlite3.connect(connection_or_path, timeout=busy_timeout_ms / 1000.0)
        else:
            self._owns_connection = False
            self.conn = connection_or_path
        self.conn.row_factory = sqlite3.Row
        self.conn.isolation_level = None
        self.conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        try:
            self.conn.execute("PRAGMA journal_mode = WAL").fetchone()
        except sqlite3.Error as exc:
            raise self._failure("schema initialization", exc) from exc
        try:
            self._initialize_schema()
        except sqlite3.Error as exc:
            raise self._failure("schema initialization", exc) from exc

    def close(self) -> None:
        """Close the connection when this adapter opened it."""
        if self._owns_connection:
            self.conn.close()

    # ---- schema -------------------------------------------------------------

    def _initialize_schema(self) -> None:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("PRAGMA user_version").fetchone()
            version = int(row[0])
            if version > SCHEMA_VERSION:
                raise SqliteStorageError(
                    f"the database carries schema version {version}, newer than"
                    f" the {SCHEMA_VERSION} this adapter supports; upgrade the"
                    " kiwicaptcha-python-sdk package"
                )
            if version == SCHEMA_VERSION:
                self._assert_table_present()
            else:
                self.conn.execute(_CREATE_TABLE)
                self.conn.execute(_CREATE_INDEX)
                self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.conn.execute("COMMIT")
        except BaseException:
            self._safe_rollback()
            raise

    def _assert_table_present(self) -> None:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'"
            " AND name = 'kiwicaptcha_challenge_records'"
        ).fetchone()
        if int(row[0]) != 1:
            raise SqliteStorageError(
                "the database is stamped with the kiwicaptcha schema version"
                " but the challenge table is missing; the file is damaged"
            )

    # ---- transitions ---------------------------------------------------------

    def _write_transition(self, body: Callable[[], Any]) -> Any:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise self._failure("the write transition", exc) from exc
        try:
            result = body()
            self.conn.execute("COMMIT")
            return result
        except sqlite3.Error as exc:
            self._safe_rollback()
            raise self._failure("the write transition", exc) from exc
        except BaseException:
            self._safe_rollback()
            raise

    def _safe_rollback(self) -> None:
        try:
            self.conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _failure(self, what: str, exc: Exception) -> SqliteStorageError:
        message = f"sqlite storage failure during {what}: {exc}"
        text = str(exc).lower()
        if "locked" in text or "busy" in text:
            message += (
                "; the write lock stayed held past the busy timeout, so raise"
                " busy_timeout_ms or serialize writers"
            )
        return SqliteStorageError(message)

    def _now_secs(self) -> int:
        if self._now is not None:
            return int(self._now())
        return int(time.time())

    # ---- row helpers -----------------------------------------------------------

    def _row(self, nonce: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(_SELECT_ROW, (nonce,)).fetchone()

    def _live_row(self, nonce: str) -> Optional[sqlite3.Row]:
        row = self._row(nonce)
        if row is None:
            return None
        if self._now_secs() >= int(row["retained_until"]):
            return None
        return row

    @staticmethod
    def _state_of(row: sqlite3.Row) -> str:
        state = row["state"]
        return state if isinstance(state, str) else ""

    @staticmethod
    def _decode_row(row: sqlite3.Row) -> Optional[tuple]:
        try:
            data = json.loads(row["record_json"])
        except (TypeError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        try:
            record = ChallengeRecord.from_array(data)
        except MalformedRecordError:
            return None
        result = None
        raw_result = row["consumed_result_json"]
        if isinstance(raw_result, str):
            try:
                decoded = json.loads(raw_result)
            except (TypeError, ValueError):
                decoded = None
            if isinstance(decoded, dict):
                try:
                    result = ConsumedResult.from_array(decoded)
                except (KeyError, TypeError, ValueError):
                    result = None
        identity = row["operation_identity"]
        return record, result, identity if isinstance(identity, str) else None

    def _consumed_from_row(self, row: sqlite3.Row) -> ConsumedRecord:
        record, result, identity = self._decode_row(row)  # type: ignore[misc]
        return ConsumedRecord(record, False, True, result, identity)

    # ---- public transitions -------------------------------------------------------

    def store(self, record: ChallengeRecord) -> None:
        """Persist one pending record, sweeping expired rows first."""
        record_json = json.dumps(
            record.to_array(), separators=(",", ":"), ensure_ascii=True
        )
        retained_until = record.expires_at + self._ttl_margin

        def body() -> None:
            self.conn.execute(
                "DELETE FROM kiwicaptcha_challenge_records WHERE retained_until <= ?",
                (self._now_secs(),),
            )
            self.conn.execute(
                "INSERT INTO kiwicaptcha_challenge_records "
                "(nonce, record_json, state, consumed_result_json,"
                " operation_identity, resume_owner, resume_until, retained_until) "
                "VALUES (?, ?, 'pending', NULL, NULL, NULL, NULL, ?) "
                "ON CONFLICT(nonce) DO UPDATE SET "
                "record_json = excluded.record_json, state = excluded.state, "
                "consumed_result_json = excluded.consumed_result_json, "
                "operation_identity = excluded.operation_identity, "
                "resume_owner = excluded.resume_owner, "
                "resume_until = excluded.resume_until, "
                "retained_until = excluded.retained_until",
                (record.nonce, record_json, retained_until),
            )

        self._write_transition(body)

    def find(self, nonce: str) -> Optional[ChallengeRecord]:
        row = self._live_row(nonce)
        if row is None:
            return None
        decoded = self._decode_row(row)
        return decoded[0] if decoded is not None else None

    def consume(self, nonce: str) -> Optional[ConsumedRecord]:
        return self._do_consume(nonce, None)

    def consume_with_operation_identity(
        self, nonce: str, operation_identity: str
    ) -> Optional[ConsumedRecord]:
        return self._do_consume(nonce, validate_operation_identity(operation_identity))

    def _do_consume(self, nonce: str, identity: Optional[str]) -> Optional[ConsumedRecord]:
        def body() -> Optional[ConsumedRecord]:
            row = self._live_row(nonce)
            if row is None:
                return None
            decoded = self._decode_row(row)
            if decoded is None:
                return None
            state = self._state_of(row)
            if state == "consumed":
                record, result, stored_identity = decoded
                return ConsumedRecord(record, False, True, result, stored_identity)
            if state != "pending":
                return None
            if (
                row["consumed_result_json"] is not None
                or row["operation_identity"] is not None
                or row["resume_owner"] is not None
            ):
                return None
            cursor = self.conn.execute(
                "UPDATE kiwicaptcha_challenge_records"
                " SET state = 'consumed', operation_identity = ?"
                " WHERE nonce = ?",
                (identity, nonce),
            )
            if identity is not None and cursor.rowcount != 1:
                raise SqliteStorageError(
                    "the consume transition could not record the operation"
                    " identity on the flipped row"
                )
            return ConsumedRecord(decoded[0], True, False, None, identity)

        return self._write_transition(body)

    def consumed_state(self, nonce: str) -> Optional[ConsumedRecord]:
        row = self._live_row(nonce)
        if row is None or self._state_of(row) != "consumed":
            return None
        return self._consumed_from_row(row)

    def commit_result(self, nonce: str, valid: bool, binding: Optional[str]) -> bool:
        return self.commit_authenticated_result(
            nonce, ConsumedResult(valid, binding)
        )

    def commit_authenticated_result(
        self, nonce: str, result: ConsumedResult
    ) -> bool:
        result_json = json.dumps(
            result.to_array(), separators=(",", ":"), ensure_ascii=True
        )

        def body() -> bool:
            row = self._live_row(nonce)
            if (
                row is None
                or self._decode_row(row) is None
                or self._state_of(row) != "consumed"
                or row["consumed_result_json"] is not None
            ):
                return False
            self.conn.execute(
                "UPDATE kiwicaptcha_challenge_records"
                " SET consumed_result_json = ? WHERE nonce = ?",
                (result_json, nonce),
            )
            return True

        return self._write_transition(body)

    def delete(self, nonce: str) -> bool:
        def body() -> bool:
            cursor = self.conn.execute(
                "DELETE FROM kiwicaptcha_challenge_records WHERE nonce = ?",
                (nonce,),
            )
            return cursor.rowcount == 1

        return self._write_transition(body)

    def delete_if_pending(self, nonce: str) -> DeleteIfPendingResult:
        def body() -> DeleteIfPendingResult:
            row = self._live_row(nonce)
            if row is None:
                return DeleteIfPendingResult("missing")
            if self._decode_row(row) is None:
                return DeleteIfPendingResult("corrupt")
            state = self._state_of(row)
            if state == "consumed":
                return DeleteIfPendingResult("consumed", self._consumed_from_row(row))
            if state == "cancelled":
                return DeleteIfPendingResult("cancelled")
            if state != "pending":
                return DeleteIfPendingResult("corrupt")
            self.conn.execute(
                "DELETE FROM kiwicaptcha_challenge_records WHERE nonce = ?",
                (nonce,),
            )
            return DeleteIfPendingResult("deleted-pending")

        return self._write_transition(body)

    def runtime_state(self, nonce: str) -> ChallengeRuntimeState:
        row = self._live_row(nonce)
        if row is None:
            return ChallengeRuntimeState(ChallengeRuntimeStateKind.MISSING)
        decoded = self._decode_row(row)
        if decoded is None:
            return ChallengeRuntimeState(ChallengeRuntimeStateKind.MISSING)
        state = self._state_of(row)
        if state == "cancelled":
            return ChallengeRuntimeState(
                ChallengeRuntimeStateKind.CANCELLED, decoded[0]
            )
        if state == "consumed":
            consumed = self._consumed_from_row(row)
            return ChallengeRuntimeState(
                ChallengeRuntimeStateKind.CONSUMED, consumed.record, consumed
            )
        if state == "pending":
            return ChallengeRuntimeState(
                ChallengeRuntimeStateKind.PENDING, decoded[0]
            )
        return ChallengeRuntimeState(ChallengeRuntimeStateKind.MISSING)

    def cancel(self, nonce: str) -> Optional[CancellationResult]:
        def body() -> Optional[CancellationResult]:
            row = self._live_row(nonce)
            if row is None or self._decode_row(row) is None:
                return None
            state = self._state_of(row)
            if state == "consumed":
                return CancellationResult("consumed")
            if state == "cancelled":
                return CancellationResult("cancelled")
            if state != "pending":
                return None
            self.conn.execute(
                "UPDATE kiwicaptcha_challenge_records SET state = 'cancelled'"
                " WHERE nonce = ?",
                (nonce,),
            )
            return CancellationResult("cancelled-now")

        return self._write_transition(body)
