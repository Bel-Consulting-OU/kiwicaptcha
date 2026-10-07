"""The store adapter contract, shared by the memory and sqlite
backends; every assertion here runs against both."""

import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, ".")

from tests.support import CLIENT_IP, ISSUED_AT, NOW, SECRET, mint_v2_record, solve_sha

from kiwicaptcha.stores.base import (
    AtomicDeleteIfPendingStorage,
    AuthenticatedResultCommitStorage,
    CancellableStorage,
    ChallengeRuntimeStateKind,
    ConsumedResult,
    ConsumedStateReadableStorage,
    OperationIdentityAwareStorage,
    RuntimeStateReadableStorage,
)
from kiwicaptcha.stores.memory import MemoryStorage
from kiwicaptcha.stores.sqlite import SqliteStorage
from kiwicaptcha.tokens import SolutionToken
from kiwicaptcha.verify import Verifier, VerifierConfig, VerifyOptions


def make_memory():
    return MemoryStorage(now=lambda: ISSUED_AT)


def make_sqlite():
    handle, path = tempfile.mkstemp(suffix=".db")
    os.close(handle)
    os.unlink(path)
    storage = SqliteStorage(path)
    storage.test_path = path
    return storage


BACKENDS = {"memory": make_memory, "sqlite": make_sqlite}


class StoreContractTest(unittest.TestCase):
    def _store_and_check(self, storage):
        self.assertIsInstance(storage, AtomicDeleteIfPendingStorage)
        self.assertIsInstance(storage, AuthenticatedResultCommitStorage)
        self.assertIsInstance(storage, CancellableStorage)
        self.assertIsInstance(storage, ConsumedStateReadableStorage)
        self.assertIsInstance(storage, OperationIdentityAwareStorage)
        self.assertIsInstance(storage, RuntimeStateReadableStorage)
        record = mint_v2_record()
        storage.store(record)
        return record

    def test_store_find_consume_once(self):
        for name, factory in BACKENDS.items():
            with self.subTest(backend=name):
                storage = factory()
                record = self._store_and_check(storage)
                found = storage.find(record.nonce)
                self.assertIsNotNone(found)
                self.assertEqual(record.challenge, found.challenge)
                consumed = storage.consume(record.nonce)
                self.assertIsNotNone(consumed)
                self.assertTrue(consumed.consumed_now)
                self.assertFalse(consumed.consumed_before)
                # The record survives the flip: the marker is the proof.
                self.assertIsNotNone(storage.find(record.nonce))
                # A concurrent loser observes the winner's transition.
                loser = storage.consume(record.nonce)
                self.assertIsNotNone(loser)
                self.assertFalse(loser.consumed_now)
                self.assertTrue(loser.consumed_before)
                if hasattr(storage, "close"):
                    storage.close()
                    os.unlink(storage.test_path)

    def test_consume_missing_is_none(self):
        for name, factory in BACKENDS.items():
            with self.subTest(backend=name):
                storage = factory()
                self.assertIsNone(storage.consume("missing-nonce-value"))
                if hasattr(storage, "close"):
                    storage.close()
                    os.unlink(storage.test_path)

    def test_identity_consume_records_winner(self):
        for name, factory in BACKENDS.items():
            with self.subTest(backend=name):
                storage = factory()
                record = self._store_and_check(storage)
                won = storage.consume_with_operation_identity(
                    record.nonce, "order-1"
                )
                self.assertIsNotNone(won)
                self.assertEqual("order-1", won.operation_identity)
                self.assertEqual("order-1", storage.consumed_state(
                    record.nonce).operation_identity)
                # A malformed identity is refused before the transition.
                record2 = mint_v2_record(nonce_bytes=bytes(range(32, 64)))
                storage.store(record2)
                with self.assertRaises(ValueError):
                    storage.consume_with_operation_identity(
                        record2.nonce, "bad identity!"
                    )
                self.assertFalse(storage.consumed_state(record2.nonce))
                if hasattr(storage, "close"):
                    storage.close()
                    os.unlink(storage.test_path)

    def test_commit_once_then_immutable(self):
        for name, factory in BACKENDS.items():
            with self.subTest(backend=name):
                storage = factory()
                record = self._store_and_check(storage)
                storage.consume(record.nonce)
                self.assertTrue(
                    storage.commit_authenticated_result(
                        record.nonce, ConsumedResult(True, "tx-1", "ab" * 32)
                    )
                )
                # A second commit is refused: the result is one-shot.
                self.assertFalse(
                    storage.commit_authenticated_result(
                        record.nonce, ConsumedResult(False, None)
                    )
                )
                retained = storage.consumed_state(record.nonce)
                self.assertTrue(retained.consumed_result.valid)
                self.assertEqual("tx-1", retained.consumed_result.binding)
                self.assertEqual("ab" * 32, retained.consumed_result.mac)
                # Committing on a pending record is refused.
                record2 = mint_v2_record(nonce_bytes=bytes(range(32, 64)))
                storage.store(record2)
                self.assertFalse(
                    storage.commit_result(record2.nonce, True, None)
                )
                if hasattr(storage, "close"):
                    storage.close()
                    os.unlink(storage.test_path)

    def test_delete_if_pending_tri_state(self):
        for name, factory in BACKENDS.items():
            with self.subTest(backend=name):
                storage = factory()
                # Missing.
                result = storage.delete_if_pending("no-such-nonce-here")
                self.assertEqual("missing", result.status)
                # Pending is deleted.
                record = self._store_and_check(storage)
                result = storage.delete_if_pending(record.nonce)
                self.assertEqual("deleted-pending", result.status)
                self.assertIsNone(storage.find(record.nonce))
                # Consumed is kept and returned.
                record2 = mint_v2_record(nonce_bytes=bytes(range(32, 64)))
                storage.store(record2)
                storage.consume(record2.nonce)
                result = storage.delete_if_pending(record2.nonce)
                self.assertEqual("consumed", result.status)
                self.assertTrue(result.was_consumed())
                self.assertIsNotNone(storage.find(record2.nonce))
                # Cancelled is kept.
                record3 = mint_v2_record(nonce_bytes=bytes(range(64, 96)))
                storage.store(record3)
                storage.cancel(record3.nonce)
                result = storage.delete_if_pending(record3.nonce)
                self.assertEqual("cancelled", result.status)
                if hasattr(storage, "close"):
                    storage.close()
                    os.unlink(storage.test_path)

    def test_cancel_transition(self):
        for name, factory in BACKENDS.items():
            with self.subTest(backend=name):
                storage = factory()
                self.assertIsNone(storage.cancel("no-such-nonce-here"))
                record = self._store_and_check(storage)
                self.assertEqual("cancelled-now", storage.cancel(record.nonce).status)
                state = storage.runtime_state(record.nonce)
                self.assertEqual(ChallengeRuntimeStateKind.CANCELLED, state.kind)
                # Idempotent.
                self.assertEqual("cancelled", storage.cancel(record.nonce).status)
                # Consumed records are finalized.
                record2 = mint_v2_record(nonce_bytes=bytes(range(32, 64)))
                storage.store(record2)
                storage.consume(record2.nonce)
                self.assertEqual("consumed", storage.cancel(record2.nonce).status)
                if hasattr(storage, "close"):
                    storage.close()
                    os.unlink(storage.test_path)

    def test_runtime_state_snapshot(self):
        for name, factory in BACKENDS.items():
            with self.subTest(backend=name):
                storage = factory()
                self.assertEqual(
                    ChallengeRuntimeStateKind.MISSING,
                    storage.runtime_state("no-such-nonce").kind,
                )
                record = self._store_and_check(storage)
                self.assertEqual(
                    ChallengeRuntimeStateKind.PENDING,
                    storage.runtime_state(record.nonce).kind,
                )
                storage.consume(record.nonce)
                state = storage.runtime_state(record.nonce)
                self.assertEqual(ChallengeRuntimeStateKind.CONSUMED, state.kind)
                self.assertIsNotNone(state.consumed)
                # The snapshot carries the record: one read, one truth.
                self.assertEqual(record.challenge, state.record.challenge)
                if hasattr(storage, "close"):
                    storage.close()
                    os.unlink(storage.test_path)

    def test_expiry_is_absence(self):
        for name, factory in BACKENDS.items():
            with self.subTest(backend=name):
                storage = factory()
                record = self._store_and_check(storage)
                if name == "memory":
                    storage._now = lambda: ISSUED_AT + 7200
                    self.assertIsNone(storage.find(record.nonce))
                    self.assertIsNone(storage.consume(record.nonce))
                else:
                    # The sqlite boundary is retained_until
                    # (expires_at + ttl_margin_secs, default 60).
                    self.assertIsNotNone(storage.find(record.nonce))
                    storage._now = lambda: ISSUED_AT + 3600
                    self.assertIsNone(storage.find(record.nonce))
                    self.assertIsNone(storage.consume(record.nonce))
                if hasattr(storage, "close"):
                    storage.close()
                    os.unlink(storage.test_path)


class MemoryStoreSpecificTest(unittest.TestCase):
    def test_bounded_retention_eviction(self):
        storage = MemoryStorage(now=lambda: ISSUED_AT, max_entries=3)
        for i in range(5):
            storage.store(mint_v2_record(nonce_bytes=bytes([i]) * 32))
        self.assertLessEqual(len(storage._records), 3)

    def test_constructor_guards(self):
        with self.assertRaises(ValueError):
            MemoryStorage(max_entries=0)
        with self.assertRaises(ValueError):
            MemoryStorage(retention_margin_secs=-1)


class SqliteStoreSpecificTest(unittest.TestCase):
    def test_schema_shared_with_php_adapter(self):
        storage = make_sqlite()
        try:
            version = storage.conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(1, version)
            tables = storage.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
                " AND name='kiwicaptcha_challenge_records'"
            ).fetchall()
            self.assertEqual(1, len(tables))
            columns = {
                row[1]
                for row in storage.conn.execute(
                    "PRAGMA table_info(kiwicaptcha_challenge_records)"
                )
            }
            self.assertEqual(
                {
                    "nonce",
                    "record_json",
                    "state",
                    "consumed_result_json",
                    "operation_identity",
                    "resume_owner",
                    "resume_until",
                    "retained_until",
                },
                columns,
            )
        finally:
            storage.close()
            os.unlink(storage.test_path)

    def test_corrupt_row_fails_closed(self):
        storage = make_sqlite()
        try:
            record = mint_v2_record()
            storage.store(record)
            storage.conn.execute(
                "UPDATE kiwicaptcha_challenge_records SET record_json = '{bad'"
                " WHERE nonce = ?",
                (record.nonce,),
            )
            self.assertIsNone(storage.find(record.nonce))
            self.assertEqual("corrupt", storage.delete_if_pending(record.nonce).status)
            self.assertEqual(
                ChallengeRuntimeStateKind.MISSING,
                storage.runtime_state(record.nonce).kind,
            )
        finally:
            storage.close()
            os.unlink(storage.test_path)

    def test_damaged_stamp_refused(self):
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(path)
        storage = SqliteStorage(path)
        storage.conn.execute("PRAGMA user_version = 99")
        storage.conn.commit()
        storage.close()
        try:
            SqliteStorage(path)
            self.fail("a newer schema stamp must be refused")
        except Exception as exc:
            self.assertIn("newer than", str(exc))
        finally:
            os.unlink(path)


class SqliteConnectionPolicyTest(unittest.TestCase):
    def test_caller_connection_is_never_mutated(self):
        import sqlite3

        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(path)
        caller = sqlite3.connect(path)
        # The host application's isolation posture: implicit
        # transactions (isolation_level == "") and its own row shape.
        self.assertEqual("", caller.isolation_level)
        self.assertIsNone(caller.row_factory)
        storage = SqliteStorage(caller)
        try:
            # The caller's connection keeps its own settings: the store
            # drove a dedicated connection instead of switching the host
            # app into autocommit.
            self.assertEqual("", caller.isolation_level)
            self.assertIsNone(caller.row_factory)
            self.assertIsNot(storage.conn, caller)
            record = mint_v2_record()
            storage.store(record)
            self.assertIsNotNone(storage.find(record.nonce))
        finally:
            storage.close()
            caller.close()
            os.unlink(path)

    def test_in_memory_caller_connection_refused(self):
        import sqlite3

        caller = sqlite3.connect(":memory:")
        try:
            SqliteStorage(caller)
            self.fail("an in-memory connection cannot be shared and must be refused")
        except ValueError as exc:
            self.assertIn("in-memory", str(exc))
        finally:
            caller.close()


class SqliteThreadedAccessTest(unittest.TestCase):
    """One shared store across request threads, the WSGI singleton.

    The adapter's connection belongs to the store, not to the thread
    that constructed it: verifications issued from worker threads must
    resolve exactly like the constructing thread's own.
    """

    def _shared(self):
        storage = make_sqlite()
        self.addCleanup(storage.close)
        verifier = Verifier(storage, VerifierConfig(now_provider=lambda: NOW))
        return storage, verifier

    def _verify(self, verifier, record, operation_identity=None):
        counter = solve_sha(record.prefix, record.salt, record.target_bits)
        token = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
        return verifier.verify(
            token,
            VerifyOptions(
                secret_key=SECRET,
                expected_scope="login",
                client_ip=CLIENT_IP,
                operation_identity=operation_identity,
            ),
        )

    def test_shared_store_serves_verifications_across_threads(self):
        storage, verifier = self._shared()
        records = [mint_v2_record(nonce_bytes=bytes([i] * 32)) for i in range(8)]
        for record in records:
            storage.store(record)
        outcomes = {}
        errors = []

        def worker(record):
            try:
                outcomes[record.nonce] = self._verify(verifier, record)
            except Exception as exc:  # pragma: no cover - the regression pin
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(r,)) for r in records]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([], errors)
        self.assertEqual(8, len(outcomes))
        for nonce, outcome in outcomes.items():
            self.assertTrue(outcome.is_ok(), f"{nonce}: {outcome.code}")
            self.assertFalse(outcome.from_stored_result)

    def test_threaded_race_is_exactly_once(self):
        storage, verifier = self._shared()
        record = mint_v2_record()
        storage.store(record)
        outcomes = []
        errors = []
        barrier = threading.Barrier(6)

        def worker():
            try:
                barrier.wait(timeout=5)
                outcomes.append(self._verify(verifier, record))
            except Exception as exc:  # pragma: no cover - the regression pin
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([], errors)
        self.assertEqual(6, len(outcomes))
        fresh = [o for o in outcomes if o.is_ok() and not o.from_stored_result]
        self.assertEqual(1, len(fresh), f"exactly one fresh winner: {[(o.code, o.from_stored_result) for o in outcomes]}")
        for outcome in outcomes:
            self.assertNotEqual("storage_unavailable", outcome.code)
            self.assertTrue(
                outcome.is_ok()
                or outcome.code in ("already_consumed", "consume_indeterminate"),
                outcome.code,
            )


if __name__ == "__main__":
    unittest.main()
