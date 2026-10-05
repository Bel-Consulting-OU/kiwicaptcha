"""The Redis store adapter against a live redis-server.

The adapter binds to a narrow client surface; the test drives it with
a standard-library RESP client over a scratch redis-server instance
started in setUpClass. When no redis-server binary is available the
suite skips, keeping the default run green everywhere.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, ".")

from tests.support import ISSUED_AT, mint_v2_record

from kiwicaptcha.stores.redis import RedisStorage
from kiwicaptcha.stores.base import ConsumedResult


class RespClient:
    """A minimal RESP client: the exact surface the adapter uses."""

    def __init__(self, host: str, port: int) -> None:
        self.sock = socket.create_connection((host, port), timeout=5)
        self.file = self.sock.makefile("rb")

    def _send(self, *parts: bytes) -> None:
        out = bytearray(b"*%d\r\n" % len(parts))
        for part in parts:
            if isinstance(part, str):
                part = part.encode()
            out += b"$%d\r\n%s\r\n" % (len(part), part)
        self.sock.sendall(bytes(out))

    def _read(self):
        line = self.file.readline()
        if not line:
            raise ConnectionError("redis closed the connection")
        kind, body = line[:1], line[1:-2]
        if kind == b"+":
            return body.decode()
        if kind == b"-":
            return Exception(body.decode())
        if kind == b":":
            return int(body)
        if kind == b"$":
            length = int(body)
            if length == -1:
                return None
            data = self.file.read(length + 2)[:-2]
            return data
        if kind == b"*":
            count = int(body)
            if count == -1:
                return None
            items = []
            for _ in range(count):
                item = self._read()
                while isinstance(item, Exception):
                    item = self._read()
                items.append(item)
            return items
        raise ConnectionError(f"unknown reply: {line!r}")

    def command(self, *parts) -> object:
        self._send(*parts)
        reply = self._read()
        if isinstance(reply, Exception):
            raise reply
        return reply

    def get(self, key):
        return self.command("GET", key)

    def set(self, key, value, ex=None, px=None):
        args = ["SET", key, value]
        if ex is not None:
            args += ["EX", str(int(ex))]
        if px is not None:
            args += ["PX", str(int(px))]
        return self.command(*args)

    def pttl(self, key):
        return self.command("PTTL", key)

    def delete(self, key):
        return self.command("DEL", key)

    def script_load(self, script):
        return self.command("SCRIPT", "LOAD", script)

    def evalsha(self, sha, numkeys, *keys_and_args):
        return self.command("EVALSHA", sha, str(numkeys), *keys_and_args)

    def eval(self, script, numkeys, *keys_and_args):
        return self.command("EVAL", script, str(numkeys), *keys_and_args)

    def close(self):
        try:
            self.file.close()
            self.sock.close()
        except OSError:
            pass


REDIS_SERVER = shutil.which("redis-server")


@unittest.skipUnless(REDIS_SERVER, "redis-server binary not available")
class RedisStoreTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="kiwi-redis-test-")
        cls.port = 6399 + (os.getpid() % 100)
        cls.proc = subprocess.Popen(
            [
                REDIS_SERVER,
                "--port", str(cls.port),
                "--save", "",
                "--appendonly", "no",
                "--dir", cls.tmpdir,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                probe = RespClient("127.0.0.1", cls.port)
                probe.command("PING")
                probe.close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            cls.proc.kill()
            raise RuntimeError("the scratch redis-server never came up")
        cls.client = RespClient("127.0.0.1", cls.port)
        cls.storage = RedisStorage(cls.client, ttl_margin_secs=60)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.client.command("FLUSHALL")

    def _stored_record(self, **mint):
        record = mint_v2_record(**mint)
        self.storage.store(record)
        return record

    def test_store_find_round_trip(self):
        record = self._stored_record()
        found = self.storage.find(record.nonce)
        self.assertIsNotNone(found)
        self.assertEqual(record.challenge, found.challenge)
        # The stored envelope is the shared wire shape: the runtime
        # markers ride the same document.
        raw = self.client.get("kiwicaptcha:" + record.nonce)
        self.assertIn(b'"state":"pending"', raw)
        self.assertIn(b'"consumed_result":null', raw)
        self.assertIn(b'"operation_identity":null', raw)

    def test_consume_exactly_once(self):
        record = self._stored_record()
        won = self.storage.consume(record.nonce)
        self.assertTrue(won.consumed_now)
        loser = self.storage.consume(record.nonce)
        self.assertTrue(loser.consumed_before)
        self.assertFalse(loser.consumed_now)
        # The key survives with its TTL preserved.
        self.assertGreater(self.client.pttl("kiwicaptcha:" + record.nonce), 0)

    def test_identity_consume_splices_envelope(self):
        record = self._stored_record()
        won = self.storage.consume_with_operation_identity(record.nonce, "order-9")
        self.assertIsNotNone(won)
        self.assertEqual("order-9", won.operation_identity)
        raw = self.client.get("kiwicaptcha:" + record.nonce)
        self.assertIn(b'"operation_identity":"order-9"', raw)
        self.assertIn(b'"state":"consumed"', raw)

    def test_commit_and_consumed_state(self):
        record = self._stored_record()
        self.storage.consume(record.nonce)
        self.assertTrue(
            self.storage.commit_authenticated_result(
                record.nonce, ConsumedResult(True, "tx-7", "ab" * 32)
            )
        )
        state = self.storage.consumed_state(record.nonce)
        self.assertIsNotNone(state)
        self.assertEqual("tx-7", state.consumed_result.binding)
        self.assertEqual("ab" * 32, state.consumed_result.mac)
        # One commit only.
        self.assertFalse(
            self.storage.commit_result(record.nonce, False, None)
        )

    def test_delete_if_pending_and_cancel(self):
        record = self._stored_record()
        self.assertEqual(
            "deleted-pending", self.storage.delete_if_pending(record.nonce).status
        )
        self.assertIsNone(self.storage.find(record.nonce))
        record2 = self._stored_record(nonce_bytes=bytes(range(32, 64)))
        self.storage.cancel(record2.nonce)
        self.assertEqual("cancelled", self.storage.delete_if_pending(record2.nonce).status)
        state = self.storage.runtime_state(record2.nonce)
        from kiwicaptcha.stores.base import ChallengeRuntimeStateKind

        self.assertEqual(ChallengeRuntimeStateKind.CANCELLED, state.kind)

    def test_runtime_state(self):
        record = self._stored_record()
        from kiwicaptcha.stores.base import ChallengeRuntimeStateKind

        self.assertEqual(
            ChallengeRuntimeStateKind.PENDING,
            self.storage.runtime_state(record.nonce).kind,
        )
        self.storage.consume(record.nonce)
        state = self.storage.runtime_state(record.nonce)
        self.assertEqual(ChallengeRuntimeStateKind.CONSUMED, state.kind)
        self.assertIsNotNone(state.consumed)

    def test_php_envelope_interop(self):
        # An envelope written exactly like the PHP store() writes it
        # (the same key set, the same marker spelling) decodes and
        # consumes through the Python adapter.
        import json

        record = mint_v2_record()
        envelope = record.to_array()
        envelope["state"] = "pending"
        envelope["consumed_result"] = None
        envelope["operation_identity"] = None
        self.client.set(
            "kiwicaptcha:" + record.nonce,
            json.dumps(envelope, separators=(",", ":"), ensure_ascii=True),
            ex=300,
        )
        found = self.storage.find(record.nonce)
        self.assertIsNotNone(found)
        self.assertEqual(record.challenge, found.challenge)
        won = self.storage.consume(record.nonce)
        self.assertTrue(won.consumed_now)

    def test_corrupt_envelope_is_missing(self):
        record = mint_v2_record()
        self.client.set(
            "kiwicaptcha:" + record.nonce,
            b'{"state":"pending","nonce":"x"}',
            ex=300,
        )
        self.assertIsNone(self.storage.find(record.nonce))
        state = self.storage.runtime_state(record.nonce)
        from kiwicaptcha.stores.base import ChallengeRuntimeStateKind

        self.assertEqual(ChallengeRuntimeStateKind.MISSING, state.kind)

    def test_duplicate_key_envelope_refused(self):
        record = mint_v2_record()
        raw = ('{"nonce":"%s","state":"pending","state":"consumed"}'
               % record.nonce).encode()
        self.client.set("kiwicaptcha:" + record.nonce, raw, ex=300)
        self.assertIsNone(self.storage.find(record.nonce))

    def test_malformed_identity_refused_before_script(self):
        record = self._stored_record()
        with self.assertRaises(ValueError):
            self.storage.consume_with_operation_identity(record.nonce, "bad id!")


if __name__ == "__main__":
    unittest.main()
