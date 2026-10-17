import os
import tempfile
import unittest

from kiwicaptcha.stores import MemoryStorage, SqliteStorage, open_store
from kiwicaptcha.stores.redis import RedisStorage


class StoreFactoryTest(unittest.TestCase):
    def test_memory_url_builds_the_memory_backend(self) -> None:
        store = open_store("memory://")
        self.assertIsInstance(store, MemoryStorage)

    def test_sqlite_url_builds_the_file_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "challenge.db")
            store = open_store(f"sqlite:///{path}")
            try:
                self.assertIsInstance(store, SqliteStorage)
                self.assertTrue(os.path.exists(path))
            finally:
                store.close()

    def test_sqlite_url_without_a_path_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            open_store("sqlite://")

    def test_unknown_scheme_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            open_store("memcached://127.0.0.1")

    def test_redis_url_uses_the_documented_extra_or_refuses_clearly(self) -> None:
        try:
            import redis  # noqa: F401
        except ImportError:
            with self.assertRaises(ValueError) as caught:
                open_store("redis://127.0.0.1:6379")
            self.assertIn("kiwicaptcha[redis]", str(caught.exception))
        else:
            store = open_store("redis://127.0.0.1:6379")
            self.assertIsInstance(store, RedisStorage)


if __name__ == "__main__":
    unittest.main()
