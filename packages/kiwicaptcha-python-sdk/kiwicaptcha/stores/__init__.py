"""Store adapters: the memory default, the SQLite file backend, and the
Redis shared backend behind the optional ``[redis]`` extra (the Redis
module imports lazily there; the adapter itself only needs a client
object with the narrow command surface)."""

from .base import (
    AtomicDeleteIfPendingStorage,
    AuthenticatedResultCommitStorage,
    CancellableStorage,
    ChallengeRuntimeState,
    ChallengeRuntimeStateKind,
    ConsumedRecord,
    ConsumedResult,
    ConsumedStateReadableStorage,
    CancellationResult,
    DeleteIfPendingResult,
    OperationIdentityAwareStorage,
    RuntimeStateReadableStorage,
    Storage,
    validate_operation_identity,
)
from .memory import DEFAULT_MAX_ENTRIES, MemoryStorage
from .sqlite import SCHEMA_VERSION, SqliteStorage, SqliteStorageError
from .redis import (
    DEFAULT_PREFIX,
    ENVELOPE_MAX_BYTES,
    RedisStorage,
    RedisStorageError,
    decode_envelope,
)

__all__ = [
    "AtomicDeleteIfPendingStorage",
    "AtomicStorage",
    "AuthenticatedResultCommitStorage",
    "CancellableStorage",
    "ChallengeRuntimeState",
    "ChallengeRuntimeStateKind",
    "ConsumedRecord",
    "ConsumedResult",
    "ConsumedStateReadableStorage",
    "CancellationResult",
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_PREFIX",
    "DeleteIfPendingResult",
    "ENVELOPE_MAX_BYTES",
    "MemoryStorage",
    "OperationIdentityAwareStorage",
    "RedisStorage",
    "RedisStorageError",
    "RuntimeStateReadableStorage",
    "SCHEMA_VERSION",
    "SqliteStorage",
    "SqliteStorageError",
    "Storage",
    "decode_envelope",
    "open_store",
    "validate_operation_identity",
]

#: The atomicity contract of the shipped backends: every consume is a
#: single-shot transition, so a concurrent consumer either wins it or
#: observes the winner. Alias of :class:`Storage`, mirroring the PHP
#: ``AtomicStorageInterface`` marker.
AtomicStorage = Storage


def open_store(url: str, **kwargs):
    """Build a store adapter from a URL.

    ``memory://`` builds :class:`MemoryStorage`. ``sqlite://`` followed
    by a path (``sqlite:///var/lib/kiwi/challenges.db``) builds
    :class:`SqliteStorage`. ``redis://`` and ``rediss://`` build
    :class:`RedisStorage` over a lazily imported official ``redis``
    client, which requires the ``[redis]`` extra. Keyword arguments
    forward to the backend constructor.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme == "memory":
        return MemoryStorage(**kwargs)
    if scheme == "sqlite":
        path = parsed.path
        if parsed.netloc not in ("", "localhost"):
            path = parsed.netloc + path
        if not path:
            raise ValueError("sqlite:// store URLs require a file path")
        return SqliteStorage(path, **kwargs)
    if scheme in ("redis", "rediss"):
        try:
            import redis as redis_module
        except ImportError as exc:  # pragma: no cover - environment guard
            raise ValueError(
                "redis:// store URLs need the optional [redis] extra:"
                " pip install kiwicaptcha[redis]"
            ) from exc
        client = redis_module.Redis.from_url(url, decode_responses=False)
        prefix = kwargs.pop("prefix", DEFAULT_PREFIX)
        return RedisStorage(client, prefix=prefix, **kwargs)
    raise ValueError(
        f"unsupported store URL scheme {scheme!r}: use memory://, sqlite:// or redis://"
    )
