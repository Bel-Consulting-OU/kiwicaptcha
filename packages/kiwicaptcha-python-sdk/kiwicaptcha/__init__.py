"""KiwiCaptcha Python server SDK.

Verifies client-submitted proof-of-work solution tokens, byte-for-byte
compatible with the PHP and Rust cores. Verification is pure-local: the
signature, the message authentication codes and the store adapter are
the only inputs, and no call ever reaches a network service.

The public surface mirrors the shared server SDK contract:

- ``Verifier.verify(token, options)`` resolves to a ``VerifyDecision``
  with ``ok``, ``disposition``, ``decision_handle`` and ``price``.
- ``kiwicaptcha.middleware`` ships the wsgi middleware plus the Django,
  Flask and FastAPI integrations.
- ``kiwicaptcha.outcomes`` is the versioned outcomes mapping and client.
- ``kiwicaptcha.stores`` provides the memory, sqlite and redis adapters
  behind one injectable storage interface.
- ``python -m kiwicaptcha.doctor`` validates a deployment.
"""

from .config import Settings, VerifierConfig
from .decision import VerifyDecision
from .errors import VerifyError, VerifyOutcome
from .middleware import (
    DjangoMiddleware,
    FastApiKiwiDependency,
    FlaskKiwiCaptcha,
    KiwiCaptchaMiddleware as DjangoKiwiCaptchaMiddleware,
    WsgiKiwiCaptcha,
)
from .outcomes import (
    MemoryOutcomeSink,
    Outcome,
    OutcomeHandle,
    OutcomeHandleDimension,
    OutcomeMap,
    OutcomeMapping,
    OutcomeReceipt,
    OutcomesClient,
)
from .records import ChallengeRecord
from .stores import (
    AtomicDeleteIfPendingStorage,
    AtomicStorage,
    AuthenticatedResultCommitStorage,
    CancellableStorage,
    ChallengeRuntimeState,
    ChallengeRuntimeStateKind,
    ConsumedRecord,
    ConsumedResult,
    ConsumedStateReadableStorage,
    DeleteIfPendingResult,
    MemoryStorage,
    OperationIdentityAwareStorage,
    RedisStorage,
    RuntimeStateReadableStorage,
    SqliteStorage,
    Storage,
    open_store,
)
from .tokens import DecodeError, SolutionToken
from .verify import VerifyOptions, Verifier

__version__ = "1.0.0"

__all__ = [
    "ChallengeRecord",
    "ChallengeRuntimeState",
    "ChallengeRuntimeStateKind",
    "ConsumedRecord",
    "ConsumedResult",
    "DecodeError",
    "DeleteIfPendingResult",
    "DjangoKiwiCaptchaMiddleware",
    "DjangoMiddleware",
    "FastApiKiwiDependency",
    "FlaskKiwiCaptcha",
    "MemoryOutcomeSink",
    "MemoryStorage",
    "OperationIdentityAwareStorage",
    "Outcome",
    "OutcomeHandle",
    "OutcomeHandleDimension",
    "OutcomeMap",
    "OutcomeMapping",
    "OutcomeReceipt",
    "OutcomesClient",
    "RedisStorage",
    "Settings",
    "SolutionToken",
    "SqliteStorage",
    "Storage",
    "Verifier",
    "VerifierConfig",
    "VerifyDecision",
    "VerifyError",
    "VerifyOptions",
    "VerifyOutcome",
    "WsgiKiwiCaptcha",
    "open_store",
    "__version__",
]
