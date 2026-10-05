"""Protocol constants shared with the PHP and Rust cores.

Every bound mirrors the PHP constants in packages/kiwicaptcha-php, so
the three implementations accept exactly the same record language.
"""

MAX_SHA_TARGET_BITS = 20
"""Hard ceiling for issued sha256 difficulty; the solver caps at 20M hashes."""

MIN_SECRET_BYTES = 32
"""Minimum master secret length in bytes."""

MIN_EXECUTION_KEY_BYTES = 32
"""Minimum execution key length in bytes."""

MAX_ARGON2_TARGET_BITS = 10
"""Ceiling for issued argon2id difficulty."""

MIN_DIFFICULTY = 1
"""Absolute stored-record difficulty floor."""

MAX_DIFFICULTY = 20
"""Absolute stored-record difficulty ceiling."""

MAX_TTL_SECS = 300
"""Hard ceiling for a stored record lifetime in seconds."""

MIN_RSW_T = 10_000
"""Floor for the rsw sequential squaring count."""

MAX_RSW_T = 300_000
"""Ceiling for the rsw sequential squaring count."""

RSW_TARGET_BITS_PIN = 1
"""The canonical target_bits pin carried by an rsw record."""

MAX_STRING_BYTES = 4096
"""Maximum wire string length of any record field."""

BASE_PROTOCOL_VERSION = 2
"""The identityless, decoyless, executionless canonical version."""

DECOY_PROTOCOL_VERSION = 3
"""The decoy-capable canonical version."""

EXECUTION_PROTOCOL_VERSION = 4
"""The execution-capable canonical version."""

RSW_IDENTITY_PROTOCOL_VERSION = 5
"""The identity-bearing rsw canonical version."""

MAX_PROTOCOL_VERSION = 5
"""Maximum accepted challenge protocol version."""

MAX_CLOCK_SKEW = 60
"""Maximum tolerated future issuance skew in seconds."""

SKEW_TOLERANCE_US = 5_000_000
"""Host clock skew tolerance for the minimum duration check, microseconds."""

MIN_ARGON_MEMORY_KIB = 8
"""Verifier process ceiling for argon2id memory."""

MAX_ARGON_MEMORY_KIB = 65_536
"""Verifier process ceiling for argon2id memory."""

MIN_ARGON_TIME = 3
"""Verifier process ceiling for argon2id time cost."""

MAX_ARGON_TIME = 16
"""Verifier process ceiling for argon2id time cost."""

MIN_PARALLELISM = 1
"""Verifier process ceiling for argon2id parallelism."""

MAX_PARALLELISM = 4
"""Verifier process ceiling for argon2id parallelism."""

MAX_SOLVER_COUNTER = 20_000_000
"""The solver search ceiling shared with the widget and the wasm core."""

MAX_DURATION_MS = 3_600_000
"""Hard ceiling for the client reported token duration."""

NONCE_B64_BYTES = 32
"""Decoded nonce length: the token nonce is base64 of 32 random bytes."""

SALT_B64_BYTES = 16
"""Decoded record salt length."""

HKDF_DEPLOY_SALT = "kiwicaptcha/deploy-salt/v1"
"""Public extraction salt of the purpose key derivation."""

INFO_CHALLENGE_SIGN = "kiwi/v2/challenge-sign"
"""Info label of the challenge signing purpose key."""

INFO_IP_BIND = "kiwi/v2/ip-bind"
"""Info label of the ip binding purpose key."""

INFO_RESULT_TOKEN = "kiwi/v2/result-token"
"""Info label of the result token purpose key."""

INFO_SERVER_STATE = "kiwi/v2/server-state"
"""Info label of the server state purpose key."""

INFO_TENANT_ROOT_PREFIX = "kiwi/v2/tenant/"
"""Prefix of the tenant root info label."""

RECORD_META_DOMAIN = "kiwi/record-meta/v1"
"""Domain line of the record metadata mac input."""

CONSUMED_RESULT_DOMAIN = "kiwi/consumed-result/v1"
"""Domain line of the consumed result mac input."""

IDENTIFIER_ALPHABET = "A-Za-z0-9._:-"
"""The narrow deployment identifier alphabet."""

DECOY_ALPHABET = "A-Za-z0-9_-"
"""The honeypot field name alphabet."""
