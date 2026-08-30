# Configuration

The bundle is configured under the `kiwi_captcha` key in
`config/packages/kiwi_captcha.yaml`. Every option is shown below with its
default and validation. Options are validated at container-compile time where
possible; the same bounds are enforced by the core package at runtime.

## Quick start (verified flow)

An ordinary installation configures four keys and nothing else. The
profile fills every safety-relevant default, the secret comes from the
environment, and the DSN builds every Redis-backed service:

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: balanced   # balanced | privacy_strict | high_abuse | compatibility
    secret_key: '%env(KIWI_SECRET_KEY)%'
    public_base_url: '%env(KIWI_PUBLIC_URL)%'
    redis_dsn: '%env(KIWI_REDIS_DSN)%'
```

- `.env`: `KIWI_SECRET_KEY` (generated), `KIWI_REDIS_DSN` and
  `KIWI_PUBLIC_URL` (localhost defaults), all written by the Flex
  recipe; see [flex-recipe.md](flex-recipe.md).
- `redis_dsn` and `public_base_url` are env-managed (twelve-factor):
  credentials, private hosts, TLS endpoints and database selection
  belong in your environment or secrets manager, never in
  source-controlled config files. The container resolves the
  placeholders; the bundle validates the resolved DSN (redis:// or
  rediss:// with a host, fail-closed) when the client is constructed.
  A literal override in
  this file is still possible and keeps the same validation.
- Install the client library: `composer require predis/predis`.
- The Flex recipe ships this exact file; see
  [flex-recipe.md](flex-recipe.md).

Boot check: `bin/console kiwicaptcha:doctor` reports one status per
check and exits non-zero on any failure. The minimal config above must
reach `[PASS] Redis reachability`, `[PASS] Storage atomicity` and no
`[FAIL]` row; every remaining `[WARN]` row names the deployment
decision still open.

What the DSN builds: the challenge storage
(`KiwiCaptcha\Storage\RedisStorage`, atomic, so the production storage
guard passes), the distributed issuance rate limiter, the Argon2id
admission semaphore and, under `high_abuse`, the risk state store. An
explicit service id wins over the DSN for its knob (`storage`,
`redis_service`, `risk.redis_service`); see "Advanced configuration"
below.

## Protection profiles

Ordinary deployments operate at the policy level: set one
`protection_profile` and let the bundle derive the safety-relevant knobs
you do not set. The profile fills **safe derived defaults** for the knobs
it governs. With `protection_profile: null` (the default) every knob
keeps its individual default and behavior is byte-identical to the
pre-profile configuration.

**The profile is the LOWEST-precedence configuration layer.** Symfony
merges your config files in order, so the bundle applies the profile as
the first, weakest layer of that merge: an explicit value in **any**
config file always wins over the profile. This matters for layered
configurations:

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: high_abuse
    rate_limit: 1          # explicit: wins over the profile's rate_limit 5

# config/packages/prod/kiwi_captcha.yaml
kiwi_captcha:
    rate_limit: 100        # a LATER layer's explicit value also wins
```

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: high_abuse

# config/packages/prod/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: compatibility   # the LAST profile wins
```

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: compatibility   # dev compatibility posture

# config/packages/prod/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: null            # explicit null CLEARS the profile
```

The layering semantics:

- The **final profile** is the last config layer containing the
  `protection_profile` key; later layers override earlier ones. An
  explicit `null` is a real selection: it clears the profile, its
  derived defaults are dropped, and the visible `protection_profile`
  field reports null in lockstep — the effective behavior always
  corresponds to the visible field. A prod overlay can therefore
  neutralize a dev compatibility profile with `protection_profile:
  null`.
- The profile fills its derived defaults only where no layer set the
  knob explicitly. The profile defaults are the first array of the
  merge, so a later layer that carries only `protection_profile` can
  never override an explicit setting from an earlier layer. A base
  `rate_limit: 1` stays 1 under a prod `protection_profile: high_abuse`
  overlay, and the profile's other defaults still apply where no layer
  set them.
- Nested values merge key-by-key: an explicit `risk.weights.replay` in
  one layer wins, and the profile still fills the other weights.
- `high_abuse` chained step-up engages when
  `risk.request_binding_authority` is wired in **any** layer; the
  conditional is evaluated on the final merged configuration. Without
  an authority anywhere, chaining stays off. An explicit
  `risk.chaining.enabled` always wins, and an explicit `true` without an
  authority is still refused at compile time.

```yaml
kiwi_captcha:
    protection_profile: balanced   # balanced | privacy_strict | high_abuse | compatibility
```

| Knob | balanced | privacy_strict | high_abuse | compatibility |
|------|----------|----------------|------------|---------------|
| `algorithm` | sha256 | sha256 | sha256 | sha256 |
| `difficulty_bits` / `argon2_difficulty_bits` | 18 / 8 | 18 / 8 | 18 / 8 | 18 / 8 |
| `argon_m_kib` / `argon_t` / `argon_p` | 0 / 3 / 1 | 0 / 3 / 1 | 0 / 3 / 1 | 0 / 3 / 1 |
| `challenge_ttl_secs` | 120 | 120 | 120 | 300 |
| `rate_limit` | 10 | 10 | 5 | 10 |
| `rate_limit_global` | 500 | 500 | 2000 | 500 |
| `resource_capacity.issuance_per_second` | 500 | 500 | 2000 | 500 |
| `privacy_mode` / `telemetry` | strict / off | strict / off | strict / off | strict / off |
| `enforce_telemetry` | false | false | false | false |
| `min_duration_ms` | derived | 0 | derived | derived |
| `binding_mode` | nonce_ip_hmac | none | nonce_ip_hmac | none |
| `risk.enabled` | false | false | true | false |
| `risk.decoy_v3_enabled` | false | false | true | false |
| `risk.client_context` | false | false | false | false |
| `risk.max_outstanding_challenges` | 20 | 20 | 10 | 20 |
| `risk.max_outstanding_challenges_global` | 100000 | 100000 | 250000 | 100000 |
| `risk.hard_limits.process_per_second` | 10000 | 10000 | 5000 | 10000 |
| `risk.weights.bad_proof / malformed / replay / action_failure` | contract | contract | 320 / 340 / 380 / 160 | contract |

Profile rationale:

- balanced is the current default configuration, documented as such.
  Picking it changes nothing: the derived values equal the tree defaults,
  so behavior is byte-identical to no profile.
- privacy_strict is the strongest first-party privacy posture. The
  binding tag is dropped (`binding_mode: none`), so no IP-derived state
  exists anywhere. Every behavioral evidence surface stays off and the
  server-side solve-timing heuristic is disabled (`min_duration_ms: 0`).
  Trade-off: relay protection is off, as documented on `binding_mode`.
- high_abuse is for public signup/login surfaces under attack. Risk
  is enabled, so it requires a Predis client and the extension fails
  fast without one. The abuse-evidence weights rise, so proven abuse
  outvotes trust signals sooner. Per-source limits tighten and the
  aggregate issuance bounds widen in lockstep. The decoy surface arms
  with protocol-v3 emission, which only engages once the central
  `min_protocol_version` floor confirms. Chained-challenge step-up
  engages automatically when `risk.request_binding_authority` is wired
  in any configuration layer (the conditional runs on the final merged
  configuration).
- compatibility maximizes integration compatibility: sha256, a
  conservative 300 s TTL (Turnstile token-lifetime parity), binding off
  (IP churn behind NAT/mobile), risk and the decoy surface off
  (protocol-v2 emission), no behavioral coupling.

The profiles never override an explicitly configured knob: the profile
defaults are merged as the lowest-precedence layer, so they apply only
where the key is absent from your configuration. `protection_profile:
null` (the default) selects no profile, and any value outside the four
names is refused.

## Advanced configuration

The per-knob reference below is the advanced layer. Most deployments set
only a `protection_profile`, `secret_key`, `public_base_url` and
`redis_dsn`, and never touch these knobs. Every option stays available
and documented; a knob set explicitly always wins over the profile.

### Base configuration

```yaml
kiwi_captcha:
    secret_key: '%env(KIWI_SECRET_KEY)%'   # required, min 16 bytes
    algorithm: sha256                       # sha256 | argon2id
    difficulty_bits: 20                     # SHA-256 leading zero bits
    argon_m_kib: 0                          # Argon2id memory (KiB); 0 = sha256 only
    argon_t: 3                              # Argon2id requires t >= 3 and p == 1
    argon_p: 1
    challenge_ttl_secs: 120
    route_prefix: /kiwi-captcha             # challenge endpoint prefix; the form
                                            # widget and standalone widget both
                                            # derive their endpoint from it
    # Production requires a shared storage (Redis). With redis_dsn set,
    # the bundle constructs the Redis-backed services itself — no
    # storage service wiring needed. Without a DSN the bundle fails fast
    # with a LogicException if ArrayStorage is configured outside the
    # test/dev environment (kernel.environment or APP_ENV).
    # storage: kiwicaptcha.storage.redis    # atomic pending→consumed Lua
    #                                       # transition: the consumed
    #                                       # record and its deterministic
    #                                       # result are retained through
    #                                       # TTL, so a later caller
    #                                       # observes the consumed state
    #                                       # instead of re-verifying
```

### Redis (`redis_dsn`)

`redis_dsn` is the first-class, high-level Redis connection setting. Set
one DSN and the bundle builds every Redis-backed service from it:

```yaml
# Twelve-factor form (recommended): the DSN lives in the environment.
kiwi_captcha:
    redis_dsn: '%env(KIWI_REDIS_DSN)%'
```

```yaml
# Literal form: the shape is validated at container build time.
kiwi_captcha:
    redis_dsn: 'redis://user:pass@redis.example.com:6379/0?prefix=kiwi'
```

What the DSN builds:

- The challenge storage (`KiwiCaptcha\Storage\RedisStorage`; atomic, so
  the production storage guard passes), the distributed issuance rate
  limiter, the Argon2id admission semaphore and, when risk is enabled,
  the risk state store. All of them run over one `Predis\Client` built
  from the DSN, so install `predis/predis` first
  (`composer require predis/predis`).
- The DSN shape is `redis://host:port/db?password=...&prefix=...` (or
  `rediss://` for TLS). The DSN is handed to `Predis\Client` verbatim,
  and the same fail-closed shape validation runs on both lanes. A
  literal DSN is validated at container build time. An env-resolved
  DSN is validated by the runtime guard when the client is constructed,
  since the value flows through the container's parameter bag and the
  load-time validation cannot see it. A malformed value
  is refused with a clear error naming the option, and an unreachable
  server is a runtime error on the first command, like any wired
  client.
- Env-managed DSNs follow twelve-factor practice: credentials, private
  hosts, TLS endpoints and database selection belong in the
  environment or a secrets manager, never in source-controlled config
  files. The manifest-declared `.env` default is
  `redis://127.0.0.1:6379/0`, and the bundle contract stays `redis://`
  or `rediss://`.
- An explicit service id wins over the DSN wherever both are set:
  `storage` (your own `StorageInterface` service), `redis_service`
  (your own client for the limiter/semaphore) and
  `risk.redis_service` (your own `Predis\Client` for the risk state).
  The DSN keeps filling the knobs you did not set.
- With `redis_dsn: null` (the default) every existing wiring stays
  byte-identical.

Validation notes:

- `secret_key`: at least 16 bytes; 32 random bytes recommended.
- `difficulty_bits`: SHA-256 difficulty, 1..=20 (the browser solver
  ceiling); the config tree ceiling tracks the core constant.
- `argon_t >= 3` and `argon_p == 1`: the intentional Argon2id protocol
  profile (libsodium's raw Argon2id interface, so Rust and PHP verify
  identical hashes).
- `challenge_ttl_secs`: bounded by the protocol ceiling (the record
  validation requires `expires_at - issued_at <= 300 s`).
- `algorithm`: the issued algorithm always comes from the server; a
  client-supplied `algorithm` field in the challenge POST is accepted only
  for forward-compatibility and never changes the issued algorithm.

### Privacy posture

```yaml
    # ── Privacy posture ──────────────────────────────────────────────────
    # privacy_mode: strict | standard (default strict). In STRICT mode the
    # extension FORCES telemetry 'off', same_origin_only true and
    # min_duration_ms 0 (the server-side solve-timing floor is a timing
    # heuristic and is disabled) — operator values for those keys are
    # overridden. In STANDARD mode the operator's choices pass through.
    # privacy_mode: strict
    # telemetry: off | minimal | full       # widget signal collection;
    #                                       # forced 'off' under strict
    # binding_mode: nonce_ip_hmac | none    # challenge IP binding; stored
    #                                       # tag is nonce-bound, never a
    #                                       # stable IP identifier; 'none'
    #                                       # issues challenges with an
    #                                       # EMPTY binding tag (maximum
    #                                       # privacy; relay protection
    #                                       # off) — fully wired through
    #                                       # to the core BindingMode.
    # same_origin_only: true                # reject cross-origin challenge
    #                                       # POSTs with 403
    #                                       # CROSS_ORIGIN_DENIED; forced
    #                                       # true under strict
    # min_duration_ms: null                 # explicit solve-timing floor in
    #                                       # ms (null = derive from
    #                                       # difficulty); forced 0 under
    #                                       # strict
    # enforce_telemetry: false              # reject bot-scored telemetry at
    #                                       # verification time
    #                                       # (defense-in-depth only)
```

The privacy modes themselves (strict vs standard, and why `binding_mode`
is never forced) are the privacy contract; see
[privacy.md](privacy.md#privacy-modes).

### Production hardening

```yaml
    # ── Production hardening ──────────────────────────────────────────────
    # Per-IP rate limit on challenge issuance (default 10 per window; 0 =
    # disabled). Mass challenge minting is what makes aggregate verification
    # work unbounded, so keep this on in production.
    # rate_limit: 10
    # Deployment-GLOBAL rate limit (default 500 per window; 0 = disabled),
    # enforced on every backend. Redis: exact distributed sliding window
    # shared by all workers. PSR-6 pool: the only no-Redis mode that
    # survives across requests (best-effort: races can briefly exceed the
    # cap). Object memory: long-lived-runtime-only (RoadRunner/Swoole/amphp
    # or a single CLI process) — under conventional PHP-FPM each request
    # rebuilds the limiter, so the object window is per-request and
    # provides no temporal limiting across requests. Global-only mode
    # (rate_limit: 0) works on all backends.
    # rate_limit_global: 500
    # rate_limit_window_secs: 60            # sliding window (default 60)
    # rate_limit_cache: null                # optional PSR-6 pool service id
    #                                       # used as the SHARED multi-process
    #                                       # fallback when no Redis client
    #                                       # exists (e.g. a Redis-backed
    #                                       # Symfony Cache pool). The pool
    #                                       # must be genuinely cross-worker:
    #                                       # a known in-memory adapter
    #                                       # (Symfony Cache ArrayAdapter or
    #                                       # a subclass) is REFUSED in
    #                                       # production, since its items
    #                                       # live per process. The class
    #                                       # check resolves parameter-
    #                                       # indirected ids
    #                                       # ('%kiwi.rate_pool%'), alias
    #                                       # chains, parent-declared pools
    #                                       # and %param% classes; a pool id
    #                                       # still unresolvable to a class
    #                                       # at compile time FAILS CLOSED
    #                                       # in production — reference a
    #                                       # concrete pool service id. The
    #                                       # pool items are namespaced per
    #                                       # deployment (empty namespace
    #                                       # keeps the legacy shapes), so
    #                                       # deployments sharing one pool
    #                                       # keep independent budgets.
    #                                       # Without a
    #                                       # pool, the fallback is a
    #                                       # per-object in-memory window:
    #                                       # temporal cross-request limiting
    #                                       # under conventional PHP-FPM
    #                                       # requires Redis or a genuinely
    #                                       # shared PSR-6 pool.
    # allow_nonredis_rate_limit_fallback: false
    #                                       # explicitly accepts the
    #                                       # non-Redis rate limiter in
    #                                       # production when any
    #                                       # temporal issuance limit is
    #                                       # set but no Redis client
    #                                       # and no rate_limit_cache
    #                                       # pool exist. Redis is the
    #                                       # exact distributed window;
    #                                       # a shared PSR-6 pool is
    #                                       # cross-request best-effort;
    #                                       # object memory is
    #                                       # long-lived-runtime-only and
    #                                       # request-local under
    #                                       # conventional PHP-FPM. The
    #                                       # deprecated
    #                                       # allow_local_global_limit_fallback
    #                                       # option still works as an
    #                                       # alias.
    #                                       # Raw client IPs are never stored:
    #                                       # every key is a peppered HMAC of
    #                                       # the IP (rate_limit_pepper
    #                                       # defaults to secret_key — a
    #                                       # compatibility fallback only).
    #                                       # The normal deployment model is
    #                                       # a dedicated stable pepper:
    #                                       # routine signing-key rotation
    #                                       # must not reset the per-client
    #                                       # rate-limit memory (the HMAC
    #                                       # identities anchor that memory,
    #                                       # and a fresh pepper derives
    #                                       # fresh identities, restarting
    #                                       # every client window empty).
    # rate_limit_pepper: '%env(KIWI_RATE_LIMIT_PEPPER)%'
    #                                       # dedicated stable abuse-identity
    #                                       # key (K_abuse-identity): HMAC
    #                                       # pepper for the per-IP rate-limit
    #                                       # pseudonyms. Stays stable across
    #                                       # routine signing-key rotations.
    # Aggregate Argon2id verification concurrency cap (default 2; 0 =
    # unlimited). Each Argon2id verification allocates argon_m_kib of memory —
    # size this to available memory. With a Redis client the cap is enforced
    # across ALL PHP-FPM workers (see the Argon2 section in operations.md).
    # argon2_max_concurrent_verifications: 2
    # argon2_saturation_pressure_cap: 64 # bounded SATURATION-PRESSURE
    #                                    # counter (NOT a queue: admission
    #                                    # is immediate and non-blocking —
    #                                    # nothing waits or queues behind
    #                                    # a saturated gate). The
    #                                    # deprecated argon2_max_waiters
    #                                    # name still works as an alias.
    # argon2_max_per_tenant: null        # PER-SCOPE CONCENTRATION cap: each
    #                                    # scope gets its own lease set in
    #                                    # addition to the global cap.
    #                                    # Null (default) derives
    #                                    # max(1, global - 1), so with the
    #                                    # default global cap of 2 one scope
    #                                    # can never occupy both slots. It
    #                                    # is a concentration cap, not a
    #                                    # guaranteed share or a
    #                                    # weighted-fair scheduler, and it
    #                                    # must be strictly below the
    #                                    # global cap (refused otherwise).
    #                                    # Anti-monopoly across scopes
    #                                    # requires a global concurrency of
    #                                    # at least 2: with a global cap of
    #                                    # exactly 1 there is only one
    #                                    # shared slot, so no implementation
    #                                    # can reserve capacity for another
    #                                    # scope.
    # argon2_lease_ms: 45000              # tokenized Redis lease lifetime in
    #                                    # ms; must exceed
    #                                    # argon2_max_verification_runtime_ms
    #                                    # by the 5000 ms safety margin
    #                                    # (compiled, see operations.md).
    # argon2_max_verification_runtime_ms: 30000
    #                                    # the deployment SLO for the
    #                                    # wall-clock a single Argon2
    #                                    # verification derivation may take
    #                                    # in this deployment, in ms. The
    #                                    # lease must exceed it by the 5000
    #                                    # ms safety margin (defaults: 45000
    #                                    # > 30000 + 5000 = 35000), enforced
    #                                    # at container compile time; the
    #                                    # declared runtime is a deployment
    #                                    # bound only, never an enforced
    #                                    # wall-clock timeout inside the
    #                                    # blocking hash (a pathological host
    #                                    # can still outlive the lease:
    #                                    # fencing keeps correctness, the
    #                                    # concurrency cap may be exceeded
    #                                    # in that expiry window).
    # argon2_semaphore_namespace: '%kernel.project_dir%'
    #                                       # per-deployment discriminator for
    #                                       # the Redis lease set and the
    #                                       # global rate-limit key; two
    #                                       # deployments sharing one Redis
    #                                       # instance must use different
    #                                       # namespaces
    # redis_service: null                   # optional Redis client service id
    #                                       # (\Redis or Predis\Client) for the
    #                                       # cross-worker Argon2 admission
    #                                       # gate and the atomic rate
    #                                       # limiter; when null, the
    #                                       # storage's own client is reused
    #                                       # if storage is RedisStorage, or
    #                                       # the redis_dsn client is used
    #                                       # when redis_dsn is set
    # strict_kid_verification: false        # OPTIONAL strict current-kid
    #                                       # verification: when true,
    #                                       # strict keyring resolution is
    #                                       # enabled even before the first
    #                                       # rotation: the current kid must
    #                                       # match from the first deployment
    #                                       # (any other kid -> UnknownKid),
    #                                       # and historical keys keep
    #                                       # verifying under rotation grace
    #                                       # when secrets_by_kid is
    #                                       # populated (historical +
    #                                       # current, never the current key
    #                                       # alone). Default false keeps
    #                                       # the legacy any-kid
    #                                       # single-secret semantics (see
    #                                       # security-hardening.md).
    # resume_claim_ttl_secs: 60             # recovery-derivation claim lease
    #                                       # (min 60): must cover the
    #                                       # maximum supported derivation
    #                                       # duration; fencing stays
    #                                       # correct on expiry (an
    #                                       # expired claim is released and
    #                                       # a retry re-claims it)
```

### Risk configuration

The adaptive risk engine is opt-in and off by default. Enabling it adds a
first-party continuity cookie; see [privacy.md](privacy.md#continuity-cookie)
and [risk-engine.md](risk-engine.md):

```yaml
kiwi_captcha:
    # public_base_url: https://captcha.example.com  # the deployment's PUBLIC
    #                                               # origin from SERVER
    #                                               # CONFIG — the same-
    #                                               # origin check compares
    #                                               # against it, never the
    #                                               # Host header (set it in
    #                                               # production)
    risk:
        enabled: true
        # client_ip_mode: symfony_trusted_proxies  # how the canonical client IP is
        #                                           # derived — Symfony's
        #                                           # trusted-proxy machinery
        #                                           # (ignores forwarding
        #                                           # headers from untrusted
        #                                           # peers) or "direct"
        #                                           # (socket peer ONLY —
        #                                           # forwarding headers are
        #                                           # ALWAYS ignored)
        # trusted_proxies:                          # CIDRs of the trusted
        #     - 10.0.0.0/8                          # reverse proxies
        # reject_ambiguous_forwarding: false        # true = 400
        #                                           # AMBIGUOUS_FORWARDING
        #                                           # when a trusted peer
        #                                           # sends BOTH
        #                                           # X-Forwarded-For and
        #                                           # Forwarded; false = log
        # container_memory_mib: null                # readiness requires
        #                                           # concurrency x
        #                                           # the FIXED Argon
        #                                           # verification envelope
        #                                           # (risk.argon_verification_
        #                                           # memory_kib)
        #                                           # + 256 MiB headroom <=
        #                                           # budget; null = invariant
        #                                           # skipped (documented)
        # The risk-v1 state lives in Redis (EVALSHA of the canonical Lua).
        # Required: risk.redis_service (a Predis\Client service id) — or the
        # bundle's redis_service / RedisStorage client when it is a Predis
        # client, or the redis_dsn client (a Predis\Client) when redis_dsn
        # is set. phpredis (\Redis) is NOT supported by the risk engine,
        # and risk.enabled without any Predis client fails at container
        # compile.
        # redis_service: kiwicaptcha.risk.redis
        namespace: '%kernel.project_dir%'   # {kiwi:<namespace>} hash tag
        # master_secret: '%env(KIWI_RISK_SECRET)%'
        #                                   # HKDF master for the risk
        #                                   # identity keys. The normal
        #                                   # deployment model is a
        #                                   # dedicated stable secret
        #                                   # (K_abuse-identity): routine
        #                                   # signing-key rotation must
        #                                   # not reset the adaptive-risk
        #                                   # memory. When null, the keys
        #                                   # derive from secret_key
        #                                   # (compatibility fallback only).
        # source_epoch_secs: 900            # source identity rotation
        # subnet_epoch_secs: 900            # subnet (/24, /56) rotation
        # state_ttl_secs: 1800              # live counter TTL
        # principal_ttl_secs: 86400
        # dedupe_ttl_secs: 60               # identical event_id applied once
        # hysteresis_ms: 60000              # global-level hysteresis window
        # network_classifier_file: null     # optional "cidr,flag" file
        # region: eu-central-1              # OPTIONAL deployment region baked
        #                                   # into every issued challenge and
        #                                   # enforced at verification (a
        #                                   # result token issued in one
        #                                   # region is never redeemable
        #                                   # elsewhere — failover-replay
        #                                   # Option A)
        # redis:                            # challenge-storage hardening
        #     wait_replicas: 1              # WAIT for N replicas after storing
        #                                   # a challenge (async-replication
        #                                   # failover can otherwise lose the
        #                                   # record and replay a consumed
        #                                   # token against a "fresh" record)
        #     wait_timeout_ms: 100          # WAIT timeout for the replicas
        #     ttl_margin_secs: 60           # extra retention on challenge /
        #                                   # replay-security state BEYOND
        #                                   # token validity (must exceed max
        #                                   # clock skew + failover margin;
        #                                   # pair with a noeviction policy
        #                                   # on the security Redis)
        # max_outstanding_challenges: 20    # anti-stockpiling: unsolved
        #                                   # challenges per source
        # max_outstanding_challenges_global: 100000  # deployment-wide cap
        # challenge_origin_allowlist:       # origin-laundering defense: when
        #     - https://app.example.com     # non-empty, challenge POSTs must
        #                                   # carry an allowlisted Origin (or
        #                                   # Referer origin when
        #                                   # enforce_origin is false);
        #                                   # everything else gets 403
        #                                   # origin_rejected. Comparison is
        #                                   # STRUCTURED NORMALIZATION:
        #                                   # scheme/host/effective-port,
        #                                   # host lowercased, default ports
        #                                   # normalized (https 443 / http
        #                                   # 80), trailing dots stripped,
        #                                   # IDN -> punycode (ext-intl),
        #                                   # IPv6 kept bracketed —
        #                                   # "https://example.com" matches
        #                                   # "https://example.com:443",
        #                                   # "https://EXAMPLE.COM." and the
        #                                   # IDN/punycode spellings, never
        #                                   # ":444" / "http://" /
        #                                   # "evil-example.com"
        # enforce_origin: false             # true = Origin REQUIRED: missing
        #                                   # or "null" Origin -> 403
        #                                   # origin_rejected even without an
        #                                   # allowlist. Server-to-server
        #                                   # integrations (no Origin) keep
        #                                   # this false — the explicitly
        #                                   # trusted mode
        # enforce_fetch_metadata: false     # reject Sec-Fetch-Site:
        #                                   # cross-site challenge requests
        #                                   # (browser-laundering signal;
        #                                   # defense-in-depth only)
        # request_binding: null             # OPTIONAL STATIC transaction
        #                                   # binding (1..128 chars of
        #                                   # [A-Za-z0-9._:-]):
        #                                   # signed into every challenge when
        #                                   # the request sends no
        #                                   # request_binding field. For
        #                                   # DYNAMIC per-transaction
        #                                   # bindings the application
        #                                   # supplies one per request (the
        #                                   # widget carries it end-to-end,
        #                                   # see "Transaction binding")
        # health:
        #     enabled: true                 # registers {prefix}/health/live
        #                                   # + /health/ready (rollback-
        #                                   # resistant readiness split)
        #     argon_verification_memory_kib: 16384  # the FIXED memory
        #                                   # envelope of ALL adaptive Argon
        #                                   # challenges (1024..65536) — the
        #                                   # server verification cost is
        #                                   # bounded by this ONE value;
        #                                   # risk escalates the TARGET
        #                                   # DIFFICULTY, never the memory
        #     argon_escalation_target_bits: [1, 4, 8] # EXACTLY 3
        #                                   # entries (Argon16/32/64), each
        #                                   # 1..20 — the expected nonce
        #                                   # search space escalation
        #     security_epoch_cache_secs: 1  # cache of the central
        #                                   # security-policy read (1..30) —
        #                                   # revocation latency is one window
        #     security_epoch_max_stale_secs: 60 # max-stale FAIL-
        #                                   # CLOSED window (min 10) — past
        #                                   # last_success + window the
        #                                   # validator returns
        #                                   # temporary_unavailable and the
        #                                   # controller refuses issuance 503
        #     decoy_v3_enabled: false        # PROTOCOL-V3 WRITER SWITCH
        #                                   # (default false): when false,
        #                                   # issuance NEVER arms the
        #                                   # authenticated decoy and always
        #                                   # emits protocol v2 (byte-
        #                                   # compatible with parent-revision
        #                                   # verifiers). When true, issuance
        #                                   # MAY arm the decoy (v3), but
        #                                   # ONLY when the central security-
        #                                   # policy floor ({kiwi:<ns>}:
        #                                   # security-policy
        #                                   # min_protocol_version) is
        #                                   # confirmed >= 3; a lower or
        #                                   # unreadable floor falls back to
        #                                   # v2 with a once-per-process
        #                                   # warning. See operations.md
        #                                   # "Protocol v3 two-phase rollout".
        #     result_receipt_signing_key: null  # OPTIONAL base64
        #                                   # 32-byte Ed25519 seed; when set,
        #                                   # valid verifications export
        #                                   # signed receipts (the HMAC
        #                                   # result verification stays
        #                                   # CENTRAL-ONLY)
        #     max_challenges_per_scope_per_minute: 0 # per-scope
        #                                   # fixed-window issuance cap
        #                                   # (0 = unlimited); > 0 requires
        #                                   # Redis; the window key carries
        #                                   # hex(hmac_sha256(scope, K_scope))
        #                                   # — the raw scope is never a
        #                                   # Redis key component
        #     policy_version: 1             # CHALLENGE security-policy epoch,
        #                                   # signed into every issued record
        #                                   # and enforced at verification —
        #                                   # BUMP it to immediately
        #                                   # invalidate ALL outstanding
        #                                   # challenges (origin/action-policy
        #                                   # changes, emergency revocation,
        #                                   # compromised tenant); cosmetic
        #                                   # changes must NOT bump it.
        #                                   # Independent of the risk-v1
        #                                   # contract version.
        #     weights: { ... }              # 13 risk-v1 weights (defaults = contract)
        #     global_floors:                # minimum action per global level
        #         1: sha16
        #         2: sha18
        #         3: sha20
        #         4: sha20
        #     scopes:
        #         login:                     # the app scope string
        #             # id: 1                # int scope in Redis state; MUST
        #             #                       # stay stable once deployed
        #             #                       # (defaults to crc32(scope name))
        #             base_risk: 100
        #             minimum: allow         # floor: never weaker than this
        #             degraded: allow        # action while the backend is down
        #             # post_solve_check: true   # valid solves re-assessed after
        #             #                       # the proof (deny -> 422
        #             #                       # kiwi.post_solve_rejected,
        #             #                       # step_up -> 422
        #             #                       # kiwi.post_solve_step_up_required)
        #         signup:
        #             base_risk: 200
        #     unknown_scope:                 # scopes NOT configured above
        #         mode: baseline             # baseline (default): engine
        #                                   # declines, default challenge is
        #                                   # issued; reject: TRUE rejection
        #                                   # (HTTP 429 RISK_DENIED, no
        #                                   # challenge); minimum: synthetic
        #                                   # policy (base_risk 100, min/
        #                                   # degraded sha20)
        #     calibration:
        #         enabled: false             # Redis score-bucket bias
        #         min_samples: 1000          # passed to the AggregateCalibrator
        #         max_adjustment: 150        #   (bias clamp bound)
        #         max_change_per_minute: 10  #   (adjustment rate bound)
        #         outcome_receipt_ttl_secs: 86400 # outcome/calibration receipt
        #                                   # + outcome-ledger lifetime (24 h
        #                                   # default; 3600..604800) — long
        #                                   # enough for fraud review /
        #                                   # moderation / chargeback labels
        #         mode: random_sample        # label selection: complete |
        #                                   # random_sample (Kiwi samples at
        #                                   # assessment time; unsampled
        #                                   # confirmations are consumed but
        #                                   # not recorded — status 2 — so
        #                                   # the label can never select
        #                                   # itself into the population) |
        #                                   # weighted (the app supplies the
        #                                   # inverse sampling probability
        #                                   # per confirmation)
        #         sampling_probability_ppm: 100000  # PPM chance a decision is
        #                                   # sampled (random_sample mode)
        #         minimum_resolution_ratio: 0.8 # random_sample resolution gate:
        #                                   # bias adjustment is suspended
        #                                   # while sampled total >=
        #                                   # min_samples but resolved/total
        #                                   # < this ratio (0 disables)
        #         false_positive_cost: 1.0  # class-normalized calibration:
        #         false_negative_cost: 2.0  #   price of a false positive vs
        #                                   #   a false negative (default:
        #                                   #   abuse slipping through costs
        #                                   #   twice a false rejection)
        #     nonce_to_decision_ttl_secs: 300   # short-lived challenge-nonce ->
        #                                   # decision-id handle TTL
        #                                   # (60..3600; independent of the
        #                                   # outcome lifetime)
        #     continuity_cookie:
        #         name: kiwi_risk_session
        #         ttl_secs: 15552000         # 180 days; 0 = session cookie
        #         # secure: null             # null = follow the request scheme
        #         # samesite: lax
        #         # http_only: true
```

### Scope identity

Scope ids are part of the Redis state identity. The `id` (or the
crc32-derived default) must stay stable once deployed. Renaming a scope or
reordering ids silently fragments its risk history. Two scopes sharing an id
collide and are refused at compile time.

`risk.allowed_scopes` (when configured) restricts issuance to the listed
scope names; a scope outside the server allowlist is refused before any
quota runs.

`risk.unknown_scope.mode` decides what happens to scopes not configured in
`risk.scopes`:

- `baseline` (default): the engine declines, and the default challenge is
  issued (no risk assessment for that scope).
- `reject`: true rejection, HTTP 429 `RISK_DENIED`, no challenge.
- `minimum`: a synthetic policy (base_risk 100, min/degraded sha20) applies.

### Transaction binding

A challenge can be bound to one application transaction. The issuing side
signs a `request_binding` (1..128 chars of `[A-Za-z0-9._:-]`)
into the record, and verification only accepts the solve when the final
POST presents the same binding. A challenge minted for one transaction is
never redeemable for another. The widget carries the binding end-to-end.
The binding is always server-originated in the bundle: the widget driver
never generates a binding of its own. The rendered widget container carries
exactly the value the backend rendered, nothing else.

Two binding modes:

1) **Client-chosen binding (public, basic anti-abuse).** The application
   lets the client choose the binding, e.g. a per-page random nonce the
   page JavaScript generates and passes to the widget. This is fine for
   basic anti-abuse (it proves the browser chose a nonce and carries it
   back), but the binding is client-controlled: it proves nothing about a
   trusted backend decision. Suitable when the binding is a transaction
   correlation tag, not an authorization signal.
2) **Backend-originated binding (the recommended sensitive-flow mode).**
   The application backend renders the binding server-side from a
   `flow_id` stored server-side. The Symfony form type's `request_binding`
   option, the static `risk.request_binding` config, or a per-render
   `request_binding` passed to the standalone widget carries a value the
   backend itself issued, a flow/session identifier the backend created
   and persists. The widget renders that value and only ever forwards it;
   the verification side enforces it against the signed record. A binding
   minted by the backend (and stored server-side) can be checked against
   the backend's own flow state after verification. A client can never
   invent a binding the backend did not issue.

- **Config** — `risk.request_binding` sets a static binding used whenever
  the request sends no `request_binding` field (e.g. server-side
  integrations). For dynamic per-transaction bindings (recommended: a
  backend-issued `flow_id` nonce per page load) the application supplies
  the value per request/form:
  - `KiwiCaptchaType` option `'request_binding' => $flowId` (defaults to the
    static config) → rendered as `data-kiwi-request-binding` on the widget
    container;
  - the standalone widget accepts `'request_binding'` in the
    `kiwi_captcha_widget({...})` context.

- **Widget flow** — the driver reads `data-kiwi-request-binding` and
  includes `request_binding` in the challenge POST body. The controller
  validates 1..128 chars of `[A-Za-z0-9._:-]` (422
  `INVALID_REQUEST_BINDING` otherwise), passes the value to the core
  Issuer, which signs it into the record, and on a successful solve
  creates the hidden `kiwi_request_binding` input in the form, next to the
  token input. The driver contains no binding-generation code (no
  `crypto.randomUUID`-style synthesis, pinned by test): the rendered
  container carries only the server-provided binding.

- **Verification** — after a valid verification, the validator compares the
  consumed record's signed binding against the request binding. The
  application controller copies the POSTed field into the request attribute
  before validating:

  ```php
  $request->attributes->set(
      KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE,
      (string) $request->request->get('kiwi_request_binding'),
  );
  $form->handleRequest($request);
  ```

  (The validator also falls back to the raw POSTed `kiwi_request_binding`
  field, so the plain widget flow works without the shim.) A bound record
  with a missing or mismatched binding fails with the same
  `invalid_or_expired` violation. No jti is exposed, the solve is burned
  (single-use), and the client re-solves. An unbound record skips the check
  entirely. The verified binding is exposed via
  `KiwiCaptchaValidator::verifiedRequestBinding()`
  (`VerifyOutcome::requestBinding()`).

### Identifier validation rules

Scope/tenant identifiers and request bindings are restricted to the
`[A-Za-z0-9._:-]+` alphabet with a 128-char ceiling. The static
`risk.request_binding` is validated against the same charset at compile
time. The verification side requires exact equality between the signed
record values and the values the final POST carries, so a challenge minted
under a valid identifier can never be redeemed under a different one. See
[Identifier validation](security-hardening.md#identifier-validation) for
the endpoint-level enforcement.

### Signing-key rotation and abuse-identity secrets

The deployment keeps two secret families with different lifetimes:

- **K_signing** (the signing key): `secret_key` plus the historical
  `secrets_by_kid` map and `revoked_kids`. Routine rotation moves the
  superseded key into the historical map, sets the new `secret_key`, and
  bumps `kid`. Rotating K_signing must be a routine, low-risk operation.
- **K_abuse-identity** (the rate/risk root keys): `rate_limit_pepper` and
  `risk.master_secret`. These derive the pseudonymous identities that
  anchor the per-client rate-limit memory and the adaptive-risk memory.

The normal deployment model is dedicated, stable root keys:

```yaml
kiwi_captcha:
    secret_key: '%env(KIWI_SECRET_KEY)%'            # K_signing, rotates
    rate_limit_pepper: '%env(KIWI_RATE_LIMIT_PEPPER)%'  # K_abuse-identity, stable
    risk:
        enabled: true
        master_secret: '%env(KIWI_RISK_SECRET)%'    # K_abuse-identity, stable
```

K_signing rotates on a schedule; K_abuse-identity stays stable for the
life of the deployment. A routine signing-key rotation therefore changes
nothing about the rate-limit windows or the risk state. An emergency root
compromise may intentionally rotate everything, resetting both families.

The derivation defaults (`rate_limit_pepper` and `risk.master_secret`
falling back to `secret_key`) are documented as a compatibility fallback
only: with those defaults in place, a routine signing-key rotation
silently resets every per-client rate-limit identity and every risk
pseudonym. The extension logs an advisory note at container build time
when rotation is configured (`kid` above 1 or a non-empty
`secrets_by_kid`) without dedicated root keys; the note never throws.

### Related documentation

- [privacy.md](privacy.md): what the privacy keys mean (modes, telemetry,
  binding).
- [risk-engine.md](risk-engine.md): how the risk options behave.
- [operations.md](operations.md): deployment options (rate limiting,
  admission gates, health endpoints, client-IP policy).
- [siteverify.md](siteverify.md): `risk.siteverify_secrets` and the
  siteverify endpoint.
- [migration.md](migration.md): `risk.sitekey_allowlist` and the migration
  surface.
