# kiwicaptcha (Python server SDK)

Python server-side verification for the KiwiCaptcha proof-of-work
captcha. Verifies client-submitted solution tokens byte-for-byte
compatible with the PHP, Rust and JavaScript cores. Verification is
pure-local: the signature check, the message authentication codes and
your store adapter are the only inputs, and no call ever reaches a
network service.

The core is pure standard library. SHA-256 and the optional RSW
time-lock algorithm are implemented in-tree, and Argon2id (RFC 9106)
verifies through the `argon2-cffi` native binding, which ships as a
core dependency and derives the 16-64 MiB rungs in milliseconds. The
in-tree pure implementation is retained only as the RFC-vector oracle
and is never reachable for argon2id verification. Admission stays
explicit: on a runtime where the binding is unusable (a `--no-deps`
install, a stripped deployment), argon2id derivation refuses with an
actionable error, the default admission gate requires the native
binding or an explicit sidecar URL, and an issuer profile that can
reach an Argon rung refuses to boot without one of them. The Redis
store adapter is the other optional extra: it speaks RESP through a
narrow client surface and runs the exact Lua transition scripts of the
PHP adapter.

## Install

```
pip install kiwicaptcha           # every algorithm, the binding included
pip install "kiwicaptcha[redis]"  # add the Redis client for redis:// stores
```

`[argon2]` remains as an empty alias extra, so the historical
`pip install "kiwicaptcha[argon2]"` spelling keeps working. A runtime
without an importable binding (a broken or `--no-deps` install)
verifies SHA-256 and RSW records on the standard library alone and
answers argon2id records with `unsupported_argon2_params`; a local
kiwicaptcha-verifier sidecar passed as `argon_sidecar_url` delegates
those records instead (see the delegation section below).

## Quickstart

Four settings carry a deployment: the `secret`, the `store`, the
`scopes` and the `profile`.

```python
from kiwicaptcha import Settings, Verifier

settings = Settings(
    secret="your-32-byte-or-longer-signing-secret",
    store="memory://",          # or sqlite:///var/lib/kiwi/challenges.db
    scopes=("login", "comment"),
    profile="standard",         # standard | argon16 | argon32 | argon64
)
verifier = settings.build_verifier()

decision = verifier.verify(raw_token, kiwicaptcha.VerifyOptions(
    secret_key=settings.secret,
    expected_scope="login",
    client_ip=client_ip,
))
if decision.ok:
    proceed()
```

`verify` resolves to a `VerifyDecision` with `ok`, `disposition`
(`allow`, `deny` or `retry`), `decision_handle` and `price`. A `deny`
answers the failure code (`expired`, `bad_signature`, `wrong_scope`,
`required_scope`, `already_consumed`, and so on). A `retry` disposition
covers storage outages and admission exhaustion, where the challenge
stays intact.

The scope option is REQUIRED (`expected_scope` is a positional
argument of `VerifyOptions`): an empty option answers the typed
`required_scope` refusal instead of silently accepting a token minted
for any scope, and every framework middleware takes the scope at
construction.

## Execution-armed records: the execution policy

An execution-armed record demands the browser-trace walker, an oracle
this SDK does not carry: the default policy fails every armed record
closed (`execution_mismatch`, documented). A deployment that issues
armed challenges verifies them either through the bundle or through
the sidecar: pass `execution_policy=ExecutionPolicy(sidecar_url=...)`
on the verify options and the armed record's single verification
delegates to a co-located `kiwicaptcha-verifier` over HTTP, whose
verdict merges into this SDK's outcome.

Single-use semantics are preserved: the sidecar consumes the record
(point the sidecar at the same store), and this SDK never
double-consumes. Trust boundary: the sidecar decides acceptances, so
it must be co-located and trusted like the verifier itself. An
unreachable sidecar answers `storage_unavailable` (the retry
disposition) with the record intact; a refused bearer denies.

## Store adapters

One interface, three backends behind `open_store`:

- `memory://` is the in-process store, single process, non-persistent.
- `sqlite:///path/to/db` is the file-backed store with `BEGIN IMMEDIATE`
  transitions, byte-compatible with the PHP adapter's schema.
- `redis://host:port` is the shared backend; the consume, cleanup,
  cancel and commit transitions run the PHP adapter's Lua scripts
  verbatim, so both SDKs can share one Redis. Any client object with
  `get`, `set`, `pttl`, `delete` and script execution works, the
  official `redis` client matches directly.

Consume is one-shot everywhere: the record is marked consumed and kept
until its retention ends, so replay protection is the consumed marker,
never absence. A consumed record replays its committed deterministic
result; a stored success replays only to the exact operation identity
recorded with the consume.

## Framework middleware

```python
from kiwicaptcha import WsgiKiwiCaptcha, DjangoMiddleware, FlaskKiwiCaptcha, FastApiKiwiDependency

# Any wsgi stack
app = WsgiKiwiCaptcha(app, verifier, settings.secret, "login",
                      scope_predicate=lambda path: path.startswith("api/submit"))

# Django: add to MIDDLEWARE via from_settings
middleware = DjangoMiddleware.from_settings(
    get_response, verifier, settings.secret, "login",
    protected_scopes=("api/submit",),
)

# Flask: install the extension, mark views
captcha = FlaskKiwiCaptcha(app, verifier, settings.secret, "login")

@app.route("/api/submit", methods=["POST"])
@captcha.protected()
def submit():
    ...

# FastAPI: one dependency per route
guard = FastApiKiwiDependency(verifier, settings.secret)

@app.post("/api/submit")
def submit(decision: VerifyDecision = Depends(guard)):
    ...
```

Every shell collects the token from the `x-kiwi-token` header, the
`kiwi_token` form field and the query string under the shared
authority rule: one distinct value verifies, while distinct values in
more than one source refuse with `token_source_conflict`.
Unauthenticated requests get `403 Forbidden` with the
machine-readable code; a retry disposition gets `503 Service
Unavailable`.

## Outcomes

The outcomes client reports the eight typed results of a protected
action onto the risk channels, the always-on ledger and the long-memory
marks. The mapping table is versioned and pinned by cross-language
vectors.

```python
from kiwicaptcha import OutcomesClient, MemoryOutcomeSink, Outcome, OutcomeHandle

sink = MemoryOutcomeSink(namespace="my-deployment")
outcomes = OutcomesClient(sink)
outcomes.report(Outcome.FRAUD_CONFIRMED, OutcomeHandle.principal(pseudonym))
```

## The doctor command

```
python -m kiwicaptcha.doctor --secret "..." --store sqlite:///kiwi.db \
    --scopes login,comment --profile standard
```

Checks the settings shape, opens the store and runs a full one-shot
roundtrip, validates the scopes, and measures the proof budget of the
configured profile. Exit code 0 means every check passed.

## Scope and compatibility

The wire surface is pinned by the shared protocol corpus: canonical
record assembly and HMAC signatures (v1 legacy and v2 through v5),
solution token encode/decode, the server-state MACs, the IP binding
derivations and the error code set. The verifier enforces the exact
cheap-gate order of the PHP core, including the policy-epoch
rollout-floor window.

Two capability notes. An execution-armed record (the signed `e=`
commitment) refuses deterministically with `execution_mismatch`: the
browser-trace walker is a browser-behavior oracle this SDK does not
carry, and an armed record must never pass without it. The
`ExecutionPolicy(sidecar_url=...)` option delegates exactly that
dimension to a co-located kiwicaptcha-verifier sidecar, which runs the
full Rust core and consumes the record.

Argon2id runs on the `argon2-cffi` binding (the `[argon2]` extra): the
in-tree pure implementation would cost seconds per 16-64 MiB rung, an
amplification an armed record turns into a denial of service, so it is
deliberately unreachable for verification. Without the binding,
derivation raises an actionable error, and the default admission gate
refuses at construction. A deployment that cannot install the binding
builds its verifier with `argon_sidecar_url` pointing at a co-located
kiwicaptcha-verifier sidecar; argon2id records then delegate to the
sidecar's full-core pass over the same plane as the execution policy,
with the sidecar consuming the record and the issuer guard refusing
any argon rung the runtime cannot verify.
