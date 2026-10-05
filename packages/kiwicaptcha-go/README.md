# kiwicaptcha (Go server SDK)

Go server-side verification for the KiwiCaptcha proof-of-work captcha.
Verifies client-submitted solution tokens byte-for-byte compatible with
the php, Rust and JavaScript cores. Verification is pure-local: the
signature check, the message authentication codes and your store
adapter are the only inputs, and no call ever reaches a network
service.

The core speaks the exact wire contract of the php core: the v4 signed
canonical with the tagged decoy, execution and rsw identity segments,
the strict serde record parser, the solution token grammar, the
server-state message authentication codes, and the full cheap-gate
order of the php Verifier, including the policy-epoch rollout-floor
window.

## Install

The module is `kiwicaptcha/kiwicaptcha-go`. The only dependency is
`golang.org/x/crypto`, used for the proof-phase argon2id recompute; it
is the quasi-standard extension library the Go project itself
maintains. The core paths (canonical, tokens, records, memory store,
Redis store and client, outcomes, middleware) are standard library
only, and the `x/crypto` import loads only on the argon2id derivation
path.

```
go get kiwicaptcha/kiwicaptcha-go
```

## Quickstart

Four settings carry a deployment: the `Secret`, the `Store` url, the
`Scopes` and the `Profile`.

```go
settings := kiwi.Settings{
    Secret: "your-32-byte-or-longer-signing-secret",
    Store:  "memory://",            // or redis://host:port
    Scopes: []string{"login", "comment"},
    Profile: "standard",            // standard | argon16 | argon32 | argon64
}
verifier, err := settings.BuildVerifier()

decision := kiwi.DecisionFromOutcome(verifier.Verify(rawToken, kiwi.VerifyOptions{
    SecretKey:     settings.Secret,
    ExpectedScope: "login",
    ClientIP:      clientIP,
}), kiwi.PriceRung("sha256", 8, 0))
if decision.OK {
    proceed()                       // decision.Disposition == "allow"
}
```

`Verify` resolves to a `VerifyDecision` with `OK`, `Disposition`
(`allow`, `deny` or `retry`), `DecisionHandle` and `Price`. A `deny`
answers the failure code (`expired`, `bad_signature`, `wrong_scope`,
`already_consumed`, and so on). A `retry` disposition covers storage
outages and admission exhaustion, where the challenge stays intact and
the same token may be resubmitted once the backend recovers.

## Store adapters

One interface, two shipped backends behind `OpenStore`:

- `memory://` is the in-process store: single process, non-persistent,
  bounded retention, one-shot consume under concurrency.
- `redis://host:port` is the shared backend. The client speaks the
  Redis wire protocol on the standard library's net package only, and
  the consume, cleanup, cancel and commit transitions run the exact
  Lua scripts of the php adapter, so both SDKs can share one Redis and
  one key space. Any client with the narrow command surface
  (`Get`, `SetWithTTL`, `Pttl`, `Del`, `Eval`, `EvalSha`,
  `ScriptLoad`) matches the `RedisClient` interface, so an existing
  deployment driver can be bound instead.

Consume is one-shot everywhere: the record is marked consumed and kept
until its retention ends, so replay protection is the consumed marker,
never absence. A consumed record replays its committed deterministic
result; a stored success replays only to the exact operation identity
recorded with the consume.

The SQLite store ships over modernc.org/sqlite, the pure-Go driver:
`sqlite://path.db` builds the file-backed single-node adapter whose
schema and state machine are the ones the php SqliteStorage writes
(one table keyed by nonce, WAL journaling, every durable transition
inside one begin-immediate transaction, exactly-once consume). The
driver is a dependency of this module only for that adapter; a
deployment that never opens a sqlite:// url exercises none of it.

## Framework middleware

```go
// net/http, the framework-neutral core
guard := kiwi.Middleware(verifier, kiwi.MiddlewareOptions{
    SecretKey:     settings.Secret,
    ExpectedScope: "login",
    ScopePredicate: func(path string) bool {
        return strings.HasPrefix(path, "api/protected")
    },
})
mux.Handle("/api/submit", guard(nextHandler))
```

Framework adapters live in the integration modules, one module per
framework so the core never pulls a framework dependency:

```go
// gin
import kin "kiwicaptcha/kiwicaptcha-go/integrations/gin"
router.Post("/api/submit", finalHandler, kin.Middleware(verifier, secret, kin.WithExpectedScope("login")))

// echo
import kie "kiwicaptcha/kiwicaptcha-go/integrations/echo"
router.Post("/api/submit", handler, kie.Middleware(verifier, secret, kie.WithExpectedScope("login")))

// chi
import kic "kiwicaptcha/kiwicaptcha-go/integrations/chi"
router.Use(kic.Middleware(verifier, kiwi.MiddlewareOptions{SecretKey: secret, ExpectedScope: "login"}))

// fiber
import kif "kiwicaptcha/kiwicaptcha-go/integrations/fiber"
app.Post("/api/submit", handler, kif.Middleware(verifier, secret, kif.WithExpectedScope("login")))
```

Every shell reads the token from the `x-kiwi-token` header, then the
`kiwi_token` form field, then the query string. Unauthenticated
requests get `403 Forbidden` with the machine-readable code; a retry
disposition gets `503 Service Unavailable`. The verified decision
rides the framework context (`http.Request` context, gin context,
echo context, fiber locals) under the package's decision key.

## Outcomes

The outcomes client reports the eight typed results of a protected
action onto the risk channels, the always-on ledger and the long-memory
marks. The mapping table is versioned and pinned by cross-language
vectors; exactly the three server-confirmed trust outcomes may subtract
risk, and exactly the four abuse outcomes write marks.

```go
sink := kiwi.NewMemoryOutcomeSink("my-deployment")
outcomes := kiwi.NewOutcomesClient(sink)
handle, _ := kiwi.NewOutcomeHandle(kiwi.DimensionPrincipal, pseudonym)
outcomes.Report(kiwi.OutcomeFraudConfirmed, handle, "evt-1", 0)
```

Bind the `OutcomeSink` interface to your own deployment store to
persist ledger entries and marks beyond the process.

## The doctor command

```
go run ./cmd/kiwicaptcha-doctor --secret "32 bytes or more" \
    --store memory:// --scopes login,comment --profile standard
```

Checks the settings shape, opens the store and runs a full one-shot
roundtrip (store, find, consume, commit, delete), validates the
scopes, and measures the proof budget of the configured profile.
Exit code 0 means every check passed.

## The verifier sidecar relationship

`kiwicaptcha-go` embeds the verifier library for in-process use: the
verify call runs inside your Go binary, with no extra process to
manage. The language-neutral verifier sidecar
(`packages/kiwicaptcha-verifier`, the Rust single static binary)
remains the one binary for every stack without a native SDK; it
exposes the same siteverify surface over a localhost socket. The two
share one wire contract, so a deployment can start on the sidecar and
move to the embedded Go verifier without re-issuing anything.

## Proof-phase algorithms

- sha256 records re-derive `sha256(prefix || counter || salt)` and
  compare the leading zero bits.
- argon2id records derive through `golang.org/x/crypto/argon2` with
  the signed parameters, a 32-byte tag, and the protocol profile
  split (parallelism 1, at least 3 passes) enforced fail closed.
- rsw records resolve the trapdoor (the active pair or the rotation
  keyring) and verify the client's final value with one modular
  exponentiation over `math/big`; the sequential-squaring client cost
  stays with the solver.

An execution-armed record (the signed `e=` commitment) refuses
deterministically with `execution_mismatch`: the browser-trace walker
is a browser-behavior oracle this SDK does not carry, and an armed
record must never pass without it. The record parser still shape
validates the stored program and checks its signed sha256 commitment.

## Scope and compatibility

The wire surface is pinned by the shared protocol corpus, replayed in
`TestProtocolCorpusConformance`: canonical record assembly and hmac
signatures (v1 legacy and v2 through v5), the solution token boundary
fixture, the rsw identity fixture, the outcomes mapping vectors, and
the php-issued golden records in `testdata/golden` (provenance in each
file), which cover the php-issued end to end: solve to ok, tampered to
bad_signature, expired, wrong scope, and the rollout-window record to
ok or rejected per the declared floor.

Not exported, deliberately: the php core's consumed-operation resume
path (`resumeConsumedOperation`), the replication barrier fence, and
the resume-derivation claim fencing, which are php deployment
recovery surfaces outside the shared server SDK contract; the
browser-trace walker described above; and a SQLite store, as
discussed. The `Store` interface is the extension point for anything
else.
