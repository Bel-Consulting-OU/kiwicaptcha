# kiwicaptcha (Java server SDK)

JVM server-side verification for the KiwiCaptcha proof-of-work captcha.
Verifies client-submitted solution tokens byte-for-byte compatible with
the php, Rust, Go and Python cores. Verification is pure-local: the
signature check, the message authentication codes and your store
adapter are the only inputs, and no call ever reaches a network service.

The core speaks the exact wire contract of the php core: the v4 signed
canonical with the tagged decoy, execution and rsw identity segments,
the strict serde record parser, the solution token grammar, the
server-state message authentication codes, and the full cheap-gate
order of the php Verifier, including the policy-epoch rollout-floor
window.

## Modules

- `kiwicaptcha-core` has zero required dependencies. The signing
  surface is the JDK's `javax.crypto.Mac` HmacSHA256 compared through
  `MessageDigest.isEqual`, and the proof-phase Argon2id recompute is a
  pure implementation over an in-tree BLAKE2b, so a sha256 deployment
  loads nothing beyond the JDK.
- `kiwicaptcha-servlet` adds the Jakarta Servlet auto-verify filter.
  `jakarta.servlet-api` is a provided dependency.
- `kiwicaptcha-spring-boot-starter` adds Spring Boot auto-configuration
  and a Spring MVC interceptor. Spring is a provided dependency of that
  module only; the core stays dependency-free.

## Install

Maven coordinates `com.kiwicaptcha:kiwicaptcha-core` (Java 17+), plus
`kiwicaptcha-servlet` or `kiwicaptcha-spring-boot-starter` when you
want the framework shell.

## Quickstart

Four settings carry a deployment: the secret, the store url, the
scopes and the profile.

```java
Settings settings = new Settings();
settings.secret = "your-32-byte-or-longer-signing-secret";
settings.store = "memory://";            // or redis://host:port
settings.scopes = List.of("login", "comment");
settings.profile = "standard";           // standard | argon16 | argon32 | argon64
Verifier verifier = settings.buildVerifier();

VerifyOutcome outcome = verifier.verify(rawToken, options);
Decision decision = Decision.fromOutcome(outcome,
        Decision.priceRung("sha256", 8, 0));
if (decision.ok) {
    proceed();                           // disposition "allow"
}
```

`Decision` is the contract-level answer: `ok`, `disposition`
(`allow`, `deny` or `retry`), `decisionHandle` and `price`. A `deny`
carries the failure code (`expired`, `bad_signature`, `wrong_scope`,
`required_scope`, `already_consumed`, and so on). A `retry`
disposition covers storage outages and admission exhaustion, where the
challenge stays intact and the same token may be resubmitted once the
backend recovers.

The scope option is REQUIRED (`Options.expectedScope`): an empty
option answers the typed `required_scope` refusal instead of silently
accepting a token minted for any scope, and the servlet filter takes
the scope as a required constructor parameter.

## Execution-armed records: the ExecutionPolicy

An execution-armed record demands the browser-trace walker, an oracle
this SDK does not carry: the default policy fails every armed record
closed (`execution_mismatch`, documented). A deployment that issues
armed challenges verifies them either through the bundle or through
the sidecar: set `Options.executionPolicy` to
`new ExecutionPolicy("http://127.0.0.1:7371", bearer, timeoutMs)` and
the armed record's single verification delegates to a co-located
kiwicaptcha-verifier over HTTP, whose verdict maps back into this
SDK's vocabulary.

Single-use semantics are preserved: the sidecar consumes the record
(point the sidecar at the same store), and this SDK never
double-consumes. Trust boundary: the sidecar decides acceptances, so
it must be co-located and trusted like the verifier itself. An
unreachable sidecar answers `storage_unavailable` (the retry
disposition) with the record intact; a refused bearer denies.

## Store adapters

One interface, two shipped backends behind `Settings.openStore`:

- `memory://` is the in-process store: single process, non-persistent,
  bounded retention, one-shot consume under concurrency.
- `redis://host:port` is the shared backend. The client speaks the
  Redis wire protocol over a plain JDK socket, and the consume,
  cleanup, cancel and commit transitions run the exact Lua scripts of
  the php adapter, so every SDK shares one Redis and one key space
  byte for byte. Any driver with the narrow command surface
  (`get`, `setWithTtl`, `pttl`, `del`, `eval`, `evalSha`,
  `scriptLoad`) matches the `RedisClient` interface, so an existing
  deployment client can be bound instead.

Consume is one-shot everywhere: the record is marked consumed and kept
until its retention ends, so replay protection is the consumed marker,
never absence. A consumed record replays its committed deterministic
result; a stored success replays only to the exact operation identity
recorded with the consume.

The SQLite store ships as the optional `kiwicaptcha-stores-sqlite`
maven module over sqlite-jdbc, so the core artifact stays
dependency-free: depend on that module and `sqlite://path.db` resolves
to the file-backed single-node adapter whose schema and state machine
are the ones the php SqliteStorage writes (one table keyed by nonce,
WAL journaling, every durable transition inside one begin-immediate
transaction, exactly-once consume). The core's `openStore` refuses a
`sqlite://` url with that pointer while the module is absent.

## Jakarta Servlet filter

```java
KiwiCaptchaFilter filter = new KiwiCaptchaFilter(verifier, secret, "login",
        path -> path.startsWith("api/protected"),  // route predicate
        List.of("10.0.0.0/8"),                     // trusted proxy CIDRs
        null);                                     // custom denial renderer
```

The trusted-proxy list decides the client IP binding: an empty list
(the default) trusts nobody, so `x-forwarded-for` and `x-real-ip` are
ignored and the socket peer is the client IP. A peer inside the list
unlocks the right-to-left forwarded walk (trusted hops skipped, the
first untrusted entry wins, an unparsable hop falls back to the peer),
and `x-real-ip` is honored only when the peer is trusted and no
forwarded chain exists.

Every protected request reads the token from the `x-kiwi-token`
header, then the `kiwi_token` form field, then the query string.
Unverified requests get `403 Forbidden` with the machine-readable
code; a retry disposition gets `503 Service Unavailable`. The verified
decision rides the `KiwiCaptchaFilter.DECISION_ATTRIBUTE` request
attribute for the wrapped handler.

## Spring Boot starter

Add the starter module and set the properties; the auto-configuration
registers the filter on your patterns.

```properties
kiwicaptcha.secret=your-32-byte-or-longer-signing-secret
kiwicaptcha.store=memory://
kiwicaptcha.url-patterns=/api/protected/*
kiwicaptcha.expected-scope=login
```

For handler-mapping verification instead of the filter, register the
`KiwiTokenInterceptor` bean; controllers read the decision under
`KiwiCaptchaFilter.DECISION_ATTRIBUTE`.

## Micronaut and Ktor

Micronaut and Ktor reuse the plain core through their filter or
interceptor shapes; neither ships as a compiled module here, and the
core API is the whole surface they need:

- Micronaut: implement `io.micronaut.http.HttpFilter`, read the token
  with `request.getParameters().get("kiwi_token")` or the
  `x-kiwi-token` header, call `verifier.verify`, and return the
  `403`/`503` response of `Decision.fromOutcome`.
- Ktor: install an `intercept(ApplicationCallPipeline.Plugins)` block
  that resolves the token, verifies, and answers with
  `call.respondText(denialJson, ContentType.Application.Json,
  HttpStatusCode.Forbidden)` before `proceed()`.

Both shells keep `verify` pure-local; the memory store plus the core
are the only artifacts they touch.

## Doctor

The doctor validates the settings shape, the secret length, a full
one-shot store roundtrip, the configured scopes and the proof budget
of the configured profile:

```
mvn -pl core package
java -jar core/target/kiwicaptcha-core-1.0.0.jar \
    --secret "32 bytes or more" --store memory:// \
    --scopes login,comment --profile standard
```

## Outcomes

The outcomes client reports the eight typed results of a protected
action onto the risk channels, the always-on ledger and the
long-memory marks. The mapping table is versioned and pinned by
cross-language vectors; exactly the three server-confirmed trust
outcomes may subtract risk, and exactly the four abuse outcomes write
marks.

```java
var sink = new Outcomes.MemoryOutcomeSink("my-deployment");
var outcomes = new Outcomes.OutcomesClient(sink);
var handle = Outcomes.OutcomeHandle.of(Outcomes.HandleDimension.PRINCIPAL, pseudonym);
outcomes.report(Outcomes.Outcome.FRAUD_CONFIRMED, handle, "evt-1", 0);
```

Bind the `OutcomeSink` interface to your own deployment store to
persist ledger entries and marks beyond the process.

## Tests and conformance

`mvn test` runs the full suite. The conformance entry replays the
shared protocol corpora under the repository's `protocol/` directory
(canonical vectors, the solution-token boundary fixture, the rsw
identity fixture, the outcomes mapping fixture), the committed
PHP-issued golden records under `testdata/golden/` with their
provenance, an RFC-grade Argon2id pin set, and the exactly-once and
replay behavior of both stores. The Redis suite starts a scratch
`redis-server` on a test port and skips when the binary is absent, so
a run without it stays green.
