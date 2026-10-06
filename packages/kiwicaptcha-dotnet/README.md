# KiwiCaptcha (.NET server SDK)

.NET server-side verification for the KiwiCaptcha proof-of-work
captcha. Verifies client-submitted solution tokens byte-for-byte
compatible with the php, Rust, Go, Python and JVM cores. Verification
is pure-local: the signature check, the message authentication codes
and your store adapter are the only inputs, and no call ever reaches
a network service.

The core speaks the exact wire contract of the php core: the v4
signed canonical with the tagged decoy, execution and rsw identity
segments, the strict serde record parser, the solution token grammar,
the server-state message authentication codes, and the full
cheap-gate order of the php Verifier, including the policy-epoch
rollout-floor window.

## Packages

One NuGet package, `KiwiCaptcha`, targets net8.0 and has zero
required package dependencies: the ASP.NET Core middleware, the Razor
tag helper and the Blazor component compile against the
`Microsoft.AspNetCore.App` framework reference (framework-dependent,
not a package dependency), and the signing surface is
`System.Security.Cryptography.HMACSHA256` compared through
`CryptographicOperations.FixedTimeEquals`. The proof-phase Argon2id
recompute is a pure implementation over an in-tree BLAKE2b, so a
sha256 deployment loads nothing beyond the base class libraries.

`KiwiCaptchaDoctor` is the doctor console (`kiwicaptcha-doctor`).

## Quickstart

Four settings carry a deployment: the secret, the store url, the
scopes and the profile.

```csharp
var settings = new Settings
{
    Secret = "your-32-byte-or-longer-signing-secret",
    StoreUrl = "memory://",            // or redis://host:port
    Scopes = new[] { "login", "comment" },
    Profile = "standard",              // standard | argon16 | argon32 | argon64
};
Verifier verifier = settings.BuildVerifier();

var outcome = verifier.Verify(rawToken, new Verifier.Options
{
    SecretKey = settings.Secret,
    ExpectedScope = "login",
    ClientIp = clientIp,
});
var decision = Decision.FromOutcome(outcome,
    Decision.PriceRung("sha256", 8, 0));
if (decision.Ok)
{
    Proceed();                          // disposition "allow"
}
```

`Decision` is the contract-level answer: `Ok`, `Disposition`
(`allow`, `deny` or `retry`), `DecisionHandle` and `Price`. A `deny`
carries the failure code (`expired`, `bad_signature`, `wrong_scope`,
`required_scope`, `already_consumed`, and so on). A `retry` disposition
covers storage outages and admission exhaustion, where the challenge
stays intact and the same token may be resubmitted once the backend
recovers.

The scope option is REQUIRED (`Options.ExpectedScope` is a `required`
property): an empty option answers the typed `required_scope` refusal
instead of silently accepting a token minted for any scope, and the
middleware takes the scope as a required constructor parameter.

## Execution-armed records: the ExecutionPolicy

An execution-armed record demands the browser-trace walker, an oracle
this SDK does not carry: the default policy fails every armed record
closed (`execution_mismatch`, documented). A deployment that issues
armed challenges verifies them either through the bundle or through
the sidecar: set `Options.ExecutionPolicy` to
`new ExecutionPolicy { SidecarUrl = "http://127.0.0.1:7371" }` and the
armed record's single verification delegates to a co-located
kiwicaptcha-verifier over HTTP, whose verdict maps back into this
SDK's vocabulary.

Single-use semantics are preserved: the sidecar consumes the record
(point the sidecar at the same store), and this SDK never
double-consumes. Trust boundary: the sidecar decides acceptances, so
it must be co-located and trusted like the verifier itself. An
unreachable sidecar answers `storage_unavailable` (the retry
disposition) with the record intact; a refused bearer denies.

## Store adapters

One interface, two shipped backends behind `Settings.OpenStore`:

- `memory://` is the in-process store: single process,
  non-persistent, bounded retention, one-shot consume under
  concurrency.
- `redis://host:port` is the shared backend. The client speaks the
  Redis wire protocol over a plain socket, and the consume, cleanup,
  cancel and commit transitions run the same Lua transitions as the
  php adapter, so every SDK shares one Redis and one key space byte
  for byte. Any driver with the narrow command surface (`Get`,
  `SetWithTtl`, `Pttl`, `Del`, `Eval`, `EvalSha`, `ScriptLoad`)
  matches the `IRedisClient` interface, so an existing deployment
  driver (StackExchange.Redis included) can be bound instead of the
  shipped RESP2 client.

Consume is one-shot everywhere: the record is marked consumed and
kept until its retention ends, so replay protection is the consumed
marker, never absence. A consumed record replays its committed
deterministic result; a stored success replays only to the exact
operation identity recorded with the consume.

The SQLite store ships over Microsoft.Data.Sqlite, the canonical
ADO.NET driver and a deliberate dependency of the library:
`sqlite://path.db` builds the file-backed single-node adapter whose
schema and state machine are the ones the php SqliteStorage writes
(one table keyed by nonce, WAL journaling, every durable transition
inside one begin-immediate transaction, exactly-once consume).

## ASP.NET Core middleware

```csharp
builder.Services.AddSingleton(verifier);
app.UseKiwiCaptcha(verifier, secret, "login",
    path => path.StartsWithSegments("/api/protected"));
```

Every protected request reads the token from the `x-kiwi-token`
header, then the `kiwi_token` form field, then the query string.
Unverified requests get `403 Forbidden` with the machine-readable
code; a retry disposition gets `503 Service Unavailable`. The
verified decision rides `HttpContext.Items[KiwiCaptchaMiddleware.
DecisionItem]` for the wrapped handler.

## Razor tag helper and Blazor component

```razor
@addTagHelper *, KiwiCaptcha

<kiwi-captcha site-key="your-site-key" scope="login" theme="dark" />
```

The Blazor component `KiwiCaptchaChallenge` renders the same anchor
markup for Blazor Server and WebAssembly pages:

```razor
<KiwiCaptchaChallenge SiteKey="your-site-key" Scope="login" ElementId="signup-challenge" />
```

Both mount the widget script, which the deployment serves; the SDK
ships the anchor, the verify pipeline and the outcomes wiring, not
the issuance policy.

## Doctor

The doctor validates the settings shape, the secret length, a full
one-shot store roundtrip, the configured scopes and the proof budget
of the configured profile:

```
dotnet run --project src/KiwiCaptchaDoctor -- \
    --secret "32 bytes or more" --store memory:// \
    --scopes login,comment --profile standard
```

Exit code 0 means every check passed.

## Outcomes

The outcomes client reports the eight typed results of a protected
action onto the risk channels, the always-on ledger and the
long-memory marks. The mapping table is versioned and pinned by
cross-language vectors; exactly the three server-confirmed trust
outcomes may subtract risk, and exactly the four abuse outcomes write
marks.

```csharp
var sink = new Outcomes.MemoryOutcomeSink("my-deployment");
var outcomes = new Outcomes.OutcomesClient(sink);
var handle = Outcomes.OutcomeHandle.Of(Outcomes.HandleDimension.Principal, pseudonym);
outcomes.Report(Outcomes.Outcome.FraudConfirmed, handle, "evt-1", 0);
```

Bind the `Outcomes.IOutcomeSink` interface to your own deployment
store to persist ledger entries and marks beyond the process.

## Tests and conformance

`dotnet test` runs the full suite. The conformance entry replays the
shared protocol corpora under the repository's `protocol/` directory
(canonical vectors, the solution-token boundary fixture, the rsw
identity fixture, the outcomes mapping fixture), the committed
PHP-issued golden records under `testdata/golden/` with their
provenance, an RFC-grade Argon2id pin set, and the exactly-once and
replay behavior of both stores. The Redis suite starts a scratch
`redis-server` on a test port and stays green when the binary is
absent.

A toolchain note, in the interest of honesty: the library targets
net8.0 and compiles against the net8.0 reference assemblies, but this
machine only carries .NET 10 runtimes, so the test run executes under
`DOTNET_ROLL_FORWARD=LatestMajor`. On a host with the .NET 8 runtime
installed, a plain `dotnet test` reproduces the same suite.
