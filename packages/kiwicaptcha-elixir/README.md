# kiwicaptcha (Elixir)

KiwiCaptcha Elixir server SDK. Verifies client-submitted proof-of-work
solution tokens, byte for byte compatible with the PHP and Rust cores.
Verification is pure local: the signature, the message authentication
codes and the store adapter are the only inputs, and no call ever
reaches a network service.

## Install

The package has zero hard dependencies; the standard library carries
the whole verify path.

```elixir
{:kiwicaptcha, path: "packages/kiwicaptcha-elixir"} # until published
```

Optional dependencies: `exqlite` for the SQLite store, `redix` for the
Redis store, `plug` for the router integration. The core compiles and
runs with none of them.

## The four-setting quickstart

Environment only, mirroring the shared quickstart:

```sh
export KIWI_PROFILE=abuse_first          # the adoption choice
export KIWI_SECRET='...32 random bytes...'
export KIWI_STORE='redis://localhost'    # or sqlite:///var/kiwi.db or memory://
export KIWI_SCOPES='login=critical,signup=high,comment=low'
mix kiwicaptcha.doctor                   # validates the deployment
```

## One-call verify (Tier B)

```elixir
result = Kiwicaptcha.verify(params["kiwi__token"], %{
  storage: store,                 # memory, SQLite or Redis adapter
  secret_key: System.get_env("KIWI_SECRET"),
  expected_scope: "login",
  client_ip: client_ip
})
result.ok                # => true
result.disposition       # => :allow
result.decision_handle   # => the verified challenge nonce
result.price             # => the paid work-ladder rung, e.g. "sha16bit"
result.code              # => "" on success, a typed wire code on failure
```

The cheap-gate order mirrors the PHP Verifier exactly: structure,
protocol gate, kid revocation and resolution, HMAC signature, Argon2id
ceilings, rsw bounds, TTL, scope, request binding, IP binding, region,
policy epoch with the rollout-floor window, issuer, execution binding,
minimum duration. Then the opt-in telemetry gate, the one-shot consume,
the proof re-derivation, the post-derive final revalidation and the
deterministic result commit.

Documented capability mappings (fail closed, matching the shipped SDK
contract):

* Execution-armed records answer `execution_mismatch`: the browser
  trace walker is a browser-behavior oracle this SDK does not carry.
* Argon2id records answer `unsupported_argon2_params`: no native
  Argon2id runtime. RSW records verify fully when the trapdoor is
  configured.

## Plug (Tier A)

```elixir
forward "/kiwi-protected", to: Kiwicaptcha.Plug,
  verify: fn _conn -> %{storage: store, secret_key: secret, expected_scope: "login"} end
```

The plug reads the `kiwi__token` field (or the `X-Kiwi-Token` header),
verifies locally, and answers 422 with a JSON error body on failure, or
a 303 redirect with `failure_redirect:`. A verified request assigns
`:kiwi` on the conn, so the decision handle, the price rung and the
request binding ride into the downstream actions. A storage outage is a
typed `storage_unavailable` 422, fail closed.

## Phoenix

The component helpers render the Tier A drop-in without any Phoenix
dependency: raw `{:safe, iodata}` tuples a template or a controller
embeds directly.

```heex
<form method="post" action="/login" {Kiwicaptcha.PhoenixComponent.form_attributes("login")}>
  <%= raw Kiwicaptcha.PhoenixComponent.form_field("login") %>
</form>
```

The hidden input carries the scope on `data-kiwi`; the driver script
declared above it solves the challenge and fills the token before
submit. Wire the verify side with the Plug above (a Phoenix controller
concern is the same two lines).

## Stores

One interface, three atomic adapters. Two racing consumers of one nonce
cannot both win the pending-to-consumed transition on any of them.

```elixir
store = Kiwicaptcha.Settings.open_store("memory://")                 # single process
store = Kiwicaptcha.Settings.open_store("sqlite:///var/kiwi.db")     # one node, zero infra
store = Kiwicaptcha.Settings.open_store("redis://localhost")         # shared fleet
```

The Redis adapter runs the same Lua scripts as the other cores
(exactly-once consume, delete-if-pending) with the identity splice
atomic with the state flip. The SQLite adapter runs every durable
transition inside one begin-immediate transaction, shares the PHP table
layout so one database file serves every SDK, and serializes writers
through one connection owner when tasks share the handle.

## Outcomes

```elixir
bound = %{sink: MySink.new(), module: MySink, namespace: "my-namespace"}
{:ok, receipt, sink} =
  Kiwicaptcha.Outcomes.report(bound, "authenticationSuccess",
    %{dimension: "principal", id: pseudonym})
```

The mapping table is the polarity authority, versioned and pinned by
the risk-v1 vectors: only server-confirmed trust outcomes may subtract
risk, and exactly the abuse outcomes write long-memory marks.

## Doctor

```sh
mix kiwicaptcha.doctor   # checks secret strength, store atomicity, rsw pair
```

Exits zero only when every check passes.

## Conformance

`mix test` runs the shared protocol corpus (solution-token-v1,
limits.json, the risk-v1 outcome vectors) and the PHP-issued golden
records committed under `test/fixtures/golden-php-vectors.json`, so
behavior cannot drift from the other cores. The Redis suite runs live
when a server answers at `KIWI_REDIS_URL` and skips cleanly otherwise.
The golden fixture records the issuing PHP version and commit in its
provenance block.

## License

MIT.
