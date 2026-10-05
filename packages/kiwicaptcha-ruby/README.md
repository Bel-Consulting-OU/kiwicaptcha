# kiwicaptcha (Ruby)

KiwiCaptcha Ruby server SDK. Verifies client-submitted proof-of-work
solution tokens, byte for byte compatible with the PHP and Rust cores.
Verification is pure local: the signature, the message authentication
codes and the store adapter are the only inputs, and no call ever
reaches a network service.

## Install

The gem has zero hard runtime dependencies; the standard library
carries the whole verify path.

```ruby
gem 'kiwicaptcha', path: 'packages/kiwicaptcha-ruby' # until published
```

Optional groups: `sqlite3` for the SQLite store, `redis` for the Redis
store, `rack` (or any Rack-compatible framework) for the middleware.

## The four-setting quickstart

Environment only, mirroring the shared quickstart:

```sh
export KIWI_PROFILE=abuse_first          # the adoption choice
export KIWI_SECRET='...32 random bytes...'
export KIWI_STORE='redis://localhost'    # or sqlite:///var/kiwi.db or memory://
export KIWI_SCOPES='login=critical,signup=high,comment=low'
bin/kiwicaptcha-doctor                   # validates the deployment
```

## One-call verify (Tier B)

```ruby
require 'kiwicaptcha'

result = KiwiCaptcha.verify(params['kiwi__token'], KiwiCaptcha::Verify::VerifyOptions.new(
  storage: store,                 # MemoryStore, RedisStore or SqliteStore
  secret_key: ENV['KIWI_SECRET'],
  expected_scope: 'login',
  client_ip: request.ip
))
result.ok                  # => true
result.disposition         # => 'allow'
result.decision_handle     # => the verified challenge nonce
result.price               # => the paid work-ladder rung, e.g. 'sha16bit'
result.code                # => '' on success, a typed wire code on failure
```

The cheap-gate order mirrors the PHP Verifier exactly: structure,
protocol gate, kid revocation and resolution, HMAC signature, Argon2id
ceilings, rsw bounds, TTL, scope, request binding, IP binding, region,
policy epoch with the rollout-floor window, issuer, execution binding,
minimum duration. Then the opt-in telemetry gate, the one-shot consume,
the proof re-derivation, the post-derive final revalidation and the
deterministic result commit.

Documented capability mappings (fail closed, matching the shipped
SDK contract):

* Execution-armed records answer `execution_mismatch`: the browser
  trace walker is a browser-behavior oracle this SDK does not carry.
* Argon2id records answer `unsupported_argon2_params`: no native
  Argon2id runtime. RSW records verify fully when the trapdoor is
  configured.

## Rack middleware (Tier A)

```ruby
use KiwiCaptcha::Rack::Verifier,
    verify: ->(env) { VerifyOptions.new(storage: store, secret_key: secret) }

post '/login' do
  # env['kiwi.verify'] carries the result: decision handle, price, binding
end
```

The middleware reads the `kiwi__token` field (or the `X-Kiwi-Token`
header), verifies locally, and answers 422 with a JSON error body on
failure, or a 303 redirect with `failure_redirect:`. A storage outage
is a typed `storage_unavailable` 422, fail closed.

## Rails

```ruby
class ApplicationController < ActionController::Base
  include KiwiCaptcha::Rails::ControllerConcern

  kiwi_verify do
    KiwiCaptcha::Verify::VerifyOptions.new(storage: $store, secret_key: ENV['KIWI_SECRET'])
  end

  before_action :kiwi_verify!, only: :create
end
```

The form helper renders the drop-in markup, the Rails equivalent of
the Django field idea:

```erb
<%= form_tag '/login', method: :post do %>
  <%= raw KiwiCaptcha::Rails::FormHelper.kiwi_form_field('login') %>
  ...
<% end %>
```

## Sinatra

```ruby
helpers KiwiCaptcha::Sinatra::Helper

post '/signup' do
  return if kiwi_verify! { $options }.nil? # the 422 body is already set
  kiwi_verify_result.decision_handle
end
```

## Stores

One interface, three atomic adapters. Two racing consumers of one nonce
cannot both win the pending-to-consumed transition on any of them.

```ruby
store = KiwiCaptcha::MemoryStore.new                          # single process
store = KiwiCaptcha::SqliteStore.new(SQLite3::Database.new(path)) # one node, zero infra
store = KiwiCaptcha::RedisStore.new(Redis.new(url: 'redis://localhost')) # shared fleet
```

The Redis adapter runs the same Lua scripts as the other cores
(exactly-once consume, delete-if-pending) with the identity splice
atomic with the state flip. The SQLite adapter runs every durable
transition inside one begin-immediate transaction and shares the PHP
table layout, so one database file serves every SDK.

## Outcomes

```ruby
sink  = MyOutcomeSink.new  # confirm_ledger, record_feedback, write_mark, forget_mark
kiwi  = KiwiCaptcha::Outcomes::Client.new(sink, 'my-namespace')
kiwi.report('authenticationSuccess', OutcomeHandle.new(dimension: 'principal', id: pseudonym))
```

The mapping table is the polarity authority, versioned and pinned by
the risk-v1 vectors: only server-confirmed trust outcomes may subtract
risk, and exactly the abuse outcomes write long-memory marks.

## Doctor

```sh
bin/kiwicaptcha-doctor   # checks secret strength, store atomicity, rsw pair
```

Exits zero only when every check passes.

## Conformance

`rake test` runs the shared protocol corpus (solution-token-v1,
limits.json, the risk-v1 outcome vectors) and the PHP-issued golden
records committed under `test/fixtures/golden-php-vectors.json`, so
behavior cannot drift from the other cores. Regenerate the golden
records with `tools/generate_golden_vectors.php` (drives the real PHP
Issuer; provenance lives inside the fixture).

## License

MIT.
