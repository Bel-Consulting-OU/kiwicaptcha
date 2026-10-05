# @kiwicaptcha/node

The Node/TypeScript server SDK for KiwiCaptcha: local token verification,
store adapters, framework middleware, the typed outcomes client and the
doctor. It implements Part 4 steps 4 and 5 of the architecture (the app
check and the outcome report) on the shared server-SDK contract.

Verify is a pure-local operation: the challenge signature, the server
state MAC and the store adapter are the only inputs. The SDK never calls
out to any network service. The core and the memory store carry zero
runtime dependencies; Redis and SQLite adapters load optional peers.

## Install

```sh
npm install @kiwicaptcha/node
# optional store backends, only the ones you use:
npm install ioredis        # Redis adapter
npm install better-sqlite3 # SQLite adapter
```

Requires Node 18 or later. TypeScript types are first-class.

## The four-setting quickstart

The whole deployment surface is four settings, the same ones the PHP and
Rust cores take:

```yaml
kiwicaptcha:
  profile: abuse_first          # enables the full detection stack
  secret: one-32-byte-random-secret
  store: 'redis://localhost'    # or 'sqlite://var/kiwi.db', or memory
  scopes:
    login:   { value: critical }
    signup:  { value: high }
    comment: { value: low }
```

The client side stays a drop-in script plus one form attribute; the
widget solves and submits the `kiwi__token` hidden input.

## Verify (one call, local, no network)

```ts
import { verify } from '@kiwicaptcha/node/verify';
import { RedisStore } from '@kiwicaptcha/node/stores';
import Redis from 'ioredis';

const storage = new RedisStore(new Redis('redis://localhost'), { prefix: 'kiwicaptcha:' });

const result = await verify(token, {
  storage,
  secretKey: process.env.KIWI_SECRET,
  expectedScope: 'login',
  clientIp: req.ip,
});

if (!result.ok) {
  // result.code is the shared snake_case vocabulary:
  // expired, wrong_scope, ip_mismatch, already_consumed, ...
  throw new Error(result.code);
}
result.disposition;      // 'allow' on a valid proof, 'deny' on failure
result.decisionHandle;   // the challenge nonce (the replay id)
result.price;            // the paid work-ladder rung, e.g. 'sha20', 'argon64', 'rsw'
result.requestBinding;   // the application transaction to re-check
result.solveDurationMs;  // server-measured, from the authenticated issuance clock
```

The verification order mirrors the cores exactly: token decode, record
structure, protocol gate, kid gate and secret resolution, the HMAC
signature over the canonical payload, process ceilings, TTL, scope,
request binding, IP binding, region, policy epoch (with the rollout
floor window), issuer, execution binding, the server-measured minimum
duration, the opt-in telemetry gate, then the one-shot consume and the
proof re-derivation with the post-derive revalidation. A replayed token
answers with the stored deterministic outcome instead of re-deriving.

## Middleware

The middleware reads the configured token field, verifies, and on
failure returns the framework-idiomatic error: a 422 JSON body
`{error: {code, detail}}`, or a redirect when configured. The
integrator writes nothing else.

```ts
// Express
import { kiwiVerifyExpress } from '@kiwicaptcha/node/middleware/express';

app.post('/login',
  kiwiVerifyExpress({
    verify: (req) => ({ storage, secretKey, expectedScope: 'login', clientIp: req.ip }),
    // tokenField: 'kiwi__token' (default), failureStatus: 422, failureRedirect: '...'
  }),
  (req, res) => res.json({ handle: req.kiwi.decisionHandle }),
);
```

```ts
// Fastify
import { kiwiVerifyFastify } from '@kiwicaptcha/node/middleware/fastify';

await app.register(kiwiVerifyFastify, {
  verify: (req) => ({ storage, secretKey, expectedScope: 'login' }),
});
app.post('/login', async (req) => ({ handle: req.kiwi.decisionHandle }));
```

Both read the token from the body field, then the `x-kiwi-token`
header, then the query string. Next.js, NestJS, Remix and SvelteKit
call `verify()` directly inside their route handler or guard; the call
is the same one call everywhere.

## Stores

One adapter interface, three implementations, all exactly-once:

- `MemoryStore`: single process; the consume transition has no
  interleaving point, so single-use holds naturally.
- `RedisStore`: the consume and cleanup transitions run as Lua scripts
  through EVALSHA (NOSCRIPT falls back to EVAL). The key
  `kiwicaptcha:<nonce>` and the flat envelope JSON are the PHP
  backend's, so a mixed PHP and Node fleet redeems cross-node.
- `SqliteStore`: every transition runs in one BEGIN IMMEDIATE
  transaction on the shared schema, so PHP and Node can share one
  database file.

```ts
import { MemoryStore, RedisStore, SqliteStore } from '@kiwicaptcha/node/stores';

const memory = new MemoryStore();
const redis = new RedisStore(ioredisClient, { prefix: 'kiwicaptcha:' });
const sqlite = new SqliteStore(new Database('var/kiwi.db'));
```

Custom backends implement `StoreAdapter` (store, find, runtimeState,
consume, commitResult, deleteIfPending); the atomicity contract is the
one requirement the verifier states on the interface.

## Outcomes

The eight typed outcomes resolve through the one versioned mapping
table shared with the risk cores. A host binds its own sink; the SDK
maps, validates the handle grammar and builds the long-memory mark
keys.

```ts
import { KiwiOutcomes } from '@kiwicaptcha/node/outcomes';

const outcomes = new KiwiOutcomes(sink, 'd');
await outcomes.report('authenticationFailure',
  { dimension: 'principal', id: pseudonym32 },
  idempotencyKey,
);
await outcomes.forget({ dimension: 'principal', id: pseudonym32 }); // erasure path
```

Only the server-confirmed trust outcomes may subtract risk; exactly the
abuse outcomes write long-memory marks. The table is asserted against
the shared vector corpus in the test suite.

## Doctor

```sh
KIWI_SECRET=... npx kiwicaptcha-doctor --store redis://localhost
# ok  secret: 32 bytes, meets the 32-byte floor
# ok  region: identifier shape valid or unset
# ok  issuer: identifier shape valid or unset
# ok  store: reachable and single-use under the probe
```

The store probe writes a nonce-shaped record, consumes it twice and
requires the second consume to answer consumed-before; a store that
cannot do this is not single-use and fails the deployment.

## Conformance

The test suite reads the SAME protocol corpus every other core reads:
`solution-token-v1`, `limits.json`, `rsw-identity-v1`,
`risk-v1/outcomes-vectors.json` and the execution differential corpus,
plus golden records issued by the PHP core (plain, bound, decoy v3,
execution-armed v4, argon2id, rsw) that must verify byte-for-byte here.
Cross-SDK drift fails CI.

## Scope notes

- Argon2id records are authentic but unrepresentable by this runtime
  (node:crypto carries no Argon2id): the verifier answers
  `unsupported_argon2_params`, the cores' fail-closed mapping. SHA-256
  and rsw proofs verify fully.
- The Argon2id admission gate and the resume-derivation claim seam are
  PHP-process surfaces and are not part of this SDK's exported API.

## License

MIT
