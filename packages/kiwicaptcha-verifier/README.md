# kiwicaptcha-verifier

The language-neutral verifier sidecar: one static binary that exposes
the provider-shaped siteverify surface over localhost HTTP or a Unix
socket, so any stack without a native SDK integrates with one local
call. The HTTP layer is std-only. See the crate documentation
(`src/lib.rs`) for the endpoint reference and the full knob list.

## Quick start

```text
KIWI_SECRET=$(openssl rand -base64 48) kiwicaptcha-verifier
curl -s http://127.0.0.1:7371/issue \
  -H 'content-type: application/json' \
  -d '{"scope":"login","remoteip":"203.0.113.9"}'
curl -s http://127.0.0.1:7371/verify \
  -H 'content-type: application/json' \
  -d '{"token":"...","scope":"login","remoteip":"203.0.113.9","expected_request_binding":"txn-A"}'
```

The secret has a 32-byte floor, and published example values are
refused at startup. While IP binding is on (the default), `remoteip` is
required on both endpoints; the loopback-only development escape hatch
is `KIWI_ALLOW_NO_REMOTEIP=1`.

The verify body's optional `expected_request_binding` is the
independent expected application-transaction binding of the
redemption: when present it is enforced as exact Option-equality
against the record's signed `request_binding` (an empty string asserts
the record must be explicitly unbound), and a mismatch is the typed
`request_binding_mismatch` refusal. When the field is absent (or null)
that check is not enforced — the backward-compatible posture for
callers that predate the field. Callers who care about the transaction
binding must send it; the Go and Node sidecar clients always forward
the binding their verification context expects.

## Challenge profiles

`KIWI_PROFILE` sets the default rung (default `sha18`). `KIWI_SCOPES`
maps each scope onto a rung, either a direct rung name or a value
class:

| value class | rung |
| ----------- | ---- |
| low | sha16 |
| standard | sha18 |
| high | sha20 |
| critical | argon16 |

Example: `KIWI_SCOPES="login=critical,comment=low"`. The rung names
sha16, sha18, sha20, argon16, argon32, argon64 and rsw are accepted
directly; the rsw rung needs the trapdoor knobs (`KIWI_RSW_MODULUS`,
`KIWI_RSW_LAMBDA`). Every issued challenge carries the timing floor
derived from its profile, and verification enforces it against the
server clock.

## Storage backends

`KIWI_STORE` selects the backend:

- `memory` (the default): volatile in-process state. A restart loses
  outstanding challenges and the replay protection with them. That is
  the documented single-node small-site trade.
- `file=DIR`: every record persists through an atomic rename with
  fsync, one JSON envelope per nonce, so a restart keeps outstanding
  challenges and answers replays with the duplicate vocabulary.
- `redis://URL`: the core crate's fused Redis verifier store, behind
  the `redis-store` build feature.

### Single node versus multi-node

The memory and file backends serve exactly one process on one host;
they are single-node by contract, with no replication and no shared
topology. A multi-node deployment runs the sidecar with the
`redis-store` build feature and points `KIWI_STORE` at one shared
`redis://URL`: nodes then share one store and one secret, a token
minted on one node verifies on another, and the one-shot consume stays
atomic across the fleet. Deployments that outgrow a sidecar entirely
move up to the bundle, which fronts the same core with the full risk
plane.

## Risk plane

Without `KIWI_RISK=1` this binary runs with no abuse-risk telemetry:
issuance and verification stay purely cryptographic, which is the
single-node small-site trade made deliberately. With `KIWI_RISK=1` and
`KIWI_RISK_URL` (plus the `redis-store` build feature), issuance runs
the adaptive risk engine's pre-issue assessment and the disposition
gates issuance: a deny refuses with 429, ladder rungs compose onto the
challenge, step-up carries its disposition in the response, and a
valid solve confirms the recorded decision in the risk store's outcome
ledger.

## Operations

- `GET /healthz` always answers `ok`.
- `GET /metrics` exposes verify outcomes, store gauges, risk-denied
  issues and connection-pool counters.
- `GET /doctor` summarizes secret, store, auth, listen, binding and
  risk posture.
- `--bearer` adds a constant-time checked credential over the
  sensitive routes.
- `--workers` bounds the connection pool (default 16); overflow
  answers 503 immediately. `--timeout-ms` bounds each connection
  (default 5000), so a stalled client holds a worker only until its
  timeout fires.
