# KiwiCaptcha

Privacy-preserving proof-of-work anti-abuse protection with first-party behavioral heuristics as a supplementary signal.
Hybrid Rust (WASM) + optimized JS solving, no external services.
No third-party tracking.
No third-party requests.
First-party behavioral signals never leave your application.
Developed by Bel Consulting OÜ (MIT license).

## What KiwiCaptcha is

KiwiCaptcha is anti-abuse protection.
A human does not solve the challenge: their CPU does, and a bot's CPU can do the same work.
The core value is economic: every signup, login, password-reset, or scraping attempt carries a real, tunable computational cost, which makes mass abuse uneconomical at scale.

Browser behavioral telemetry is a supplementary signal, not the security boundary.
It is client-controlled and forgeable.
The security property is the proof-of-work cost; everything else is defense-in-depth.
The guarantees and non-guarantees are stated in [the security document](SECURITY.md).

## Features

- Two proof-of-work algorithms, explicitly selected: `Sha256` (hash-based, extremely cheap server-side verification) and `Argon2id` (memory-hard, reduces the parallelism advantage of specialized hardware).
  The algorithm is carried on every challenge, so the solver and the verifier can never disagree about the computation.
- Hybrid Solving Engine: the widget embeds a Rust/WASM solver with an optimized pure-JS SHA-256 fallback for browsers without WebAssembly.
- Difficulty derived per algorithm: SHA-256 scales to 20 bits (~1M hashes, the browser solver ceiling); Argon2id is capped at 10 bits because every memory-hard hash is ~1000x more expensive.
- Server-side minimum solve duration: a timing-anomaly heuristic, not a proof of human behavior.
  The floor only rejects solves that arrive faster than the theoretical minimum, measured server-side.
  The client-reported duration is forgeable and serves only as telemetry.
- HMAC-signed, nonce-bound IP binding: the challenge records an HMAC tag derived from the issuing client IP (the tag changes with every nonce, so it creates no stable IP-derived identifier), and verification recomputes it from the current request's IP.
  A relay mitigation, not a guarantee.
- Single-use with bounded verification cost: verification consumes the challenge; per-nonce attempt accounting bounds the cost of wrong candidates.
  Deployments must additionally rate-limit challenge issuance and cap aggregate Argon2id verification concurrency; the Symfony bundle ships both.
- Widget: a modern, responsive browser widget with native dark mode and no external dependencies (no external JS, no iframes, no third-party hosts), with optional CSP nonce support.
- First-party behavioral telemetry, off by default: the widget collects no hardware-capability, device-memory, or screen signals unless the operator explicitly enables the coarse client-context opt-in.
  `minimal` mode reports only aggregate widget interaction counts and `full` adds `navigator.webdriver` and at most 20 coarse 250 ms timing samples.
- Auto-tuning difficulty: SHA-256 target bits scale with solver load; Argon2id difficulty is static (each hash is expensive).

The full per-feature documentation (protocol v2 signing, clock policy, attempt accounting, key rotation, revocation) is in [the Rust core documentation](packages/kiwicaptcha/README.md).

## Architecture

```
┌──────────┐  POST {prefix}/challenge {scope}   ┌────────────────────────────┐
│ Browser  │ ──────────────────────────────────▶│  Your App                  │
│ (widget) │◀─── {nonce, challenge, salt,       │                            │
│          │      algorithm, targetBits, ...}   │ Redis:                     │
│          │                                    │ kcaptcha:{                 │
│ WASM/JS  │  POST /auth/login {kiwi__token}    │   nonce} →                 │
│ solver   │ ──────────────────────────────────▶│ record                     │
│          │                                    │                            │
│          │                                    │ verify:                    │
│          │                                    │ cheap checks: structure,   │
│          │                                    │ signature, TTL, scope,     │
│          │                                    │ binding, timing            │
│          │                                    │ atomic pending→consumed →  │
│          │                                    │ consumed-record recheck →  │
│          │                                    │ derive exactly once →      │
│          │                                    │ commit deterministic result│
└──────────┘                                    └────────────────────────────┘
```

The widget resolves the challenge endpoint against the page origin and refuses cross-origin endpoints outright.
The solver and driver are embedded at render time, so nothing is fetched from a third party.

## Components

| Directory | What | Language |
|-----------|------|----------|
| `packages/kiwicaptcha` | Core engine: issuance, verification, telemetry, widget | Rust. |
| `packages/kiwicaptcha-wasm` | WASM solvers (SHA-256 + Argon2id) + embed tooling | Rust → wasm32. |
| `packages/kiwicaptcha-php` | Framework-neutral PHP 8.1+ core | PHP (ext-sodium). |
| `packages/kiwicaptcha-risk` | Adaptive risk engine: state protocol (canonical Redis Lua), calibration, outcome ledger | Rust. |
| `packages/kiwicaptcha-risk-php` | Protocol-identical PHP mirror of the risk engine, serving the Symfony bundle's risk layer | PHP. |
| `packages/kiwicaptcha/integrations/symfony` | Standalone Symfony bundle (`bel-consulting/kiwicaptcha-symfony`) | PHP. |

The Rust crate and the PHP SDK are protocol-identical and share a language-neutral JSON record schema.
The risk engines (Rust and PHP) are byte-identical in the state protocol; both embed the same canonical Lua and reproduce the same golden scoring fixtures.

## Five-minute installation (Symfony)

The single Symfony integration is the standalone bundle `bel-consulting/kiwicaptcha-symfony` (in `packages/kiwicaptcha/integrations/symfony`), which depends on the framework-neutral PHP core via Composer:

```bash
composer require bel-consulting/kiwicaptcha-symfony
```

```php
// config/bundles.php
BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle::class => ['all' => true],
```

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    secret_key: '%env(KIWI_SECRET_KEY)%'   # required, min 16 bytes
    algorithm: sha256                       # sha256 | argon2id
    difficulty_bits: 20
    route_prefix: /kiwi-captcha
```

The step-by-step walkthrough (form type, Twig widget, challenge endpoint, and the jti / `(jti, action)` idempotency contract) is the bundle's [documentation](packages/kiwicaptcha/integrations/symfony/README.md), starting at [docs/getting-started.md](packages/kiwicaptcha/integrations/symfony/docs/getting-started.md).

## One minimal example (Rust)

The whole quick-start (issue → solve → verify) is one **executable example** that CI runs and asserts ends in `VerifyOutcome::Valid` (`examples/quickstart.rs`).
The full code is in [the Rust core documentation](packages/kiwicaptcha/README.md).
In outline:

```rust
use kiwicaptcha::{BindingMode, ChallengeConfig, PoWAlgorithm, issue_challenge};

let config = ChallengeConfig {
    secret_key: "replace-with-32-random-bytes".into(), // >= 16 bytes required
    algorithm: PoWAlgorithm::Sha256, // or PoWAlgorithm::Argon2id
    m_kib: 0,                        // Argon2id memory (KiB); ignored for SHA-256
    t: 1, p: 1,
    target_bits: 16,                 // SHA-256 difficulty (leading zero bits)
    argon2_target_bits: 8,           // ignored for SHA-256
    ttl_secs: 120,
    min_duration_ms: None,           // None => derived from the difficulty
    auto_tune: false,
    auto_tune_min_bits: 10, auto_tune_max_bits: 20,
    binding_mode: BindingMode::Bound, // nonce-bound IP binding (relay mitigation)
    policy_version: 1,               // the security-policy epoch
    region: None, issuer: None,
    kid: 1,
};

let issued = issue_challenge(&config, "login", &client_ip, now_unix, now_ns, active_solves, None)?;
// Persist issued.record in Redis, keyed by nonce (kcaptcha:{nonce}).
// Send issued.challenge to the client as JSON; the client solves it and
// submits the solution token; verify_solution(&mut ctx) re-derives the
// proof and returns VerifyOutcome::Valid { nonce, request_binding }.
```

The record's fields (scope, IP binding tag, region, policy epoch, ...) are described in the [glossary](packages/kiwicaptcha/integrations/symfony/docs/glossary.md).

## Storage and single-use semantics

Single-use semantics are enforced by consuming the record on verification.
The consumed record is retained until its TTL with the committed deterministic result.
A replay returns the retained outcome rather than null: `AlreadyConsumed` unless the caller supplies the exact operation identity recorded by the original consume, in which case that outcome is reproduced.
Atomicity under concurrency is opt-in: implementations that guarantee strict single-use (exactly one caller wins the pending-to-consumed transition even when two requests race) implement `AtomicStorageInterface`.

| Adapter | Use case |
|---------|----------|
| `ArrayStorage` | tests, CLI, single-worker only, never production. |
| `Psr6Storage` | any PSR-6 pool; single-use under concurrency is best-effort (read-then-delete), using `StorageInterface`, not `AtomicStorageInterface`. |
| `RedisStorage` | atomic single-use via the Lua pending→consumed transition (record retained until TTL; deterministic-result commit; `ReplicaWaitException` barriers when `wait_replicas > 0`). Recommended for production. |

Records are persisted as **language-neutral JSON** (keys matching the Rust crate's serde schema one-to-one), so a PHP service and a Rust service can read each other's records from the same Redis instance.
The Symfony bundle fails fast with a `LogicException` if storage is left at the in-memory default outside `test`/`dev`.

## CSP

`kiwi_widget_html(endpoint, scope, csp_nonce)` emits `<style nonce="...">` and `<script nonce="...">` when a nonce is supplied.
Without a nonce the widget still works under CSP that allows `'unsafe-inline'`, or where the application post-processes the HTML.

WebAssembly requires `'wasm-unsafe-eval'`.
WASM compilation is a dynamic code-execution operation, so a strict CSP3 policy must allow it in `script-src`:

```
script-src 'nonce-<nonce>' 'wasm-unsafe-eval';
style-src 'nonce-<nonce>';
```

In SHA-256 mode the widget falls back to the pure-JS solver when WASM compilation is blocked, so `'wasm-unsafe-eval'` is optional there.
Argon2id mode requires WASM; there is no JS fallback for the memory-hard solver.
The memory-hard solver runs off the main thread in a Web Worker; the full worker/CSP requirements (including `worker-src blob:`) are authoritative in [the security document](SECURITY.md#csp--worker-requirements).

## Argon2id profile

KiwiCaptcha requires `t >= 3` and `p == 1` for Argon2id.
This is an intentional protocol profile: `p == 1` reflects libsodium's raw Argon2id interface, so Rust and PHP verify identical hashes.
Recommended profiles, both libsodium-verifiable and browser-feasible:

| Profile | m_kib | t | p | argon2_target_bits |
|---------|-------|---|---|--------------------|
| Mobile / low-memory | 8192 (8 MiB) | 3 | 1 | 6 |
| Desktop | 65536 (64 MiB, the WASM heap ceiling) | 3 | 1 | 8 |

SHA-256 difficulty is capped at 20 bits; Argon2id difficulty at 10 bits.
The core crate documents both profiles as complete `ChallengeConfig` values.

## Migration bridge

KiwiCaptcha's `{prefix}/api.js?compat=recaptcha|hcaptcha|turnstile` loader is the migration surface for incumbent pages (recaptcha v2/v3, hCaptcha, Turnstile).
Pages change only their provider script URL while retaining their existing widget markup, callbacks, and provider globals; the backend verifies through the provider-shaped `/siteverify` endpoint.
The bridge is a migration bridge, not a universal drop-in replacement.
The covered surface, the intentional differences (v3 scores are not emulated; the Turnstile subset; token lifetime parity at `challenge_ttl_secs: 300`), and the sitekey-to-scope mapping are documented in [docs/migration.md](packages/kiwicaptcha/integrations/symfony/docs/migration.md) and [docs/siteverify.md](packages/kiwicaptcha/integrations/symfony/docs/siteverify.md).

## Hardening

The core verifier enforces IP binding itself (not left to the route layer), counts attempts intrinsically on every verification call, verifies the HMAC in constant time, rejects secrets under 16 bytes, and bounds token/nonce/scope shapes.
The WASM solver uses a layout-matched allocator.
The authoritative hardening and operational contracts (Redis requirements, proxy/IP-binding assumptions, release governance, supported versions) are in [the security document](SECURITY.md).

## Test status

[![CI](https://github.com/Bel-Consulting-OU/kiwicaptcha/actions/workflows/ci.yml/badge.svg)](https://github.com/Bel-Consulting-OU/kiwicaptcha/actions/workflows/ci.yml)

The Rust crate is versioned at `1.7.0` ahead of its first crates.io
publication (the name is not yet on the registry); the current public
API is the frozen pre-publication baseline.

GitHub Actions is the source of truth for test status: Rust (fmt, clippy with `-D warnings`, tests, wasm32 build), PHP 8.1–8.4 (composer validation + PHPUnit), Symfony 6.4/7.x/8.x (container compilation + KernelBrowser), real-Redis concurrency, and browser specs (widget, security, migration, accessibility).
A cross-language compatibility suite runs in both directions (PHP issues → Rust verifies; Rust issues → PHP verifies) for both algorithms.
The PHP and Symfony suites are pinned to fixtures generated by the Rust crate, so the implementations can never drift apart.

## Product limitations

- Proof of computation, not proof of humanness.
  Any automated client that pays the same cost succeeds.
- Telemetry is client-controlled and therefore forgeable.
  Privacy Strict collects no behavioral or device telemetry at all.
- IP binding is a best-effort check.
  IPs legitimately change behind NAT/proxies; operators can disable the check entirely.
  It is a relay mitigation, with no guarantee attached.
- Server-side timing needs a trusted clock.
  The minimum-duration floor is measured by your server, so hosts must be NTP-synced; a fast bot can simply wait before submitting.
- The WASM solver and its JS fallback are released as open source.
  The value lies in the cost per attempt; nothing is impossible to solve.

The complete threat-model statement (including proof-of-work outsourcing, IP-rotation anonymity, network-level metadata, compromised hosts, and transport-level 0-RTT) is in [the security document](SECURITY.md#what-kiwicaptcha-explicitly-does-not-protect-against).

## Further reading

- [The security document](SECURITY.md) is the authoritative security reference.
- [The Rust core documentation](packages/kiwicaptcha/README.md) covers protocol, API reference, WASM regeneration, and Lua script versioning.
- [The Symfony bundle documentation](packages/kiwicaptcha/integrations/symfony/README.md) and its [docs directory](packages/kiwicaptcha/integrations/symfony/docs/) cover getting started, configuration, risk engine, chained challenges, siteverify, migration, privacy, operations, security hardening, troubleshooting, glossary, and the claims registry.
- Accessibility (WCAG 2.2 AA evidence, scope and limitations): the [Symfony accessibility statement](packages/kiwicaptcha/integrations/symfony/Resources/ACCESSIBILITY.md) and the [WASM accessibility statement](packages/kiwicaptcha-wasm/ACCESSIBILITY.md).
- Protocol material: the [risk-v1 protocol documentation](protocol/risk-v1/README.md), the canonical risk-v1 state protocol.

## Licensing

MIT, see [the license](LICENSE).
Copyright 2026 Bel Consulting OÜ.
