# Security Policy

## Supported versions

Security fixes are released for the **latest minor of every supported major
line** of each artifact:

| Artifact | Supported lines |
|---|---|
| `kiwicaptcha` (Rust core) | latest `1.x` (currently `1.1.0`) |
| `kiwicaptcha-php` | latest `1.x` |
| `kiwicaptcha-risk` (Rust) | latest `0.1.x` — pre-1.0: fixes land on `0.1` |
| `kiwicaptcha-risk-php` | latest `0.1.x` — pre-1.0: fixes land on `0.1` |
| `kiwicaptcha-wasm` (assets + embed tooling) | current `2026-08-r1` solver protocol id — older protocol ids are NOT patched; upgrade the asset set |
| Symfony bundle (`packages/kiwicaptcha/integrations/symfony`) | latest release of each major |

Repository releases are **monorepo snapshots**: each artifact keeps its
own independent version. For example, the `v1.2.0` repository release
contains Rust core `1.1.0`, `kiwicaptcha-php` `1.x`, the risk engines
`0.1.x`, the `2026-08-r1` solver build, and the current Symfony bundle
release. Advisories always name the **artifact and its version** (e.g.
"kiwicaptcha (Rust core) 1.1.0"), never a bare repository tag.

Users are expected to run the newest supported release. When a vulnerability
is fixed, the fix is backported to all supported lines; unsupported lines
receive no fixes and should be upgraded or removed.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability.

Report through [GitHub Security Advisories] — "Report a vulnerability" on
this repository — which is private until triaged. Please include:
- the affected component and version (commit or release);
- a description of the vulnerability and its impact;
- reproduction steps, ideally with a minimal proof of concept.

You will receive an acknowledgment within 3 business days and a triage
assessment. We ask for a 90-day coordinated-disclosure window from the
report before public disclosure, unless the issue is already being
exploited.

## Release and branch governance (audit round 20)

- **`refs/heads/main` is protected by an active branch ruleset**: pull
  requests are required (1 approving review, stale-review dismissal,
  last-push approval, review-thread resolution, CODEOWNERS review for
  `.github/workflows/**`, `protocol/**`, verifier/Redis code and build
  tooling), ALL required security CI checks must pass (strict; the set is
  maintained in the ruleset — currently 21 check contexts including the
  standalone quick-start end-to-end job and the workflow-lint job),
  deletion/force-push are blocked, linear history is required, and commits
  must be signed. The trust model: organization admins retain an explicit
  always-bypass — this is operational protection, not mathematical
  impossibility.
- **`refs/tags/v*` are protected by an active tag ruleset**: deletion and
  non-fast-forward updates are blocked, creation is restricted to
  organization admins (the same documented trust model).
- **GitHub Immutable Releases is ENABLED** (`PUT
  /repos/{owner}/{repo}/immutable-releases` — the setting is also
  available in Settings -> General -> Immutable Releases). It applies to
  FUTURE releases only: the release object locks its tag and assets after
  publication and carries a release-level attestation. `v1.6.10` and
  earlier were published while the setting was off and remain mutable;
  `v1.6.11` is the first release published under it. The release workflow
  verifies every published release: `immutable: true` via the API and
  `gh release verify`.

  **Immutability enforcement chain (audit round 25 — no silent gaps).**
  The plain `GITHUB_TOKEN` has NO `administration` scope, so the
  admin-gated immutable-releases endpoints are unreadable by the release
  workflow's job identity (403 "not accessible by integration"). The
  pipeline therefore enforces immutability through a four-layer chain, in
  which every layer is either a hard failure or a live proof:

  1. **Organization policy**: `PUT /orgs/{org}/settings/immutable-releases`
     with `enforced_repositories=all` (verified live: the org currently
     reports `all`) — repository-level drift is impossible; changing it
     requires an org-admin action.
  2. **Admin-declared gate**: the repository VARIABLE
     `IMMUTABLE_RELEASES_ENFORCED` must equal `true`. It is set by an org
     admin as part of the governance contract, and the release gate
     REFUSES the release (before any build/attestation) when the variable
     is unset or not `true`. A release can never proceed unless an org
     admin has declared the governance in place.
  3. **Direct preflight (fail-closed when readable)**: when the run
     identity CAN read the admin-gated endpoints (a GitHub App or an
     admin-token run), the workflow additionally requires the repository
     setting `enabled: true` AND the org policy to be `all` — or
     `selected` WITH this repository verified in the selected set. The
     App-based read-only principal is the documented upgrade path for
     fully-privileged direct preflights; the plain token's 403 is not a
     silent gap because layers 1, 2 and 4 carry the guarantee.
  4. **Mandatory post-publish proof**: every published release is checked
     for `immutable: true` via the API and with `gh release verify`; a
     failure AUTO-DELETES the release and fails the run (containment), so
     a public mutable release can never be the outcome of a successful
     release run.
- The workflow additionally fails instead of clobbering an existing
  release (`--clobber` is never used), and it refuses an existing release
  in the gate before any build or attestation work.
- **Publication is CI-gated**: `.github/workflows/release.yml` verifies
  that the exact tag-triggered CI run succeeded (head_sha + head_branch +
  event) and that the commit is reachable from protected `main` before
  building, attesting, or publishing anything.
- **Tested bytes == released bytes**: the release pipeline rebuilds the
  assets under the strict pinned toolchain and fails unless `git diff
  --exit-code` shows they are byte-identical to the committed assets that
  the browser suite and Symfony byte-parity job tested.
- Releases are published atomically (`gh release create` with the assets
  inline: draft → upload → publish); a failure never leaves a public
  partial release.

[GitHub Security Advisories]: https://github.com/Bel-Consulting-OU/kiwicaptcha/security/advisories

## Asset / protocol-id coupling

The four browser assets in `packages/kiwicaptcha-wasm/assets/` are
**version-locked as a set** — the widget driver, the worker, and the WASM
glue/solver must come from the **same build**:

- `widget-driver.js` embeds `KIWI_SOLVER_PROTOCOL_ID` (currently
  `2026-08-r1`) and embeds a copy of the worker source; the worker
  verifies the wasm glue's exported `solver_protocol_version()` before
  `ready`.
- The worker declares the same constant and reports it in its handshake
  (`ready` / `done` messages). The driver validates it; a mismatch enters
  the controlled `kiwi:solver-mismatch` state and the driver **never**
  accepts a solution from a mismatched worker.
- The wasm glue (`kiwicaptcha-wasm.js`) is built by the release pipeline
  (`.github/workflows/release.yml` on every `v*` tag): strict deterministic
  build, SHA-256 + SRI manifests, SLSA provenance attestation, and asset
  upload to the GitHub release. The release publishes the immutable
  tag-bound JS/CSS artifacts plus the manifests; integrators who want
  content-addressed names (e.g. `argon-solver.<sha256>.wasm` extracted
  from the glue) apply that pattern at their CDN layer (see
  `packages/kiwicaptcha-wasm/SECURITY.md`); the glue and the driver/worker
  of the same protocol id must be paired.

Operational requirements:

- Serve the assets from **immutable, versioned URLs** — never a mutable
  `latest.js` alias.
- Pin every `<script>`-loaded asset with **SRI** (`integrity` sha384 +
  `crossorigin`) — see `packages/kiwicaptcha-wasm/SECURITY.md` for the
  hash tooling and the exact patterns. A `new Worker(url)` has no
  `integrity=` facility, so the standalone worker (`kiwi-worker.js`) is
  protected by the immutable versioned URL + the content-addressed release
  hash + the worker's protocol-id handshake (the driver refuses a mismatched
  worker). A mixed-version set (cached worker from an old release next to
  a new driver) must never reach a page; the mismatch state is the
  controlled failure, not a silent fallback.
- Recompute the SRI hashes on every rebuild; the ATTACHED
  `SHA256SUMS`/`SRI.txt` release manifests are the authoritative record
  (the release notes reference them).

## CSP / Worker requirements

The memory-hard solver runs off the main thread in a Web Worker:

- **Blob-worker default:** the driver builds the worker from a Blob URL of
  locally embedded code (`URL.createObjectURL`). A CSP with
  `worker-src 'self'` and no `blob:` allowance blocks it — allow
  `worker-src blob:` (a nonce'd/self-inlined driver creates the Blob, so
  no network origin is involved).
- **Explicit worker URL:** set `data-kiwi-worker-src` on the widget
  container to a **same-origin** asset URL, and allow that origin in
  `worker-src` (or use `worker-src 'self'` when serving it yourself).
  Cross-origin worker URLs are never fetched by the driver.
- **No synchronous Argon2id on the main thread.** Argon2id has no JS
  fallback and is never executed synchronously in the page; it runs only
  inside the worker (WASM). When the worker is unavailable, SHA-256 mode
  falls back to the chunked JS solver — Argon2id mode simply cannot solve.
  A CSP that blocks the worker therefore disables Argon2id challenges;
  choose `worker-src` accordingly.
- **WASM compilation:** a strict CSP3 policy must also allow
  `'wasm-unsafe-eval'` in `script-src` for the WASM solver (optional in
  SHA-256 mode thanks to the JS fallback, required for Argon2id).
- Style/script inline rules are unchanged: with a CSP nonce the emitted
  `<style>`/`<script>` carry `nonce="..."`; without one, `'unsafe-inline'`
  or application post-processing is required (see the root README).

## Proxy / IP-binding assumptions

Challenge issuance and verification bind the record to the issuing client
IP via a nonce-bound HMAC tag. The **canonical client IP** is decided by
exactly one knob, `risk.client_ip_mode`:

- `symfony_trusted_proxies` (default): forwarding headers
  (`X-Forwarded-For`, `Forwarded`) are honored only from
  `risk.trusted_proxies` (CIDRs/exact IPs; empty by default — nothing is
  trusted unless the operator configures it). Trusted-proxy configuration
  is global Symfony state once set.
- `direct`: forwarding headers are always ignored; the socket peer
  (`REMOTE_ADDR`) is the canonical IP.

Assumptions operators must verify:

- **Trusted proxies only:** any proxy in front must be listed in
  `risk.trusted_proxies`; an unlisted proxy means solves verify against
  the proxy's IP, not the client's — weakening relay mitigation and rate
  attribution.
- **Header singularity:** `Origin`, `Forwarded`, `X-Forwarded-For` and
  `X-Real-IP` are security-singular — duplicates are rejected with HTTP
  400 `DUPLICATE_HEADER` before any header-derived identity is trusted.
  The edge/WAF should also refuse duplicated headers.
- **Exact-IP binding (no network tolerance):** verification derives the
  nonce-bound binding HMAC from the CURRENT canonical client IP and
  compares it with `hash_equals` — an exact match only. There is NO /24 or
  /56 migration tolerance: any different IP, including a legitimate HTTP/3
  QUIC migration mid-session, fails closed (`IpMismatch`, challenge
  burned) and the client re-solves from the new address. Deployments that
  must tolerate legitimate network changes should prefer
  `request_binding` (per-page nonce) over IP binding for high-value
  scopes.
- IP binding is **relay mitigation, not a guarantee** — it never leaks a
  stable IP-derived identifier, and operators may disable it.

## Redis requirements

The security Redis (challenge storage, replay guards, rate/outstanding
counters, risk-v1 state, calibration buckets, admission leases) is a
**trusted control-plane component**, not a cache:

- **`maxmemory-policy noeviction` is mandatory.** KiwiCaptcha state must
  never be evicted mid-window: an evicted challenge record or
  consumed-state guard silently re-enables replay and stockpiling windows.
  Size `maxmemory` for the worst case (`max_outstanding_challenges_global`
  outstanding records × record size, plus risk state and lease sets, with
  headroom). Alert on `evicted_keys > 0` and `used_memory` > 70% of
  `maxmemory` — **observed eviction is a security incident**, not a
  capacity event.
- **Verified `WAIT` barriers + TTL margin for replay safety:** with async
  replication, configure `wait_replicas` (a Redis `WAIT` follows EVERY
  durability-critical write — challenge issuance, the pending→consumed
  transition, and the deterministic-result commit) and `wait_timeout_ms`.
  The acknowledgement count is VERIFIED: fewer than `wait_replicas` acked
  replicas fails the operation closed (`ReplicaWaitException` /
  `replica wait not satisfied`). Configure `ttl_margin_secs` beyond token
  validity so consumed-state guards outlive validity + clock skew +
  failover margin. On a replica-less server a configured barrier fails
  closed by design — `wait_replicas` is a hard durability contract.
  **Promotion invariant (audit round 15):** `WAIT N` proves that at least
  N replicas acknowledged the write — it does NOT constrain WHICH replicas
  your failover manager may promote. For replay-safe promotion, operators
  must either set the acknowledgement threshold to cover EVERY eligible
  failover target during the challenge lifetime, or configure the
  failover policy/topology so a lagging/non-current replica can never be
  promoted (promotion-eligibility gates, `min-replicas-to-write` style
  replication gating, or a quorum/consensus design whose semantics you
  can actually guarantee). Without that deployment invariant, a
  promotion can resurrect a consumed record from a stale replica.
- **Script versioning:** the risk engine runs the canonical
  `risk-v1.lua` (protocol/risk-v1) verbatim via `EVALSHA` with an
  automatic `NOSCRIPT` fallback — the script's SHA is a protocol artifact,
  pinned by the `risk-v1` protocol directory and mirrored byte-identically
  into the Rust and PHP packages (CI enforces explicit `cmp` byte parity
  across all nine protocol scripts on every push). The Lua is
  versioned (`v4` semantics at the time of writing); never hand-edit any
  of the three copies, and never load a modified script into a
  deployment whose stores were written by the canonical one.
- **Bounded pool, fail fast:** a bounded connection pool (5–10 per
  worker) with short command timeouts; the engine treats a slow/failed
  Redis command as a typed refusal (429 / temporary_unavailable), never a
  hang.
- **Cluster safety:** all keys share the hash tag `{kiwi:<deployment>}`,
  so the state script stays single-node atomic and Redis Cluster safe.

## What KiwiCaptcha explicitly does NOT protect against

KiwiCaptcha is anti-abuse protection with a bounded, honest threat model.
The following are **outside its guarantees**:

- **Proof-of-work outsourcing.** The protocol verifies that *some* client
  paid the computational cost — it cannot verify the cost was paid
  locally. Farms, click services, and device pools that solve on behalf of
  others pass, and open-source solvers make custom clients trivial.
- **IP-rotation anonymity.** Attackers rotating through many IPs evade
  per-source attribution; the subnet dimension and global pressure limit
  the damage but cannot identify a rotating adversary.
- **Network-level metadata.** ISPs, TLS-terminating proxies, and anyone
  between the client and your origin can observe challenge issuance,
  token traffic, and behavioral telemetry endpoints — KiwiCaptcha adds no
  transport-level confidentiality beyond what the application's own
  HTTPS/TLS provides.
- **Compromised hosts and customer code.** If the application server,
  the Redis instance, or the page's own JavaScript is compromised, all
  KiwiCaptcha state and verification logic is attacker-controlled. The
  widget's in-memory-only token and worker isolation are defense-in-depth
  against accidental leakage, not against a compromised page.
- **Transport-level 0-RTT replay caveat.** Where the application enables
  TLS 1.3 0-RTT early data, an attacker can replay a captured early-data
  request. KiwiCaptcha's server-side single-use consumption (the atomic
  pending→consumed transition) and replay guards mitigate the *effects* of
  such replays, but the transport
  behavior itself is the application's TLS configuration.
- **Human-vs-bot discrimination.** This is a cost-imposing PoW system, not
  a CAPTCHA in the Turing-test sense; behavioral telemetry is a
  client-controlled, forgeable supplement and never the security
  boundary.
