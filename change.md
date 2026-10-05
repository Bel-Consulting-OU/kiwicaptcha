
No diminished functioning. Every mechanism is specified to work fully. Where a resource bound is needed, it is a correctness bound (bounded memory, bounded CPU per request), never a reduction of detection quality.
Zero cloud cost. Every component runs on commodity self-hosted infrastructure the adopter already operates: a web server, PHP or a Rust binary, and Redis (or a documented single-node fallback). No managed database, no third-party API, no paid feed is ever required. Optional data feeds (e.g. ASN tables) ship as free, redistributable files.
Zero contradictions. Terms, dimensions, dispositions, and contracts are defined once (Part 1) and used identically everywhere. Part 12 is a consistency ledger that cross-checks the whole document.
Ease first. The average integrator must reach working protection in under ten minutes with four settings and one code snippet (Part 7).
Part 0 — Open items that must close first

These are the known-open findings from the code audit. They are prerequisites: the architecture below assumes a clean base. Each has an exact fix and a definition of done. (Severity: all are low-to-moderate; none blocks the architecture conceptually, but all must be closed before the new work lands so regressions are attributable.)

# Location	Exact change	Done when

1	widget-driver.js kiwiScan()	Before scanning, cancel and delete every widget record whose W.isConnected is false; add !W.isConnected to the isCancelled predicate passed into solve().	A Turbo/htmx navigation test solving mid-flight fires no callback for the removed widget and leaves core.counts().widgets equal to the live count.
2	KiwiHealthController::apcuPut()	Store the probe-debounce .state entry with a 60 s TTL; keep the 1 s TTL only for the readiness-result cache.	Under PHP-FPM, one failed PING keeps readiness; two consecutive failures flip it.
3	Policy-version check, both verifiers	During a declared rollout window accept central_min ≤ record.policy_version ≤ expected; strict equality otherwise.	A mixed N/N+1 fleet redeems cross-node with zero spurious rejections; outside a window, a wrong epoch is still rejected.
4	hysteresis.rs + PHP ScopeActionHysteresis	Edge fallback targets action_for_score(score − 10) when escalating and action_for_score(score + 10) when dropping, instead of previous ± 1 band.	Allow→605 yields Sha20; Argon64→141 yields Sha16; shared cross-language vectors pin both.
5	hysteresis.rs	Replace the global Mutex<HashMap<(u32, Vec<u8></u8>)>> with a sharded LRU keyed by (u32, [u8;16]); O(1) eviction, no per-call allocation.	p95 assessment latency at or below the current baseline at 64 concurrent threads.
6	ChallengeController::buildIssuanceVariantIssuer()	Add Config::withOverrides() and Issuer::withConfig() to the core; delete all reflection.	A test proves every Config constructor parameter survives an override round-trip.
7	Configuration::isEnvPlaceholder()	Treat a literal empty string as invalid, not as a deferred %env()%.	A build-time failure fires for secrets_by_kid: {1: ''}.
8	siteverify_secrets floor	Raise from 16 to 32 bytes.	Config-tree test rejects a 16-byte S2S secret.
9	createWithObligation()	Route the chain + obligation writes through the atomic create-or-get Lua.	A fault injected between the two writes never orphans a chain.
10	Health epoch-lag logging	Move the "last logged" de-duplication into APCu.	Under FPM the lag logs once per change, not once per request.
11	widget-risk.js	Remove the page-global kiwiActiveBlobUrl; ownership is strictly per-solve teardown().	Two concurrent inline-mode widgets both solve in all three engines.
12	ScopeIssuanceCap	Sliding window; alert as the cap is approached.	A boundary-straddling burst yields exactly the cap, never twice.
13–21	Cosmetic	CSS [data-theme] override hook; expired and solver-mismatch slot coloring; KEEPTTL in outcome_confirm.lua; explicit null for action/cdata in Rust siteverify.rs; doctor checkSecret aggregating all findings; chain-store 'corrupt' return consistency; four orphan/misattached docblocks; WASM header comment (alloc/dealloc, not __wbindgen_*); run() indentation.	Lint and tests green.
Part 1 — Canonical vocabulary (single source of truth)

Everything downstream uses exactly these terms. Defined once; never redefined.

1.1 Identity dimensions

An identity vector is computed once per request. Each dimension is an HMAC-pseudonym; raw values never leave process memory and never enter Redis, logs, or metrics.

Dimension	Raw input	Key granularity	Epoch-rotated	Default TTL	Purpose
source	client IP	IPv4 /32, IPv6 /64	yes	30 min (fast), 24 h (slow)	per-client velocity
subnet	client IP	IPv4 /24, IPv6 /56	yes	30 min	neighborhood velocity
asn	client IP → ASN	AS number	yes	6 h	proxy-pool pressure
session	continuity cookie	16-byte id	no	30 min	cross-request continuity
principal	authenticated user id	app-supplied	no	24 h	account reputation
target	pre-auth claimed id (e.g. username)	normalized → HMAC	no	24 h	victim-account protection
agent	verified-agent key id	config id	no	n/a	accountable automation
1.2 Evidence signals

Grouped by trust polarity. Attacker-controllable signals may only add risk or repay a specific debt; they may never subtract risk. Only server-confirmed outcomes subtract risk. (This is the existing trust-source invariant, preserved exactly.)

Risk-adding (attacker-influenceable): source_fast, source_slow, subnet_fast, asn_pressure, issue_debt, bad_proof, malformed, replay, action_failure, scope_switch, global_pressure, network_risk, honeypot, session_inconsistency, tls_inconsistency, target_failures, target_spread, scope_failure_ratio, solve_anomaly, interaction_anomaly.
Trust-granting (server-confirmed only): trust_credit (source/session), principal_credit, agent_credit, abuse_mark (negative, long-memory).
1.3 Dispositions

The decision plane emits exactly one disposition per request:

allow — no challenge.
price(work) — a proof-of-work rung from the ladder.
step_up — hand off to a second factor.
deny — refuse, with a signed Retry-After.
quarantine — pass to the app but mark kiwi.quarantine=true; the app accepts the submission and withholds it from publication. On the wire this is indistinguishable from allow.
1.4 The work ladder

Allow → Sha16 → Sha18 → Sha20 → Argon16 → Argon32 → Argon64 → RSW → StepUp → Deny/Quarantine. RSW (sequential time-lock) is a first-class rung whenever a trapdoor is configured. Ordering is total and identical across both cores.

1.5 Outcomes

Reported by the application after the fact: confirmedLegitimate, stepUpCompleted, authenticationSuccess, authenticationFailure, spamReported, chargeback, accountBanned, fraudConfirmed. Each maps, through one versioned table, onto risk events, ledger confirmation, and marks.

1.6 Planes

Eight planes; every component belongs to exactly one:

Identity · 2. Evidence · 3. Decision · 4. Enforcement · 5. Outcomes ·
Agents · 7. Storage/Scale · 8. Observability/Economics.
Part 2 — Architectural principles
One identity computation per request. Every plane reads the same IdentityVector. No plane recomputes a pseudonym. Cost budget: < 20 µs.
Additive evidence, authoritative outcomes. Polarity from §1.2 is enforced in the Lua apply_feedback path and proven by property tests.
Fail-closed under uncertainty. A corrupt record, an unreadable store, a stale policy — all deny or step up, never silently pass.
Attacker cost is a measured, published quantity (Plane 8). "Secure" means "priced above the abuse value for every scope," demonstrated by benchmark, not asserted.
Victim protection is correctness, not a softening. Signals about a target protect that target's account; signals from an attacker escalate the attacker's own dimensions. These never cross. This is not a reduced mode; it is the precise, full-strength behavior.
Zero cloud dependency. Every datum the system needs is either derivable locally or shipped as a free redistributable file.
Byte-identical cross-language cores. Rust and PHP produce identical canonical bytes, identity vectors, scores, and decisions on a shared vector corpus. CI enforces this.
Bounded everything. Per-request CPU, per-key memory, per-dimension cardinality, and script work are all bounded by documented constants.
Part 3 — Plane-by-plane architecture

Each component states: what it is, the exact data structures and contracts, the zero-cost guarantee, and the definition of done.

Plane 1 — Identity

3.1.1 IdentityVector. A value object with the seven dimensions of §1.1, computed once, cached on the request. Contract file protocol/risk-v2/identity.json declares, per dimension: the HMAC context string, granularity, epoch policy, TTL, and cardinality bound. Both cores and a CI check assert against it.

Done: shared fixtures (canonical inputs, Unicode, IPv4-mapped spellings, boundary epochs) yield identical vectors in both languages; computation < 20 µs measured.

3.1.2 Target identifier. TargetIdentifierResolverInterface; default FormFieldTargetResolver reads a per-scope field name. Normalization is a versioned pipeline: NFKC → Unicode case-fold → trim → optional per-provider email canonicalization (shipped as a free static table, not a service). Only HMAC(normalized) is stored.

Done: a confusables/homoglyph fuzz corpus collapses variants of one identifier to one target; a scanner test proves the raw value never reaches Redis, logs, or metrics.

3.1.3 Context-bound trust. Trust earned by a session is stored per ASN bucket: trust[session][asn_bucket]. A session presenting from an ASN bucket where it earned nothing gets zero credit there, full credit in its home bucket(s). This defeats shared-cookie botnets without reducing a real user's cross-network experience (their known buckets keep trust).

Done: a trusted cookie replayed from 1,000 foreign ASNs earns nothing; a genuine home→mobile commute keeps trust.

3.1.4 ASN resolution, zero-cost. ASN lookups use a free, redistributable dataset (e.g. a public routing-table export or the free IPtoASN dataset), shipped as a versioned MMDB/CSV and loaded from disk. Hot reload is atomic and digest-verified; no network call, no paid feed, ever. Unknown ASN → its own bucket per /16 (v4) or /32 (v6).

Done: every v4/v6 test vector resolves deterministically; a hot reload never serves a half-swapped table; the doctor prints the dataset digest and age.

Plane 2 — Evidence

3.2.1 Signal store. All §1.2 signals. New signals and their storage:

Signal	Definition	Storage (bounded)
target_failures	leaky-bucket auth failures / target	counter field in target hash
target_spread	distinct source and asn per target in window	two HyperLogLogs, ≤ 12 KB each, sparse
scope_failure_ratio	failures ÷ attempts per scope	sharded leaky counters (Plane 7)
asn_pressure	velocity + failures per ASN bucket	ASN hash
abuse_mark	server-confirmed abuse (long memory)	mark:<dim></dim>:<id></id>, §3.5.3
solve_anomaly	measured solve time ÷ fastest qualified-device p1 for the rung	computed vs. client-perf table
interaction_anomaly	from rebuilt telemetry (§3.2.3)	token payload

3.2.2 Honeypot/decoy. Preserved exactly as today: per-challenge, authenticated, polymorphic, strictly additive evidence (docs/decoy-adaptation-analysis.md). Enhancement: a confirmed decoy hit also raises that session's price by one rung for 10 minutes — an escalation, not a block, and never applied until the autofill-qualification matrix passes for all registered surfaces (so a password manager can never trip it on a real user).

3.2.3 Telemetry rebuilt as real evidence. Listeners attach at the form containing the widget (not the widget alone, which is why today's signal is near-empty for real users). Payload carries only coarse, privacy-preserving aggregates: event-class counts, quantized inter-event entropy, focus-transition count, paste-vs-type ratio. No raw coordinates, no key values, no timing series. Schema and privacy contract are published and fixture-tested.

Done: real-user samples from the device matrix score in the human band; an AI agent driving genuine input is scored as evidence (never classified as "absent"); the entropy rule's minimum-sample count equals the payload cap (no dead rule).

3.2.4 Execution dimension as a real browser boundary (v6). Today's browserless oracle forges v1–v5 by design. v6 requires web-platform semantics a pure reimplementation cannot shortcut, executed in a real layout engine: randomized-CSS computed geometry, MutationObserver delivery order, real event phases with listener side effects, Range/Selection over a constructed text graph, IntersectionObserver thresholds. The verifier checks the trace against an envelope derived from the cross-engine qualification matrix.

Done: the existing oracle and a jsdom/happy-dom emulator both fail ≥ 99.9% over 10⁵ programs; Chromium, Firefox, WebKit (plus mobile) pass 100%; the cost of a full-fidelity headless emulator is measured and published (Plane 8).

Plane 3 — Decision

3.3.1 Continuous pricing. work = price(risk, value_class, trust_in_current_asn, untrusted_scope_pressure). Output quantizes to the client-supported rung set. Monotone in risk, sub-linear in trust, sharp for marked identities. Replaces discrete band-to-action mapping while keeping the ladder as the output alphabet.

Done: property tests prove monotonicity and floor/cap invariants; a shared 10⁵-vector corpus yields identical output in both cores.

3.3.2 Pressure targets unproven identities only — at full strength. Global floors, scope pressure, and Argon-capacity step-ups apply in full to identities with no trust in their current ASN bucket. Trusted identities keep their individual price. This is not a weaker mode for anyone; it is the precise separation of attacker surge from established users, applied at full force to the attacker.

Done: under an L4 storm, trusted-session p95 solve time changes ≤ 5%; untrusted traffic is fully escalated.

3.3.3 Decisive attacker handling. A marked identity → maximum rung (RSW). A corroborated attacker (mark and decoy/replay/bad-proof) → deny for the mark TTL. Signals on a target → step_up on that account's next login; the attacking source/session/asn/agent take the floors and denials. A victim's own dimensions are never escalated by attacks aimed at them.

Done: in the stuffing simulator (Part 9), attacker identities are denied within N attempts while the victim logs in with exactly one step-up and zero lockouts.

3.3.4 Quarantine for confirmed spammers. Wire-indistinguishable from allow (body, timing within the measured noise floor, headers). The app holds the submission from publication.

Done: a wire-diff harness cannot distinguish quarantine from allow.

Plane 4 — Enforcement

3.4.1 The ladder of §1.4; RSW promoted to first-class; the doctor requires a trapdoor under the abuse_first profile.

3.4.2 Step-up contract. StepUpHandlerInterface::begin(Request, StepUpContext): Response and ::complete(Request): StepUpResult. Reference handlers: WebAuthn (phishing-resistant), email OTP, TOTP. Completion emits stepUpCompleted, crediting principal and target so a legitimate user is not stepped up twice. Today only the typed violation code exists.

3.4.3 Chained challenges (existing) carry the continuous price from §3.3.1.

Plane 5 — Outcomes

3.5.1 Framework bridges. Auto-enabled subscribers translate framework auth/security events into §1.5 outcomes. Symfony first (LoginFailureEvent/LoginSuccessEvent/CheckPassportEvent), then the bridges listed in Part 6. Idempotency key = HMAC(request id).

Success-trust rule (new in apply_feedback, both cores): authenticationSuccess always credits principal; it credits session/source only when that identity's windowed failure ratio < θ and the target was not under spread attack. This blocks a credential stuffer with valid stolen credentials from farming source trust — without weakening a normal user's trust gain.

3.5.2 Typed outcomes API. KiwiOutcomes::report(Outcome, Handle) where Handle ∈ {nonce, decision id, principal, target, session, agent}. One versioned mapping table.

3.5.3 Long-memory marks. mark:<dim></dim>:<id></id> for principal/target/session/ agent/asn; default 90-day TTL; written only by server-confirmed outcomes; each carries kind, count, first/last timestamps. KiwiOutcomes::forget(Handle) supports erasure requests.

3.5.4 Calibration hardening. Labels carry a provenance class (human_review, payment_network, security_event), weighted accordingly. Per-source label-volume caps + a robust trimmed-mean estimator over clipped boundary distances.

Done: 10⁵ forged confirmedLegitimate labels via any app path move the bias ≤ 1 point.

Plane 6 — Agents

3.6.1 Verified agents (RFC 9421 HTTP Message Signatures). risk.agents.<name></name>: key id, Ed25519 public keys (rotation-capable), allowed scopes, per-minute/per-day quota, price tier, contact. Signature covers @method, @target-uri, content-digest, with created/expires/nonce (single-use in Redis). Verified requests skip the widget for allowed scopes and are priced at their tier; outcomes and marks attribute to the agent id.

Done: passes RFC 9421 vectors; replay/skew/header-strip/alg-confusion all fail; quota overrun escalates; a revoked key fails within one config reload.

3.6.2 Native solver crate + CLI (kiwicaptcha-solver). Shares code with the WASM solver; documented JSON flow (GET challenge → solve → POST). Gives unauthenticated well-behaved automation a supported path at the same price as a browser. Publishing it concedes nothing: solver secrecy was never part of the model, and public solvers already exist for peer systems.

Plane 7 — Storage and scale (zero cloud, horizontally scalable)

3.7.1 The ceiling. Today every key shares one hash tag {kiwi:<ns></ns>} → one Cluster slot → one primary. Cluster-safe but not Cluster-scalable.

3.7.2 Sharded keyspace. Per-identity families: {kiwi:<ns></ns>:<dim></dim>:<2-byte id prefix>}. Per-nonce families: {kiwi:<ns></ns>:n:<nonce prefix></nonce>}. Scope/global aggregates: sharded counters scope:<id></id>:<shard 0..15>, merged on read with a ≤ 1 s staleness contract. Assessment is one pipelined batch of per-dimension scripts on their own slots — still one network round trip, throughput scaling with shard count. Per-dimension dedupe by event id makes a partial-batch retry idempotent. Single-use consume, chain transitions, and idempotency stay single-slot; each transition's atomicity boundary is documented and model-checked (Part 9).

Done: throughput scales ≥ 0.9× linearly from 1→8 shards; p99 assessment ≤ 3 ms at 5× peak; all invariant suites pass on a 3-primary Cluster.

3.7.3 Zero-infrastructure fallback. Redis is the recommended backend but not the only one. Ship first-class adapters requiring no extra services:

SQLite + WAL (single-node, atomic via transactions; perfect for small sites and the default "just works" path).
APCu + flock (single PHP host, no network).
Filesystem (atomic rename; documented limits).

All adapters implement the same atomicity contract and pass the same invariant and model-checking suites. A small site pays zero infrastructure cost and still gets single-use, replay-safe verification.

Done: the full invariant suite passes on SQLite and APCu adapters; the doctor recommends the right backend for the detected deployment.

3.7.4 HA/durability. Verified WAIT and HA authority preserved; published per-plane availability SLO; a tested failover runbook (Part 9).

Plane 8 — Observability and economics (self-hosted only)

3.8.1 Metrics exporter. APCu/Redis-aggregated counters exported as Prometheus text at /kiwi-captcha/metrics behind its own auth, preserving redaction rules. (Prometheus/Grafana are themselves free and self-hosted; no cloud is implied.)

3.8.2 kiwicaptcha:bench. Measures native attacker cost per rung on the adopter's own CPU; imports free, published GPU/FPGA reference numbers; outputs $/1,000 solves. The doctor proves each scope's value class is priced above its declared abuse value.

3.8.3 Explanations. Each decision log carries top contributors (exist in both cores) and the identity dimensions involved — never their values.

Part 4 — Reference request lifecycle (no contradictions)

A single, authoritative sequence every integration follows:

Issue. Client requests a challenge for scope. Server computes the IdentityVector (Plane 1), runs pre-issue assessment (Planes 2–3), and issues a signed, MAC-protected, single-use record priced by §3.3.1.
Solve. The widget (or an SDK, or the native solver) produces the proof; execution/decoy/telemetry evidence rides along.
Verify. Server atomically consumes the record (Plane 7), re-runs post-solve assessment, and emits a disposition (§1.3). A token is returned to the app.
App check. The app calls verify(token) server-side (local, no network) → {ok, disposition, decisionHandle}.
Outcome. Later, the app reports outcomes via the auto-bridge (Plane 5) or KiwiOutcomes::report. Marks and calibration update.

Every SDK in Part 6 implements exactly steps 2 and 4 on the client/server split appropriate to its platform; nothing deviates from this lifecycle.

Part 5 — The "it just works" integration model

Three integration tiers, each a strict superset of ease:

Tier A — Drop-in (zero backend code). A  tag + a form attribute. A framework plugin/middleware auto-verifies the token on submit and auto-wires outcomes. The average user never writes verification code.
Tier B — One-call server verify. kiwi.verify(token) → boolean/struct, for custom handlers.
Tier C — Full control. Direct access to disposition, price, dimensions, step-up, quarantine, and outcomes.

The default profile abuse_first turns on everything in Part 3. The entire required configuration surface is four settings (Part 7).

Part 6 — SDKs and compatibility layers (exact specifications)

Every SDK implements the same lifecycle (Part 4), the same wire protocol, and the same four-setting config. All are MIT-licensed, dependency-minimal, and self-contained. "Verify" is always a local operation (signature + MAC + the store adapter); it never calls out to any network service.

6.1 Server SDKs (token verification + outcome wiring)

Each provides: verify(token, opts) → {ok, disposition, decisionHandle, price}; an idiomatic framework middleware/plugin; an outcomes client; a store adapter interface with Redis + SQLite + in-memory implementations; a doctor command.

Platform	Package	Framework integrations (auto-verify + auto-outcomes)	Notes
PHP	kiwicaptcha/kiwicaptcha-php (core, exists)	Symfony bundle (exists; extend), Laravel package, WordPress plugin, Drupal module, Composer-generic	WordPress plugin is high-leverage: a huge share of the vulnerable long tail.
Node/TS	@kiwicaptcha/node	Express, Fastify, Next.js (route handler + middleware), NestJS, Remix, SvelteKit	TS types first-class.
Python	kiwicaptcha	Django (middleware + form field + admin), Flask, FastAPI, DRF	Django form field mirrors reCAPTCHA field ergonomics.
Go	kiwicaptcha-go	net/http middleware, Gin, Echo, Chi, Fiber	Single binary; can also run as the sidecar (6.4).
Ruby	kiwicaptcha gem	Rails (form helper + controller concern), Sinatra, Rack middleware
Java/Kotlin	com.kiwicaptcha	Spring Boot starter, Jakarta Servlet filter, Micronaut, Ktor
.NET	KiwiCaptcha (NuGet)	ASP.NET Core middleware + Razor tag helper, Blazor component
Rust	kiwicaptcha (core, exists)	Axum, Actix, Tower layer	The verifier reference.
Elixir	kiwicaptcha (hex)	Phoenix plug + component

Shared server-SDK contract (identical across all):

verify is pure-local; store adapter is injectable (Redis | SQLite | memory).
Middleware reads the configured token field, verifies, and on failure returns the framework-idiomatic error (422/redirect/JSON) — the integrator writes nothing.
Outcomes auto-wire to the framework's auth events where they exist; otherwise a two-line manual hook is documented.
A doctor subcommand validates config, secrets, store, and ASN dataset.
A cross-SDK conformance suite (Part 9, D4.7) runs identical vectors against every SDK so behavior cannot drift.
6.2 Client SDKs (widget + headless solve)
Platform	Package	Contents
Browser JS	@kiwicaptcha/browser (exists as the widget)	Auto-render, explicit render, promise API, events, a11y, i18n.
React	@kiwicaptcha/react	<KiwiCaptcha onVerify></kiwicaptcha> component + hook.
Vue	@kiwicaptcha/vue	SFC component + composable.
Svelte / Angular / Solid	respective packages	Idiomatic component each.
React Native / Expo	@kiwicaptcha/react-native	Native-thread solver (no WebView PoW); native modules for iOS/Android.
iOS (Swift)	KiwiCaptcha (SPM)	SwiftUI + UIKit widget; native solver.
Android (Kotlin)	kiwicaptcha-android	Jetpack Compose + View widget; native solver.
Flutter	kiwicaptcha (pub.dev)	Widget + Dart solver via FFI to the Rust core.
6.3 Drop-in compatibility shims (zero-rewrite migration)

Each presents the incumbent's exact client API and server verify shape, so migration is a key/URL swap:

reCAPTCHA v2/v3 shim — grecaptcha.render/execute/getResponse/reset; server siteverify response shape (success, challenge_ts, hostname, action, cdata, error-codes). (Partly exists; complete it, including  parity.)
hCaptcha shim — hcaptcha.* API; populates both h-captcha-response and g-recaptcha-response; hCaptcha siteverify shape.
Cloudflare Turnstile shim — turnstile.render/execute/reset/remove; Turnstile siteverify shape; managed/invisible/non-interactive modes.
ALTCHA / Friendly Captcha widget-attribute shims — recognize their element/attribute conventions so existing markup keeps working.

A kiwicaptcha:migrate command scans a codebase for incumbent keys/URLs and emits the shim config.

6.4 Language-neutral verifier sidecar (covers every other stack)

A single static Go/Rust binary (kiwicaptcha-verifier) exposing a localhost HTTP/Unix-socket verify endpoint and the same metrics/doctor surfaces. Any language without a native SDK integrates with a one-line local HTTP call. It is self-hosted, runs as a normal process or container the adopter already manages, and makes no external calls. This guarantees universal coverage at zero cloud cost while native SDKs mature.

6.5 Platform plugins (no-code audiences)
WordPress (forms, login, comments, WooCommerce), Drupal, Joomla.
Discourse, phpBB, Flarume.
Gitea/Forgejo, GitLab (self-hosted) sign-up protection.
Nginx/Caddy/Traefik auth-request module for gating arbitrary routes.
Keycloak / Authentik / Zitadel authenticator SPI (self-hosted IdPs).
Part 7 — The four-setting quickstart (ease target)

The entire required surface for a strong default deployment:

yaml
kiwicaptcha:
  profile: abuse_first          # enables all of Part 3
  secret: '%env(KIWI_SECRET)%'  # one 32-byte random secret
  store: 'redis://localhost'    # or 'sqlite://var/kiwi.db' — zero extra infra
  scopes:
    login:   { value: critical }
    signup:  { value: high }
    comment: { value: low }

Client (drop-in):

html

<script src="/kiwi.js" defer></script>

<form method="post" data-kiwi="login">…</form>

That is the whole integration for Tier A. The framework plugin verifies on submit and wires outcomes automatically. kiwicaptcha:doctor then confirms the deployment is sound (secret length, store reachability, ASN dataset present, every scope priced above its value class).

Progressive disclosure: everything else (per-dimension weights, custom resolvers, agents, step-up handlers, pricing curves) is optional and documented in layered guides (public → integration → maintainer), which already exist.

Part 8 — Zero-cost and sustainability guarantees
No paid dependency anywhere. ASN data, email-canonicalization tables, and GPU/FPGA reference costs are all free, redistributable files committed to the repo and refreshed by a free scheduled job.
No service to operate. The sidecar and metrics endpoint run on the adopter's own box. The red-team program (Part 9) runs in the adopter's or maintainer's own CI with local LLM agents (Part 10) — no paid API required.
Small-site path is first-class. SQLite/APCu adapters mean a hobby site runs the full protection with zero added infrastructure.
Bus-factor mitigation. Cross-SDK conformance (D4.7), model checking (D4.3), and the fully automated red-team (Part 10) encode the project's knowledge as executable gates, so correctness survives contributor turnover.
Part 9 — Red-team program (fully automated, LLM-driven, maximally aggressive)

Thesis: the red team is not a periodic human exercise. It is a permanent, self-hosted, LLM-agent-driven adversary that runs continuously against a production-equivalent target, invents new attacks, and gates every release. It assumes full knowledge (source, docs, this spec) and unlimited creativity within the adopter's own hardware budget — no cloud, no paid API (Part 10).

9.1 Principles
Production-equivalent targets only. No simplified fixtures count.
Economic truth is the primary metric. Every campaign reports attacker cost per successful abuse, not just pass/fail.
Every finding becomes a permanent failing-first regression test.
Full-knowledge adversary. The agents read everything.
False positives are a failure. Human baseline traffic runs in every campaign; any legitimate denial fails the release.
9.2 Target environment

Nginx + TLS 1.3 + a real CDN-like reverse proxy (header strip/add); PHP-FPM, FrankenPHP worker mode, and the Rust verifier; Redis Sentinel (2 replicas, verified WAIT) and Redis Cluster (3 primaries) and the SQLite adapter — all three storage backends exercised; every profile; chaining on; all asset modes; all locales; and replayed human-like traffic from the device matrix for continuous false-positive measurement.

9.3 Campaigns (each with actor budget, success criteria, required result)
D3.1 Commodity no-JS bots — 10⁶ req/h of forged/replayed/omitted tokens. Required: 0 accepted; issuance/outstanding caps hold.
D3.2 Stealth headless — Playwright/Puppeteer-stealth, undetected-chromedriver, patched Chromium, CDP input synthesis; legitimate solving at scale; adaptive decoy fill/skip; telemetry spoofing. Required: priced/escalated per §3.3; decoy never revealed; spoofed telemetry scored as evidence, never as "human."
D3.3 Native PoW farms — strongest rentable hardware: SHA-NI/AVX-512 CPUs, GPU SHA-256/Argon2id kernels, GPU/GMP RSW squaring. Required: published $/1,000 per rung; every value class priced above its abuse value; RSW shown non-parallelizable per challenge.
D3.4 Residential/mobile proxy pools — 10⁴–10⁶ IPs, ≥ 500 ASNs, IPv6 /64 rotation, IPv4 CGNAT. Required: ASN + target dimensions catch it; scope_failure_ratio fires; cost/accepted-abuse ≥ threshold; CGNAT-sharing real users not escalated beyond their own price.
D3.5 Credential stuffing — OpenBullet-class, 10⁶-pair list, 0.1–2% hit, over D3.4's pool, against login + reset. Required: cost/compromised-account ≥ critical threshold; each targeted account protected by step-up within ≤ 5 spread failures; zero victim lockouts; attacker identities denied within bounds.
D3.6 Token brokering/relay — malicious embeds, opener chains, foreign origins; relay to a farm within TTL; stockpiling; cross-scope/binding/node replay. Required: origin/scope/binding enforcement holds; stockpiles bounded by caps; zero cross-scope/binding acceptance.
D3.7 Human solver farms vs step-up — OTP relay, Evilginx-class phishing proxies, SIM-swap-assisted flows per handler. Required: WebAuthn phishing-resistant end-to-end; OTP rate-bound + single-use; relayed OTPs attributable.
D3.8 AI computer-use agents — unauthenticated abusive agent vs verified agent. Required: abusive agent priced/escalated; verified agent 100% within quota, 0% after revocation.
D3.9 Risk-engine gaming — trust farming, shared trusted cookies, hysteresis boundary riding, calibration poisoning via every outcome path, mark evasion by churn, forced victim escalation via shared network. Required: farmed trust never crosses ASNs; calibration movement ≤ 1 point; churned identities start untrusted; victims unaffected.
D3.10 Infrastructure attacker — Redis R/W compromise (dump replay, MAC strip/transplant, epoch/policy manipulation), Sentinel failover mid-consume, partitions, ±10 min clock skew, libfaketime jumps, primary restart with new run id. Run on all three storage backends. Required: zero acceptance of forged/stripped/replayed/rolled-back state under every fault schedule; HA authority refuses stale primaries.
D3.11 Denial-of-service — Argon verification amplification; issuance/SiteVerify floods with idempotency-key churn; oversized-record Lua CPU; asset-route/ETag abuse; readiness-probe storms; hysteresis-map churn. Required: p99 latency + admission bounds hold at 5× peak; legitimate traffic within SLO; no request exceeds its documented resource bound.
D3.12 Protocol/parser — CL/TE and HTTP/2→1.1 downgrade smuggling through the real proxy chain; Unicode/confusable/normalization differentials; duplicate-key/parameter pollution; full Rust↔PHP↔every-SDK differential of every wire format. Required: zero differentials, zero desyncs, across all SDKs.
D3.13 Client/supply chain — SRI bypass, service-worker MITM, malicious extensions, host-page prototype pollution/DOM clobbering, CSP-bypass gadgets, compromised CDN serving altered assets. Required: driver integrity, module provenance, fail-closed asset loading all hold.
D3.14 Privacy adversary — full Redis/SQLite dumps, logs, metrics, backups; attempt re-identification of a known IP/email/user and cross-epoch linkage. Required: no raw identifier recoverable; linkage bounded by documented session/principal lifetimes.
D3.15 Multi-tenant — shared store, colliding raw namespaces/secrets/scope names. Required: zero cross-tenant read/write/replay.
D3.16 Accessibility/compatibility — every password manager, browser autofill, screen reader, switch-access device in the registry. Required: zero decoy fills, zero escalations, full task completion; all autofill surfaces pass with exact versions.
D3.17 Cross-SDK parity attack — the same attack replayed through every server SDK and the sidecar. Required: identical rejection across all; no SDK is a weak link.
9.4 Techniques and tooling
D4.1 Coverage-guided fuzzing — cargo-fuzz (token/record/canonical/ interpreter/RSW/reply decoders), php-fuzzer (same surfaces), Lua scanner vs live redis-server. 24 h/target/release, zero crashes.
D4.2 Differential fuzzing — every Rust↔PHP↔SDK pair; 10⁷ inputs; zero divergences.
D4.3 Model checking — TLA+ (TLC/Apalache) for consume/commit/resume, SiteVerify idempotency, chain/disposition transitions, marks lifecycle, failover with WAIT/promotion, on all three storage backends. Zero safety violations for all bounded schedules.
D4.4 Chaos — Toxiproxy latency/partitions, Redis kill/failover, clock jumps; continuous in staging.
D4.5 Load — k6/Gatling realistic mixes at 1×/3×/5× peak.
D4.6 Browser red team — three engines + mobile, stealth tooling, full adversarial corpus.
D4.7 Cross-SDK conformance — one vector corpus asserted against every SDK and the sidecar; drift fails CI.
9.5 Release exit criteria (all required)

Zero open findings ≥ medium · every value class meets its D3 cost threshold · D3.5 targets met incl. zero victim lockouts · confirmed-legitimate escalation ≤ 0.1% and denial = 0 · human solve p95 within budget on every qualified tier incl. mobile · 100% verified-agent pass within quota · zero model-checking violations · zero fuzz divergences/crashes · B7.2 scale targets met on Cluster · D3.14 privacy scanner clean · D3.17 cross-SDK parity clean.

Part 10 — The automated LLM red-team engine (self-hosted, no cloud cost)

A permanent adversary built from locally-run open-weight models, so the entire program costs only the adopter's own compute.

10.1 Architecture
Orchestrator — a Rust/Python controller scheduling campaigns (Part 9), budgeting actor resources, and collecting economic metrics.
Local model runtime — open-weight models served by a local runtime (llama.cpp / vLLM / Ollama) on the maintainer's or adopter's own GPU/CPU. No external API is ever called. A small model handles routine fuzz-seed mutation; a larger local model handles novel-attack synthesis.
Agent roles (each a prompted loop over the local model + tools):
Recon agent — reads source, docs, and this spec; builds an attack-surface map and hypotheses.
Exploit-synthesis agent — writes new attack scripts (browser, protocol, risk-gaming) and new fuzz grammars.
Economic agent — runs kiwicaptcha:bench and the farms (D3.3) and computes cost/accepted-abuse per scope.
Triage agent — reproduces, minimizes, and classifies findings; files each as a failing-first regression test.
Regression agent — re-runs the full corpus of every past finding each night.
Tool sandbox — headless browsers, proxy-pool simulators, Toxiproxy, redis-server/SQLite, the fuzzers, and the TLA+ checker, all local.
10.2 Aggressiveness mandate
Continuous, not periodic. The engine runs 24/7 against staging.
Self-escalating. When a campaign finds nothing, the synthesis agent is prompted to combine two prior techniques, raise actor budgets, and target the newest code first.
Novelty-seeking. A coverage/novelty score rewards attacks that reach unexercised code paths or new economic regimes; the orchestrator allocates more budget to high-novelty lineages.
Full-knowledge. Agents are given the diff of every release and told to attack the change first.
Economic framing. Every synthesized attack must end with a cost number; "it was blocked" is insufficient — the agent must prove the block is also uneconomical to overcome.
10.3 Guardrails (so the automation itself is trustworthy)
Runs only against the project's own staging target; a hard allowlist prevents any external host.
All generated exploits are committed as tests; nothing runs that isn't reviewable.
Findings are reproduced deterministically before they gate a release (no flaky-gate).
The engine's own prompts, seeds, and model versions are pinned and committed, so a run is reproducible and auditable.
10.4 Outputs
A living THREATS.md of every attack class and its current economic result.
A public, continuously-updated cost-to-abuse table per value class — the product's headline evidence, and something no competitor publishes.
A permanent, ever-growing regression corpus.
Part 11 — Phased execution order
Part 0 (close open items).
Plane 1 (identity, incl. target + ASN + context-bound trust), then Plane 5.1–5.2 (outcomes + framework bridges), then Plane 3.3 (attacker denial). This trio delivers most of the abuse-stopping gain.
Plane 7.2–7.3 (sharding + zero-infra adapters) — required before scale campaigns are valid.
Plane 6 (agents + native solver), Plane 2 (evidence rebuild), Plane 3.1 (pricing), Plane 8 (observability + economics).
Part 6 SDKs in market-reach order: WordPress + Node + Python + the sidecar first (widest coverage), then the rest; compatibility shims in parallel.
Part 5/7 ease layer and the abuse_first profile throughout.
Parts 9–10 run from day one, gating every step; D3.1–D3.5 and the LLM engine come online first.
Part 12 — Consistency ledger (zero-contradiction check)

Explicit cross-checks resolving every potential tension in this document:
