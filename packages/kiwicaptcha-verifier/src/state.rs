//! The sidecar's shared state and request handlers.
//!
//! The verify path follows the core verifier's own sequence, with the
//! store lock split from the derivation:
//!
//! 1. consume: one short lock, the atomic pending to consumed transition
//!    (the one-shot authority; exactly one caller wins per nonce);
//! 2. derive: the proof check runs with no lock held (the expensive
//!    Argon2id or SHA-256 work is never serialized behind the store);
//! 3. commit: one short lock, the verdict lands on the consumed record.
//!
//! One-shot semantics are exactly the production model: the consume
//! burns the record on the first verify regardless of the outcome, so
//! each nonce drives at most one derivation and a failed candidate can
//! never fund a second attempt against the same record.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kiwicaptcha::challenge::{
    issue_challenge_with_profile, now_epoch_micros, BindingMode, ChallengeConfig, ChallengeRecord,
    PoWAlgorithm, DEFAULT_RSW_T,
};
use kiwicaptcha::profile::ChallengeProfile;
use kiwicaptcha::siteverify::siteverify_response_with_metadata;
use kiwicaptcha::verify::{
    verify_solution, RequestBindingExpectation, VerifyContext, VerifyOutcome,
};
use kiwicaptcha::SolutionToken;

use crate::config::{
    parse_scopes, BindingConfig, Rung, ScopePlan, StoreConfig, CHALLENGE_TTL_SECS, DEFAULT_PROFILE,
};
use crate::riskplane::{compose_rung, disposition_json, RiskPlane};
use crate::server::{constant_time_eq, PoolMetrics, Request, Response, METRICS_CONTENT_TYPE};
use crate::store::{
    AdmissionOutcome, CapacityLimits, ConsumeOutcome, FileStore, MemoryStore, PeekOutcome,
    RecordMeta, RecordStore,
};

/// The sidecar's counters: the verify outcomes and the risk-denied
/// issues, for `/metrics`.
#[derive(Default)]
struct Metrics {
    scrapes: AtomicU64,
    issues_denied: AtomicU64,
    verifies: AtomicU64,
    outcomes: Mutex<BTreeMap<String, u64>>,
}

impl Metrics {
    fn record_outcome(&self, code: &str) {
        self.verifies.fetch_add(1, Ordering::Relaxed);
        let mut map = self.outcomes.lock().expect("metrics lock");
        *map.entry(code.to_string()).or_insert(0) += 1;
    }
}

/// The full construction parameters, with hardened defaults. The binary
/// fills this from the CLI and the environment; tests assemble it
/// directly.
pub struct SidecarConfig {
    pub secret_key: String,
    pub bearer: Option<String>,
    pub plan: ScopePlan,
    pub listen_label: String,
    pub store: Arc<dyn RecordStore>,
    pub risk: Option<RiskPlane>,
    pub binding: BindingConfig,
    pub allow_no_remoteip: bool,
    pub rsw: Option<crate::config::RswTrapdoorConfig>,
    /// The execution arming key: when set, every issued challenge arms
    /// the ExecutionChallengeV1 dimension (the deterministic program
    /// mints from this key, the nonce, the scope and the action). The
    /// same floor applies as everywhere: arming without the key is the
    /// default, and a key below the core's byte floor is refused at
    /// startup.
    pub execution_key: Option<String>,
    /// The execution dimension protocol version of armed issuance,
    /// 1..=MAX_EXECUTION_VERSION.
    pub execution_version: u8,
    /// The server-owned required execution tier: 0 = no mandate (the
    /// default). When armed issuance would mint below this tier (the
    /// client's capability capped by the node's execution_version), the
    /// request is refused with the shared
    /// `CLIENT_EXECUTION_VERSION_UNSUPPORTED` answer — never silently
    /// downgraded to a weaker grammar, the controller's rule.
    pub execution_required_version: u8,
    /// The Argon admission budget in KiB: the sum of in-flight
    /// memory-hard derivations may never exceed it (the default four
    /// 64 MiB derivations). Meters the RECORD's own m_kib, so mixed
    /// Argon sizes share one honest memory bound.
    pub argon_budget_kib: u64,
    /// The hard live-pending-challenge ceiling (0 = no ceiling): TTL
    /// bounds record AGE, never cardinality — at R issues/s a TTL of T
    /// seconds holds about R×T live records — so an Internet-reachable
    /// issuer needs its own bound. Every backend enforces it inside the
    /// atomic admission (prune → count → compare → insert as one store
    /// transition): the in-process stores hold their state lock across
    /// the sequence, Redis runs it as one server-side Lua transaction
    /// shared by all nodes on the keyspace, and the expired-record
    /// prune is part of the admission itself so a full store reopens
    /// the moment its records expire.
    pub max_pending: u64,
    /// The hard total-live-record ceiling (0 = no ceiling): pending
    /// AND consumed tombstones together. The pending ceiling alone is
    /// not a resource bound — a client can issue, burn a candidate to
    /// move the record into consumed, and issue again, keeping pending
    /// slots free while store cardinality grows to burn_rate × TTL.
    /// This ceiling closes that loop under the same atomic admission.
    pub max_live_records: u64,
}

impl SidecarConfig {
    /// The minimal configuration: memory store, no risk plane, binding
    /// on, the default profile for every named scope.
    pub fn minimal(secret_key: String, scopes: Vec<String>, listen_label: &str) -> Self {
        let default_rung =
            crate::config::parse_rung(DEFAULT_PROFILE).expect("the default rung parses");
        let plan = parse_scopes(Some(&scopes.join(",")), default_rung)
            .expect("scope names from code are valid");
        SidecarConfig {
            secret_key,
            bearer: None,
            plan,
            listen_label: listen_label.to_string(),
            store: Arc::new(MemoryStore::new()),
            risk: None,
            binding: BindingConfig::Bound,
            allow_no_remoteip: false,
            rsw: None,
            execution_key: None,
            execution_version: 1,
            execution_required_version: 0,
            max_pending: crate::config::DEFAULT_MAX_PENDING_CHALLENGES,
            max_live_records: crate::config::DEFAULT_MAX_LIVE_RECORDS,
            argon_budget_kib: ArgonSemaphore::DEFAULT_MAX_KIB,
        }
    }
}

/// The typed `/issue` body. Unknown fields and mistyped values refuse
/// with the typed 400 (the public surface's strict parse), and an
/// absent `scope` keeps the documented `login` default — a present but
/// non-string scope is garbage, never a silent fallback.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueRequest {
    #[serde(default)]
    scope: Option<String>,
    remoteip: Option<String>,
    action: Option<String>,
    cdata: Option<String>,
    /// The application transaction binding, signed into the record like
    /// the Symfony controller signs it. Present-but-empty normalizes to
    /// unbound (the controller's rule); any other value must match the
    /// shared identifier charset or the request is refused with the
    /// controller's 422 `INVALID_REQUEST_BINDING` before any state.
    #[serde(default)]
    request_binding: Option<String>,
}

/// The typed `/verify` body — exactly the field set every shipped SDK
/// delegation sends (Go, Node, Python and .NET send a subset), unknown
/// fields refuse. An absent or null `expected_request_binding` keeps
/// the legacy unenforced posture; an empty string asserts the record
/// must carry no binding.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    token: Option<String>,
    scope: Option<String>,
    remoteip: Option<String>,
    expected_request_binding: Option<String>,
    operation_identity: Option<String>,
    /// Forwarded by the Go/Node/Python delegations for wire
    /// completeness. Accepted so the SDK payloads parse, and evaluated
    /// at the delegation seam — the sidecar's local gate does not
    /// re-run it (the SDK runs the telemetry gate first).
    #[serde(default)]
    enforce_telemetry: Option<bool>,
}

/// The shared interpretation of a raw `Kiwi-Execution-Max-Version`
/// header value — the exact mirror of the PHP core's
/// `ExecutionVersionPolicy::clientCapability()`, so this sidecar, the
/// Symfony controller, the PHP core callers and the reference
/// deployment can never diverge on what a client advertises:
///
/// - absent → the v1 compatibility floor (1);
/// - exactly `0` after trim → capability zero: the client cannot
///   execute the dimension at all, and issuance must never arm it;
/// - a canonical decimal → that capability, clamped to
///   1..=MAX_EXECUTION_VERSION;
/// - anything else (garbage, whitespace, a sign) → 1: a malformed
///   value is a capability claim, never a gate, and degrades.
fn client_execution_capability(raw: Option<&str>) -> u8 {
    let Some(raw) = raw else {
        return 1;
    };
    if raw.trim() == "0" {
        return 0;
    }
    // The canonical grammar is matched against the RAW value, exactly
    // like the PHP `preg_match('/^(?:0|[1-9][0-9]*)$/D', $raw)`: a
    // padded " 5 " is garbage and degrades to the floor.
    let canonical = {
        let bytes = raw.as_bytes();
        !bytes.is_empty() && bytes[0] != b'0' && bytes.iter().all(|b| b.is_ascii_digit())
    };
    if !canonical {
        return 1;
    }
    // A pure-digit value that overflows u64 is a huge canonical
    // advertisement: it clamps to the generator maximum, exactly like
    // the PHP integer cast then `min(..., MAX_EXECUTION_VERSION)`.
    let n = raw.parse::<u64>().unwrap_or(u64::MAX);
    (n.min(kiwicaptcha::execution::MAX_EXECUTION_VERSION as u64)) as u8
}

/// The shared identifier charset of scope, binding and action values:
/// 1..=128 bytes of `[A-Za-z0-9._:-]` — the same shape the Symfony
/// controller's `IDENTIFIER_PATTERN` enforces before anything reaches
/// an issuer.
fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(
            |b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-'),
        )
}

/// The shared operation-identity grammar: 1..=128 bytes of
/// `[A-Za-z0-9_-]` — the core's `OperationIdentity` contract (the
/// alphabet is what makes the Lua splice safe). Validated once at the
/// HTTP boundary so Memory, File and Redis accept exactly the same
/// identities instead of diverging (the Redis path already refuses
/// through the core; the in-process stores would have accepted any
/// string).
fn valid_operation_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

/// The Argon admission gate: a NONBLOCKING, memory-weighted budget
/// bounding concurrent memory-hard derivations. Each admission is
/// weighted by the record's own `m_kib` — the memory the derivation
/// will actually claim — so mixed-size Argon challenges share one KiB
/// budget (the default four 64 MiB derivations) and `workers × 64 MiB`
/// can never become the process working set. Admission is a `try`:
/// HTTP workers never sleep on this lock (a blocked worker pool is a
/// starvation DoS), and exhaustion answers `capacity_exceeded` with the
/// record left pending and retryable — the PHP
/// `VerificationAdmissionGate` contract. SHA/RSW never touch the gate.
pub struct ArgonSemaphore {
    budget_kib: Mutex<u64>,
    max_kib: u64,
}

impl ArgonSemaphore {
    /// The shipped default: four 64 MiB derivations.
    pub const DEFAULT_MAX_KIB: u64 = 4 * 65_536;

    /// A gate with the default budget.
    pub fn new() -> Self {
        Self::with_budget(Self::DEFAULT_MAX_KIB)
    }

    /// A gate with an explicit KiB budget (tests and tuning).
    pub fn with_budget(max_kib: u64) -> Self {
        ArgonSemaphore {
            budget_kib: Mutex::new(max_kib),
            max_kib,
        }
    }

    /// Try to reserve `kib` of the budget. `false` means exhaustion:
    /// the caller must refuse with `capacity_exceeded` and leave the
    /// record untouched. Never blocks beyond the mutex itself.
    pub fn try_acquire(&self, kib: u32) -> bool {
        let kib = kib as u64;
        if kib == 0 {
            // A record with no declared memory cost claims no budget
            // (verify_solution rejects the Argon parameters themselves
            // if they are malformed; admission only meters the weight).
            return true;
        }
        let mut budget = self.budget_kib.lock().expect("argon gate lock");
        if *budget >= kib {
            *budget -= kib;
            true
        } else {
            false
        }
    }

    /// Return a reservation. Must be called exactly once per
    /// successful `try_acquire`; the budget clamps at the ceiling so a
    /// stray release can never mint capacity.
    pub fn release(&self, kib: u32) {
        let kib = kib as u64;
        if kib == 0 {
            return;
        }
        let mut budget = self.budget_kib.lock().expect("argon gate lock");
        *budget = (*budget + kib).min(self.max_kib);
    }
}

impl Default for ArgonSemaphore {
    /// The shipped default: four 64 MiB derivations.
    fn default() -> Self {
        Self::new()
    }
}

/// The sidecar's shared state: configuration, store, metrics and the
/// connection-pool counters.
pub struct SidecarState {
    secret_key: String,
    bearer: Option<String>,
    secret_warned: bool,
    plan: ScopePlan,
    listen_label: String,
    store: Arc<dyn RecordStore>,
    risk: Option<RiskPlane>,
    binding: BindingConfig,
    allow_no_remoteip: bool,
    execution_key: Option<String>,
    execution_version: u8,
    execution_required_version: u8,
    /// The atomic store-admission ceilings (pending and total-live).
    capacity: CapacityLimits,
    rsw: Option<crate::config::RswTrapdoorConfig>,
    pub(crate) pool: PoolMetrics,
    metrics: Metrics,
    /// The Argon admission gate: a nonblocking, memory-weighted budget
    /// over the record's actual `m_kib`. Without it, `workers ×
    /// 64 MiB` (up to 64 GiB at the worker cap) is the theoretical
    /// Argon working-set floor. Admission is classified from the
    /// AUTHENTICATED stored record (never the present-day scope rung),
    /// so a risk-escalated or pre-reconfig Argon record still meters.
    /// SHA/RSW rungs never touch this gate.
    argon_gate: ArgonSemaphore,
}

impl SidecarState {
    /// The compatibility constructor: the hardened defaults (memory
    /// store, the default profile rung, binding on, no risk plane) over
    /// bare scope names.
    pub fn new(
        secret_key: String,
        bearer: Option<String>,
        scopes: Vec<String>,
        listen_label: &str,
    ) -> Self {
        let mut config = SidecarConfig::minimal(secret_key, scopes, listen_label);
        config.bearer = bearer;
        SidecarState::build(config)
    }

    /// The full constructor over validated configuration.
    pub fn build(config: SidecarConfig) -> Self {
        let secret_warned = crate::config::is_example_secret(&config.secret_key);
        SidecarState {
            secret_key: config.secret_key,
            bearer: config.bearer.filter(|b| !b.is_empty()),
            secret_warned,
            plan: config.plan,
            listen_label: config.listen_label,
            store: config.store,
            risk: config.risk,
            binding: config.binding,
            allow_no_remoteip: config.allow_no_remoteip,
            execution_key: config.execution_key,
            execution_version: config.execution_version,
            execution_required_version: config.execution_required_version,
            capacity: CapacityLimits {
                max_pending: config.max_pending,
                max_live: config.max_live_records,
            },
            rsw: config.rsw,
            pool: PoolMetrics::default(),
            metrics: Metrics::default(),
            argon_gate: ArgonSemaphore::with_budget(config.argon_budget_kib),
        }
    }

    /// The configured scopes with their rungs (the `/doctor` summary).
    pub fn scopes(&self) -> Vec<(String, Rung)> {
        self.plan.entries().to_vec()
    }

    fn authorized(&self, presented: Option<&str>) -> bool {
        match (&self.bearer, presented) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(expected), Some(presented)) => {
                constant_time_eq(expected.as_bytes(), presented.as_bytes())
            }
        }
    }

    /// The companion metadata as it may be USED: `action`, `cdata` and
    /// `decision_id` survive only when their MAC verifies over this
    /// record's challenge (the tag the issuer wrote at /issue time).
    /// A storage writer that swaps a field invalidates the tag and the
    /// fields are dropped — the success itself is unaffected, the
    /// risk confirmation id just never lands, and no attacker-chosen
    /// value can reach a response. Presentation-only by contract:
    /// applications must not authorize on these fields.
    fn authenticated_meta(&self, mut meta: RecordMeta, challenge: &str) -> RecordMeta {
        let derived = kiwicaptcha::keys::DerivedKeys::from_master(&self.secret_key, None);
        let authentic = kiwicaptcha::challenge::verify_companion_meta_mac(
            &derived,
            challenge,
            meta.action.as_deref(),
            meta.cdata.as_deref(),
            meta.decision_id.as_deref(),
            meta.mac.as_deref(),
        );
        if !authentic {
            meta.action = None;
            meta.cdata = None;
            meta.decision_id = None;
        }
        meta
    }

    /// The one request handler: pure over the parsed request, so the
    /// integration tests drive the same code the socket serves.
    pub(crate) fn handle(&self, req: &Request) -> Response {
        let bearer = req.bearer();
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/healthz") => Response::text(200, "ok\n"),
            ("GET", "/metrics") => {
                if !self.authorized(bearer) {
                    return Response::unauthorized();
                }
                self.metrics.scrapes.fetch_add(1, Ordering::Relaxed);
                Response::raw(200, METRICS_CONTENT_TYPE, self.render_metrics())
            }
            ("GET", "/doctor") => {
                if !self.authorized(bearer) {
                    return Response::unauthorized();
                }
                Response::json(200, self.render_doctor())
            }
            ("POST", "/verify") => {
                if !self.authorized(bearer) {
                    return Response::unauthorized();
                }
                if req.has_query {
                    // The public surface's shape: the challenge POSTs
                    // answer 422 QUERY_PARAMETERS_NOT_ALLOWED, so the
                    // sidecar answers the same code instead of silently
                    // dropping the query the sender wrote.
                    return self.error_response(
                        422,
                        "QUERY_PARAMETERS_NOT_ALLOWED",
                        "the /verify endpoint accepts no query parameters",
                    );
                }
                self.handle_verify(&req.body)
            }
            ("POST", "/issue") => {
                if !self.authorized(bearer) {
                    return Response::unauthorized();
                }
                if req.has_query {
                    return self.error_response(
                        422,
                        "QUERY_PARAMETERS_NOT_ALLOWED",
                        "the /issue endpoint accepts no query parameters",
                    );
                }
                self.handle_issue(&req.body, req.execution_max_version.as_deref())
            }
            _ => Response::json(404, "{\"error\":\"not found\"}\n".to_string()),
        }
    }

    /// Ingest a record minted elsewhere in this process (the embedder's
    /// own issuance path): the challenge must have been minted under
    /// this sidecar's secret. The store ceilings apply here too — a
    /// saturated store refuses the ingest exactly like /issue (the
    /// embedder then serves a challenge its verifier will answer
    /// record_not_found, the fail-closed shape of a refused write).
    pub fn inject_record(
        &self,
        record: ChallengeRecord,
        action: Option<String>,
        cdata: Option<String>,
    ) -> Result<(), String> {
        match self
            .store
            .try_put_pending(
            &record,
            {
                let mut meta = RecordMeta {
                    action,
                    cdata,
                    decision_id: None,
                    operation_identity: None,
                    remoteip: None,
                    scope: None,
                    mac: None,
                };
                // Bind the ingest's presentation fields to the challenge
                // exactly like /issue does (see companion_meta_mac).
                let derived = kiwicaptcha::keys::DerivedKeys::from_master(&self.secret_key, None);
                meta.mac = Some(kiwicaptcha::challenge::companion_meta_mac(
                    &derived,
                    &record.challenge,
                    meta.action.as_deref(),
                    meta.cdata.as_deref(),
                    meta.decision_id.as_deref(),
                ));
                meta
            },
            self.capacity,
            record.issued_at,
        ) {
            AdmissionOutcome::Admitted => Ok(()),
            AdmissionOutcome::PendingFull | AdmissionOutcome::LiveFull => Err(
                "challenge_store_full: the store ceiling refused the ingest; the record is not stored and must never be served".to_string(),
            ),
            AdmissionOutcome::Failed(e) => Err(e),
        }
    }

    /// Resolve the remoteip the request presents, under the binding
    /// posture. While IP binding is on (the default), a missing remoteip
    /// is a typed 400; the development escape hatch restores the
    /// loopback fallback explicitly.
    fn resolve_remoteip(&self, provided: Option<&str>) -> Result<String, Response> {
        let provided = provided.map(str::trim).filter(|s| !s.is_empty());
        match provided {
            Some(ip) => match ip.parse::<IpAddr>() {
                // The canonical text of the parsed address is what
                // binds: "2001:DB8::1" and "2001:db8:0:0:0:0:0:1" are
                // one identity, so the binding tag can never be split
                // by spelling. Non-ASCII, zone ids and other lookalike
                // forms never parse and are refused here.
                Ok(addr) => Ok(addr.to_string()),
                Err(_) => Err(self.error_response(
                    400,
                    "remoteip_invalid",
                    "remoteip must be a valid IPv4 or IPv6 address",
                )),
            },
            None => {
                if self.binding == BindingConfig::Bound && !self.allow_no_remoteip {
                    return Err(self.error_response(
                        400,
                        "remoteip_required",
                        "remoteip is required while IP binding is on (pass the client IP, or start with --allow-no-remoteip for loopback-only development)",
                    ));
                }
                Ok("127.0.0.1".to_string())
            }
        }
    }

    fn handle_issue(&self, body: &[u8], execution_header: Option<&str>) -> Response {
        let parsed: IssueRequest = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                return self.error_response(
                    400,
                    "bad_request",
                    "the request body is not a valid /issue document (unknown fields and mistyped values are refused)",
                )
            }
        };
        let scope = parsed.scope.as_deref().unwrap_or("login");
        let Some(scope_rung) = self.plan.rung_of(scope) else {
            let allowed = self.plan.names();
            let body = serde_json::json!({
                "error": "scope_not_allowed",
                "kiwi-code": "scope_not_allowed",
                "allowed": allowed,
            });
            return Response::json(400, format!("{body}\n"));
        };
        // The transaction binding, exactly the controller's contract:
        // null/absent (and an empty string, normalized to null) is the
        // unbound shape; anything else must match the shared identifier
        // charset or the request is refused with 422
        // INVALID_REQUEST_BINDING before any state exists.
        let request_binding: Option<&str> = match parsed.request_binding.as_deref() {
            None => None,
            Some("") => None,
            Some(binding) => {
                if !valid_identifier(binding) {
                    return self.error_response(
                        422,
                        "INVALID_REQUEST_BINDING",
                        "request_binding must be 1-128 characters of [A-Za-z0-9._:-]",
                    );
                }
                Some(binding)
            }
        };
        // The store ceilings as a PRUNED fast pre-check, before any
        // risk work or store write: `live_counts` drops expired
        // records within the call, so a store whose pending slots are
        // all held by expired records reopens here instead of
        // refusing forever (the count said full, the insert that
        // would prune never ran). The pre-check is advisory — the
        // authoritative bound is the atomic `try_put_pending` below,
        // which owns the count/insert race across every backend.
        if self.capacity.max_pending > 0 || self.capacity.max_live > 0 {
            let now_unix = now_epoch_micros() / 1_000_000;
            let (pending, live) = self.store.live_counts(now_unix);
            if self.capacity.max_pending > 0 && pending >= self.capacity.max_pending {
                return self.error_response(
                    503,
                    "challenge_store_full",
                    &format!(
                        "the live pending-challenge ceiling of {} is reached; retry shortly or raise --max-pending-challenges",
                        self.capacity.max_pending
                    ),
                );
            }
            if self.capacity.max_live > 0 && live >= self.capacity.max_live {
                return self.error_response(
                    503,
                    "challenge_store_full",
                    &format!(
                        "the total live-challenge ceiling of {} is reached; retry shortly or raise --max-live-records",
                        self.capacity.max_live
                    ),
                );
            }
        }
        let remoteip = match self.resolve_remoteip(parsed.remoteip.as_deref()) {
            Ok(ip) => ip,
            Err(response) => return response,
        };
        // The client's execution capability: an explicit zero means
        // the client cannot execute the dimension at all. When this
        // deployment arms every issuance (an execution key is
        // configured), minting an armed challenge would hand the client
        // a program it cannot run and minting an unarmed one would
        // silently waive the deployment's mandate — the deterministic
        // client-unsupported refusal answers instead, before any risk
        // assessment, admission slot or record write. Without a key
        // nothing arms, so the zero-capability client is served the
        // plain challenge exactly like any other.
        let client_capability = client_execution_capability(execution_header);
        let effective_version = client_capability.min(self.execution_version);
        if client_capability == 0 && self.execution_key.is_some() {
            return self.error_response(
                422,
                "CLIENT_EXECUTION_VERSION_UNSUPPORTED",
                "this deployment requires an execution-capable client; reload the page or upgrade the widget",
            );
        }
        // The server-owned required tier (execution_required_version):
        // the client capability is never an authority over the grammar
        // a hostile solver must solve. An armed request that would mint
        // below the mandate is refused deterministically — never
        // downgraded to the weaker grammar — the controller's rule.
        if self.execution_key.is_some()
            && self.execution_required_version > 0
            && effective_version < self.execution_required_version
        {
            return self.error_response(
                422,
                "CLIENT_EXECUTION_VERSION_UNSUPPORTED",
                &format!(
                    "this deployment requires the execution version {} client; reload the page or upgrade the widget",
                    self.execution_required_version
                ),
            );
        }
        // The pre-issue assessment when the risk plane is wired: the
        // disposition gates issuance. A deny refuses with 429; every
        // other action composes onto the issued rung (the ladder only
        // raises); step-up carries its disposition in the response.
        let (effective_rung, disposition, decision_id) = match &self.risk {
            None => (scope_rung, None, None),
            Some(plane) => {
                let ip: IpAddr = remoteip.parse().unwrap_or(IpAddr::from([127, 0, 0, 1]));
                match plane.assess_pre_issue(scope, ip) {
                    Ok(decision) => {
                        if decision.action == kiwicaptcha_risk::action::RiskAction::Deny {
                            self.metrics.issues_denied.fetch_add(1, Ordering::Relaxed);
                            let retry_ms = decision.retry_after_ms.unwrap_or(1000).max(1);
                            let body = serde_json::json!({
                                "error": "risk_denied",
                                "kiwi-code": "risk_denied",
                                "risk": disposition_json(&decision),
                            });
                            return Response::json(429, format!("{body}\n")).with_header(
                                "retry-after",
                                format!("{}", retry_ms.div_ceil(1000)),
                            );
                        }
                        let decision_id = Some(decision.decision_id.clone());
                        (
                            compose_rung(scope_rung, decision.action, self.rsw.is_some()),
                            Some(disposition_json(&decision)),
                            decision_id,
                        )
                    }
                    Err(e) => {
                        return self.error_response(503, "risk_unavailable", &e);
                    }
                }
            }
        };
        let config = self.challenge_config(effective_rung);
        let now_ns = now_epoch_micros();
        let now_unix = now_ns / 1_000_000;
        let profile = effective_rung.profile();
        let action = parsed.action.as_deref();
        // The grammar this issuance mints: the client's advertised
        // capability capped by the node's execution_version, the mirror
        // of the controller's effectiveExecutionVersion (the sidecar has
        // no central fleet floor of its own — the node cap is the
        // deployment tier).
        let issued = match self.execution_key {
            Some(_) => {
                match kiwicaptcha::challenge::issue_challenge_with_execution(
                    &config,
                    scope,
                    &remoteip,
                    now_unix,
                    now_ns,
                    0,
                    request_binding,
                    true,
                    action,
                    Some(effective_version),
                    false,
                ) {
                    Ok(i) => i,
                    Err(e) => return self.error_response(500, "issue_failed", &e.to_string()),
                }
            }
            None => match issue_challenge_with_profile(
                &config,
                scope,
                &remoteip,
                now_unix,
                now_ns,
                0,
                &profile,
                request_binding,
            ) {
                Ok(i) => i,
                Err(e) => return self.error_response(500, "issue_failed", &e.to_string()),
            },
        };
        let mut meta = RecordMeta {
            action: parsed.action.clone(),
            cdata: parsed.cdata.clone(),
            decision_id,
            operation_identity: None,
            remoteip: Some(remoteip.clone()),
            scope: Some(scope.to_string()),
            mac: None,
        };
        // Bind the presentation fields to this challenge: the reader
        // drops them whenever the stored tag does not verify, so a
        // storage writer can never make the success assert a swapped
        // action or cdata (sidecar-local contract; smeta is never
        // written by PHP).
        let derived = kiwicaptcha::keys::DerivedKeys::from_master(&self.secret_key, None);
        meta.mac = Some(kiwicaptcha::challenge::companion_meta_mac(
            &derived,
            &issued.record.challenge,
            meta.action.as_deref(),
            meta.cdata.as_deref(),
            meta.decision_id.as_deref(),
        ));
        // The authoritative admission: prune, both ceiling checks and
        // the insert are ONE store transition (the fast pre-check
        // above can race concurrent issuers; this cannot).
        match self
            .store
            .try_put_pending(&issued.record, meta, self.capacity, now_unix)
        {
            AdmissionOutcome::Admitted => {}
            AdmissionOutcome::PendingFull => {
                return self.error_response(
                    503,
                    "challenge_store_full",
                    &format!(
                        "the live pending-challenge ceiling of {} is reached; retry shortly or raise --max-pending-challenges",
                        self.capacity.max_pending
                    ),
                );
            }
            AdmissionOutcome::LiveFull => {
                return self.error_response(
                    503,
                    "challenge_store_full",
                    &format!(
                        "the total live-challenge ceiling of {} is reached; retry shortly or raise --max-live-records",
                        self.capacity.max_live
                    ),
                );
            }
            AdmissionOutcome::Failed(e) => {
                return self.error_response(500, "store_write_failed", &e);
            }
        }
        // The provider challenge wire (the camelCase PoW key set the
        // native solver parses), plus the additive profile and risk
        // fields. The optional security fields ride the canonical
        // snake_case spelling the stored-record schema owns: the native
        // clients parse `execution_program` (and `rsw_modulus` below),
        // so the challenge response carries the canonical names, never
        // a sidecar-private camelCase dialect.
        let c = &issued.challenge;
        let mut wire = serde_json::json!({
            "nonce": c.nonce,
            "challenge": c.challenge,
            "salt": c.salt,
            "algorithm": c.algorithm.as_str(),
            "mKib": c.m_kib,
            "t": c.t,
            "p": c.p,
            "targetBits": c.target_bits,
            "ttlSecs": c.ttl_secs,
            "minDurationMs": c.min_duration_ms,
            "prefix": c.prefix,
            "profile": effective_rung.as_str(),
        });
        if let Some(program) = &c.execution_program {
            wire["execution_program"] = serde_json::Value::String(program.clone());
            // The version the issuer actually minted (signed into the
            // record), never the node's configured cap: the wire echoes
            // the grammar the client must solve.
            wire["execution_version"] = serde_json::Value::from(
                issued.record.execution_version.unwrap_or(effective_version),
            );
        }
        // The rsw public modulus rides the client-facing response (the
        // solver squares modulo n); lambda never leaves the server. The
        // key is the solver's snake_case field.
        if let Some(modulus) = &c.rsw_modulus {
            wire["rsw_modulus"] = serde_json::Value::String(modulus.clone());
        }
        if let Some(risk) = disposition {
            wire["risk"] = risk;
        }
        Response::json(200, format!("{wire}\n"))
    }

    fn handle_verify(&self, body: &[u8]) -> Response {
        let parsed: VerifyRequest = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                self.metrics.record_outcome("bad_request");
                return self.provider_response(&["bad_request"], Some("bad_request"));
            }
        };
        let token = parsed.token.as_deref().unwrap_or("");
        let scope = parsed.scope.as_deref().unwrap_or("");
        // The caller's telemetry posture rides the delegation: when the
        // request asserts enforce_telemetry, this full-core pass enforces
        // it too, so a raw caller can never see a watered-down verdict
        // the SDKs would have refused locally.
        let enforce_telemetry = parsed.enforce_telemetry.unwrap_or(false);
        // Present field binds the record's signed request binding.
        // Absent or null keeps the legacy unenforced posture so older
        // callers still verify. An empty string asserts the record must
        // carry no binding at all.
        let expected_request_binding = match parsed.expected_request_binding.as_deref() {
            None => RequestBindingExpectation::Unenforced,
            Some("") => RequestBindingExpectation::Exact(None),
            Some(s) => RequestBindingExpectation::Exact(Some(s)),
        };
        let remoteip = match self.resolve_remoteip(parsed.remoteip.as_deref()) {
            Ok(ip) => ip,
            Err(response) => return response,
        };
        if token.is_empty() || scope.is_empty() {
            self.metrics.record_outcome("bad_request");
            return self.provider_response(&["missing-input-response"], Some("bad_request"));
        }
        // The configured scope set is an allow-list on verification
        // too, exactly like issuance and like every SDK verifier's
        // scopeAllowed gate: a scope outside the plan answers
        // wrong_scope in the provider envelope, never a record lookup.
        if self.plan.rung_of(scope).is_none() {
            self.metrics.record_outcome("wrong_scope");
            return self.provider_response(&["invalid-input-response"], Some("wrong_scope"));
        }
        let decoded = match SolutionToken::decode(token) {
            Ok(d) => d,
            Err(_) => {
                self.metrics.record_outcome("malformed_token");
                return self
                    .provider_response(&["invalid-input-response"], Some("malformed_token"));
            }
        };
        let now_ns = now_epoch_micros();
        let now_unix = now_ns / 1_000_000;
        // 0. Consume input grammar: the identity is validated once at
        // the HTTP boundary so Memory, File and Redis accept exactly
        // the same shapes (the core's OperationIdentity contract:
        // 1..=128 bytes of [A-Za-z0-9_-]).
        let request_identity = parsed
            .operation_identity
            .as_deref()
            .filter(|s| !s.is_empty());
        if let Some(identity) = request_identity {
            if !valid_operation_identity(identity) {
                self.metrics.record_outcome("bad_request");
                return self.provider_response(&["bad_request"], Some("bad_request"));
            }
        }
        // The canonical client IP the fresh derivation and the replay
        // gate both bind against (computed once, before any store
        // transition).
        let client_ip = match self.binding {
            BindingConfig::Bound => Some(remoteip.as_str()),
            BindingConfig::None => None,
        };
        // 1. Peek: the pre-consume snapshot. Admission classifies from
        // the AUTHENTICATED STORED RECORD's own algorithm and memory
        // weight — never the present-day scope rung — so a
        // risk-escalated SHA scope that minted Argon, or a scope
        // reconfigured Argon→SHA while records are outstanding, still
        // meters. An already-consumed record resolves its replay below
        // without spending a scarce reservation (the PHP verifier's
        // ordering). Admission is a try: exhaustion answers
        // capacity_exceeded with the record left pending and retryable,
        // and an HTTP worker never sleeps on the gate.
        let admitted_kib: Option<u32> = match self.store.peek(&decoded.nonce, now_unix) {
            PeekOutcome::Unavailable(_) => {
                self.metrics.record_outcome("storage_unavailable");
                return self.provider_response(&["internal-error"], Some("storage_unavailable"));
            }
            PeekOutcome::NotFound => {
                self.metrics.record_outcome("record_not_found");
                return self
                    .provider_response(&["invalid-input-response"], Some("record_not_found"));
            }
            PeekOutcome::Consumed => None,
            PeekOutcome::Pending(record) => {
                if record.algorithm == PoWAlgorithm::Argon2id {
                    if !self.argon_gate.try_acquire(record.m_kib) {
                        return self.capacity_response();
                    }
                    Some(record.m_kib)
                } else {
                    None
                }
            }
        };
        // 2. Consume: one short lock, the one-shot transition.
        let (record, meta) = match self
            .store
            .consume(&decoded.nonce, now_unix, request_identity)
        {
            ConsumeOutcome::Won { record, meta } => (*record, meta),
            ConsumeOutcome::AlreadyConsumed {
                meta,
                succeeded,
                stored,
            } => {
                // The consume lost the race (or this was a replay
                // against a peeked-consumed record): no derivation will
                // run, so the admission reservation (if this path took
                // one before the peek classified it as pending) goes
                // back immediately.
                if let Some(kib) = admitted_kib {
                    self.argon_gate.release(kib);
                }
                // An idempotent retry of a delegated verification (the
                // caller forwarded operation_identity) must return the
                // stored success, not already_consumed. Without the
                // identity the one-shot provider shape stands.
                //
                // SECURITY: a stored success is replayed only after TWO
                // independent gates. First the authenticated gate: the
                // committed server-state MAC must verify over the
                // record, verdict, binding and operation identity the
                // winner signed — a storage writer without the master
                // secret cannot produce one, and a MAC-less legacy
                // result is never a grant. Then the context gate: the
                // CURRENT request's scope, binding expectation, IP and
                // operation identity must all hold against the STORED
                // RECORD — the original result may have been
                // legitimate while the retry's context is not (the SDK
                // verifiers' replaySecurityCheck exists for exactly
                // this). Any mismatch is a plain already_consumed,
                // never a success.
                let identity = request_identity.unwrap_or("");
                let stored_identity = meta.operation_identity.as_deref().unwrap_or("");
                let identity_matches = !identity.is_empty() && identity == stored_identity;
                if identity_matches && succeeded == Some(true) {
                    let authentic = stored.as_ref().is_some_and(|s| {
                        kiwicaptcha::challenge::verify_consumed_result_mac(
                            &kiwicaptcha::keys::DerivedKeys::from_master(&self.secret_key, None),
                            &s.record.challenge,
                            true,
                            s.record.request_binding.as_deref(),
                            meta.operation_identity.as_deref(),
                            &s.mac,
                        )
                    });
                    if let (true, Some(s)) = (authentic, stored.as_ref()) {
                        // Scope: the record's own signed scope is the
                        // authority; a retry under any other scope is a
                        // plain replay.
                        let scope_ok = s.record.scope == scope;
                        // Binding: the exact-equality contract the fresh
                        // derivation enforces, re-run against the stored
                        // record's binding (constant time, like the
                        // core's own expectation check).
                        let binding_ok = match &expected_request_binding {
                            RequestBindingExpectation::Unenforced => true,
                            RequestBindingExpectation::Exact(None) => {
                                s.record.request_binding.is_none()
                            }
                            RequestBindingExpectation::Exact(Some(want)) => {
                                match s.record.request_binding.as_deref() {
                                    Some(have) => {
                                        constant_time_eq(have.as_bytes(), want.as_bytes())
                                    }
                                    None => false,
                                }
                            }
                        };
                        // IP: the record's SIGNED binding tag is the
                        // authority — re-derived from this request's
                        // canonical client IP exactly like the fresh
                        // derivation does (v1 legacy hash vs the
                        // nonce-bound tag), constant-time compared.
                        // Companion metadata (smeta.remoteip) never
                        // authorizes a replay: a storage writer may
                        // mutate it without holding the master secret.
                        let ip_ok = if s.record.binding_tag.is_empty() {
                            true
                        } else if let Some(ip) = client_ip {
                            let expected: Option<String> = match s.record.protocol_version {
                                1 => Some(kiwicaptcha::challenge::hash_ip(ip, &self.secret_key)),
                                _ => kiwicaptcha::challenge::binding_tag_for_tenant(
                                    &s.record.nonce,
                                    ip,
                                    &self.secret_key,
                                    None,
                                )
                                .ok(),
                            };
                            expected.as_deref().is_some_and(|tag| {
                                constant_time_eq(tag.as_bytes(), s.record.binding_tag.as_bytes())
                            })
                        } else {
                            false
                        };
                        if scope_ok && binding_ok && ip_ok {
                            // A replay echoes nothing the companion MAC
                            // does not cover: swap action/cdata in the
                            // store and the success still returns, but
                            // never with the attacker's values on it.
                            let meta = self.authenticated_meta(meta, s.record.challenge.as_str());
                            self.metrics.record_outcome("ok");
                            let mut wire = serde_json::json!({
                                "success": true,
                                "kiwi-code": "ok",
                                "error-codes": [],
                            });
                            if let Some(action) = &meta.action {
                                wire["action"] = action.clone().into();
                            }
                            if let Some(cdata) = &meta.cdata {
                                wire["cdata"] = cdata.clone().into();
                            }
                            return Response::json(200, format!("{wire}\n"));
                        }
                        // Context mismatch: the stored success belongs to a
                        // different security context. Refuse, never replay.
                    }
                    // MAC mismatch or absent material: the stored success
                    // is not authentic under this sidecar's secret.
                }
                self.metrics.record_outcome("already_consumed");
                return self.provider_response(&["timeout-or-duplicate"], Some("already_consumed"));
            }
            ConsumeOutcome::NotFound => {
                if let Some(kib) = admitted_kib {
                    self.argon_gate.release(kib);
                }
                self.metrics.record_outcome("record_not_found");
                return self
                    .provider_response(&["invalid-input-response"], Some("record_not_found"));
            }
            ConsumeOutcome::Unavailable(_) => {
                if let Some(kib) = admitted_kib {
                    self.argon_gate.release(kib);
                }
                self.metrics.record_outcome("storage_unavailable");
                return self.provider_response(&["internal-error"], Some("storage_unavailable"));
            }
        };
        // The companion presentation fields authenticate against this
        // record's challenge before anything reads them (the risk
        // confirmation id and the success echo below): a tampered or
        // legacy-unsigned companion contributes nothing instead of
        // surfacing storage-writer-chosen metadata.
        let meta = self.authenticated_meta(meta, &record.challenge);
        // The test-only derivation gate (never installed in production):
        // a derivation blocked here sits after the consume transition
        // above has returned and before the commit below runs, holding
        // nothing — which is exactly the invariant the integration tests
        // prove through this seam. The admission reservation (argons
        // only) IS held across the derivation: it is released after the
        // proof returns, on every path below.
        derivation_gate::consult(&decoded.nonce);
        // 3. Derive: no lock held. The scope's rung supplies the timing
        // floor even for a foreign injected record; the record's own
        // floor rides on top (the verifier takes the max). The Argon
        // admission itself was already classified and reserved from the
        // RECORD before the consume (never from this rung).
        let mut record = record;
        let floor = self
            .plan
            .rung_of(scope)
            .unwrap_or_else(|| self.default_rung())
            .min_duration_ms();
        let outcome = verify_solution(&mut VerifyContext {
            record: &mut record,
            secret_key: &self.secret_key,
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter: decoded.counter,
            duration_ms: decoded.duration_ms,
            now_unix: None,
            now_ns,
            min_duration_ms: floor,
            expected_scope: Some(scope),
            expected_request_binding,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip,
            // The token's own optional execution segments: an armed
            // record demands the browser-trace walker, which only this
            // full-core surface carries, so the sidecar is the one
            // verifier that can resolve an execution binding.
            execution_digest: decoded.execution_digest.as_deref(),
            execution_trace: decoded.execution_trace.as_deref(),
            telemetry: Some(&decoded.telemetry),
            enforce_telemetry,
            // The one-shot bound is the store transition above (one
            // derivation per nonce, the production model), so no
            // per-record attempt ceiling applies.
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: decoded.rsw_proof.as_deref(),
            rsw_modulus_n: self.rsw.as_ref().map(|r| r.modulus_n.as_str()),
            rsw_lambda: self.rsw.as_ref().map(|r| r.lambda.as_str()),
            rsw_keyring: None,
        });
        if let Some(kib) = admitted_kib {
            self.argon_gate.release(kib);
        }
        // 4. Commit: one short lock, the verdict lands. The result is
        // written through the authenticated seam: a MAC over the
        // challenge, verdict, binding and operation identity, so a
        // storage writer without the master secret cannot forge
        // `valid=true` on a consumed record. Only the Redis backend
        // stores the MAC; memory and file fall back to the boolean.
        let valid = matches!(outcome, VerifyOutcome::Valid { .. });
        let op_id = meta.operation_identity.as_deref();
        let mac = kiwicaptcha::challenge::consumed_result_mac(
            &kiwicaptcha::keys::DerivedKeys::from_master(&self.secret_key, None),
            &record.challenge,
            valid,
            record.request_binding.as_deref(),
            op_id,
        );
        self.store
            .commit_with_mac(&decoded.nonce, &record, valid, op_id, Some(&mac));
        let core_code = match &outcome {
            VerifyOutcome::Valid { .. } => "ok",
            VerifyOutcome::Invalid(reason) => reason.code(),
        };
        self.metrics.record_outcome(core_code);
        // The risk plane reports outcomes: a valid solve confirms the
        // recorded decision in the outcome ledger, an invalid one books
        // the invalid-proof event. Best effort on both.
        if let Some(plane) = &self.risk {
            let ip: IpAddr = remoteip.parse().unwrap_or(IpAddr::from([127, 0, 0, 1]));
            if valid {
                if let Some(decision_id) = &meta.decision_id {
                    plane.confirm_legitimate(scope, ip, decision_id, &decoded.nonce);
                }
            } else {
                plane.report_invalid_proof(scope, ip, &decoded.nonce);
            }
        }
        let response = siteverify_response_with_metadata(
            &outcome,
            Some(&record),
            meta.action.as_deref(),
            meta.cdata.as_deref(),
        );
        match serde_json::to_value(&response) {
            Ok(mut value) => {
                value["kiwi-code"] = serde_json::Value::String(core_code.to_string());
                Response::json(200, format!("{value}\n"))
            }
            Err(_) => self.provider_response(&["internal-error"], Some("internal_error")),
        }
    }

    fn default_rung(&self) -> Rung {
        crate::config::parse_rung(DEFAULT_PROFILE).expect("the default rung parses")
    }

    /// The challenge config under the configured rung. The profile
    /// supplies the proof-of-work parameters; the timing floor derives
    /// from the core (never zero) at issuance.
    fn challenge_config(&self, rung: Rung) -> ChallengeConfig {
        let profile = rung.profile();
        ChallengeConfig {
            secret_key: self.secret_key.clone(),
            algorithm: profile.algorithm,
            m_kib: profile.m_kib,
            t: if profile.algorithm == kiwicaptcha::challenge::PoWAlgorithm::Rsw {
                self.rsw.as_ref().map(|r| r.t).unwrap_or(DEFAULT_RSW_T)
            } else {
                profile.t
            },
            p: profile.p,
            target_bits: profile.target_bits as u32,
            argon2_target_bits: profile.target_bits as u32,
            ttl_secs: CHALLENGE_TTL_SECS,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: profile.target_bits as u32,
            auto_tune_max_bits: profile.target_bits as u32,
            binding_mode: match self.binding {
                BindingConfig::Bound => BindingMode::Bound,
                BindingConfig::None => BindingMode::None,
            },
            policy_version: 1,
            region: None,
            issuer: None,
            kid: 1,
            execution_key: self.execution_key.clone(),
            rsw_modulus_n: self.rsw.as_ref().map(|r| r.modulus_n.clone()),
            rsw_lambda: self.rsw.as_ref().map(|r| r.lambda.clone()),
            rsw_t: self.rsw.as_ref().map(|r| r.t).unwrap_or(DEFAULT_RSW_T),
            tenant: None,
        }
    }

    /// The typed error shape for the endpoint-level refusals (400 and
    /// up): a stable machine code plus a human detail.
    fn error_response(&self, status: u16, code: &str, detail: &str) -> Response {
        let body = serde_json::json!({
            "error": code,
            "kiwi-code": code,
            "detail": detail,
        });
        Response::json(status, format!("{body}\n"))
    }

    /// The typed admission-exhaustion refusal: the core's
    /// `capacity_exceeded` vocabulary (internal-error family — every
    /// SDK maps it to the retryable storage disposition), the record
    /// left pending and intact. Never a burn, never a block.
    fn capacity_response(&self) -> Response {
        self.metrics.record_outcome("capacity_exceeded");
        let response = siteverify_response_with_metadata(
            &VerifyOutcome::Invalid(kiwicaptcha::verify::VerifyError::CapacityExceeded),
            None,
            None,
            None,
        );
        match serde_json::to_value(&response) {
            Ok(mut value) => {
                value["kiwi-code"] = serde_json::Value::String("capacity_exceeded".to_string());
                Response::json(200, format!("{value}\n"))
            }
            Err(_) => self.provider_response(&["internal-error"], Some("capacity_exceeded")),
        }
    }

    /// The provider failure shape with the additive core code (status
    /// 200; the siteverify vocabulary lives in the body).
    fn provider_response(&self, codes: &[&str], core: Option<&str>) -> Response {
        let mut value = serde_json::json!({
            "success": false,
            "challenge_ts": serde_json::Value::Null,
            "hostname": serde_json::Value::Null,
            "action": serde_json::Value::Null,
            "cdata": serde_json::Value::Null,
            "error-codes": codes,
        });
        if let Some(core) = core {
            value["kiwi-code"] = serde_json::Value::String(core.to_string());
        }
        Response::json(200, format!("{value}\n"))
    }

    fn render_metrics(&self) -> String {
        let scrapes = self.metrics.scrapes.load(Ordering::Relaxed);
        let denied = self.metrics.issues_denied.load(Ordering::Relaxed);
        let (accepted, rejected, timeouts) = self.pool.snapshot();
        let outcomes = self.metrics.outcomes.lock().expect("metrics lock").clone();
        let (pending, consumed) = self.store.counts();
        let mut out = String::new();
        out.push_str("# HELP kiwicaptcha_verifier_verifies_total Siteverify requests by outcome (the core wire-code vocabulary).\n");
        out.push_str("# TYPE kiwicaptcha_verifier_verifies_total counter\n");
        for (code, count) in &outcomes {
            out.push_str(&format!(
                "kiwicaptcha_verifier_verifies_total{{outcome=\"{code}\"}} {count}\n"
            ));
        }
        if outcomes.is_empty() {
            out.push_str("kiwicaptcha_verifier_verifies_total{outcome=\"ok\"} 0\n");
        }
        out.push_str("# HELP kiwicaptcha_exporter_scrapes_total Total metrics scrapes served by this exporter.\n");
        out.push_str("# TYPE kiwicaptcha_exporter_scrapes_total counter\n");
        out.push_str(&format!("kiwicaptcha_exporter_scrapes_total {scrapes}\n"));
        out.push_str("# HELP kiwicaptcha_verifier_records The store's live challenge records.\n");
        out.push_str("# TYPE kiwicaptcha_verifier_records gauge\n");
        out.push_str(&format!(
            "kiwicaptcha_verifier_records{{state=\"pending\"}} {pending}\nkiwicaptcha_verifier_records{{state=\"consumed\"}} {consumed}\n"
        ));
        out.push_str("# HELP kiwicaptcha_verifier_issues_denied_total Issuance requests refused by the risk plane.\n");
        out.push_str("# TYPE kiwicaptcha_verifier_issues_denied_total counter\n");
        out.push_str(&format!(
            "kiwicaptcha_verifier_issues_denied_total {denied}\n"
        ));
        out.push_str(
            "# HELP kiwicaptcha_verifier_pool_connections Connection-pool counters since start.\n",
        );
        out.push_str("# TYPE kiwicaptcha_verifier_pool_connections counter\n");
        out.push_str(&format!(
            "kiwicaptcha_verifier_pool_connections{{kind=\"accepted\"}} {accepted}\nkiwicaptcha_verifier_pool_connections{{kind=\"rejected\"}} {rejected}\nkiwicaptcha_verifier_pool_connections{{kind=\"timed_out\"}} {timeouts}\n"
        ));
        out
    }

    fn render_doctor(&self) -> String {
        let secret_ok = self.secret_key.len() >= crate::config::MIN_SECRET_BYTES;
        let store_probe = self.store.probe();
        let mut checks = Vec::new();
        checks.push(serde_json::json!({
            "name": "secret",
            "ok": secret_ok && !self.secret_warned,
            "detail": if self.secret_warned {
                format!("{} bytes, a published example value accepted only through the development escape hatch", self.secret_key.len())
            } else {
                format!("{} bytes ({} is the enforced minimum)", self.secret_key.len(), crate::config::MIN_SECRET_BYTES)
            },
        }));
        checks.push(serde_json::json!({
            "name": "store",
            // A real probe, not a constant: the Redis backend must
            // answer a PING and the file store must list its records
            // directory for this check to stay green.
            "ok": store_probe.is_ok(),
            "detail": match &store_probe {
                Ok(fact) => format!("{} — probe: {fact}", self.store.describe()),
                Err(reason) => format!("{} — probe FAILED: {reason}", self.store.describe()),
            },
        }));
        checks.push(serde_json::json!({
            "name": "auth",
            "ok": true,
            "detail": if self.bearer.is_some() {
                "bearer credential configured (constant-time compare on /verify, /issue, /metrics and /doctor)".to_string()
            } else {
                "no bearer configured: the loopback-only binding is the boundary (configure one before exposing the socket further)".to_string()
            },
        }));
        checks.push(serde_json::json!({
            "name": "listen",
            "ok": true,
            "detail": self.listen_label,
        }));
        checks.push(serde_json::json!({
            "name": "binding",
            "ok": true,
            "detail": match self.binding {
                BindingConfig::Bound => if self.allow_no_remoteip {
                    "bound (remoteip required; the loopback development escape hatch is set)".to_string()
                } else {
                    "bound (remoteip required on /issue and /verify)".to_string()
                },
                BindingConfig::None => "none (no nonce-bound IP tag; remoteip optional)".to_string(),
            },
        }));
        checks.push(serde_json::json!({
            "name": "risk",
            "ok": true,
            "detail": match &self.risk {
                Some(plane) => format!("adaptive risk plane wired (policy version {})", plane.policy_version()),
                None => "not wired: this all-in-one binary runs without abuse-risk telemetry; the bundle is the full plane".to_string(),
            },
        }));
        let ok = checks
            .iter()
            .filter(|c| c["ok"] == serde_json::Value::Bool(true))
            .count()
            == checks.len();
        let rungs: serde_json::Map<String, serde_json::Value> = self
            .plan
            .entries()
            .iter()
            .map(|(name, rung)| (name.clone(), serde_json::json!(rung.as_str())))
            .collect();
        serde_json::to_string(&serde_json::json!({
            "ok": ok,
            "checks": checks,
            "scopes": rungs,
        }))
        .unwrap_or_else(|_| "{\"ok\":false}\n".to_string())
            + "\n"
    }
}

/// Re-exported for the integration tests: the rung table's profile of
/// the default rung (the docs reference it).
pub fn default_profile() -> ChallengeProfile {
    crate::config::parse_rung(DEFAULT_PROFILE)
        .expect("the default rung parses")
        .profile()
}

/// The test-only derivation gate: a process-wide hook consulted on the
/// verify path between the consume transition and the derivation. The
/// integration tests install a closure that blocks one chosen nonce (a
/// channel receive) to hold a verification mid-flight while another
/// completes, which proves directly that the store is never held across
/// a hash derivation — the wall-clock concurrency estimate this replaced
/// could not tell lock serialization from memory-bandwidth contention.
/// Production installs nothing: the consult is one mutex-guarded option
/// check per verify.
#[doc(hidden)]
pub mod derivation_gate {
    use std::sync::{Arc, Mutex, OnceLock};

    type Hook = Arc<dyn Fn(&str) + Send + Sync>;

    fn slot() -> &'static Mutex<Option<Hook>> {
        static SLOT: OnceLock<Mutex<Option<Hook>>> = OnceLock::new();
        SLOT.get_or_init(|| Mutex::new(None))
    }

    /// Install the hook (replacing any previous one).
    pub fn install(hook: impl Fn(&str) + Send + Sync + 'static) {
        *slot().lock().expect("the derivation gate lock") = Some(Arc::new(hook));
    }

    /// Remove the hook.
    pub fn remove() {
        *slot().lock().expect("the derivation gate lock") = None;
    }

    /// Consulted by the verify path. The hook clone runs with no lock
    /// held: it may block arbitrarily long.
    pub fn consult(nonce: &str) {
        let hook = slot().lock().expect("the derivation gate lock").clone();
        if let Some(hook) = hook {
            hook(nonce);
        }
    }
}

/// The provider challenge wire (the camelCase PoW key set the native
/// solver parses, with the optional security fields on the canonical
/// snake_case spellings) of a minted challenge, spelled exactly as the
/// `/issue` endpoint emits it. The integration tests drive the same
/// renderer.
pub fn issue_wire_of(issued: &kiwicaptcha::challenge::Issued) -> String {
    let c = &issued.challenge;
    let mut wire = serde_json::json!({
        "nonce": c.nonce,
        "challenge": c.challenge,
        "salt": c.salt,
        "algorithm": c.algorithm.as_str(),
        "mKib": c.m_kib,
        "t": c.t,
        "p": c.p,
        "targetBits": c.target_bits,
        "ttlSecs": c.ttl_secs,
        "minDurationMs": c.min_duration_ms,
        "prefix": c.prefix,
    });
    if let Some(modulus) = &c.rsw_modulus {
        wire["rsw_modulus"] = serde_json::Value::String(modulus.clone());
    }
    format!("{wire}\n")
}

/// The store backends the binary can select (re-exported so the tests
/// and the binary share one construction path).
pub fn open_store(
    config: &StoreConfig,
    limits: crate::store::CapacityLimits,
) -> Result<Arc<dyn RecordStore>, String> {
    match config {
        StoreConfig::Memory => Ok(Arc::new(MemoryStore::new())),
        StoreConfig::File(path) => Ok(Arc::new(FileStore::open(path)?)),
        #[cfg(feature = "redis-store")]
        StoreConfig::Redis(url) => Ok(Arc::new(crate::store::RedisStore::connect(
            url,
            "kiwi:verifier:",
            limits,
        )?)),
        #[cfg(not(feature = "redis-store"))]
        StoreConfig::Redis(url) => Err(format!(
            "KIWI_STORE={url} needs the redis-store build feature (rebuild with: cargo build --features redis-store); this build serves memory and file stores only"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned cross-language capability contract, consumed the way
    /// the PHP `ExecutionCapabilityMatrixTest` consumes it: one
    /// fixture, one interpretation, no issuer/parser disagreement.
    const CAPABILITY_MATRIX: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/execution-v1/capability-matrix.json"
    ));

    #[test]
    fn capability_matrix_fixture_pins_the_shared_policy() {
        let matrix: serde_json::Value =
            serde_json::from_str(CAPABILITY_MATRIX).expect("the capability matrix parses");
        assert_eq!(
            matrix["header"], "Kiwi-Execution-Max-Version",
            "the sidecar parses exactly the fixture's header"
        );

        // Every native client advertises 0: capability none, never armed.
        for id in ["android", "ios", "flutter", "react-native-native"] {
            let client = matrix["clients"]
                .as_array()
                .expect("clients array")
                .iter()
                .find(|c| c["id"] == id)
                .unwrap_or_else(|| panic!("the matrix must pin {id}"));
            assert_eq!(client["capability"], 0, "{id} must advertise capability 0");
            assert_eq!(
                client_execution_capability(Some("0")),
                0,
                "an explicit 0 reads as CAPABILITY_NONE for {id}"
            );
        }

        // The shared interpretations, edge for edge with the PHP test.
        for raw in [None, Some(""), Some("  "), Some("garbage")] {
            assert_eq!(
                client_execution_capability(raw),
                1,
                "absent/empty/whitespace/garbage reads as the v1 floor (got {raw:?})"
            );
        }
        assert_eq!(client_execution_capability(Some("2")), 2);
        assert_eq!(
            client_execution_capability(Some("01")),
            1,
            "leading zeros are not canonical"
        );
        assert_eq!(
            client_execution_capability(Some("99")),
            kiwicaptcha::execution::MAX_EXECUTION_VERSION,
            "a huge canonical advertisement clamps to the generator maximum"
        );
    }
}
