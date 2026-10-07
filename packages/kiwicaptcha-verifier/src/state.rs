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
    DEFAULT_RSW_T,
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
use crate::store::{ConsumeOutcome, FileStore, MemoryStore, RecordMeta, RecordStore};

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
        }
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
    rsw: Option<crate::config::RswTrapdoorConfig>,
    pub(crate) pool: PoolMetrics,
    metrics: Metrics,
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
        let secret_warned = crate::config::EXAMPLE_SECRETS.contains(&config.secret_key.as_str());
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
            rsw: config.rsw,
            pool: PoolMetrics::default(),
            metrics: Metrics::default(),
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
                self.handle_verify(&req.body)
            }
            ("POST", "/issue") => {
                if !self.authorized(bearer) {
                    return Response::unauthorized();
                }
                self.handle_issue(&req.body)
            }
            _ => Response::json(404, "{\"error\":\"not found\"}\n".to_string()),
        }
    }

    /// Ingest a record minted elsewhere in this process (the embedder's
    /// own issuance path): the challenge must have been minted under
    /// this sidecar's secret.
    pub fn inject_record(
        &self,
        record: ChallengeRecord,
        action: Option<String>,
        cdata: Option<String>,
    ) {
        let _ = self.store.put_pending(
            &record,
            RecordMeta {
                action,
                cdata,
                decision_id: None,
            },
        );
    }

    /// Resolve the remoteip the request presents, under the binding
    /// posture. While IP binding is on (the default), a missing remoteip
    /// is a typed 400; the development escape hatch restores the
    /// loopback fallback explicitly.
    fn resolve_remoteip(&self, parsed: &serde_json::Value) -> Result<String, Response> {
        let provided = parsed
            .get("remoteip")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
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

    fn handle_issue(&self, body: &[u8]) -> Response {
        let parsed: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                return self.error_response(
                    400,
                    "bad_request",
                    "the request body is not valid JSON",
                )
            }
        };
        let scope = parsed
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("login");
        let Some(scope_rung) = self.plan.rung_of(scope) else {
            let allowed = self.plan.names();
            let body = serde_json::json!({
                "error": "scope_not_allowed",
                "kiwi-code": "scope_not_allowed",
                "allowed": allowed,
            });
            return Response::json(400, format!("{body}\n"));
        };
        let remoteip = match self.resolve_remoteip(&parsed) {
            Ok(ip) => ip,
            Err(response) => return response,
        };
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
                            compose_rung(scope_rung, decision.action),
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
        let action = parsed.get("action").and_then(|v| v.as_str());
        let issued = match self.execution_key {
            Some(_) => {
                match kiwicaptcha::challenge::issue_challenge_with_execution(
                    &config,
                    scope,
                    &remoteip,
                    now_unix,
                    now_ns,
                    0,
                    None,
                    true,
                    action,
                    Some(self.execution_version),
                    false,
                ) {
                    Ok(i) => i,
                    Err(e) => return self.error_response(500, "issue_failed", &e.to_string()),
                }
            }
            None => match issue_challenge_with_profile(
                &config, scope, &remoteip, now_unix, now_ns, 0, &profile, None,
            ) {
                Ok(i) => i,
                Err(e) => return self.error_response(500, "issue_failed", &e.to_string()),
            },
        };
        let meta = RecordMeta {
            action: parsed
                .get("action")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            cdata: parsed
                .get("cdata")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            decision_id,
        };
        if let Err(e) = self.store.put_pending(&issued.record, meta) {
            return self.error_response(500, "store_write_failed", &e);
        }
        // The provider challenge wire (the camelCase key set the native
        // solver parses), plus the additive profile and risk fields.
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
            wire["executionProgram"] = serde_json::Value::String(program.clone());
            wire["executionVersion"] = serde_json::Value::from(self.execution_version);
        }
        if let Some(risk) = disposition {
            wire["risk"] = risk;
        }
        Response::json(200, format!("{wire}\n"))
    }

    fn handle_verify(&self, body: &[u8]) -> Response {
        let parsed: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                self.metrics.record_outcome("bad_request");
                return self.provider_response(&["bad_request"], Some("bad_request"));
            }
        };
        let token = parsed.get("token").and_then(|v| v.as_str()).unwrap_or("");
        let scope = parsed.get("scope").and_then(|v| v.as_str()).unwrap_or("");
        // Present field binds the record's signed request binding.
        // Absent or null keeps the legacy unenforced posture so older
        // callers still verify. An empty string asserts the record must
        // carry no binding at all.
        let expected_request_binding = match parsed.get("expected_request_binding") {
            None | Some(serde_json::Value::Null) => RequestBindingExpectation::Unenforced,
            Some(serde_json::Value::String(s)) if s.is_empty() => {
                RequestBindingExpectation::Exact(None)
            }
            Some(serde_json::Value::String(s)) => {
                RequestBindingExpectation::Exact(Some(s.as_str()))
            }
            Some(_) => {
                self.metrics.record_outcome("bad_request");
                return self.provider_response(&["bad_request"], Some("bad_request"));
            }
        };
        let remoteip = match self.resolve_remoteip(&parsed) {
            Ok(ip) => ip,
            Err(response) => return response,
        };
        if token.is_empty() || scope.is_empty() {
            self.metrics.record_outcome("bad_request");
            return self.provider_response(&["missing-input-response"], Some("bad_request"));
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
        // 1. Consume: one short lock, the one-shot transition.
        let (record, meta) = match self.store.consume(&decoded.nonce, now_unix) {
            ConsumeOutcome::Won { record, meta } => (*record, meta),
            ConsumeOutcome::AlreadyConsumed { meta, succeeded } => {
                // An idempotent retry of a delegated verification (the
                // caller forwarded operation_identity) must return the
                // stored success, not already_consumed. Without the
                // identity the one-shot provider shape stands.
                let identity = parsed
                    .get("operation_identity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if identity != "" && succeeded == Some(true) {
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
                self.metrics.record_outcome("already_consumed");
                return self.provider_response(&["timeout-or-duplicate"], Some("already_consumed"));
            }
            ConsumeOutcome::NotFound => {
                self.metrics.record_outcome("record_not_found");
                return self
                    .provider_response(&["invalid-input-response"], Some("record_not_found"));
            }
            ConsumeOutcome::Unavailable(_) => {
                self.metrics.record_outcome("storage_unavailable");
                return self.provider_response(&["internal-error"], Some("storage_unavailable"));
            }
        };
        // 2. Derive: no lock held. The scope's rung supplies the timing
        // floor even for a foreign injected record; the record's own
        // floor rides on top (the verifier takes the max).
        let mut record = record;
        let floor = self
            .plan
            .rung_of(scope)
            .unwrap_or_else(|| self.default_rung())
            .min_duration_ms();
        let client_ip = match self.binding {
            BindingConfig::Bound => Some(remoteip.as_str()),
            BindingConfig::None => None,
        };
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
            enforce_telemetry: false,
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
        // 3. Commit: one short lock, the verdict lands.
        let valid = matches!(outcome, VerifyOutcome::Valid { .. });
        self.store.commit(&decoded.nonce, &record, valid);
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
            "ok": true,
            "detail": self.store.describe(),
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

/// The provider challenge wire (the camelCase key set the native solver
/// parses) of a minted challenge, spelled exactly as the `/issue`
/// endpoint emits it. The integration tests drive the same renderer.
pub fn issue_wire_of(issued: &kiwicaptcha::challenge::Issued) -> String {
    let c = &issued.challenge;
    let wire = serde_json::json!({
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
    format!("{wire}\n")
}

/// The store backends the binary can select (re-exported so the tests
/// and the binary share one construction path).
pub fn open_store(config: &StoreConfig) -> Result<Arc<dyn RecordStore>, String> {
    match config {
        StoreConfig::Memory => Ok(Arc::new(MemoryStore::new())),
        StoreConfig::File(path) => Ok(Arc::new(FileStore::open(path)?)),
        #[cfg(feature = "redis-store")]
        StoreConfig::Redis(url) => Ok(Arc::new(crate::store::RedisStore::connect(
            url,
            "kiwi:verifier:",
        )?)),
        #[cfg(not(feature = "redis-store"))]
        StoreConfig::Redis(url) => Err(format!(
            "KIWI_STORE={url} needs the redis-store build feature (rebuild with: cargo build --features redis-store); this build serves memory and file stores only"
        )),
    }
}
