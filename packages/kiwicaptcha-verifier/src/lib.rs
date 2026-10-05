//! The KiwiCaptcha language-neutral verifier sidecar.
//!
//! A single static binary that exposes the provider-shaped siteverify
//! surface over localhost HTTP or a Unix socket, so any stack without a
//! native SDK integrates with one local call:
//!
//! ```text
//! KIWI_SECRET=0123456789abcdef0123456789abcdef kiwicaptcha-verifier
//! curl -s http://127.0.0.1:7371/verify \
//!   -H 'content-type: application/json' \
//!   -d '{"token":"...","scope":"login"}'
//! ```
//!
//! The HTTP surface is std-only: a hand-rolled HTTP/1.1 reader on the
//! standard library's TCP and Unix sockets. No framework dependency
//! exists, and the process makes no outbound connections at all — it
//! opens its listening socket and answers requests; every byte of a
//! verification stays on the host.
//!
//! Endpoints:
//! - `POST /verify` `{token, scope, remoteip?}` — the provider JSON
//!   shape (`success`, `challenge_ts`, `hostname`, `action`, `cdata`,
//!   `error-codes`), built by the core crate's siteverify mapper, plus
//!   one additive `kiwi-code` field carrying the precise core wire code
//!   (`ok`, `wrong_scope`, ...) for callers that want it. Incumbent
//!   consumers read only the provider fields.
//! - `POST /issue` `{scope, remoteip?, algorithm?, action?, cdata?}` —
//!   mints through the workspace issuer and stores the record, the
//!   single-node all-in-one path.
//! - `GET /metrics` — Prometheus text (the same series-name family as
//!   the bundle's exporter).
//! - `GET /healthz` — always `ok` while the process runs.
//! - `GET /doctor` — a JSON config/store/secret check summary.
//!
//! Authentication: `KIWI_BEARER` (or `--bearer`) enables the sidecar's
//! own bearer credential on `/verify`, `/issue`, `/metrics` and
//! `/doctor`, compared in constant time exactly like the metrics
//! exporter's secret. When no bearer is configured the loopback-only
//! binding is the boundary; a deployment that exposes the socket
//! further must configure one.
//!
//! Storage scope (single node): the sidecar keeps its own in-process
//! store — pending records, consumed-result tombstones retained until
//! the challenge TTL (a replay answers `timeout-or-duplicate`), and the
//! issuance-bound action/cdata metadata. It fronts one node's
//! challenges; a multi-node deployment uses the core crate's fused
//! Redis verifier (the `redis` feature) instead of this process.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kiwicaptcha::challenge::{
    issue_challenge, now_epoch_micros, BindingMode, ChallengeConfig, ChallengeRecord, PoWAlgorithm,
    DEFAULT_RSW_T,
};
use kiwicaptcha::siteverify::siteverify_response_with_metadata;
use kiwicaptcha::verify::{verify_solution, VerifyContext, VerifyOutcome};
use kiwicaptcha::{RequestBindingExpectation, SolutionToken};

/// The Prometheus exposition content type (text format 0.0.4), the
/// same value the bundle's exporter serves.
pub const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The largest request body the reader accepts (a solution token is a
/// few hundred bytes; anything larger is a misuse or an attack).
const MAX_BODY_BYTES: usize = 1 << 20;

/// The maximum request line + header block the reader buffers.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The default TCP bind: loopback only.
pub const DEFAULT_LISTEN: &str = "http://127.0.0.1:7371";

/// The verification attempts ceiling per record (the wrong-candidate
/// cost bound, particularly for memory-hard records).
const MAX_ATTEMPTS: u32 = 8;

/// The parsed listen address.
#[derive(Debug, Clone)]
pub enum ListenAddr {
    Http(SocketAddr),
    Unix(PathBuf),
}

/// Parse a listen string: `http://127.0.0.1:7371` or
/// `unix:///path/to/socket`. HTTP bindings outside the loopback range
/// are refused — the sidecar is a localhost service by contract.
pub fn parse_listen(raw: &str) -> Result<ListenAddr, String> {
    if let Some(path) = raw.strip_prefix("unix://") {
        if path.is_empty() {
            return Err("unix:// needs a socket path".to_string());
        }
        return Ok(ListenAddr::Unix(PathBuf::from(path)));
    }
    let host_port = raw.strip_prefix("http://").ok_or_else(|| {
        format!("unrecognized listen address: {raw} (want http://IP:PORT or unix:///PATH)")
    })?;
    let addr: SocketAddr = host_port
        .parse()
        .map_err(|e| format!("cannot parse listen address {raw}: {e}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "refusing to bind {addr}: the sidecar binds loopback only (127.0.0.1 or ::1)"
        ));
    }
    Ok(ListenAddr::Http(addr))
}

/// Constant-time byte equality (a missing credential fails closed; a
/// length mismatch still walks the presented bytes so the comparison
/// time carries no signal).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// The in-process store: pending records, consumed-result tombstones
/// (retained until the challenge TTL so a replay answers
/// `timeout-or-duplicate`, never a bare not-found), and the
/// issuance-bound provider metadata.
#[derive(Default)]
struct Store {
    pending: HashMap<String, ChallengeRecord>,
    consumed: HashMap<String, ChallengeRecord>,
    metadata: HashMap<String, (Option<String>, Option<String>)>,
}

impl Store {
    fn prune_expired(&mut self, now_unix: u64) {
        self.pending.retain(|_, r| r.expires_at > now_unix);
        self.consumed.retain(|_, r| r.expires_at > now_unix);
        // Metadata outlives its record only within the TTL window; the
        // nonce keyspace is shared with the records.
        self.metadata
            .retain(|k, _| self.pending.contains_key(k) || self.consumed.contains_key(k));
    }
}

/// Counters and gauges for `/metrics` (per process, which is the whole
/// deployment for this sidecar).
#[derive(Default)]
struct Metrics {
    scrapes: AtomicU64,
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

/// The sidecar's shared state: configuration, store and metrics.
pub struct SidecarState {
    secret_key: String,
    bearer: Option<String>,
    scopes: Vec<String>,
    listen_label: String,
    store: Mutex<Store>,
    metrics: Metrics,
}

impl SidecarState {
    /// Build the state. `listen_label` is the configured listen string
    /// echoed by `/doctor` and the startup line.
    pub fn new(
        secret_key: String,
        bearer: Option<String>,
        scopes: Vec<String>,
        listen_label: &str,
    ) -> Self {
        Self {
            secret_key,
            bearer: bearer.filter(|b| !b.is_empty()),
            scopes: if scopes.is_empty() {
                vec!["login".to_string()]
            } else {
                scopes
            },
            listen_label: listen_label.to_string(),
            store: Mutex::new(Store::default()),
            metrics: Metrics::default(),
        }
    }

    /// Ingest a record minted elsewhere in this process (the embedder's
    /// own issuance path): the challenge must have been minted under
    /// this sidecar's secret. `action`/`cdata` are the issuance-bound
    /// provider metadata echoed on a successful verify.
    pub fn inject_record(
        &self,
        record: ChallengeRecord,
        action: Option<String>,
        cdata: Option<String>,
    ) {
        let mut store = self.store.lock().expect("store lock");
        store.metadata.insert(record.nonce.clone(), (action, cdata));
        store.pending.insert(record.nonce.clone(), record);
    }

    /// The configured scopes (the `/doctor` summary reads the same
    /// list).
    pub fn scopes(&self) -> &[String] {
        &self.scopes
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
    fn handle(&self, req: &Request) -> Response {
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
                Response::raw(200, "application/json", self.render_doctor())
            }
            ("POST", "/verify") => {
                if !self.authorized(bearer) {
                    return Response::unauthorized();
                }
                Response::raw(200, "application/json", self.handle_verify(&req.body))
            }
            ("POST", "/issue") => {
                if !self.authorized(bearer) {
                    return Response::unauthorized();
                }
                Response::raw(200, "application/json", self.handle_issue(&req.body))
            }
            _ => Response::raw(
                404,
                "application/json",
                "{\"error\":\"not found\"}\n".to_string(),
            ),
        }
    }

    fn handle_verify(&self, body: &[u8]) -> String {
        let parsed: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                self.metrics.record_outcome("bad_request");
                return self.provider_json(&[], Some("bad_request"));
            }
        };
        let token = parsed.get("token").and_then(|v| v.as_str()).unwrap_or("");
        let scope = parsed.get("scope").and_then(|v| v.as_str()).unwrap_or("");
        let remoteip = parsed
            .get("remoteip")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1");
        if token.is_empty() || scope.is_empty() {
            self.metrics.record_outcome("bad_request");
            return self.provider_json(&["missing-input-response"], Some("bad_request"));
        }
        let decoded = match SolutionToken::decode(token) {
            Ok(d) => d,
            Err(_) => {
                self.metrics.record_outcome("malformed_token");
                return self.provider_json(&["invalid-input-response"], Some("malformed_token"));
            }
        };
        let now_ns = now_epoch_micros();
        let now_unix = now_ns / 1_000_000;
        let outcome;
        let record_snapshot;
        {
            let mut store = self.store.lock().expect("store lock");
            store.prune_expired(now_unix);
            let Some(mut record) = store.pending.remove(&decoded.nonce) else {
                // A consumed nonce answers the provider duplicate
                // vocabulary while its tombstone lives.
                if store.consumed.contains_key(&decoded.nonce) {
                    self.metrics.record_outcome("already_consumed");
                    return self.provider_json(&["timeout-or-duplicate"], Some("already_consumed"));
                }
                self.metrics.record_outcome("record_not_found");
                return self.provider_json(&["invalid-input-response"], Some("record_not_found"));
            };
            outcome = verify_solution(&mut VerifyContext {
                record: &mut record,
                secret_key: &self.secret_key,
                tenant: None,
                secrets_by_kid: None,
                revoked_kids: None,
                counter: decoded.counter,
                duration_ms: decoded.duration_ms,
                now_unix: None,
                now_ns,
                min_duration_ms: 0,
                expected_scope: Some(scope),
                expected_request_binding: RequestBindingExpectation::Unenforced,
                expected_region: None,
                expected_issuer: None,
                expected_policy_version: None,
                policy_version_floor: None,
                client_ip: Some(remoteip),
                execution_digest: None,
                execution_trace: None,
                telemetry: Some(&decoded.telemetry),
                enforce_telemetry: false,
                max_attempts: MAX_ATTEMPTS,
                accept_legacy_v1: false,
                rsw_proof: decoded.rsw_proof.as_deref(),
                rsw_modulus_n: None,
                rsw_lambda: None,
                rsw_keyring: None,
            });
            match &outcome {
                VerifyOutcome::Valid { .. } => {
                    // Single-use: the tombstone keeps the provider
                    // duplicate answer alive until the TTL, and the
                    // metadata rides along for the same window.
                    store.consumed.insert(record.nonce.clone(), record.clone());
                }
                VerifyOutcome::Invalid(_) => {
                    // The attempt accounting must survive a failed
                    // candidate.
                    store.pending.insert(record.nonce.clone(), record.clone());
                }
            }
            record_snapshot = Some(record);
        }
        let (action, cdata) = {
            let store = self.store.lock().expect("store lock");
            store
                .metadata
                .get(&decoded.nonce)
                .cloned()
                .unwrap_or((None, None))
        };
        let core_code = match &outcome {
            VerifyOutcome::Valid { .. } => "ok",
            VerifyOutcome::Invalid(reason) => reason.code(),
        };
        self.metrics.record_outcome(core_code);
        let response = siteverify_response_with_metadata(
            &outcome,
            record_snapshot.as_ref(),
            action.as_deref(),
            cdata.as_deref(),
        );
        match serde_json::to_value(&response) {
            Ok(mut value) => {
                value["kiwi-code"] = serde_json::Value::String(core_code.to_string());
                let mut out = value.to_string();
                out.push('\n');
                out
            }
            Err(_) => self.provider_json(&["internal-error"], Some("internal_error")),
        }
    }

    fn handle_issue(&self, body: &[u8]) -> String {
        let parsed: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return "{\"error\":\"bad request\"}\n".to_string(),
        };
        let scope = parsed
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("login");
        if !self.scopes.iter().any(|s| s == scope) {
            return format!(
                "{{\"error\":\"scope not allowed\",\"allowed\":{}}}\n",
                serde_json::to_string(&self.scopes).unwrap_or_default()
            );
        }
        let remoteip = parsed
            .get("remoteip")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1");
        let algorithm = match parsed.get("algorithm").and_then(|v| v.as_str()) {
            Some("argon2id") => PoWAlgorithm::Argon2id,
            _ => PoWAlgorithm::Sha256,
        };
        let argon = algorithm == PoWAlgorithm::Argon2id;
        let config = ChallengeConfig {
            secret_key: self.secret_key.clone(),
            algorithm,
            m_kib: if argon { 64 } else { 0 },
            t: if argon { 3 } else { 1 },
            p: 1,
            target_bits: 8,
            argon2_target_bits: 4,
            ttl_secs: 120,
            min_duration_ms: Some(0),
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 8,
            binding_mode: BindingMode::Bound,
            policy_version: 1,
            region: None,
            issuer: None,
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: DEFAULT_RSW_T,
            tenant: None,
        };
        let now_ns = now_epoch_micros();
        let now_unix = now_ns / 1_000_000;
        let issued = match issue_challenge(&config, scope, remoteip, now_unix, now_ns, 0, None) {
            Ok(i) => i,
            Err(e) => return format!("{{\"error\":\"issue failed: {e}\"}}\n"),
        };
        let action = parsed
            .get("action")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let cdata = parsed
            .get("cdata")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        self.inject_record(issued.record, action, cdata);
        // The provider wire vocabulary (the PHP challenge toArray key
        // set), directly parseable by the native solver.
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
        if let Some(decoy) = &c.decoy_field {
            wire["decoy_field"] = serde_json::json!(decoy);
        }
        if let Some(program) = &c.execution_program {
            wire["execution_program"] = serde_json::json!(program);
        }
        let mut out = wire.to_string();
        out.push('\n');
        out
    }

    /// The provider failure shape with the additive core code.
    fn provider_json(&self, codes: &[&str], core: Option<&str>) -> String {
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
        let mut out = value.to_string();
        out.push('\n');
        out
    }

    fn render_metrics(&self) -> String {
        let scrapes = self.metrics.scrapes.load(Ordering::Relaxed);
        let outcomes = self.metrics.outcomes.lock().expect("metrics lock").clone();
        let (pending, consumed) = {
            let mut store = self.store.lock().expect("store lock");
            store.prune_expired(now_epoch_micros() / 1_000_000);
            (store.pending.len(), store.consumed.len())
        };
        let mut out = String::new();
        // The verify family: labels carry only the core wire-code
        // vocabulary (the same redaction rule as the bundle exporter's
        // outcome labels).
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
        out.push_str(
            "# HELP kiwicaptcha_verifier_records The in-process store's live challenge records.\n",
        );
        out.push_str("# TYPE kiwicaptcha_verifier_records gauge\n");
        out.push_str(&format!(
            "kiwicaptcha_verifier_records{{state=\"pending\"}} {pending}\nkiwicaptcha_verifier_records{{state=\"consumed\"}} {consumed}\n"
        ));
        out
    }

    fn render_doctor(&self) -> String {
        let secret_ok = self.secret_key.len() >= 32;
        let mut checks = Vec::new();
        checks.push(serde_json::json!({
            "name": "secret",
            "ok": secret_ok,
            "detail": format!("{} bytes (32 recommended minimum)", self.secret_key.len()),
        }));
        checks.push(serde_json::json!({
            "name": "store",
            "ok": true,
            "detail": "in-process memory (single node); multi-node deployments use the core crate's Redis verifier",
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
        let ok = checks
            .iter()
            .filter(|c| c["ok"] == serde_json::Value::Bool(true))
            .count()
            == checks.len();
        serde_json::to_string(&serde_json::json!({
            "ok": ok,
            "checks": checks,
            "scopes": self.scopes,
        }))
        .unwrap_or_else(|_| "{\"ok\":false}\n".to_string())
            + "\n"
    }
}

/// A parsed HTTP request (method, path, the Authorization bearer and
/// the body).
struct Request {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

impl Request {
    fn bearer(&self) -> Option<&str> {
        self.authorization
            .as_deref()
            .and_then(|v| v.strip_prefix("Bearer "))
    }
}

/// The response tuple the handlers return.
struct Response {
    status: u16,
    content_type: &'static str,
    body: String,
}

impl Response {
    fn raw(status: u16, content_type: &'static str, body: String) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }

    fn text(status: u16, body: &str) -> Self {
        Self::raw(status, "text/plain; charset=utf-8", body.to_string())
    }

    fn unauthorized() -> Self {
        Self::raw(
            401,
            "text/plain; charset=utf-8",
            "unauthorized\n".to_string(),
        )
    }

    fn status_line(&self) -> &'static str {
        match self.status {
            200 => "200 OK",
            401 => "401 Unauthorized",
            404 => "404 Not Found",
            405 => "405 Method Not Allowed",
            413 => "413 Payload Too Large",
            400 => "400 Bad Request",
            _ => "500 Internal Server Error",
        }
    }
}

/// Read one HTTP/1.1 request from the stream (request line, headers,
/// Content-Length body). The reader never allocates more than the two
/// bounded caps.
fn read_request<R: Read>(stream: &mut R) -> Result<Request, String> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HEAD_BYTES {
            return Err("header block too large".to_string());
        }
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed mid-head".to_string());
        }
        head.extend_from_slice(&chunk[..n]);
    }
    let split = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "no header terminator".to_string())?;
    let head_text = String::from_utf8_lossy(&head[..split]).to_string();
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| "empty request".to_string())?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let path = target.split('?').next().unwrap_or("").to_string();
    let mut content_length = 0usize;
    let mut authorization = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value
                .parse()
                .map_err(|_| "bad content-length".to_string())?;
        } else if name == "authorization" {
            authorization = Some(value.to_string());
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err("body too large".to_string());
    }
    let mut body = head[split + 4..].to_vec();
    if body.len() > content_length {
        body.truncate(content_length);
    }
    while body.len() < content_length {
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed mid-body".to_string());
        }
        body.extend_from_slice(&chunk[..n.min(content_length - body.len())]);
    }
    Ok(Request {
        method,
        path,
        authorization,
        body,
    })
}

/// Serve one connection: read, handle, answer, close (one request per
/// connection; a local sidecar call pays nothing for keep-alive).
fn serve_connection<S: Read + Write>(stream: &mut S, state: &SidecarState) {
    let response = match read_request(stream) {
        Ok(req) => state.handle(&req),
        Err(_) => Response::text(400, "bad request\n"),
    };
    let head = format!(
        "HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n",
        response.status_line(),
        response.content_type,
        response.body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(response.body.as_bytes());
    let _ = stream.flush();
}

/// The TCP accept loop (one thread per connection; the sidecar fronts
/// one application's local verifications).
pub fn serve_http(listener: TcpListener, state: Arc<SidecarState>) -> std::io::Result<()> {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = stream.set_nodelay(true);
            serve_connection(&mut stream, &state);
        });
    }
    Ok(())
}

/// The Unix-socket accept loop (the same handler; permissions of the
/// socket file are the deployment's boundary).
pub fn serve_unix(path: &std::path::Path, state: Arc<SidecarState>) -> std::io::Result<()> {
    use std::os::unix::net::UnixListener;
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            serve_connection(&mut stream, &state);
        });
    }
    Ok(())
}

/// Bind and serve on the parsed address; returns only on error.
pub fn serve(listen: &ListenAddr, state: Arc<SidecarState>) -> std::io::Result<()> {
    match listen {
        ListenAddr::Http(addr) => {
            let listener = TcpListener::bind(addr)?;
            serve_http(listener, state)
        }
        ListenAddr::Unix(path) => serve_unix(path, state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_loopback_binds() {
        assert!(parse_listen("http://0.0.0.0:7371").is_err());
        assert!(parse_listen("http://192.0.2.10:7371").is_err());
        assert!(parse_listen("http://127.0.0.1:7371").is_ok());
        assert!(parse_listen("unix:///tmp/kiwi.sock").is_ok());
        assert!(parse_listen("gopher://x").is_err());
    }

    #[test]
    fn constant_time_compare_matches_only_equal_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn healthz_answers_ok_without_credentials() {
        let state = SidecarState::new("s".to_string(), Some("tok".to_string()), vec![], "x");
        let req = Request {
            method: "GET".to_string(),
            path: "/healthz".to_string(),
            authorization: None,
            body: Vec::new(),
        };
        let res = state.handle(&req);
        assert_eq!(res.status, 200);
        assert_eq!(res.body, "ok\n");
    }

    #[test]
    fn verify_requires_the_configured_bearer() {
        let state = SidecarState::new("s".to_string(), Some("tok".to_string()), vec![], "x");
        let req = Request {
            method: "POST".to_string(),
            path: "/verify".to_string(),
            authorization: None,
            body: b"{}".to_vec(),
        };
        assert_eq!(state.handle(&req).status, 401);
        let req_ok = Request {
            method: "POST".to_string(),
            path: "/verify".to_string(),
            authorization: Some("Bearer tok".to_string()),
            body: b"{}".to_vec(),
        };
        let res = state.handle(&req_ok);
        assert_eq!(res.status, 200);
        assert!(res.body.contains("\"success\":false"));
    }

    #[test]
    fn unknown_routes_answer_not_found() {
        let state = SidecarState::new("s".to_string(), None, vec![], "x");
        let req = Request {
            method: "GET".to_string(),
            path: "/nope".to_string(),
            authorization: None,
            body: Vec::new(),
        };
        assert_eq!(state.handle(&req).status, 404);
    }
}
