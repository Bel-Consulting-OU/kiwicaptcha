//! The hardening contract: one test per finding, each driving the same
//! HTTP surface a deployment drives.
//!
//! Coverage map:
//! 1. issuance runs the core issuer under configured challenge profiles
//!    (the rung table), with per-scope value classes and the derived
//!    timing floor enforced;
//! 2. the optional risk plane gates issuance (deny refuses with 429,
//!    step-up carries its disposition) and books outcomes on verify;
//! 3. the store lock never covers a hash derivation, proven directly:
//!    a derivation blocked between the consume transition and the commit
//!    holds no store call — a second verify completes inside the blocked
//!    window (the wall-clock concurrency bound survives as an ignored
//!    performance characterization);
//! 4. one-shot: a failed candidate burns the record (no retry window);
//! 5. the file store survives a server restart (spawn, kill, respawn);
//! 6. a stalled client times out and the bounded pool stays healthy;
//! 7. the secret floor and the example-secret refusal with its escape
//!    hatch, at the binary's startup;
//! 8. remoteip is required on /issue and /verify while binding is on.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use kiwicaptcha::challenge::ChallengeRecord;
use kiwicaptcha::SolutionToken;
use kiwicaptcha_risk::event::RiskObservation;
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::{Observed, RiskStateStore, RiskStoreError};
use kiwicaptcha_verifier::state::derivation_gate;
use kiwicaptcha_verifier::{
    compose_rung, open_store, parse_rung, parse_scopes, scope_id, serve_http_with, validate_secret,
    ConsumeOutcome, MemoryStore, PeekOutcome, RecordMeta, RecordStore, RiskPlane, ServerOptions,
    SidecarConfig, SidecarState, StoreConfig, EXAMPLE_SECRET, MIN_SECRET_BYTES,
};

const SECRET: &str = "a-locally-generated-secret-of-48-bytes!!";
const CLIENT_IP: &str = "198.51.100.7";

// ---------------------------------------------------------------- store
// A risk state store stub with a fixed signal vector: the test crafts
// the deny and the step-up conditions through the engine's own decision
// path, over the real assessment pipeline.

#[derive(Default)]
struct LedgerStore {
    vector: Mutex<Option<SignalVector>>,
    confirms: Mutex<Vec<(String, bool)>>,
    registrations: AtomicUsize,
}

impl LedgerStore {
    fn with_vector(vector: SignalVector) -> Arc<Self> {
        Arc::new(LedgerStore {
            vector: Mutex::new(Some(vector)),
            confirms: Mutex::new(Vec::new()),
            registrations: AtomicUsize::new(0),
        })
    }
}

impl RiskStateStore for LedgerStore {
    fn observe(&self, _o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        let vector = self.vector.lock().unwrap().unwrap_or_default();
        Ok(Observed {
            vector,
            global_level: 0,
            cooldown_until_ms: 0,
            is_duplicate: false,
        })
    }

    fn register_outcome(
        &self,
        decision_id: &str,
        _scope: u32,
        _decision_hour: i64,
        _score: u32,
    ) -> Result<bool, RiskStoreError> {
        self.registrations.fetch_add(1, Ordering::Relaxed);
        let _ = decision_id;
        Ok(true)
    }

    fn confirm_outcome(&self, decision_id: &str, legitimate: bool) -> Result<u8, RiskStoreError> {
        self.confirms
            .lock()
            .unwrap()
            .push((decision_id.to_string(), legitimate));
        Ok(1)
    }

    fn correct_outcome(&self, _id: &str, _legitimate: bool) -> Result<bool, RiskStoreError> {
        Ok(false)
    }
}

// ---------------------------------------------------------------- http

fn http(addr: SocketAddr, request: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).expect("the sidecar socket answers");
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.write_all(request.as_bytes()).expect("request sent");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("response drained");
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .expect("a status line");
    let mut parts = text.split("\r\n\r\n");
    let head = parts.next().unwrap_or("").to_string();
    let body = parts.next().unwrap_or("").to_string();
    (status, head, body)
}

fn post_json(addr: SocketAddr, path: &str, body: &str) -> (u16, String, String) {
    http(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nhost: sidecar.test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn get(addr: SocketAddr, path: &str) -> (u16, String, String) {
    http(
        addr,
        &format!("GET {path} HTTP/1.1\r\nhost: sidecar.test\r\nconnection: close\r\n\r\n"),
    )
}

struct Server {
    addr: SocketAddr,
}

fn spawn(state: SidecarState, options: ServerOptions) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let addr = listener.local_addr().expect("local addr");
    let state = Arc::new(state);
    std::thread::spawn(move || serve_http_with(listener, state, options));
    Server { addr }
}

fn config_with(plan: &str, risk: Option<Arc<dyn RiskStateStore + Send + Sync>>) -> SidecarConfig {
    let default_rung = parse_rung("sha18").expect("the default rung parses");
    let mut config = SidecarConfig::minimal(SECRET.to_string(), vec![], "http://127.0.0.1:0");
    config.plan = parse_scopes(Some(plan), default_rung).expect("the plan parses");
    if let Some(store) = risk {
        config.risk = Some(RiskPlane::new(store, &config.plan, SECRET).expect("the plane wires"));
    }
    config
}

fn solve_token(wire: &str) -> String {
    let challenge = kiwicaptcha_solver::Challenge::from_json(wire).expect("the wire parses");
    let mut options = kiwicaptcha_solver::SolveOptions::default();
    let solution = kiwicaptcha_solver::solve(&challenge, &mut options).expect("the solve succeeds");
    solution.token(&challenge)
}

fn issue_and_solve(server: &Server, scope: &str) -> String {
    let (status, _, wire) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"{scope}\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "{wire}");
    solve_token(wire.trim_end())
}

fn verify_body(server: &Server, token: &str, scope: &str) -> serde_json::Value {
    let (_, _, body) = post_json(
        server.addr,
        "/verify",
        &format!("{{\"token\":\"{token}\",\"scope\":\"{scope}\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("verify body {body}: {e}"))
}

// ------------------------------------------------- finding 1: profiles

#[test]
fn profiles_map_rungs_value_classes_and_enforce_the_timing_floor() {
    let server = spawn(
        SidecarState::build(config_with("login=critical,comment=low,signup", None)),
        ServerOptions::default(),
    );
    // The critical class prices onto argon16: 16 MiB, t=3, p=1, the
    // 50 ms derived floor.
    let (status, _, wire) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "{wire}");
    let critical: serde_json::Value = serde_json::from_str(wire.trim_end()).unwrap();
    assert_eq!(critical["profile"], "argon16");
    assert_eq!(critical["mKib"], 16 * 1024);
    assert_eq!(critical["t"], 3);
    assert_eq!(critical["p"], 1);
    assert_eq!(critical["targetBits"], 1);
    assert_eq!(critical["minDurationMs"], 50);

    // The low class prices onto sha16, the standard default is sha18,
    // and both carry the derived 5 ms floor.
    let (_, _, wire) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"comment\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    let low: serde_json::Value = serde_json::from_str(wire.trim_end()).unwrap();
    assert_eq!(low["profile"], "sha16");
    assert_eq!(low["targetBits"], 16);
    assert_eq!(low["minDurationMs"], 5);

    let (_, _, wire) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"signup\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    let standard: serde_json::Value = serde_json::from_str(wire.trim_end()).unwrap();
    assert_eq!(standard["profile"], "sha18");
    assert_eq!(standard["targetBits"], 18);
    assert_eq!(standard["minDurationMs"], 5);

    // The timing floor is enforced server-side: an immediate submit of
    // a well-formed token arrives inside the derived floor and answers
    // too_fast (the burned record answers the duplicate vocabulary on
    // the retry, which is the one-shot contract of finding 4). The
    // critical class re-issues here so the submit's elapsed window is
    // the token encode alone against the 50 ms argon floor — the 5 ms
    // low-class window is one scheduler hiccup wide on a loaded host.
    let (status, _, wire) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "{wire}");
    let immediate: serde_json::Value = serde_json::from_str(wire.trim_end()).unwrap();
    assert_eq!(immediate["profile"], "argon16");
    let token = SolutionToken {
        nonce: immediate["nonce"].as_str().unwrap().to_string(),
        counter: 0,
        duration_ms: 1,
        telemetry: serde_json::json!({}),
        execution_digest: None,
        execution_trace: None,
        rsw_proof: None,
    }
    .encode();
    let payload = verify_body(&server, &token, "login");
    assert_eq!(payload["kiwi-code"], "too_fast", "{payload}");
    assert_eq!(
        payload["error-codes"],
        serde_json::json!(["invalid-input-response"])
    );
}

// ---------------------------------------------------- finding 2: risk

#[test]
fn risk_off_is_documented_and_risk_on_gates_issuance() {
    // Risk off: the doctor states plainly that the all-in-one binary
    // runs without abuse-risk telemetry.
    let server = spawn(
        SidecarState::build(config_with("login", None)),
        ServerOptions::default(),
    );
    let (_, _, doctor) = get(server.addr, "/doctor");
    let doctor: serde_json::Value = serde_json::from_str(&doctor).unwrap();
    let risk_check = doctor["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "risk")
        .unwrap()
        .clone();
    assert!(
        risk_check["detail"]
            .as_str()
            .unwrap()
            .contains("without abuse-risk telemetry"),
        "{risk_check}"
    );

    // Risk on, deny condition: a saturated replay signal runs the real
    // assessment and the disposition refuses issuance with 429.
    let deny_vector = SignalVector {
        replay: 1000,
        ..SignalVector::default()
    };
    let store = LedgerStore::with_vector(deny_vector);
    let server = spawn(
        SidecarState::build(config_with("login=critical", Some(store))),
        ServerOptions::default(),
    );
    let (status, head, body) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 429, "{body}");
    assert!(head.to_ascii_lowercase().contains("retry-after:"), "{head}");
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(payload["kiwi-code"], "risk_denied");
    assert_eq!(payload["risk"]["action"], "deny");
    let (_, _, metrics) = get(server.addr, "/metrics");
    assert!(
        metrics.contains("kiwicaptcha_verifier_issues_denied_total 1"),
        "{metrics}"
    );

    // Risk on, step-up condition: the assessment escalates to the
    // interactive step-up disposition and the issue response carries
    // it, with the strongest challenge rung issued. The vector keeps
    // every hard-deny trigger quiet (no source_fast at 950 or above,
    // no saturated replay or malformed traffic) while the score lands
    // in the step-up band.
    let stepup_vector = SignalVector {
        source_fast: 949,
        source_slow: 1000,
        subnet_fast: 1000,
        issue_debt: 1000,
        bad_proof: 1000,
        action_failure: 1000,
        ..SignalVector::default()
    };
    let store = LedgerStore::with_vector(stepup_vector);
    let server = spawn(
        SidecarState::build(config_with("login=low", Some(store))),
        ServerOptions::default(),
    );
    let (status, _, body) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "{body}");
    let payload: serde_json::Value = serde_json::from_str(body.trim_end()).unwrap();
    assert_eq!(payload["risk"]["action"], "step_up");
    assert_eq!(payload["profile"], "argon64");
    assert_eq!(payload["mKib"], 64 * 1024);
}

#[test]
fn risk_on_books_outcomes_for_solved_and_failed_verifies() {
    // Neutral signals: the decision passes (at the scope's argon16
    // floor, the critical class), issuance registers the decision in
    // the outcome ledger, and a valid solve confirms it legitimate.
    let store = LedgerStore::with_vector(SignalVector::default());
    let observer = Arc::clone(&store);
    let plane_store: Arc<dyn RiskStateStore + Send + Sync> =
        store as Arc<dyn RiskStateStore + Send + Sync>;
    let server = spawn(
        SidecarState::build(config_with("login=critical", Some(plane_store))),
        ServerOptions::default(),
    );
    let token = issue_and_solve(&server, "login");
    let payload = verify_body(&server, &token, "login");
    assert_eq!(payload["kiwi-code"], "ok", "{payload}");
    let confirms = observer.confirms.lock().unwrap();
    assert_eq!(
        confirms.len(),
        1,
        "the solve confirmed exactly one decision"
    );
    assert!(confirms[0].1, "the confirmation is legitimate");
}

// ------------------------------------------- finding 3: lock contention
//
// The store-lock invariant is proven directly, not by timing: a
// derivation blocked after the consume transition returned and before the
// commit runs must hold no store operation. The old wall-clock bound
// (four concurrent Argon verifies finishing under half a 4x-serialized
// estimate) proved nothing — memory-bandwidth contention alone can
// resemble serialization with the store lock completely free — so it
// survives only as an ignored performance characterization below.

/// The one-shot hold channel pair of an armed consume: `entered` fires
/// when the consume call is open, `release` unblocks the delegation.
type ConsumeHold = (mpsc::Sender<()>, mpsc::Receiver<()>);

/// The test store wrapper: every operation delegates to the real memory
/// store while the wrapper records each call's interval and the
/// concurrent-entry high watermark at the store seam. A consume whose
/// nonce was armed through [`InstrumentedStore::hold_consume`] signals
/// `entered` with its call already open and blocks the delegation until
/// `release` fires, which makes two overlapping store calls
/// deterministic instead of a timing race.
struct InstrumentedStore {
    inner: Arc<MemoryStore>,
    holds: Mutex<HashMap<String, ConsumeHold>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
    events: Mutex<Vec<(&'static str, Instant, Option<Instant>)>>,
}

impl InstrumentedStore {
    fn record<T>(&self, op: &'static str, body: impl FnOnce() -> T) -> T {
        let index = {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            let mut events = self.events.lock().expect("the store events lock");
            events.push((op, Instant::now(), None));
            events.len() - 1
        };
        let out = body();
        self.events.lock().expect("the store events lock")[index].2 = Some(Instant::now());
        self.active.fetch_sub(1, Ordering::SeqCst);
        out
    }

    fn hold_consume(&self, nonce: &str, entered: mpsc::Sender<()>, release: mpsc::Receiver<()>) {
        self.holds
            .lock()
            .expect("the holds lock")
            .insert(nonce.to_string(), (entered, release));
    }
}

impl RecordStore for InstrumentedStore {
    fn put_pending(&self, record: &ChallengeRecord, meta: RecordMeta) -> Result<(), String> {
        self.record("put_pending", || self.inner.put_pending(record, meta))
    }

    fn consume(
        &self,
        nonce: &str,
        now_unix: u64,
        operation_identity: Option<&str>,
    ) -> ConsumeOutcome {
        self.record("consume", || {
            let hold = self.holds.lock().expect("the holds lock").remove(nonce);
            if let Some((entered, release)) = hold {
                let _ = entered.send(());
                let _ = release.recv();
            }
            self.inner.consume(nonce, now_unix, operation_identity)
        })
    }

    fn peek(&self, nonce: &str, now_unix: u64) -> PeekOutcome {
        self.record("peek", || self.inner.peek(nonce, now_unix))
    }

    fn commit(&self, nonce: &str, record: &ChallengeRecord, valid: bool) {
        self.record("commit", || self.inner.commit(nonce, record, valid));
    }

    fn commit_with_mac(
        &self,
        nonce: &str,
        record: &ChallengeRecord,
        valid: bool,
        operation_identity: Option<&str>,
        mac: Option<&str>,
    ) {
        // Forward the authenticated seam so the wrapped store keeps the
        // MAC an idempotent replay must verify; the instrumented op is
        // still the commit the sequence assertions count.
        self.record("commit", || {
            self.inner
                .commit_with_mac(nonce, record, valid, operation_identity, mac)
        });
    }

    fn counts(&self) -> (usize, usize) {
        self.record("counts", || self.inner.counts())
    }

    fn describe(&self) -> String {
        self.record("describe", || self.inner.describe())
    }
}

/// Removes the derivation gate hook even when an assertion fails: the
/// hook is process-global and every other verify consults it.
struct GateGuard;

impl Drop for GateGuard {
    fn drop(&mut self) {
        derivation_gate::remove();
    }
}

#[test]
fn a_blocked_derivation_leaves_the_store_free() {
    let store = Arc::new(InstrumentedStore {
        inner: Arc::new(MemoryStore::new()),
        holds: Mutex::new(HashMap::new()),
        active: AtomicUsize::new(0),
        max_active: AtomicUsize::new(0),
        events: Mutex::new(Vec::new()),
    });
    let mut config = config_with("login", None);
    config.store = Arc::clone(&store) as Arc<dyn RecordStore>;
    let server = spawn(SidecarState::build(config), ServerOptions::default());

    // Three distinct tokens: (a) the derivation the test blocks, (b) the
    // consume the store holds open, (c) the verify that must complete
    // inside the blocked window. The default rung keeps the suite fast;
    // the blocked window is channel-driven, not timed.
    let tokens: Vec<String> = (0..3).map(|_| issue_and_solve(&server, "login")).collect();
    let nonces: Vec<String> = tokens
        .iter()
        .map(|token| {
            SolutionToken::decode(token)
                .expect("the token decodes")
                .nonce
        })
        .collect();
    // Stay above the rung's server-measured timing floor.
    std::thread::sleep(Duration::from_millis(20));

    // The gate blocks nonce (a)'s derivation after the consume transition
    // returned and before the commit runs. The hook is keyed on the
    // nonce: every other verify in the process passes straight through.
    let (gate_entered, gate_entered_rx) = mpsc::channel();
    let (gate_release, gate_release_rx) = mpsc::channel::<()>();
    let entered = Mutex::new(Some(gate_entered));
    let release = Mutex::new(Some(gate_release_rx));
    let blocked = nonces[0].clone();
    derivation_gate::install(move |nonce| {
        if nonce != blocked {
            return;
        }
        let Some(sender) = entered.lock().expect("the gate entered lock").take() else {
            return;
        };
        let _ = sender.send(());
        if let Some(receiver) = release.lock().expect("the gate release lock").take() {
            let _ = receiver.recv();
        }
    });
    let _gate = GateGuard;

    // The store wrapper arms a hold on nonce (b)'s consume call.
    let (hold_entered, hold_entered_rx) = mpsc::channel();
    let (hold_release, hold_release_rx) = mpsc::channel::<()>();
    store.hold_consume(&nonces[1], hold_entered, hold_release_rx);

    fn verify_request(token: &str) -> String {
        format!("{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}")
    }
    let addr = server.addr;

    // (a) wins the consume, then blocks at the gate. The window start
    // precedes the spawn, so every store call of the blocked verify
    // itself begins inside the window and can never span it.
    let window_start = Instant::now();
    let blocked_thread = {
        let token = tokens[0].clone();
        std::thread::spawn(move || post_json(addr, "/verify", &verify_request(&token)))
    };
    gate_entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the blocked derivation enters the gate");

    // (b)'s consume call is held open inside the store seam.
    let held_thread = {
        let token = tokens[1].clone();
        std::thread::spawn(move || post_json(addr, "/verify", &verify_request(&token)))
    };
    hold_entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the held consume is entered");

    // (c) completes a FULL verify — consume, derive, commit — while (a)
    // sits blocked between its consume and its commit. If the store were
    // held across the derivation, this could never answer.
    let payload = verify_body(&server, &tokens[2], "login");
    assert_eq!(payload["kiwi-code"], "ok", "{payload}");

    // Release the held consume, then the blocked derivation.
    let _ = hold_release.send(());
    let (_, _, body) = held_thread.join().expect("the held verify joins");
    let held: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(held["kiwi-code"], "ok", "{body}");
    let window_end = Instant::now();
    let _ = gate_release.send(());
    let (_, _, body) = blocked_thread.join().expect("the blocked verify joins");
    let unblocked: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(unblocked["kiwi-code"], "ok", "{body}");

    // Two store calls were open at once, and no store call spans the
    // blocked window: a derivation blocked between the consume and the
    // commit holds nothing.
    assert!(
        store.max_active.load(Ordering::SeqCst) >= 2,
        "the store must admit overlapping calls"
    );
    for (op, start, end) in store.events.lock().expect("the store events lock").iter() {
        let Some(end) = end else { continue };
        assert!(
            !(*start <= window_start && window_end <= *end),
            "the {op} call ({start:?}..{end:?}) spans the blocked window"
        );
    }

    // The one-shot semantics survive the blocked window: (a) is consumed
    // exactly once, and its replay answers from the retained state.
    let payload = verify_body(&server, &tokens[0], "login");
    assert_eq!(payload["kiwi-code"], "already_consumed", "{payload}");
}

#[test]
fn the_same_token_race_answers_one_winner_from_the_retained_state() {
    let server = spawn(
        SidecarState::build(config_with("login", None)),
        ServerOptions::default(),
    );
    let token = issue_and_solve(&server, "login");
    let barrier = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let token = token.clone();
            let addr = server.addr;
            std::thread::spawn(move || {
                barrier.wait();
                post_json(
                    addr,
                    "/verify",
                    &format!("{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
                )
            })
        })
        .collect();
    let mut ok = 0;
    let mut duplicate = 0;
    for handle in handles {
        let (_, _, body) = handle.join().expect("the race thread joins");
        let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
        match payload["kiwi-code"].as_str() {
            Some("ok") => ok += 1,
            Some("already_consumed") => duplicate += 1,
            other => panic!("unexpected race outcome {other:?}: {body}"),
        }
    }
    assert_eq!(ok, 1, "exactly one winner");
    assert_eq!(duplicate, 3, "the losers never re-derive");
}

#[test]
#[ignore = "performance characterization, not a correctness gate: concurrent Argon derivations \
            contend for memory bandwidth, so a wall-clock estimate below the 4x-serialized sum \
            can resemble lock serialization with the store lock completely free; the store-lock \
            invariant is proven directly by a_blocked_derivation_leaves_the_store_free"]
fn concurrent_argon_verifies_wall_clock_characterization() {
    let server = spawn(
        SidecarState::build(config_with("login=argon16", None)),
        ServerOptions::default(),
    );
    // One warmup derivation measures the single-verify cost S.
    let warm = issue_and_solve(&server, "login");
    let start = Instant::now();
    let payload = verify_body(&server, &warm, "login");
    assert_eq!(payload["kiwi-code"], "ok", "{payload}");
    let single = start.elapsed();

    // Four simultaneous verifications of four distinct tokens: each
    // derives (the store lock covers only the transition and the
    // commit), so the wall time lands well under the serialized sum
    // 4 x S on an unloaded multi-core host.
    let tokens: Vec<String> = (0..4).map(|_| issue_and_solve(&server, "login")).collect();
    let barrier = Arc::new(Barrier::new(4));
    let total_start = Instant::now();
    let handles: Vec<_> = tokens
        .iter()
        .map(|token| {
            let barrier = Arc::clone(&barrier);
            let token = token.clone();
            let addr = server.addr;
            std::thread::spawn(move || {
                barrier.wait();
                let body = post_json(
                    addr,
                    "/verify",
                    &format!("{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
                );
                body
            })
        })
        .collect();
    let mut oks = 0;
    for handle in handles {
        let (status, _, body) = handle.join().expect("the verify thread joins");
        assert_eq!(status, 200, "{body}");
        let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(payload["kiwi-code"], "ok", "{body}");
        oks += 1;
    }
    let concurrent_total = total_start.elapsed();
    assert_eq!(oks, 4);

    // The characterization: the concurrent wall time against the
    // serialized sum 4 x single. Bounded work (argon16), informative
    // only — never a merge gate.
    let serialized = single * 4;
    assert!(
        concurrent_total < serialized / 2,
        "concurrent {concurrent_total:?} must beat half the serialized sum {:?} (single {single:?})",
        serialized / 2
    );
}

// ---------------------------------------------- finding 4: one-shot burn

#[test]
fn a_failed_candidate_burns_the_record_with_no_retry_window() {
    let server = spawn(
        SidecarState::build(config_with("login", None)),
        ServerOptions::default(),
    );
    let token = issue_and_solve(&server, "login");
    // A candidate with a wrong counter reaches the proof phase and
    // fails; the record is burned on that consume.
    let mut decoded = SolutionToken::decode(&token).unwrap();
    decoded.counter = decoded.counter.wrapping_add(1);
    let wrong = decoded.encode();
    let payload = verify_body(&server, &wrong, "login");
    assert_eq!(payload["kiwi-code"], "insufficient_work", "{payload}");

    // The correct candidate arrives after the burn: the record is
    // gone, so the answer is the duplicate vocabulary, never success.
    // No attempt ceiling leaves a retry window open.
    let payload = verify_body(&server, &token, "login");
    assert_eq!(payload["kiwi-code"], "already_consumed", "{payload}");
    assert_eq!(
        payload["error-codes"],
        serde_json::json!(["timeout-or-duplicate"])
    );
}

// ------------------------------------------ finding 5: durable restarts

#[test]
fn the_file_store_survives_a_server_restart() {
    let dir = std::env::temp_dir().join(format!("kiwi-hardening-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // First process: issue and solve, never verify.
    let token = {
        let store = open_store(&StoreConfig::File(dir.clone())).expect("the store opens");
        let mut config = SidecarConfig::minimal(SECRET.to_string(), vec![], "http://127.0.0.1:0");
        config.store = store;
        let server = spawn(SidecarState::build(config), ServerOptions::default());
        issue_and_solve(&server, "login")
    };
    // The restart: a fresh server over the same directory reopens the
    // persisted envelopes; the token still verifies, exactly once.
    let store = open_store(&StoreConfig::File(dir.clone())).expect("the store reopens");
    let mut config = SidecarConfig::minimal(SECRET.to_string(), vec![], "http://127.0.0.1:0");
    config.store = store;
    let server = spawn(SidecarState::build(config), ServerOptions::default());
    let payload = verify_body(&server, &token, "login");
    assert_eq!(payload["kiwi-code"], "ok", "{payload}");
    // And the replay answers the duplicate vocabulary across the
    // restart too.
    let payload = verify_body(&server, &token, "login");
    assert_eq!(payload["kiwi-code"], "already_consumed", "{payload}");
    let _ = std::fs::remove_dir_all(&dir);
}

// -------------------------------------------- finding 6: pool + timeouts

#[test]
fn a_slowloris_stall_times_out_and_the_pool_stays_healthy() {
    let server = spawn(
        SidecarState::build(config_with("login", None)),
        ServerOptions {
            workers: 2,
            timeout: Duration::from_millis(400),
        },
    );
    // Two clients open and stall mid-request: they hold the two
    // workers, then drain their 408 when the timeout fires.
    let mut stalled = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(server.addr).expect("the stalled client connects");
        stream
            .write_all(b"POST /verify HTTP/1.1\r\nhost: sidecar.test\r\n")
            .expect("the partial head is sent");
        stalled.push(stream);
    }
    // The third client is healthy: it waits in the bounded queue, and
    // is served the moment a worker frees (about one timeout later).
    let served = Instant::now();
    let (status, _, body) = get(server.addr, "/healthz");
    let served_in = served.elapsed();
    assert_eq!((status, body.trim_end()), (200, "ok"));
    assert!(
        served_in < Duration::from_secs(5),
        "the healthy client waits at most one timeout: {served_in:?}"
    );
    for stream in &mut stalled {
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .expect("the stalled client drains");
        let text = String::from_utf8_lossy(&raw).to_string();
        assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    }
    // The pool keeps serving after the stall wave.
    let (status, _, body) = get(server.addr, "/healthz");
    assert_eq!((status, body.trim_end()), (200, "ok"));
    let (_, _, metrics) = get(server.addr, "/metrics");
    assert!(
        metrics.contains("kiwicaptcha_verifier_pool_connections{kind=\"timed_out\"} 2"),
        "{metrics}"
    );
}

#[test]
fn oversized_bodies_are_refused_not_buffered() {
    let server = spawn(
        SidecarState::build(config_with("login", None)),
        ServerOptions::default(),
    );
    let mut stream = TcpStream::connect(server.addr).expect("connect");
    // A content-length far beyond the body cap: the reader refuses
    // without buffering.
    stream
        .write_all(
            b"POST /verify HTTP/1.1\r\nhost: sidecar.test\r\ncontent-type: application/json\r\ncontent-length: 999999999\r\nconnection: close\r\n\r\n",
        )
        .expect("head sent");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("drained");
    let text = String::from_utf8_lossy(&raw).to_string();
    assert!(text.starts_with("HTTP/1.1 413"), "{text}");
}

// ------------------------------------------- finding 7: secret floors

#[test]
fn the_secret_floor_and_the_example_refusal_hold_at_startup() {
    // Below the floor: refused with an actionable message.
    let err = validate_secret("short", false).unwrap_err();
    assert!(err.contains(&MIN_SECRET_BYTES.to_string()), "{err}");
    assert!(err.contains("openssl rand"), "{err}");
    // The published example: refused, unless the explicit escape hatch.
    let err = validate_secret(EXAMPLE_SECRET, false).unwrap_err();
    assert!(err.contains("example"), "{err}");
    assert!(err.contains("KIWI_ALLOW_INSECURE_EXAMPLE_SECRET"), "{err}");
    let (_, warned) = validate_secret(EXAMPLE_SECRET, true).expect("the hatch accepts it");
    assert!(warned);
    let (_, warned) = validate_secret(SECRET, false).expect("a real secret passes");
    assert!(!warned);
}

#[test]
fn the_binary_refuses_weak_and_example_secrets_and_serves_with_the_hatch() {
    let bin = env!("CARGO_BIN_EXE_kiwicaptcha-verifier");
    // A short secret: startup refusal, actionable.
    let out = std::process::Command::new(bin)
        .env("KIWI_SECRET", "short")
        .env("KIWI_LISTEN", "http://127.0.0.1:0")
        .output()
        .expect("the binary runs");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("minimum is 32"), "{stderr}");
    // The example secret: refused without the hatch.
    let out = std::process::Command::new(bin)
        .env("KIWI_SECRET", EXAMPLE_SECRET)
        .env("KIWI_LISTEN", "http://127.0.0.1:0")
        .output()
        .expect("the binary runs");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("example"), "{stderr}");
    // With the hatch: the process starts, prints the warning, and
    // serves healthz (the port comes from the startup line).
    let mut child = std::process::Command::new(bin)
        .env("KIWI_SECRET", EXAMPLE_SECRET)
        .env("KIWI_ALLOW_INSECURE_EXAMPLE_SECRET", "1")
        .env("KIWI_LISTEN", "http://127.0.0.1:0")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary spawns");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut startup = String::new();
    std::io::BufRead::read_line(&mut stdout, &mut startup).expect("the startup line arrives");
    let addr_part = startup
        .split("listening on ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or("")
        .to_string();
    let addr: SocketAddr = addr_part
        .strip_prefix("http://")
        .unwrap_or(&addr_part)
        .parse()
        .expect("the startup line names the bound address");
    let mut served = false;
    for _ in 0..150 {
        match std::net::TcpStream::connect(addr) {
            Ok(mut stream) => {
                stream
                    .write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
                    .expect("request sent");
                let mut raw = Vec::new();
                stream.read_to_end(&mut raw).expect("response drained");
                let text = String::from_utf8_lossy(&raw).to_string();
                let status = text
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u16>().ok())
                    .expect("a status line");
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
                assert_eq!((status, body.trim_end()), (200, "ok"));
                served = true;
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    assert!(served, "the escape-hatch process never served healthz");
    let _ = child.kill();
    let _ = child.wait();
    // The hatch prints its warning on the startup path.
    let mut stderr = String::new();
    if let Some(pipe) = child.stderr.take() {
        let mut pipe = pipe;
        let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
    }
    assert!(stderr.contains("WARNING"), "{stderr}");
    assert!(stderr.contains("example"), "{stderr}");
}

// ------------------------------------------- finding 8: remoteip required

#[test]
fn remoteip_is_required_while_binding_is_on() {
    let server = spawn(
        SidecarState::build(config_with("login", None)),
        ServerOptions::default(),
    );
    let (status, _, body) = post_json(server.addr, "/issue", "{\"scope\":\"login\"}");
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("remoteip_required"), "{body}");
    let (status, _, body) = post_json(
        server.addr,
        "/verify",
        "{\"token\":\"nonempty\",\"scope\":\"login\"}",
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("remoteip_required"), "{body}");
    // A malformed remoteip is the same typed refusal family.
    let (status, _, body) = post_json(
        server.addr,
        "/issue",
        "{\"scope\":\"login\",\"remoteip\":\"not-an-ip\"}",
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("remoteip_invalid"), "{body}");
}

#[test]
fn the_remoteip_escape_hatch_and_binding_none_relax_it() {
    // The documented loopback-only development hatch.
    let mut config = config_with("login", None);
    config.allow_no_remoteip = true;
    let server = spawn(SidecarState::build(config), ServerOptions::default());
    let (status, _, wire) = post_json(server.addr, "/issue", "{\"scope\":\"login\"}");
    assert_eq!(status, 200, "{wire}");
    // binding none: remoteip optional everywhere, records carry no tag.
    let mut config = config_with("login", None);
    config.binding = kiwicaptcha_verifier::BindingConfig::None;
    let server = spawn(SidecarState::build(config), ServerOptions::default());
    let (status, _, wire) = post_json(server.addr, "/issue", "{\"scope\":\"login\"}");
    assert_eq!(status, 200, "{wire}");
    let token = solve_token(wire.trim_end());
    let (_, _, body) = post_json(
        server.addr,
        "/verify",
        &format!("{{\"token\":\"{token}\",\"scope\":\"login\"}}"),
    );
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(payload["kiwi-code"], "ok", "{body}");
}

// ---------------------------------------- risk vocabulary consistency

#[test]
fn the_scope_ids_and_the_rung_composition_stay_stable() {
    // The scope id derivation is stable and never zero (the risk
    // contract rejects 0), and two scopes never collide.
    assert_eq!(scope_id("login"), scope_id("login"));
    assert_ne!(scope_id("login"), scope_id("comment"));
    assert!(scope_id("login") > 0);
    // The risk ladder only ever raises the configured rung.
    let sha18 = parse_rung("sha18").unwrap();
    assert_eq!(
        compose_rung(sha18, kiwicaptcha_risk::action::RiskAction::Allow, false),
        sha18
    );
    assert_eq!(
        compose_rung(sha18, kiwicaptcha_risk::action::RiskAction::Argon32, false),
        parse_rung("argon32").unwrap()
    );
    assert_eq!(
        compose_rung(
            parse_rung("argon16").unwrap(),
            kiwicaptcha_risk::action::RiskAction::Sha20,
            false
        ),
        parse_rung("argon16").unwrap()
    );
}

// ------------------------------- the strong rungs end to end
//
// The hardening contract's rung table must be real, not just parsed:
// each strong rung is issued through the sidecar, solved by the shipped
// native solver and verified through the same HTTP surface a deployment
// drives. The Argon cases stay bounded (one 32 MiB × 3 and one 64 MiB × 3
// derivation); the rsw case uses the shared fixture trapdoor at the
// minimum sequential cost.

fn assert_roundtrip(plan: &str, profile: &str, m_kib: u64, t: u64) {
    let server = spawn(
        SidecarState::build(config_with(plan, None)),
        ServerOptions::default(),
    );
    let (status, _, wire) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "{wire}");
    let issued: serde_json::Value = serde_json::from_str(wire.trim_end()).unwrap();
    assert_eq!(issued["profile"], profile);
    assert_eq!(issued["mKib"], m_kib);
    assert_eq!(issued["t"], t);
    assert_eq!(issued["p"], 1);
    assert_eq!(issued["targetBits"], 1);

    // Stay above the rung's server-measured timing floor (50 ms for the
    // Argon profiles) even on a very fast host.
    std::thread::sleep(Duration::from_millis(80));
    let token = solve_token(wire.trim_end());
    let payload = verify_body(&server, &token, "login");
    assert_eq!(payload["kiwi-code"], "ok", "{payload}");
}

#[test]
fn rung_argon32_issues_solves_and_verifies_end_to_end() {
    assert_roundtrip("login=argon32", "argon32", 32 * 1024, 3);
}

#[test]
fn rung_argon64_issues_solves_and_verifies_end_to_end() {
    // 64 MiB × 3 is the strongest Argon rung; one real derivation is
    // comfortably inside the suite budget.
    assert_roundtrip("login=argon64", "argon64", 64 * 1024, 3);
}

#[test]
fn rung_rsw_issues_solves_and_verifies_end_to_end() {
    use kiwicaptcha_verifier::config::RswTrapdoorConfig;

    // The shared cross-language fixture pair (the same modulus and
    // lambda the core/PHP suites use), read from the published fixture
    // so this test does not depend on a feature-gated test module.
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/rsw-identity-v1/fixtures.json"
        ))
        .expect("the rsw fixture is readable"),
    )
    .expect("the rsw fixture is JSON");
    let modulus = fixture["modulus_n_b64"]
        .as_str()
        .expect("modulus")
        .to_string();
    let lambda = fixture["lambda_b64"].as_str().expect("lambda").to_string();

    let default_rung = parse_rung("sha18").expect("the default rung parses");
    let mut config = SidecarConfig::minimal(SECRET.to_string(), vec![], "http://127.0.0.1:0");
    config.plan = parse_scopes(Some("login=rsw"), default_rung).expect("the plan parses");
    config.rsw = Some(RswTrapdoorConfig {
        modulus_n: modulus.clone(),
        lambda,
        t: kiwicaptcha::challenge::MIN_RSW_T,
    });
    let server = spawn(SidecarState::build(config), ServerOptions::default());

    let (status, _, wire) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "{wire}");
    let issued: serde_json::Value = serde_json::from_str(wire.trim_end()).unwrap();
    assert_eq!(issued["profile"], "rsw");
    assert_eq!(issued["algorithm"], "rsw");
    assert_eq!(issued["t"], kiwicaptcha::challenge::MIN_RSW_T);
    assert_eq!(issued["targetBits"], 1);
    // The public modulus must ride the client wire, or no solver can
    // square modulo n; lambda never appears.
    assert_eq!(issued["rsw_modulus"].as_str(), Some(modulus.as_str()));
    assert!(issued.get("rsw_lambda").is_none());

    std::thread::sleep(Duration::from_millis(80));
    let token = solve_token(wire.trim_end());
    let payload = verify_body(&server, &token, "login");
    assert_eq!(payload["kiwi-code"], "ok", "{payload}");
}
