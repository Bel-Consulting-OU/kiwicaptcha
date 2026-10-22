//! Fresh probes for the redesigned sidecar admission state machine:
//! classification from the AUTHENTICATED STORED RECORD (never the
//! present-day scope rung), nonblocking capacity refusals that never
//! burn the challenge, no worker starvation under saturation, the
//! live-pending ceiling, and the HTTP-boundary operation-identity
//! grammar. These are the adversarial conditions the original audit
//! attacked: static config vs dynamic escalation, resource admission vs
//! one-shot mutation ordering, and the memory semaphore vs the HTTP
//! worker topology.

#![allow(clippy::all)]
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kiwicaptcha_verifier::state::derivation_gate;
use kiwicaptcha_verifier::{
    parse_scopes, serve_http_with, ServerOptions, SidecarConfig, SidecarState,
};

const SECRET: &str = "a-locally-generated-secret-of-48-bytes!!";
const CLIENT_IP: &str = "198.51.100.7";

fn spawn_with(configure: impl FnOnce(&mut SidecarConfig)) -> SocketAddr {
    let mut config = SidecarConfig::minimal(SECRET.to_string(), vec![], "http://127.0.0.1:0");
    configure(&mut config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let addr = listener.local_addr().expect("local addr");
    let state = Arc::new(SidecarState::build(config));
    std::thread::spawn(move || serve_http_with(listener, state, ServerOptions::default()));
    addr
}

fn post_json(addr: SocketAddr, target: &str, body: &str) -> (u16, String) {
    let request = format!(
        "POST {target} HTTP/1.1\r\nhost: sidecar.test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).expect("the sidecar socket answers");
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.write_all(request.as_bytes()).expect("request sent");
    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) => {}
        Err(_) if !response.is_empty() => {}
        Err(e) => panic!("response drained: {e}"),
    }
    let text = String::from_utf8_lossy(&response).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = match text.find("\r\n\r\n") {
        Some(end) => text[end + 4..].trim_end().to_string(),
        None => String::new(),
    };
    (status, body)
}

fn issue_and_solve(addr: SocketAddr, scope: &str) -> String {
    let (status, wire) = post_json(
        addr,
        "/issue",
        &format!("{{\"scope\":\"{scope}\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "{wire}");
    let challenge = kiwicaptcha_solver::Challenge::from_json(&wire).expect("the wire parses");
    let mut options = kiwicaptcha_solver::SolveOptions::default();
    let solution = kiwicaptcha_solver::solve(&challenge, &mut options).expect("the solve succeeds");
    solution.token(&challenge)
}

fn verify_body(token: &str, scope: &str, identity: Option<&str>) -> String {
    let id = identity
        .map(|i| format!(",\"operation_identity\":\"{i}\""))
        .unwrap_or_default();
    format!("{{\"token\":\"{token}\",\"scope\":\"{scope}\",\"remoteip\":\"{CLIENT_IP}\"{id}}}")
}

fn default_rung() -> kiwicaptcha_verifier::Rung {
    kiwicaptcha_verifier::parse_rung(kiwicaptcha_verifier::DEFAULT_PROFILE)
        .expect("the default rung parses")
}

/// Config-skew classification: the record is Argon (minted while the
/// plan said argon16) but the verifying state's plan says sha16 — the
/// risk-escalation shape too, where the rung the plan names is not the
/// rung the record carries. Admission must meter the RECORD: with a
/// budget that cannot fit the record's m_kib the verify answers
/// capacity_exceeded (a config-rung classifier would have skipped the
/// gate and verified), the refusal never burns the challenge, and the
/// same token verifies once capacity exists.
#[test]
fn argon_admission_classifies_from_the_record_not_the_plan() {
    // Shared store: issued under an Argon plan, verified under a SHA plan.
    let store: Arc<dyn kiwicaptcha_verifier::RecordStore> =
        Arc::new(kiwicaptcha_verifier::MemoryStore::new());

    let issue_addr = spawn_with(|c| {
        c.store = Arc::clone(&store);
        c.plan = parse_scopes(Some("login=argon16,shascope=sha16"), default_rung()).expect("plan");
    });
    let token = issue_and_solve(issue_addr, "login");
    // The minted record must really be the memory-hard shape.
    let (status, wire) = post_json(
        issue_addr,
        "/issue",
        r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
    );
    assert_eq!(status, 200, "{wire}");
    assert!(
        wire.contains("\"mKib\":16384"),
        "the argon16 rung must mint mKib 16384: {wire}"
    );

    // The verifying state: the plan now names SHA for login, and the
    // budget cannot fit a 16 MiB derivation.
    let tight_addr = spawn_with(|c| {
        c.store = Arc::clone(&store);
        c.plan = parse_scopes(Some("login=sha16,shascope=sha16"), default_rung()).expect("plan");
        c.argon_budget_kib = 1024;
    });

    let started = Instant::now();
    let (status, body) = post_json(tight_addr, "/verify", &verify_body(&token, "login", None));
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(r#""kiwi-code":"capacity_exceeded""#),
        "the record's Argon class must meter even though the plan says sha16: {body}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the refusal is a try, never a blocking wait"
    );

    // The refusal burned nothing: the same token under the same tight
    // state refuses AGAIN (not record_not_found) and then verifies
    // under a state whose budget fits the record.
    let (_, again) = post_json(tight_addr, "/verify", &verify_body(&token, "login", None));
    assert!(
        again.contains(r#""kiwi-code":"capacity_exceeded""#),
        "the refused record stays pending: {again}"
    );
    let (status, ok) = post_json(issue_addr, "/verify", &verify_body(&token, "login", None));
    assert_eq!(status, 200, "{ok}");
    assert!(
        ok.contains(r#""kiwi-code":"ok""#),
        "the retry succeeds once capacity exists (the record was never burned): {ok}"
    );
}

/// Worker topology: while one Argon derivation holds the entire
/// (single-record) budget at the derivation gate, a second Argon verify
/// must be REFUSED FAST (capacity_exceeded, record intact) instead of
/// parking an HTTP worker, and a SHA verify on the same state must run
/// to completion meanwhile — the pool is never globally blocked.
#[test]
fn saturation_refuses_fast_and_never_parks_workers() {
    let store: Arc<dyn kiwicaptcha_verifier::RecordStore> =
        Arc::new(kiwicaptcha_verifier::MemoryStore::new());
    let plan = |config: &mut SidecarConfig| {
        config.store = Arc::clone(&store);
        config.plan =
            parse_scopes(Some("login=argon16,shascope=sha16"), default_rung()).expect("plan");
    };
    let issue_addr = spawn_with(plan);
    let token1 = issue_and_solve(issue_addr, "login");
    let token2 = issue_and_solve(issue_addr, "login");
    let sha_token = issue_and_solve(issue_addr, "shascope");

    // The verifying state shares the store and fits exactly one 16 MiB
    // derivation.
    let addr = spawn_with(|c| {
        plan(c);
        c.argon_budget_kib = 16384;
    });

    // Hold token1's derivation at the gate (after admission+consume,
    // holding its reservation).
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_slot = std::sync::Mutex::new(Some(entered_tx));
    let release_slot = std::sync::Mutex::new(Some(release_rx));
    let held_nonce = kiwicaptcha::SolutionToken::decode(&token1)
        .expect("decode")
        .nonce;
    derivation_gate::install(move |nonce| {
        if nonce != held_nonce {
            return;
        }
        let Some(sender) = entered_slot.lock().expect("entered lock").take() else {
            return;
        };
        let _ = sender.send(());
        if let Some(receiver) = release_slot.lock().expect("release lock").take() {
            let _ = receiver.recv();
        }
    });
    let guard = GateGuard;

    let a_addr = addr;
    let t1 = token1.clone();
    let holder = std::thread::spawn(move || {
        let (status, body) = post_json(a_addr, "/verify", &verify_body(&t1, "login", None));
        (status, body)
    });
    if entered_rx.recv_timeout(Duration::from_secs(10)).is_err() {
        // Surface what the holder actually saw instead of a bare timeout.
        let _ = release_tx.send(());
        let (status, body) = holder.join().expect("holder thread");
        panic!(
            "the first argon verify never reached the derivation gate (status {status}): {body}"
        );
    }

    // Second Argon verify against a saturated budget: refused fast.
    let refused_at = Instant::now();
    let (status, body) = post_json(addr, "/verify", &verify_body(&token2, "login", None));
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(r#""kiwi-code":"capacity_exceeded""#),
        "a saturated budget refuses the second argon verify: {body}"
    );
    assert!(
        refused_at.elapsed() < Duration::from_secs(2),
        "the refusal must return promptly — an HTTP worker never parks on the gate"
    );

    // A SHA verify on the same state completes while the argon
    // derivation still holds the budget.
    let (status, body) = post_json(addr, "/verify", &verify_body(&sha_token, "shascope", None));
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(r#""kiwi-code":"ok""#),
        "sha traffic is never starved by argon saturation: {body}"
    );

    // Release the holder; its own verify completes; the refused argon
    // token now verifies (its record survived the refusal).
    release_tx.send(()).expect("release the holder");
    let (status, body) = holder.join().expect("holder thread");
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(r#""kiwi-code":"ok""#),
        "the held argon derivation completes after release: {body}"
    );
    let (status, body) = post_json(addr, "/verify", &verify_body(&token2, "login", None));
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(r#""kiwi-code":"ok""#),
        "the previously refused argon token verifies once capacity frees: {body}"
    );
    drop(guard);
}

/// Removes the derivation-gate hook even when an assertion fails.
struct GateGuard;
impl Drop for GateGuard {
    fn drop(&mut self) {
        derivation_gate::remove();
    }
}

/// The live-pending ceiling: issuance above the bound refuses with the
/// typed store_full answer, and the refusal poisons nothing — the
/// already-issued challenge still verifies.
#[test]
fn the_pending_ceiling_refuses_issuance_without_poisoning() {
    let addr = spawn_with(|c| {
        c.max_pending = 1;
    });
    let token = issue_and_solve(addr, "login");

    let (status, body) = post_json(
        addr,
        "/issue",
        r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
    );
    assert_eq!(status, 503, "the second issue must hit the ceiling: {body}");
    assert!(body.contains("challenge_store_full"), "{body}");

    // The first challenge is untouched by the ceiling refusal.
    let (status, body) = post_json(addr, "/verify", &verify_body(&token, "login", None));
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(r#""kiwi-code":"ok""#),
        "the ceiling refusal never poisons an outstanding record: {body}"
    );
}

/// The operation-identity grammar at the HTTP boundary: a malformed
/// identity refuses before any store transition (so Memory, File and
/// Redis accept the same shapes), and the record survives for a
/// well-formed retry.
#[test]
fn operation_identity_grammar_is_enforced_before_any_transition() {
    let addr = spawn_with(|_| {});
    let token = issue_and_solve(addr, "login");

    for bad in ["has space", "colon:bad", "!!", &"x".repeat(129)] {
        let (status, body) = post_json(addr, "/verify", &verify_body(&token, "login", Some(bad)));
        assert_eq!(status, 200, "identity {bad:?}: {body}");
        assert!(
            body.contains(r#""kiwi-code":"bad_request"#),
            "identity {bad:?} must refuse at the boundary: {body}"
        );
    }

    // A well-formed identity on the same (still pending) record runs
    // the normal path: the grammar refusal never consumed anything.
    let (status, body) = post_json(
        addr,
        "/verify",
        &verify_body(&token, "login", Some("ok-id_1-2")),
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        !body.contains("bad_request"),
        "a valid identity proceeds past the boundary: {body}"
    );
    assert!(
        body.contains(r#""kiwi-code":"ok""#),
        "the record was never burned by the grammar refusals: {body}"
    );
}
