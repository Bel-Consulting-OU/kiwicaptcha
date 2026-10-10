//! The end-to-end sidecar contract: a real challenge minted by the
//! workspace issuer, solved by the workspace solver, redeemed through
//! the sidecar's localhost HTTP surface, with the observability plane
//! and the bearer authentication shape-tested alongside.
//!
//! Every connection the test opens targets the loopback ephemeral port
//! the server bound (the no-outbound-calls property holds by
//! construction: the client dials only that address, and the pinned
//! bind test proves the server refuses anything off loopback).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use kiwicaptcha::challenge::{issue_challenge, now_epoch_micros, BindingMode, ChallengeConfig};
use kiwicaptcha::{Issued, PoWAlgorithm};
use kiwicaptcha_verifier::{
    parse_listen, serve_http_with, ServerOptions, SidecarConfig, SidecarState,
};

const SECRET: &str = "a-locally-generated-secret-of-48-bytes!!";
const CLIENT_IP: &str = "198.51.100.7";

/// The std-only test HTTP client: one request per connection, read to
/// the server's close, exactly like the sidecar's contract.
fn http(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("the sidecar socket answers");
    assert!(stream.peer_addr().unwrap().ip().is_loopback());
    stream.write_all(request.as_bytes()).expect("request sent");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("response drained");
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .expect("a status line");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn post_json(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
    http(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nhost: sidecar.test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn post_json_bearer(addr: SocketAddr, path: &str, body: &str, bearer: &str) -> (u16, String) {
    http(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer {bearer}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    http(
        addr,
        &format!("GET {path} HTTP/1.1\r\nhost: sidecar.test\r\nconnection: close\r\n\r\n"),
    )
}

fn get_bearer(addr: SocketAddr, path: &str, bearer: &str) -> (u16, String) {
    http(
        addr,
        &format!(
            "GET {path} HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer {bearer}\r\nconnection: close\r\n\r\n"
        ),
    )
}

fn sha_config() -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.to_string(),
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 2,
        ttl_secs: 300,
        min_duration_ms: None,
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
        rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
        tenant: None,
    }
}

/// Mint through the workspace issuer under the sidecar's secret, and
/// wait out the rung's timing floor so the solve is redeemable.
fn mint(scope: &str) -> Issued {
    let now_ns = now_epoch_micros();
    let issued = issue_challenge(
        &sha_config(),
        scope,
        CLIENT_IP,
        now_ns / 1_000_000,
        now_ns,
        0,
        None,
    )
    .expect("issuance succeeds");
    std::thread::sleep(Duration::from_millis(10));
    issued
}

struct Server {
    addr: SocketAddr,
    state: Arc<SidecarState>,
}

fn spawn_with(state: SidecarState, options: ServerOptions) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let addr = listener.local_addr().expect("local addr");
    let state = Arc::new(state);
    let loop_state = Arc::clone(&state);
    std::thread::spawn(move || serve_http_with(listener, loop_state, options));
    Server { addr, state }
}

fn spawn(state: SidecarState) -> Server {
    spawn_with(state, ServerOptions::default())
}

fn solve_token(wire: &str) -> String {
    let challenge = kiwicaptcha_solver::Challenge::from_json(wire).expect("the wire parses");
    let mut options = kiwicaptcha_solver::SolveOptions::default();
    let solution = kiwicaptcha_solver::solve(&challenge, &mut options).expect("the solve succeeds");
    solution.token(&challenge)
}

#[test]
fn solve_verify_replay_and_scope_end_to_end() {
    let server = spawn(SidecarState::new(
        SECRET.to_string(),
        None,
        vec!["login".to_string(), "signup".to_string()],
        "http://127.0.0.1:0",
    ));

    // A real challenge from the workspace issuer lands in the store.
    let issued = mint("login");
    let wire = kiwicaptcha_verifier::issue_wire_of(&issued);
    server.state.inject_record(
        issued.record,
        Some("checkout".to_string()),
        Some("c-91".to_string()),
    );
    let token = solve_token(&wire);

    // The happy path: the provider shape with the issuance-bound
    // metadata echoed.
    let (status, body) = post_json(
        server.addr,
        "/verify",
        &format!("{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(payload["success"], serde_json::Value::Bool(true));
    assert_eq!(payload["kiwi-code"], "ok");
    assert_eq!(payload["action"], "checkout");
    assert_eq!(payload["cdata"], "c-91");
    assert!(payload["error-codes"].as_array().unwrap().is_empty());
    assert!(payload["challenge_ts"].as_str().unwrap().ends_with('Z'));

    // The single-use replay answers the provider duplicate vocabulary.
    let (_, replay) = post_json(
        server.addr,
        "/verify",
        &format!("{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    let replay_payload: serde_json::Value = serde_json::from_str(&replay).expect("json body");
    assert_eq!(replay_payload["success"], serde_json::Value::Bool(false));
    assert_eq!(
        replay_payload["error-codes"],
        serde_json::json!(["timeout-or-duplicate"])
    );
    assert_eq!(replay_payload["kiwi-code"], "already_consumed");

    // A fresh challenge under the wrong scope carries the precise core
    // code beside the collapsed provider code. The failed candidate
    // burns the record (one-shot), so both verifications land in the
    // consumed tombstone.
    let other = mint("login");
    let other_wire = kiwicaptcha_verifier::issue_wire_of(&other);
    server.state.inject_record(other.record, None, None);
    let other_token = solve_token(&other_wire);
    let (_, wrong) = post_json(
        server.addr,
        "/verify",
        &format!(
            "{{\"token\":\"{other_token}\",\"scope\":\"signup\",\"remoteip\":\"{CLIENT_IP}\"}}"
        ),
    );
    let wrong_payload: serde_json::Value = serde_json::from_str(&wrong).expect("json body");
    assert_eq!(wrong_payload["success"], serde_json::Value::Bool(false));
    assert_eq!(wrong_payload["kiwi-code"], "wrong_scope");
    assert_eq!(
        wrong_payload["error-codes"],
        serde_json::json!(["invalid-input-response"])
    );

    // The metrics plane carries the outcome families.
    let (metrics_status, metrics) = get(server.addr, "/metrics");
    assert_eq!(metrics_status, 200);
    assert!(metrics.contains("# TYPE kiwicaptcha_verifier_verifies_total counter"));
    assert!(metrics.contains("kiwicaptcha_verifier_verifies_total{outcome=\"ok\"} 1"));
    assert!(metrics.contains("kiwicaptcha_verifier_verifies_total{outcome=\"already_consumed\"} 1"));
    assert!(metrics.contains("kiwicaptcha_verifier_verifies_total{outcome=\"wrong_scope\"} 1"));
    assert!(metrics.contains("kiwicaptcha_exporter_scrapes_total 1"));
    // Both records are burned: the success and the wrong-scope
    // candidate (the one-shot consume has no retry window).
    assert!(metrics.contains("kiwicaptcha_verifier_records{state=\"consumed\"} 2"));
    assert!(metrics.contains("kiwicaptcha_verifier_records{state=\"pending\"} 0"));

    // The doctor summary and the always-open health probe.
    let (doctor_status, doctor) = get(server.addr, "/doctor");
    assert_eq!(doctor_status, 200);
    let doctor_payload: serde_json::Value = serde_json::from_str(&doctor).expect("json body");
    assert_eq!(doctor_payload["ok"], serde_json::Value::Bool(true));
    let names: Vec<&str> = doctor_payload["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    for name in ["secret", "store", "auth", "listen", "binding", "risk"] {
        assert!(names.contains(&name), "doctor must check {name}: {doctor}");
    }
    let (health_status, health) = get(server.addr, "/healthz");
    assert_eq!((health_status, health.trim_end()), (200, "ok"));
}

#[test]
fn issue_endpoint_mints_and_redeems() {
    let server = spawn(SidecarState::new(
        SECRET.to_string(),
        None,
        vec!["login".to_string()],
        "http://127.0.0.1:0",
    ));
    let (status, wire) = post_json(
        server.addr,
        "/issue",
        &format!(
            "{{\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\",\"action\":\"login\",\"cdata\":\"seed-7\"}}"
        ),
    );
    assert_eq!(status, 200, "{wire}");
    let token = solve_token(wire.trim_end());
    let (_, body) = post_json(
        server.addr,
        "/verify",
        &format!("{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(payload["success"], serde_json::Value::Bool(true));
    assert_eq!(payload["action"], "login");
    assert_eq!(payload["cdata"], "seed-7");

    // A scope outside the configured plan is a typed 400 at issuance.
    let (bad_status, bad) = post_json(
        server.addr,
        "/issue",
        &format!("{{\"scope\":\"admin\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(bad_status, 400);
    assert!(bad.contains("scope_not_allowed"), "{bad}");
}

#[test]
fn bearer_authentication_gates_the_sensitive_routes() {
    let mut config = SidecarConfig::minimal(SECRET.to_string(), vec![], "http://127.0.0.1:0");
    config.bearer = Some("sidecar-credential".to_string());
    let server = spawn(SidecarState::build(config));
    // Without the credential every sensitive route refuses; healthz
    // stays open for the process manager.
    assert_eq!(post_json(server.addr, "/verify", "{}").0, 401);
    assert_eq!(post_json(server.addr, "/issue", "{}").0, 401);
    assert_eq!(get(server.addr, "/metrics").0, 401);
    assert_eq!(get(server.addr, "/doctor").0, 401);
    assert_eq!(get(server.addr, "/healthz").0, 200);
    // A wrong credential fails closed the same way.
    assert_eq!(
        post_json_bearer(server.addr, "/verify", "{}", "wrong").0,
        401
    );
    // The right credential reaches the handler (the typed remoteip
    // refusal proves the route, not the auth, rejected it).
    let (status, body) = post_json_bearer(
        server.addr,
        "/verify",
        "{\"token\":\"x\",\"scope\":\"login\"}",
        "sidecar-credential",
    );
    assert_eq!(status, 400);
    assert!(body.contains("remoteip_required"), "{body}");
    let (metrics_status, _) = get_bearer(server.addr, "/metrics", "sidecar-credential");
    assert_eq!(metrics_status, 200);
}

#[test]
fn the_unix_socket_surface_serves_the_same_handler() {
    use std::os::unix::net::UnixStream;
    let dir = std::env::temp_dir().join(format!("kiwi-sidecar-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("verify.sock");
    let state = Arc::new(SidecarState::new(
        SECRET.to_string(),
        None,
        vec![],
        "unix:///tmp/kiwi-sidecar/verify.sock",
    ));
    {
        let path = path.clone();
        let state = Arc::clone(&state);
        std::thread::spawn(move || kiwicaptcha_verifier::serve_unix(&path, state));
    }
    // The socket file appears once the listener binds.
    let mut ready = false;
    for _ in 0..100 {
        if path.exists() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(ready, "the unix socket never appeared");
    let mut stream = UnixStream::connect(&path).expect("unix socket connect");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nhost: sidecar.test\r\nconnection: close\r\n\r\n")
        .expect("request sent");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("response drained");
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("ok\n"), "{text}");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn the_server_refuses_bindings_off_loopback() {
    // The no-outbound-calls property is structural: the only socket the
    // process opens is its listener (plus an operator-selected store
    // backend), and a listener off loopback can not even be configured.
    assert!(parse_listen("http://127.0.0.1:7371").is_ok());
    assert!(parse_listen("http://0.0.0.0:7371").is_err());
    assert!(parse_listen("http://203.0.113.9:7371").is_err());
    // The core clock helper the verify path reads stays available (the
    // sidecar shares the core's clock, no second time source).
    assert!(now_epoch_micros() > 1_700_000_000 * 1_000_000);
}

#[test]
fn expected_request_binding_is_enforced_when_the_caller_states_it() {
    let server = spawn(SidecarState::new(
        SECRET.to_string(),
        None,
        vec!["login".to_string()],
        "http://127.0.0.1:0",
    ));

    let mint_bound = |binding: Option<&str>| -> Issued {
        let now_ns = now_epoch_micros();
        let issued = issue_challenge(
            &sha_config(),
            "login",
            CLIENT_IP,
            now_ns / 1_000_000,
            now_ns,
            0,
            binding,
        )
        .expect("issuance succeeds");
        std::thread::sleep(Duration::from_millis(10));
        issued
    };

    // Equal binding redeems.
    let ok = mint_bound(Some("txn-A"));
    let ok_wire = kiwicaptcha_verifier::issue_wire_of(&ok);
    server.state.inject_record(ok.record.clone(), None, None);
    let ok_token = solve_token(&ok_wire);
    let (status, body) = post_json(
        server.addr,
        "/verify",
        &format!(
            "{{\"token\":\"{ok_token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\",\"expected_request_binding\":\"txn-A\"}}"
        ),
    );
    assert_eq!(status, 200, "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(payload["success"], serde_json::Value::Bool(true), "{body}");

    // A different expected binding refuses the same-shaped record.
    let other = mint_bound(Some("txn-A"));
    let other_wire = kiwicaptcha_verifier::issue_wire_of(&other);
    server.state.inject_record(other.record, None, None);
    let other_token = solve_token(&other_wire);
    let (status, body) = post_json(
        server.addr,
        "/verify",
        &format!(
            "{{\"token\":\"{other_token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\",\"expected_request_binding\":\"txn-B\"}}"
        ),
    );
    assert_eq!(status, 200, "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(payload["success"], serde_json::Value::Bool(false), "{body}");
    assert_eq!(payload["kiwi-code"], "request_binding_mismatch", "{body}");

    // An empty expectation asserts the record carries no binding.
    let bare = mint_bound(None);
    let bare_wire = kiwicaptcha_verifier::issue_wire_of(&bare);
    server.state.inject_record(bare.record, None, None);
    let bare_token = solve_token(&bare_wire);
    let (status, body) = post_json(
        server.addr,
        "/verify",
        &format!(
            "{{\"token\":\"{bare_token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\",\"expected_request_binding\":\"\"}}"
        ),
    );
    assert_eq!(status, 200, "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(payload["success"], serde_json::Value::Bool(true), "{body}");

    // A bound record cannot satisfy the empty expectation.
    let bound = mint_bound(Some("txn-A"));
    let bound_wire = kiwicaptcha_verifier::issue_wire_of(&bound);
    server.state.inject_record(bound.record, None, None);
    let bound_token = solve_token(&bound_wire);
    let (_, body) = post_json(
        server.addr,
        "/verify",
        &format!(
            "{{\"token\":\"{bound_token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\",\"expected_request_binding\":\"\"}}"
        ),
    );
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(payload["success"], serde_json::Value::Bool(false), "{body}");
    assert_eq!(payload["kiwi-code"], "request_binding_mismatch", "{body}");
}
