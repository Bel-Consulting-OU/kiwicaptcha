//! The CLI integration tests: a stub deployment on 127.0.0.1 that answers
//! the challenge route by minting a real challenge through the workspace
//! issuer and the siteverify route by running the real core verifier, so
//! the binary's whole flow (fetch, solve, post, exit code) is proven
//! against the same verifier a deployment runs.

use kiwicaptcha::{
    issue_challenge, now_epoch_micros, verify_solution, BindingMode, ChallengeConfig,
    ChallengeRecord, PoWAlgorithm, RequestBindingExpectation, SolutionToken, VerifyContext,
    VerifyOutcome,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const SITEVERIFY_SECRET: &str = "stub-siteverify-secret-0123456789abcdef";

/// The shared state between the stub threads and the test.
struct StubState {
    records: Mutex<HashMap<String, ChallengeRecord>>,
    presented: Mutex<Vec<String>>,
}

/// Spawn the stub deployment; returns its base URL (the challenge route
/// is `/challenge`, the verify route `/siteverify`, the bundle's own
/// layout the CLI derives its default verify endpoint from) beside the
/// shared state the assertions read.
fn spawn_stub() -> (String, Arc<StubState>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the stub binds a free port");
    let addr = listener.local_addr().expect("the stub reports its address");
    let state = Arc::new(StubState {
        records: Mutex::new(HashMap::new()),
        presented: Mutex::new(Vec::new()),
    });
    let thread_state = Arc::clone(&state);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let state = Arc::clone(&thread_state);
            std::thread::spawn(move || handle(stream, state));
        }
    });
    (format!("http://{addr}"), state)
}

fn handle(mut stream: TcpStream, state: Arc<StubState>) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let Some((method, path, body)) = read_request(&mut stream) else {
        return;
    };
    let (status, body) = route(&method, &path, &body, &state);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).ok();
}

/// Read one request: the head, then exactly Content-Length body bytes.
fn read_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).ok()?;
        if n == 0 {
            return None;
        }
        raw.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&raw).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?.to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; length];
    if length > 0 {
        stream.read_exact(&mut body).ok()?;
    }
    Some((method, path, String::from_utf8_lossy(&body).to_string()))
}

fn route(method: &str, path: &str, body: &str, state: &StubState) -> (u16, String) {
    match (method, path) {
        ("POST", "/challenge") => {
            let payload: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => return (400, "{\"error\":{\"code\":\"bad-request\"}}".into()),
            };
            if payload.get("scope").and_then(|s| s.as_str()) != Some("login") {
                return (422, "{\"error\":{\"code\":\"INVALID_SCOPE\"}}".into());
            }
            let now_ns = now_epoch_micros();
            let issued = issue_challenge(
                &challenge_config(),
                "login",
                "127.0.0.1",
                now_ns / 1_000_000,
                now_ns,
                0,
                None,
            )
            .expect("issuance");
            state
                .records
                .lock()
                .unwrap()
                .insert(issued.challenge.nonce.clone(), issued.record.clone());
            (200, wire_json(&issued))
        }
        ("POST", "/siteverify") => {
            let payload: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        400,
                        "{\"success\":false,\"error-codes\":[\"bad-request\"]}".into(),
                    )
                }
            };
            if payload.get("secret").and_then(|s| s.as_str()) != Some(SITEVERIFY_SECRET) {
                return (
                    200,
                    "{\"success\":false,\"error-codes\":[\"invalid-input-secret\"]}".into(),
                );
            }
            let Some(response) = payload.get("response").and_then(|r| r.as_str()) else {
                return (
                    200,
                    "{\"success\":false,\"error-codes\":[\"missing-input-response\"]}".into(),
                );
            };
            state.presented.lock().unwrap().push(response.to_string());
            let Ok(token) = SolutionToken::decode(response) else {
                return (
                    200,
                    "{\"success\":false,\"error-codes\":[\"invalid-input-response\"]}".into(),
                );
            };
            let records = state.records.lock().unwrap();
            let Some(record) = records.get(&token.nonce) else {
                return (
                    200,
                    "{\"success\":false,\"error-codes\":[\"invalid-input-response\"]}".into(),
                );
            };
            match verify_record(record, &token) {
                VerifyOutcome::Valid { .. } => (
                    200,
                    "{\"success\":true,\"challenge_ts\":null,\"hostname\":null,\"action\":null,\"cdata\":null,\"error-codes\":[]}".into(),
                ),
                VerifyOutcome::Invalid(_) => (
                    200,
                    "{\"success\":false,\"challenge_ts\":null,\"hostname\":null,\"action\":null,\"cdata\":null,\"error-codes\":[\"invalid-input-response\"]}".into(),
                ),
            }
        }
        _ => (404, "{\"error\":{\"code\":\"not-found\"}}".into()),
    }
}

fn challenge_config() -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.to_string(),
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 2,
        ttl_secs: 300,
        min_duration_ms: Some(0),
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 8,
        binding_mode: BindingMode::None,
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

/// The endpoint's own wire: the PHP Challenge::toArray key set.
fn wire_json(issued: &kiwicaptcha::Issued) -> String {
    let c = &issued.challenge;
    serde_json::json!({
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
    })
    .to_string()
}

/// The siteverify route's verification: the core verifier itself.
fn verify_record(record: &ChallengeRecord, token: &SolutionToken) -> VerifyOutcome {
    let now_ns = now_epoch_micros();
    let now_unix_value = now_ns / 1_000_000;
    let mut now_unix = move || now_unix_value;
    let mut record = record.clone();
    let mut ctx = VerifyContext {
        record: &mut record,
        secret_key: SECRET,
        tenant: None,
        secrets_by_kid: None,
        revoked_kids: None,
        counter: token.counter,
        duration_ms: token.duration_ms,
        now_unix: Some(&mut now_unix),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        policy_version_floor: None,
        client_ip: None,
        execution_digest: None,
        execution_trace: None,
        telemetry: Some(&token.telemetry),
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
        rsw_proof: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_keyring: None,
    };
    verify_solution(&mut ctx)
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kiwicaptcha-solver"))
        .args(args)
        .output()
        .expect("the CLI binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn cli_solves_and_verifies_end_to_end_over_http() {
    let (base, state) = spawn_stub();
    let (code, stdout, stderr) = run_cli(&[
        "solve",
        "--endpoint",
        &format!("{base}/challenge"),
        "--scope",
        "login",
        "--secret",
        SITEVERIFY_SECRET,
    ]);
    assert_eq!(code, 0, "a verified solve exits zero; stderr: {stderr}");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert_eq!(parsed["solved"], true);
    assert_eq!(parsed["verified"], true);
    assert_eq!(parsed["error-codes"], serde_json::json!([]));
    assert!(parsed["token"].as_str().is_some_and(|t| !t.is_empty()));

    // The load-bearing assertion: the token the CLI posted is accepted by
    // the workspace's own verifier, re-run here against the stored record.
    let token_wire = state
        .presented
        .lock()
        .unwrap()
        .pop()
        .expect("the CLI must have presented a token to the verify route");
    let token = SolutionToken::decode(&token_wire).expect("the presented token decodes");
    let record = state
        .records
        .lock()
        .unwrap()
        .get(&token.nonce)
        .cloned()
        .expect("the stub stored the challenge record for the nonce");
    assert!(
        matches!(verify_record(&record, &token), VerifyOutcome::Valid { .. }),
        "the workspace verifier must accept the CLI's token"
    );
}

#[test]
fn cli_challenge_subcommand_prints_the_raw_challenge_json() {
    let (base, _state) = spawn_stub();
    let (code, stdout, stderr) = run_cli(&[
        "challenge",
        "--endpoint",
        &format!("{base}/challenge"),
        "--scope",
        "login",
    ]);
    assert_eq!(code, 0, "the challenge fetch exits zero; stderr: {stderr}");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is the raw challenge JSON");
    assert!(parsed.get("nonce").is_some());
    assert!(parsed.get("prefix").is_some());
}

#[test]
fn cli_solve_without_a_secret_prints_the_token_for_the_form_flow() {
    let (base, _state) = spawn_stub();
    let (code, stdout, stderr) = run_cli(&[
        "solve",
        "--endpoint",
        &format!("{base}/challenge"),
        "--scope",
        "login",
    ]);
    assert_eq!(code, 0, "the solve-only mode exits zero; stderr: {stderr}");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert_eq!(parsed["solved"], true);
    assert!(parsed["verified"].is_null());
    assert!(parsed["token"].as_str().is_some_and(|t| !t.is_empty()));
}

#[test]
fn cli_reports_a_rejected_secret_with_exit_one() {
    let (base, _state) = spawn_stub();
    let (code, stdout, stderr) = run_cli(&[
        "solve",
        "--endpoint",
        &format!("{base}/challenge"),
        "--scope",
        "login",
        "--secret",
        "wrong-secret",
    ]);
    assert_eq!(
        code, 1,
        "a rejected verification exits one; stderr: {stderr}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert_eq!(parsed["solved"], true);
    assert_eq!(parsed["verified"], false);
    assert_eq!(
        parsed["error-codes"],
        serde_json::json!(["invalid-input-secret"]),
        "the server's error code is printed"
    );
}

#[test]
fn cli_reports_a_refused_challenge_with_exit_one() {
    let (base, _state) = spawn_stub();
    let (code, stdout, stderr) = run_cli(&[
        "challenge",
        "--endpoint",
        &format!("{base}/challenge"),
        "--scope",
        "not-the-login-scope",
    ]);
    assert_eq!(code, 1, "a refused challenge exits one; stderr: {stderr}");
    assert!(
        stdout.contains("INVALID_SCOPE"),
        "the server's error code is printed: {stdout}"
    );
}

#[test]
fn cli_usage_errors_exit_two() {
    let (code, _, stderr) = run_cli(&["solve", "--scope", "login"]);
    assert_eq!(
        code, 2,
        "a missing --endpoint is a usage error; stderr: {stderr}"
    );
    let (code, _, _) = run_cli(&["bogus-subcommand"]);
    assert_eq!(code, 2);
    let (code, _, _) = run_cli(&[]);
    assert_eq!(code, 2);
    let (code, _, stderr) = run_cli(&[
        "solve",
        "--endpoint",
        "http://127.0.0.1:9/challenge",
        "--scope",
        "login",
    ]);
    assert_eq!(code, 2, "a transport failure exits two; stderr: {stderr}");
}

#[test]
fn cli_help_documented_flow_and_price() {
    let (code, stdout, _) = run_cli(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("browser's price"),
        "the help states the browser-price contract"
    );
    assert!(
        stdout.contains("20,000,000 hashes"),
        "the help states the cap"
    );
    assert!(
        stdout.contains("/siteverify"),
        "the help documents the verify route"
    );
}
