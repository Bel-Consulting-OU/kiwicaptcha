//! Fresh probes for the two issuance-surface contracts: the strict
//! typed parser (unknown fields and mistyped values refuse, query
//! parameters answer the public 422 shape) and the shared
//! `Kiwi-Execution-Max-Version` capability policy (absent = v1 floor,
//! explicit 0 = never arm, canonical = clamped grammar).

#![allow(clippy::all)]
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use kiwicaptcha_verifier::{serve_http_with, ServerOptions, SidecarConfig, SidecarState};

const SECRET: &str = "a-locally-generated-secret-of-48-bytes!!";

fn spawn() -> SocketAddr {
    spawn_with(|_| {})
}

fn spawn_with(configure: impl FnOnce(&mut SidecarConfig)) -> SocketAddr {
    let mut config = SidecarConfig::minimal(SECRET.to_string(), vec![], "http://127.0.0.1:0");
    configure(&mut config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let addr = listener.local_addr().expect("local addr");
    let state = Arc::new(SidecarState::build(config));
    std::thread::spawn(move || serve_http_with(listener, state, ServerOptions::default()));
    addr
}

/// One POST over a raw connection; returns (status, body).
fn post(addr: SocketAddr, target: &str, body: &str, extra_headers: &[(&str, &str)]) -> (u16, String) {
    let mut headers = String::new();
    for (name, value) in extra_headers {
        headers.push_str(&format!("{name}: {value}\r\n"));
    }
    let request = format!(
        "POST {target} HTTP/1.1\r\nhost: sidecar.test\r\ncontent-type: application/json\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).expect("the sidecar socket answers");
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
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

const ISSUE_BODY: &str = r#"{"scope":"login","remoteip":"198.51.100.7"}"#;

// ------------------------------------------------------- strict parsing

#[test]
fn issue_refuses_unknown_fields() {
    let addr = spawn();
    let (status, body) = post(
        addr,
        "/issue",
        r#"{"scope":"login","remoteip":"198.51.100.7","bogus_field":1}"#,
        &[],
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("bad_request"), "{body}");
}

#[test]
fn issue_refuses_a_mistyped_scope_instead_of_defaulting_to_login() {
    let addr = spawn();
    // A non-string scope used to fall through `as_str()` into the
    // `login` default; the typed parse refuses it as garbage.
    let (status, body) = post(addr, "/issue", r#"{"scope":123,"remoteip":"198.51.100.7"}"#, &[]);
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("bad_request"), "{body}");
    // An ABSENT scope still takes the documented default.
    let (status, body) = post(addr, "/issue", r#"{"remoteip":"198.51.100.7"}"#, &[]);
    assert_eq!(status, 200, "the absent scope keeps the login default: {body}");
}

#[test]
fn verify_refuses_unknown_fields_but_accepts_the_sdk_payload_shape() {
    let addr = spawn();
    let (status, body) = post(
        addr,
        "/verify",
        r#"{"token":"x","scope":"login","remoteip":"198.51.100.7","bogus":true}"#,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(r#""kiwi-code":"bad_request""#), "{body}");
    // The Go/Node/Python delegation payload carries enforce_telemetry:
    // it must parse (and fail later at the token, not at the parser).
    let (status, body) = post(
        addr,
        "/verify",
        r#"{"token":"x","scope":"login","remoteip":"198.51.100.7","enforce_telemetry":true,"operation_identity":"op-1"}"#,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(r#""kiwi-code":"malformed_token""#),
        "the SDK payload must reach the token gate, not the parser: {body}"
    );
    // A mistyped enforce_telemetry is garbage, not a silent drop.
    let (_, body) = post(
        addr,
        "/verify",
        r#"{"token":"x","scope":"login","remoteip":"198.51.100.7","enforce_telemetry":"yes"}"#,
        &[],
    );
    assert!(body.contains(r#""kiwi-code":"bad_request""#), "{body}");
}

#[test]
fn issue_and_verify_answer_the_public_422_for_query_parameters() {
    let addr = spawn();
    let (status, body) = post(addr, "/issue?sitekey=abc", ISSUE_BODY, &[]);
    assert_eq!(status, 422, "{body}");
    assert!(body.contains("QUERY_PARAMETERS_NOT_ALLOWED"), "{body}");
    // A bare '?' (empty query string) still counts: the sender wrote a
    // query, and the public shape refuses the shape, not its contents.
    let (status, body) = post(addr, "/verify?", r#"{"token":"x","scope":"login","remoteip":"198.51.100.7"}"#, &[]);
    assert_eq!(status, 422, "{body}");
    assert!(body.contains("QUERY_PARAMETERS_NOT_ALLOWED"), "{body}");
    // The status line itself carries 422 (not the 500 fallback).
    let mut stream = TcpStream::connect(addr).expect("socket");
    stream
        .write_all(
            b"POST /issue?x=1 HTTP/1.1\r\nhost: sidecar.test\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
        )
        .expect("sent");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 422 "), "{text}");
}

// ---------------------------------------------------- execution capability

/// The shared `clientCapability` mapping, probed through the header on
/// a deployment WITH an execution key (every issuance would arm).
#[test]
fn an_explicit_zero_capability_refuses_an_armed_deployment() {
    let addr = spawn_with(|c| {
        c.execution_key = Some("01".repeat(32));
        c.execution_version = 6;
    });
    for advertised in ["0", " 0 ", "00", "-1"] {
        let (status, body) = post(
            addr,
            "/issue",
            ISSUE_BODY,
            &[("kiwi-execution-max-version", advertised)],
        );
        // Only the exact zero (after trim) is the capability-none
        // statement; the malformed shapes degrade to the v1 floor and
        // are served an armed v1 challenge.
        if advertised.trim() == "0" {
            assert_eq!(status, 422, "advertised {advertised:?}: {body}");
            assert!(
                body.contains("CLIENT_EXECUTION_VERSION_UNSUPPORTED"),
                "{body}"
            );
        } else {
            assert_eq!(status, 200, "advertised {advertised:?}: {body}");
        }
    }
}

#[test]
fn a_zero_capability_client_is_served_when_nothing_would_arm() {
    // Without an execution key nothing arms, so the plain challenge is
    // issued exactly like any other — the zero is not a refusal.
    let addr = spawn();
    let (status, body) = post(
        addr,
        "/issue",
        ISSUE_BODY,
        &[("kiwi-execution-max-version", "0")],
    );
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("execution_program"), "{body}");
}

fn issue_with_capability(header: Option<&str>) -> (u16, serde_json::Value) {
    let addr = spawn_with(|c| {
        c.execution_key = Some("01".repeat(32));
        c.execution_version = 6;
    });
    let headers = header
        .map(|h| vec![("kiwi-execution-max-version", h)])
        .unwrap_or_default();
    let (status, body) = post(addr, "/issue", ISSUE_BODY, &headers);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    (status, value)
}

#[test]
fn the_advertised_capability_caps_the_minted_grammar() {
    // Absent header: the v1 compatibility floor — an older driver that
    // never advertises receives version 1, never the node cap.
    let (status, wire) = issue_with_capability(None);
    assert_eq!(status, 200, "{wire}");
    assert!(wire["execution_program"].is_string(), "{wire}");
    assert_eq!(wire["execution_version"], 1, "absent = v1 floor: {wire}");

    // A canonical advertisement is clamped to the node cap.
    let (status, wire) = issue_with_capability(Some("3"));
    assert_eq!(status, 200, "{wire}");
    assert_eq!(wire["execution_version"], 3, "{wire}");

    let (status, wire) = issue_with_capability(Some("6"));
    assert_eq!(status, 200, "{wire}");
    assert_eq!(wire["execution_version"], 6, "{wire}");

    // Above the node cap and above the generator maximum: clamped to
    // the node cap (which the CLI bounds by MAX_EXECUTION_VERSION).
    let (status, wire) = issue_with_capability(Some("99"));
    assert_eq!(status, 200, "{wire}");
    assert_eq!(wire["execution_version"], 6, "{wire}");

    // Garbage degrades to the floor — a claim, never a gate.
    let (status, wire) = issue_with_capability(Some("banana"));
    assert_eq!(status, 200, "{wire}");
    assert_eq!(wire["execution_version"], 1, "{wire}");
}

// ------------------------------------------------- enforce_telemetry seam

/// Issue one challenge and hand back (nonce, min_duration_ms).
fn issue_nonce_and_floor(addr: SocketAddr) -> (String, u64) {
    let (status, body) = post(addr, "/issue", ISSUE_BODY, &[]);
    assert_eq!(status, 200, "{body}");
    let wire: serde_json::Value = serde_json::from_str(&body).expect("the wire parses");
    (
        wire["nonce"].as_str().expect("nonce").to_string(),
        wire["minDurationMs"].as_u64().expect("floor"),
    )
}

/// A structurally shaped token over a real nonce with EMPTY telemetry:
/// the telemetry gate runs BEFORE the proof check, so the same token
/// answers `telemetry_rejected` only when the delegation asserts the
/// posture — proving the forwarded flag is honored, not dropped.
#[test]
fn enforce_telemetry_rides_the_delegation_and_gates_the_verdict() {
    let addr = spawn();
    let craft = |enforce: bool| -> (u16, String) {
        let (nonce, floor) = issue_nonce_and_floor(addr);
        let duration_ms = floor + 50;
        let token = kiwicaptcha::SolutionToken {
            nonce,
            counter: 0, // never a winning proof; the gate must fire first
            duration_ms,
            telemetry: serde_json::json!({}),
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
        }
        .encode();
        // The receipt clock runs before the telemetry gate: a claimed
        // duration must be within the wall time since issuance, so the
        // probe waits out its own claim.
        std::thread::sleep(Duration::from_millis(duration_ms + 50));
        post(
            addr,
            "/verify",
            &format!(
                r#"{{"token":"{token}","scope":"login","remoteip":"198.51.100.7","enforce_telemetry":{enforce}}}"#
            ),
            &[],
        )
    };
    let (status, enforced) = craft(true);
    assert_eq!(status, 200, "{enforced}");
    assert!(
        enforced.contains(r#""kiwi-code":"telemetry_rejected""#),
        "asserted posture must gate the empty telemetry: {enforced}"
    );
    let (status, unenforced) = craft(false);
    assert_eq!(status, 200, "{unenforced}");
    assert!(
        !unenforced.contains("telemetry_rejected"),
        "the unasserted posture must NOT gate: {unenforced}"
    );
    assert!(
        unenforced.contains("insufficient_work") || unenforced.contains("invalid"),
        "the same token falls through to the proof gate: {unenforced}"
    );
}
