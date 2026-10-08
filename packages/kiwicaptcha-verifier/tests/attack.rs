//! The adversarial HTTP-framing and surface contract: raw-socket
//! attacks the hardening suite does not cover — request smuggling
//! shapes (Transfer-Encoding / duplicate / non-canonical
//! Content-Length), auth bypass attempts, path and method confusion,
//! deep/NaN/oversized JSON, unicode remoteip spellings, and the
//! one-shot same-token race under parallel raw connections.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use kiwicaptcha::SolutionToken;
use kiwicaptcha_verifier::{serve_http_with, ServerOptions, SidecarConfig, SidecarState};

const SECRET: &str = "a-locally-generated-secret-of-48-bytes!!";
const CLIENT_IP: &str = "198.51.100.7";

fn spawn(bearer: Option<&str>) -> SocketAddr {
    let config = {
        let mut config = SidecarConfig::minimal(SECRET.to_string(), vec![], "http://127.0.0.1:0");
        config.bearer = bearer.map(str::to_string);
        config
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let addr = listener.local_addr().expect("local addr");
    let state = Arc::new(SidecarState::build(config));
    std::thread::spawn(move || serve_http_with(listener, state, ServerOptions::default()));
    addr
}

/// Send raw bytes and drain the answer (the server closes after one
/// request per connection). A connection reset after the server
/// already answered (the TCP close-with-unread-data artifact of a
/// refused head or body) still yields whatever bytes arrived.
fn raw(addr: SocketAddr, request: impl AsRef<[u8]>) -> String {
    let mut stream = TcpStream::connect(addr).expect("the sidecar socket answers");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    stream.write_all(request.as_ref()).expect("request sent");
    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) => {}
        Err(_) if !response.is_empty() => {}
        Err(e) => panic!("response drained: {e}"),
    }
    String::from_utf8_lossy(&response).to_string()
}

fn status_of(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

fn issue(addr: SocketAddr, bearer: &str, body: &str) -> (u16, String) {
    let auth = if bearer.is_empty() {
        String::new()
    } else {
        format!("authorization: Bearer {bearer}\r\n")
    };
    let response = raw(
        addr,
        format!(
            "POST /issue HTTP/1.1\r\nhost: sidecar.test\r\n{auth}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    (status_of(&response), response)
}

fn verify(addr: SocketAddr, bearer: &str, body: &str) -> (u16, String) {
    let auth = if bearer.is_empty() {
        String::new()
    } else {
        format!("authorization: Bearer {bearer}\r\n")
    };
    let response = raw(
        addr,
        format!(
            "POST /verify HTTP/1.1\r\nhost: sidecar.test\r\n{auth}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    (status_of(&response), response)
}

fn issue_and_solve(addr: SocketAddr, bearer: &str, remoteip: &str) -> String {
    let body = format!("{{\"scope\":\"login\",\"remoteip\":\"{remoteip}\"}}");
    let (status, response) = issue(addr, bearer, &body);
    assert_eq!(status, 200, "{response}");
    let start = response.find("\r\n\r\n").expect("a body") + 4;
    let wire = response[start..].trim_end();
    let challenge = kiwicaptcha_solver::Challenge::from_json(wire).expect("the wire parses");
    let mut options = kiwicaptcha_solver::SolveOptions::default();
    let solution = kiwicaptcha_solver::solve(&challenge, &mut options).expect("the solve succeeds");
    solution.token(&challenge)
}

// ------------------------------------------------------ framing attacks

#[test]
fn transfer_encoding_is_refused_outright_never_smuggled() {
    let addr = spawn(None);
    // Chunked framing alone: the reader understands identity framing
    // only, and a chunked body must be refused instead of misparsed.
    let response = raw(
        addr,
        b"POST /verify HTTP/1.1\r\nhost: sidecar.test\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n0\r\n\r\n",
    );
    assert_eq!(status_of(&response), 400, "{response}");
    // The classic CL.TE probe: a transfer-encoding alongside a
    // content-length is a smuggling shape and refuses before any body
    // byte is consumed.
    let response = raw(
        addr,
        b"POST /verify HTTP/1.1\r\nhost: sidecar.test\r\ncontent-length: 4\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n0\r\n\r\nGET /doctor HTTP/1.1\r\nhost: sidecar.test\r\n\r\n",
    );
    assert_eq!(status_of(&response), 400, "{response}");
    // Transfer-Encoding: identity is still ambiguous framing for this
    // reader and is refused the same way.
    let response = raw(
        addr,
        b"POST /verify HTTP/1.1\r\nhost: sidecar.test\r\ntransfer-encoding: identity\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
    );
    assert_eq!(status_of(&response), 400, "{response}");
}

#[test]
fn content_length_must_be_one_canonical_decimal() {
    let addr = spawn(None);
    let body = r#"{"token":"x","scope":"login","remoteip":"198.51.100.7"}"#;
    for (declared, label) in [
        ("05", "leading zero"),
        ("+5", "explicit plus"),
        ("-1", "negative"),
        ("5.0", "decimal"),
        ("0x10", "hexadecimal"),
        ("five", "word"),
        ("", "empty"),
        ("1 2", "inner space"),
    ] {
        let response = raw(
            addr,
            format!(
                "POST /verify HTTP/1.1\r\nhost: sidecar.test\r\ncontent-length: {declared}\r\nconnection: close\r\n\r\n{body}"
            )
            .as_bytes(),
        );
        assert_eq!(status_of(&response), 400, "{label}: {response}");
    }
}

#[test]
fn duplicate_content_length_and_duplicate_authorization_refuse() {
    let addr = spawn(None);
    let body = "{}";
    let response = raw(
        addr,
        format!(
            "POST /verify HTTP/1.1\r\nhost: sidecar.test\r\ncontent-length: {}\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    assert_eq!(status_of(&response), 400, "{response}");
    let response = raw(
        addr,
        "POST /verify HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer a\r\nauthorization: Bearer b\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
    );
    assert_eq!(status_of(&response), 400, "{response}");
}

#[test]
fn an_overstated_body_never_pulls_the_next_request_in() {
    let addr = spawn(None);
    // Content-Length says 5, but a full second request trails: only
    // the declared bytes may form the body and only one response may
    // come back (one request per connection, connection: close).
    let response = raw(
        addr,
        b"POST /verify HTTP/1.1\r\nhost: sidecar.test\r\ncontent-length: 5\r\nconnection: close\r\n\r\nxxxxxGET /doctor HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer s\r\n\r\n",
    );
    // The 5-byte body is not JSON: the provider failure shape answers
    // it — and the smuggled /doctor must never answer at all.
    assert_eq!(status_of(&response), 200, "{response}");
    assert!(
        response.contains("bad_request"),
        "the truncated body must not parse: {response}"
    );
    assert_eq!(
        response.matches("HTTP/1.1 ").count(),
        1,
        "smuggled request answered: {response}"
    );
}

#[test]
fn oversized_bodies_refuse_at_the_reader() {
    let addr = spawn(None);
    // Declared over the cap: refused before any body byte is buffered.
    let response = raw(
        addr,
        b"POST /verify HTTP/1.1\r\nhost: sidecar.test\r\ncontent-length: 70000\r\nconnection: close\r\n\r\n",
    );
    assert_eq!(status_of(&response), 413, "{response}");
    // The 64 KiB document itself (just under the cap) is readable and
    // reaches the JSON handler.
    let big = format!("{{\"pad\":\"{}\",\"remoteip\":\"{CLIENT_IP}\"}}", "a".repeat(65_300));
    let (status, _) = verify(addr, "", &big);
    assert_eq!(status, 200, "a body under the cap must reach the handler");
}

// ------------------------------------------------------ surface confusion

#[test]
fn path_confusion_never_crosses_the_route_table() {
    let addr = spawn(Some("gate-secret"));
    for path in [
        "/verify/../doctor",
        "/verify/..%2fdoctor",
        "/./doctor",
        "//doctor",
        "/doctor/",
        "/doctor%00",
        "/Doctor",
        "/metrics/../verify",
        "/verify%2f",
    ] {
        let response = raw(
            addr,
            format!("GET {path} HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer gate-secret\r\nconnection: close\r\n\r\n"),
        );
        assert_eq!(status_of(&response), 404, "{path}: {response}");
    }
    // The exact routes still work under their exact names.
    let response = raw(
        addr,
        "GET /healthz HTTP/1.1\r\nhost: sidecar.test\r\nconnection: close\r\n\r\n",
    );
    assert_eq!(status_of(&response), 200, "{response}");
    // A query string is ignored, not a router input.
    let response = raw(
        addr,
        "GET /healthz?next=/doctor HTTP/1.1\r\nhost: sidecar.test\r\nconnection: close\r\n\r\n",
    );
    assert_eq!(status_of(&response), 200, "{response}");
}

#[test]
fn method_override_and_case_tricks_never_reinterpret_a_request() {
    let addr = spawn(Some("gate-secret"));
    // A GET to the POST surface is a 404 (the table is exact).
    let response = raw(
        addr,
        "GET /verify HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer gate-secret\r\nconnection: close\r\n\r\n",
    );
    assert_eq!(status_of(&response), 404, "{response}");
    // Lower-case method bytes do not match the table.
    let response = raw(
        addr,
        "post /verify HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer gate-secret\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
    );
    assert_eq!(status_of(&response), 404, "{response}");
    // An override header is inert: the request line alone decides.
    let response = raw(
        addr,
        "POST /metrics HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer gate-secret\r\nx-http-method-override: GET\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    );
    assert_eq!(status_of(&response), 404, "{response}");
    // Absolute-form targets never map onto the route table.
    let response = raw(
        addr,
        "POST http://sidecar.test/verify HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer gate-secret\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
    );
    assert_eq!(status_of(&response), 404, "{response}");
}

#[test]
fn auth_bypass_shapes_all_fail_closed() {
    let addr = spawn(Some("gate-secret"));
    let protected = [
        ("GET", "/metrics"),
        ("GET", "/doctor"),
        ("POST", "/verify"),
        ("POST", "/issue"),
    ];
    for (method, path) in protected {
        let content = if method == "POST" {
            "content-length: 0\r\n"
        } else {
            ""
        };
        for auth_line in [
            // No credential at all.
            "",
            // Scheme-case trickery and prefix mangling. (Trailing
            // OWS after a valid bearer is legal HTTP and strips away
            // before the compare — that is not a bypass shape.)
            "authorization: bearer gate-secret\r\n",
            "authorization: BEARER gate-secret\r\n",
            "authorization: Bearer  gate-secret\r\n",
            "authorization: Bearer gate-secret extra\r\n",
            "authorization: Bearer gate-wrong\r\n",
            "authorization: Basic Z2F0ZS1zZWNyZXQ=\r\n",
            "authorization: Bearer\r\n",
            // The wrong header family entirely.
            "x-kiwi-bearer: gate-secret\r\n",
            "x-bearer: gate-secret\r\n",
        ] {
            let response = raw(
                addr,
                format!("{method} {path} HTTP/1.1\r\nhost: sidecar.test\r\n{auth_line}{content}connection: close\r\n\r\n"),
            );
            assert_eq!(
                status_of(&response),
                401,
                "{method} {path} with [{auth_line}]: {response}"
            );
        }
    }
    // The exact credential still opens the surfaces.
    let response = raw(
        addr,
        "GET /doctor HTTP/1.1\r\nhost: sidecar.test\r\nauthorization: Bearer gate-secret\r\nconnection: close\r\n\r\n",
    );
    assert_eq!(status_of(&response), 200, "{response}");
}

// ------------------------------------------------------ JSON body attacks

#[test]
fn json_body_attack_shapes_never_reach_the_verifier() {
    let addr = spawn(None);
    // Deep nesting: the serde recursion ceiling refuses the document.
    let deep = "[".repeat(200) + &"]".repeat(200);
    let (status, response) = verify(addr, "", &deep);
    assert_eq!(status, 200, "{response}");
    assert!(
        response.contains("bad_request"),
        "deep nesting must be refused: {response}"
    );
    // NaN/Infinity tokens are not JSON and never parse.
    for body in [
        r#"{"token":NaN,"scope":"login"}"#,
        r#"{"token":Infinity,"scope":"login"}"#,
        r#"{"token":-Infinity,"scope":"login"}"#,
    ] {
        let (status, response) = verify(addr, "", body);
        assert_eq!(status, 200, "{response}");
        assert!(
            response.contains("bad_request"),
            "non-JSON numbers must be refused: {response}"
        );
    }
    // A UTF-16 BOM body (raw wide bytes) never parses as JSON.
    let mut utf16: Vec<u8> = vec![0xFF, 0xFE];
    for unit in "{\"token\":\"x\"}".encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let response = raw(
        addr,
        &format!(
            "POST /verify HTTP/1.1\r\nhost: sidecar.test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            utf16.len()
        )
        .into_bytes()
        .into_iter()
        .chain(utf16)
        .collect::<Vec<u8>>(),
    );
    assert_eq!(status_of(&response), 200, "{response}");
    assert!(
        response.contains("bad_request"),
        "UTF-16 BOM body must be refused: {response}"
    );
    // Non-string token members are missing tokens, never coerced.
    let (status, response) = verify(
        addr,
        "",
        &format!(r#"{{"token":123,"scope":"login","remoteip":"{CLIENT_IP}"}}"#),
    );
    assert_eq!(status, 200, "{response}");
    assert!(
        response.contains("missing-input-response"),
        "numeric token must not coerce: {response}"
    );
    // Unknown fields are ignored, not honored as bindings.
    let token = issue_and_solve(addr, "", CLIENT_IP);
    let (_, response) = verify(
        addr,
        "",
        &format!(
            "{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\",\"kiwi-code\":\"ok\",\"success\":true}}"
        ),
    );
    assert!(
        response.contains("\"kiwi-code\":\"ok\""),
        "a real solve verifies: {response}"
    );
    assert!(
        !response.contains("\"success\":true,\"challenge_ts\":\"ok\""),
        "request fields never forge the answer: {response}"
    );
}

// ------------------------------------------------------ remoteip attacks

#[test]
fn unicode_and_zone_remoteip_forms_are_refused() {
    let addr = spawn(None);
    for remoteip in [
        "２０３.０.１１３.７",           // fullwidth digits
        "127.0.0.1\u{202e}",           // RTL override
        "fe80::1%eth0",                // zone id
        "fe80::1%25eth0",              // encoded zone id
        "127.0.0.1\u{0}",              // embedded null
        "127.0.0.\u{ff11}",            // fullwidth 1 in the last octet
        "\u{ff11}27.0.0.1",            // fullwidth leading digit
        "127.0.0.1:80",                // a port is not an address
        "::ffff:127.0.0.1%1",          // mapped + zone
        "  127.0.0.1  \u{202e}",       // whitespace trim must not launder a bidi override
    ] {
        let body = serde_json::json!({"scope": "login", "remoteip": remoteip}).to_string();
        let (status, response) = issue(addr, "", &body);
        // Either the remoteip validator refuses it or the JSON parser
        // rejects the form — never an issued challenge bound to a
        // fabricated identity.
        assert!(
            response.contains("remoteip_invalid") || response.contains("bad_request"),
            "remoteip {remoteip:?} must be refused (status {status}): {response}"
        );
        assert_ne!(status, 200, "remoteip {remoteip:?} issued a challenge");
    }
}

#[test]
fn remoteip_spellings_canonicalize_to_one_binding() {
    let addr = spawn(None);
    // The long IPv6 spelling at issue time, the short spelling at
    // verify time: one identity, so the binding must hold.
    let token = issue_and_solve(addr, "", "2001:0db8:0000:0000:0000:0000:0000:0001");
    let (status, response) = verify(
        addr,
        "",
        &format!("{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"2001:db8::1\"}}"),
    );
    assert_eq!(status, 200, "{response}");
    assert!(
        response.contains("\"kiwi-code\":\"ok\""),
        "canonical spelling must bind: {response}"
    );
    // And the reverse order: short at issue, long at verify.
    let token = issue_and_solve(addr, "", "2001:db8::2");
    let (status, response) = verify(
        addr,
        "",
        &format!(
            "{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"2001:0db8:0000:0000:0000:0000:0000:0002\"}}"
        ),
    );
    assert_eq!(status, 200, "{response}");
    assert!(
        response.contains("\"kiwi-code\":\"ok\""),
        "canonical spelling must bind both ways: {response}"
    );
}

// ------------------------------------------------------ one-shot under fire

#[test]
fn the_same_token_race_still_has_exactly_one_winner() {
    let addr = spawn(None);
    let token = issue_and_solve(addr, "", CLIENT_IP);
    let barrier = Arc::new(Barrier::new(6));
    let handles: Vec<_> = (0..6)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let token = token.clone();
            std::thread::spawn(move || {
                barrier.wait();
                verify(addr, "", &format!("{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"))
            })
        })
        .collect();
    let mut ok = 0;
    let mut duplicate = 0;
    for handle in handles {
        let (_, response) = handle.join().expect("the race thread joins");
        if response.contains("\"kiwi-code\":\"ok\"") {
            ok += 1;
        } else if response.contains("\"kiwi-code\":\"already_consumed\"") {
            duplicate += 1;
        } else {
            panic!("unexpected race outcome: {response}");
        }
    }
    assert_eq!(ok, 1, "exactly one winner");
    assert_eq!(duplicate, 5, "every loser answers already_consumed");
}

// ------------------------------------------------------ header bombs

#[test]
fn header_bombs_are_capped_and_never_hang_the_pool() {
    let addr = spawn(None);
    // A header block past the head cap: refused without buffering more.
    let mut request = String::from("GET /healthz HTTP/1.1\r\nhost: sidecar.test\r\n");
    for i in 0..64 {
        request.push_str(&format!("x-pad-{i}: {}\r\n", "a".repeat(1024)));
    }
    request.push_str("connection: close\r\n\r\n");
    let response = raw(addr, request.as_bytes());
    assert_eq!(status_of(&response), 400, "{response}");
    // The pool still answers after the bomb.
    let response = raw(addr, b"GET /healthz HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n");
    assert_eq!(status_of(&response), 200, "{response}");
    // A token candidate in an oversized header never reaches /verify.
    let token = SolutionToken {
        nonce: "n".repeat(12),
        counter: 0,
        duration_ms: 1000,
        telemetry: serde_json::json!({}),
        execution_digest: None,
        execution_trace: None,
        rsw_proof: None,
    }
    .encode();
    let (status, _) = verify(
        addr,
        "",
        &format!("{{\"token\":\"{token}\",\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "a normal document still parses after the bomb");
}

#[test]
fn an_idempotent_retry_with_operation_identity_returns_the_stored_success() {
    let addr = spawn(None);
    let token = issue_and_solve(addr, "", CLIENT_IP);
    let body = |identity: &str| {
        format!(
            r#"{{"token":"{token}","scope":"login","remoteip":"{CLIENT_IP}","operation_identity":"{identity}"}}"#
        )
    };
    let (status, first) = verify(addr, "", &body("op-retry-1"));
    assert_eq!(status, 200, "{first}");
    assert!(first.contains("success"), "{first}");
    // The idempotent retry (same operation_identity) returns the stored
    // success, not already_consumed.
    let (status, retry) = verify(addr, "", &body("op-retry-1"));
    assert_eq!(status, 200, "{retry}");
    assert!(!retry.contains("already_consumed"), "idempotent retry must return the stored success: {retry}");
    assert!(retry.contains("success"), "{retry}");
    // A different identity is a plain replay.
    let (_, other) = verify(addr, "", &body("op-other"));
    assert!(other.contains("already_consumed") || other.contains("timeout-or-duplicate"), "{other}");
}
