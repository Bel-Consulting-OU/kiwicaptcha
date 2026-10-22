//! The authenticated-replay contract, probed fresh: an idempotent retry
//! may return the stored success ONLY when the committed server-state
//! MAC verifies under the sidecar's own secret. These probes tamper with
//! the commit seam itself (a forged tag, a dropped tag) and assert the
//! replay refuses — the attack a storage writer without the master
//! secret would mount. The control proves an honest commit still
//! replays, so a broken gate cannot hide behind a dead feature.

#![allow(clippy::all)]
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use kiwicaptcha_verifier::{
    serve_http_with, ConsumeOutcome, RecordMeta, RecordStore, ServerOptions, SidecarConfig,
    SidecarState,
};

const SECRET: &str = "a-locally-generated-secret-of-48-bytes!!";
const CLIENT_IP: &str = "198.51.100.7";

/// How the probe store tampers with the authenticated commit seam.
#[derive(Clone, Copy)]
enum Tamper {
    /// Store a well-formed but wrong tag (what a writer without the
    /// master secret can produce: any 64 hex characters).
    Forged,
    /// Drop the tag entirely (the legacy unauthenticated shape).
    Dropped,
    /// Corrupt the companion metadata's remoteip on every consume
    /// answer — the D3.10 storage-plane writer mutating the
    /// unauthenticated sidecar companion after a legitimate success.
    MetaRemoteip,
}

/// A memory store whose `commit_with_mac` is dishonest — the stand-in
/// for a hostile or legacy storage writer.
struct TamperStore {
    inner: kiwicaptcha_verifier::MemoryStore,
    mode: Tamper,
}

impl RecordStore for TamperStore {
    fn put_pending(
        &self,
        record: &kiwicaptcha::challenge::ChallengeRecord,
        meta: RecordMeta,
    ) -> Result<(), String> {
        self.inner.put_pending(record, meta)
    }

    fn consume(
        &self,
        nonce: &str,
        now_unix: u64,
        operation_identity: Option<&str>,
    ) -> ConsumeOutcome {
        let outcome = self.inner.consume(nonce, now_unix, operation_identity);
        if matches!(self.mode, Tamper::MetaRemoteip) {
            // The companion is NOT authenticated: rewrite the remoteip
            // the sidecar stored alongside the record.
            return match outcome {
                ConsumeOutcome::Won { record, mut meta } => {
                    meta.remoteip = Some("203.0.113.9".to_string());
                    ConsumeOutcome::Won { record, meta }
                }
                ConsumeOutcome::AlreadyConsumed {
                    mut meta,
                    succeeded,
                    stored,
                } => {
                    meta.remoteip = Some("203.0.113.9".to_string());
                    ConsumeOutcome::AlreadyConsumed {
                        meta,
                        succeeded,
                        stored,
                    }
                }
                other => other,
            };
        }
        outcome
    }

    fn peek(&self, nonce: &str, now_unix: u64) -> kiwicaptcha_verifier::store::PeekOutcome {
        self.inner.peek(nonce, now_unix)
    }

    fn commit(&self, nonce: &str, record: &kiwicaptcha::challenge::ChallengeRecord, valid: bool) {
        self.inner.commit(nonce, record, valid);
    }

    fn commit_with_mac(
        &self,
        nonce: &str,
        record: &kiwicaptcha::challenge::ChallengeRecord,
        valid: bool,
        operation_identity: Option<&str>,
        mac: Option<&str>,
    ) {
        match self.mode {
            Tamper::Dropped => self.inner.commit(nonce, record, valid),
            Tamper::Forged => {
                let forged = "ab".repeat(32);
                self.inner
                    .commit_with_mac(nonce, record, valid, operation_identity, Some(&forged));
            }
            // This mode tampers only the companion metadata: the MAC
            // seam stays honest.
            Tamper::MetaRemoteip => {
                self.inner
                    .commit_with_mac(nonce, record, valid, operation_identity, mac)
            }
        }
    }

    fn counts(&self) -> (usize, usize) {
        self.inner.counts()
    }

    fn describe(&self) -> String {
        "tamper probe over the in-process memory store".to_string()
    }
}

fn spawn(tamper: Option<Tamper>) -> SocketAddr {
    spawn_scopes(vec![], tamper)
}

fn spawn_scopes(scopes: Vec<String>, tamper: Option<Tamper>) -> SocketAddr {
    let mut config = SidecarConfig::minimal(SECRET.to_string(), scopes, "http://127.0.0.1:0");
    if let Some(mode) = tamper {
        config.store = Arc::new(TamperStore {
            inner: kiwicaptcha_verifier::MemoryStore::new(),
            mode,
        });
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let addr = listener.local_addr().expect("local addr");
    let state = Arc::new(SidecarState::build(config));
    std::thread::spawn(move || serve_http_with(listener, state, ServerOptions::default()));
    addr
}

fn raw(addr: SocketAddr, request: impl AsRef<[u8]>) -> String {
    let mut stream = TcpStream::connect(addr).expect("the sidecar socket answers");
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.write_all(request.as_ref()).expect("request sent");
    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) => {}
        Err(_) if !response.is_empty() => {}
        Err(e) => panic!("response drained: {e}"),
    }
    String::from_utf8_lossy(&response).to_string()
}

fn body_of(response: &str) -> String {
    match response.find("\r\n\r\n") {
        Some(end) => response[end + 4..].trim_end().to_string(),
        None => String::new(),
    }
}

fn post_json(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
    let response = raw(
        addr,
        format!(
            "POST {path} HTTP/1.1\r\nhost: sidecar.test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, body_of(&response))
}

fn issue_and_solve(addr: SocketAddr) -> String {
    let (status, wire) = post_json(
        addr,
        "/issue",
        &format!("{{\"scope\":\"login\",\"remoteip\":\"{CLIENT_IP}\"}}"),
    );
    assert_eq!(status, 200, "{wire}");
    let challenge = kiwicaptcha_solver::Challenge::from_json(&wire).expect("the wire parses");
    let mut options = kiwicaptcha_solver::SolveOptions::default();
    let solution = kiwicaptcha_solver::solve(&challenge, &mut options).expect("the solve succeeds");
    solution.token(&challenge)
}

fn verify_body(token: &str, identity: &str) -> String {
    format!(
        r#"{{"token":"{token}","scope":"login","remoteip":"{CLIENT_IP}","operation_identity":"{identity}"}}"#
    )
}

/// A forged tag (well-formed, wrong key) never replays: the retry must
/// answer the duplicate vocabulary, never a success.
#[test]
fn a_forged_mac_never_replays_the_stored_success() {
    let addr = spawn(Some(Tamper::Forged));
    let token = issue_and_solve(addr);
    let (status, first) = post_json(addr, "/verify", &verify_body(&token, "op-forged-1"));
    assert_eq!(status, 200, "{first}");
    assert!(
        first.contains(r#""success":true"#),
        "the fresh derivation must succeed: {first}"
    );
    let (status, retry) = post_json(addr, "/verify", &verify_body(&token, "op-forged-1"));
    assert_eq!(status, 200, "{retry}");
    assert!(
        retry.contains(r#""kiwi-code":"already_consumed"#),
        "a forged MAC must never replay the stored success: {retry}"
    );
    assert!(
        !retry.contains(r#""success":true"#),
        "a forged MAC must never replay the stored success: {retry}"
    );
}

/// A MAC-less legacy commit never replays either: absent material is
/// not authentic material.
#[test]
fn a_macless_commit_never_replays_the_stored_success() {
    let addr = spawn(Some(Tamper::Dropped));
    let token = issue_and_solve(addr);
    let (status, first) = post_json(addr, "/verify", &verify_body(&token, "op-dropped-1"));
    assert_eq!(status, 200, "{first}");
    assert!(
        first.contains(r#""success":true"#),
        "the fresh derivation must succeed: {first}"
    );
    let (status, retry) = post_json(addr, "/verify", &verify_body(&token, "op-dropped-1"));
    assert_eq!(status, 200, "{retry}");
    assert!(
        retry.contains(r#""kiwi-code":"already_consumed"#),
        "a MAC-less result must never replay the stored success: {retry}"
    );
    assert!(
        !retry.contains(r#""success":true"#),
        "a MAC-less result must never replay the stored success: {retry}"
    );
}

/// The control: an honest commit still replays its stored success to
/// the same operation identity, so the refusals above prove the gate
/// and not a dead feature.
#[test]
fn an_honest_commit_still_replays_its_stored_success() {
    let addr = spawn(None);
    let token = issue_and_solve(addr);
    let (status, first) = post_json(addr, "/verify", &verify_body(&token, "op-honest-1"));
    assert_eq!(status, 200, "{first}");
    assert!(first.contains(r#""success":true"#), "{first}");
    let (status, retry) = post_json(addr, "/verify", &verify_body(&token, "op-honest-1"));
    assert_eq!(status, 200, "{retry}");
    assert!(
        retry.contains(r#""kiwi-code":"ok"#) && retry.contains(r#""success":true"#),
        "the honest idempotent retry must return the stored success: {retry}"
    );
    // A different identity is still a plain replay — the MAC gate does
    // not widen who may replay.
    let (_, other) = post_json(addr, "/verify", &verify_body(&token, "op-other-1"));
    assert!(
        other.contains("already_consumed") || other.contains("timeout-or-duplicate"),
        "{other}"
    );
}

// ------------------------------------------- cross-context replay gates

/// The replay re-runs the binding expectation against the stored
/// record: an idempotent retry that asserts a DIFFERENT binding than
/// the record carries is a plain replay, never a success. Before the
/// gate the sidecar hard-coded binding_ok = true, so any identity
/// retry could cross binding contexts.
#[test]
fn replay_refuses_a_binding_expectation_mismatch() {
    let addr = spawn(None);
    let token = issue_and_solve(addr);
    // The issued record is unbound; the first verify enforces nothing.
    let first = format!(
        r#"{{"token":"{token}","scope":"login","remoteip":"{CLIENT_IP}","operation_identity":"op-bind-1"}}"#
    );
    let (status, ok) = post_json(addr, "/verify", &first);
    assert_eq!(status, 200, "{ok}");
    assert!(ok.contains(r#""success":true"#), "{ok}");

    // The same operation, now asserting a transaction binding the
    // record does not carry: refused.
    let mismatch = format!(
        r#"{{"token":"{token}","scope":"login","remoteip":"{CLIENT_IP}","operation_identity":"op-bind-1","expected_request_binding":"req-tx-1"}}"#
    );
    let (status, refused) = post_json(addr, "/verify", &mismatch);
    assert_eq!(status, 200, "{refused}");
    assert!(
        refused.contains(r#""kiwi-code":"already_consumed"#),
        "a binding expectation the record cannot satisfy must never replay: {refused}"
    );
    assert!(!refused.contains(r#""success":true"#), "{refused}");

    // The empty-string assertion (the record must be explicitly
    // unbound) matches the unbound record and still replays — the
    // gate checks the contract, it does not refuse every expectation.
    let exact_unbound = format!(
        r#"{{"token":"{token}","scope":"login","remoteip":"{CLIENT_IP}","operation_identity":"op-bind-1","expected_request_binding":""}}"#
    );
    let (status, matched) = post_json(addr, "/verify", &exact_unbound);
    assert_eq!(status, 200, "{matched}");
    assert!(
        matched.contains(r#""kiwi-code":"ok"#) && matched.contains(r#""success":true"#),
        "the exact-empty expectation on an unbound record still replays: {matched}"
    );
}

/// The replay re-runs the SCOPE against the stored record itself (not
/// the issuance metadata): a retry under another in-plan scope is a
/// plain replay, never a success.
#[test]
fn replay_refuses_a_scope_mismatch_against_the_stored_record() {
    let addr = spawn_scopes(vec!["login".to_string(), "signup".to_string()], None);
    let token = issue_and_solve(addr); // issued for scope "login"
    let first = format!(
        r#"{{"token":"{token}","scope":"login","remoteip":"{CLIENT_IP}","operation_identity":"op-scope-1"}}"#
    );
    let (status, ok) = post_json(addr, "/verify", &first);
    assert_eq!(status, 200, "{ok}");
    assert!(ok.contains(r#""success":true"#), "{ok}");

    // "signup" is in the plan (it passes the issuance allow-list), but
    // the record's own scope is "login": the replay gate refuses.
    let other_scope = format!(
        r#"{{"token":"{token}","scope":"signup","remoteip":"{CLIENT_IP}","operation_identity":"op-scope-1"}}"#
    );
    let (status, refused) = post_json(addr, "/verify", &other_scope);
    assert_eq!(status, 200, "{refused}");
    assert!(
        refused.contains(r#""kiwi-code":"already_consumed"#),
        "a cross-scope retry must never replay the stored success: {refused}"
    );
    assert!(!refused.contains(r#""success":true"#), "{refused}");
}

/// The replay-authorization boundary: companion metadata is NOT
/// authenticated (the result MAC covers challenge/verdict/binding/
/// identity — not smeta), so it must never authorize or deny a replay.
/// A storage writer corrupting the companion's remoteip cannot break a
/// legitimate retry (the record's SIGNED binding tag answers the IP
/// question), and a retry from a DIFFERENT client IP is still refused
/// because the record itself says so.
#[test]
fn replay_authorization_ignores_companion_metadata_and_binds_the_record() {
    let addr = spawn(Some(Tamper::MetaRemoteip));
    let token = issue_and_solve(addr);
    let (status, ok) = post_json(addr, "/verify", &verify_body(&token, "op-meta-1"));
    assert_eq!(status, 200, "{ok}");
    assert!(ok.contains(r#""success":true"#), "{ok}");

    // The companion now lies about the client IP; the retry from the
    // REAL client still replays: authorization reads the record's
    // signed binding tag, never smeta.remoteip.
    let (status, retry) = post_json(addr, "/verify", &verify_body(&token, "op-meta-1"));
    assert_eq!(status, 200, "{retry}");
    assert!(
        retry.contains(r#""kiwi-code":"ok"#) && retry.contains(r#""success":true"#),
        "a corrupted companion must not deny the legitimate replay: {retry}"
    );

    // And a retry from a DIFFERENT client IP is refused even though
    // the (tampered) companion could have been made to match it: the
    // record's binding tag is the authority.
    let cross = format!(
        r#"{{"token":"{token}","scope":"login","remoteip":"203.0.113.42","operation_identity":"op-meta-1"}}"#
    );
    let (status, refused) = post_json(addr, "/verify", &cross);
    assert_eq!(status, 200, "{refused}");
    assert!(
        refused.contains(r#""kiwi-code":"already_consumed"#),
        "a cross-IP retry is refused by the record's signed binding: {refused}"
    );
    assert!(!refused.contains(r#""success":true"#), "{refused}");
}
