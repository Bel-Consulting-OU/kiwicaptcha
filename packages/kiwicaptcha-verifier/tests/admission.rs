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
#[cfg(feature = "redis-store")]
use kiwicaptcha_verifier::store::{AdmissionOutcome, CapacityLimits};
use kiwicaptcha_verifier::{
    parse_scopes, serve_http_with, RecordStore, ServerOptions, SidecarConfig, SidecarState,
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
    // A sha16 solve can finish in well under the record's min-duration
    // floor on a fast core; give the server clock the floor before the
    // caller verifies, exactly like the widget's own floor wait.
    std::thread::sleep(Duration::from_millis(10));
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

/// Issue without solving; returns the minted nonce.
fn issue_nonce(addr: SocketAddr) -> String {
    let (status, wire) = post_json(
        addr,
        "/issue",
        r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
    );
    assert_eq!(status, 200, "{wire}");
    kiwicaptcha_solver::Challenge::from_json(&wire)
        .expect("the wire parses")
        .nonce
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// Burn a solved challenge into a consumed tombstone: bump the proof
/// counter inside the token so verification consumes the record and
/// commits a failing verdict (the tombstone stays live until TTL).
fn burn(addr: SocketAddr, token: &str) {
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token)
        .expect("token is standard base64");
    let text = String::from_utf8(raw).expect("token decodes utf-8");
    let mut parts: Vec<String> = text.split('.').map(str::to_string).collect();
    assert_eq!(parts.len(), 4, "token shape: {text}");
    let counter: u64 = parts[1].parse().expect("numeric counter");
    parts[1] = (counter + 1).to_string();
    let tampered =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, parts.join("."));
    let (status, body) = post_json(addr, "/verify", &verify_body(&tampered, "login", None));
    assert_eq!(status, 200, "burn verify: {body}");
    assert!(
        body.contains(r#""success":false"#),
        "the bumped counter must fail verification (and burn the record): {body}"
    );
}

/// The wedge the pruned admission closes: a store whose pending slot
/// is held ONLY by an expired record must reopen. The old pre-check
/// counted raw map sizes, refused forever, and never ran the insert
/// that would prune — a self-sustaining challenge_store_full.
#[test]
fn expired_records_never_wedge_the_pending_ceiling() {
    let store: Arc<dyn RecordStore> = Arc::new(kiwicaptcha_verifier::MemoryStore::new());
    let addr = spawn_with(|c| {
        c.store = Arc::clone(&store);
        c.max_pending = 1;
    });

    // Fill the ceiling with a live record.
    let nonce = issue_nonce(addr);
    let now = unix_now();
    let (status, body) = post_json(
        addr,
        "/issue",
        r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
    );
    assert_eq!(status, 503, "the live record holds the ceiling: {body}");
    assert!(body.contains("challenge_store_full"), "{body}");

    // Rewrite the stored entry as already-expired (same nonce): the map
    // now holds a record the store would reap on sight, but the raw
    // counts still say "full".
    let template = match store.peek(&nonce, now) {
        kiwicaptcha_verifier::PeekOutcome::Pending(record) => *record,
        other => panic!("the issued record is pending: {other:?}"),
    };
    let mut expired = template.clone();
    expired.expires_at = now.saturating_sub(10);
    store
        .put_pending(&expired, Default::default())
        .expect("the expired rewrite lands");

    // The pruned pre-check and the atomic admission both see through
    // the expired entry: issuance reopens (the old counts() check
    // refused here forever).
    let (status, body) = post_json(
        addr,
        "/issue",
        r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
    );
    assert_eq!(
        status, 200,
        "a full-of-expired store must reopen, not wedge: {body}"
    );

    // …and the ceiling still binds the fresh record.
    let (status, body) = post_json(
        addr,
        "/issue",
        r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
    );
    assert_eq!(
        status, 503,
        "the fresh record holds the ceiling again: {body}"
    );
    assert!(body.contains("challenge_store_full"), "{body}");
    let (pending, _) = store.live_counts(unix_now());
    assert_eq!(pending, 1, "exactly the fresh record is pending");
}

/// The check-then-insert race: fifty issuers hitting a cap of one at
/// the same instant. The atomic admission admits exactly one; the old
/// count-outside-the-lock path let several through.
#[test]
fn fifty_concurrent_issues_admit_exactly_one_at_cap_one() {
    const CALLERS: usize = 50;
    let store: Arc<dyn RecordStore> = Arc::new(kiwicaptcha_verifier::MemoryStore::new());
    let addr = spawn_with(|c| {
        c.store = Arc::clone(&store);
        c.max_pending = 1;
    });
    let barrier = Arc::new(std::sync::Barrier::new(CALLERS));
    let mut handles = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            post_json(
                addr,
                "/issue",
                r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
            )
        }));
    }
    let mut admitted = 0usize;
    let mut refused = 0usize;
    for handle in handles {
        let (status, body) = handle.join().expect("issuer thread");
        match status {
            200 => admitted += 1,
            503 => {
                assert!(
                    body.contains("challenge_store_full"),
                    "typed refusal: {body}"
                );
                refused += 1;
            }
            other => panic!("unexpected status {other}: {body}"),
        }
    }
    assert_eq!(admitted, 1, "exactly one issuer wins a cap of one");
    assert_eq!(refused, CALLERS - 1, "every loser gets the typed 503");
    let (pending, live) = store.live_counts(unix_now());
    assert_eq!(
        (pending, live),
        (1, 1),
        "the store holds exactly one record"
    );
}

/// The total-live ceiling under burn-and-reissue churn: every burn
/// frees a pending slot (the record moves to consumed) but keeps the
/// record live, so without a live bound a client grows the store to
/// burn_rate × TTL while the pending ceiling never trips.
#[test]
fn burn_churn_is_bounded_by_the_total_live_ceiling() {
    let store: Arc<dyn RecordStore> = Arc::new(kiwicaptcha_verifier::MemoryStore::new());
    let addr = spawn_with(|c| {
        c.store = Arc::clone(&store);
        // The pending bound alone would allow this churn: three
        // pending slots, two live records total.
        c.max_pending = 3;
        c.max_live_records = 2;
    });

    let token = issue_and_solve(addr, "login");
    burn(addr, &token);
    let (pending, live) = store.live_counts(unix_now());
    assert_eq!((pending, live), (0, 1), "the burn freed pending, not live");

    let token = issue_and_solve(addr, "login");
    burn(addr, &token);
    let (pending, live) = store.live_counts(unix_now());
    assert_eq!((pending, live), (0, 2), "both tombstones are live");

    // Pending has room (0 < 3) but the total bound is reached: the
    // refusal must be the LIVE ceiling, not the pending one.
    let (status, body) = post_json(
        addr,
        "/issue",
        r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
    );
    assert_eq!(status, 503, "the live ceiling refuses the churn: {body}");
    assert!(body.contains("challenge_store_full"), "{body}");
    assert!(
        body.contains("total live-challenge ceiling"),
        "the refusal names the ceiling that fired: {body}"
    );
}

/// The multi-node bound: two sidecar states over two independent
/// handles on the same Redis keyspace must share ONE ceiling (the
/// admission is a server-side transaction, not a client-side count),
/// consumed tombstones must keep occupying the live bound, and the
/// score-prune must reopen the ceiling once the records expire.
#[cfg(feature = "redis-store")]
#[test]
fn redis_admission_ceiling_is_one_transaction_across_handles() {
    let url = ["TEST_REDIS_URL", "RISK_REDIS_URL"]
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            eprintln!("skipping redis admission test: no TEST_REDIS_URL/RISK_REDIS_URL");
            String::new()
        });
    if url.is_empty() {
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let prefix = format!("kiwi-adv-adm-{stamp:x}:");
    let store_a: Arc<dyn RecordStore> = Arc::new(
        kiwicaptcha_verifier::store::RedisStore::connect(&url, &prefix).expect("handle A"),
    );
    let store_b: Arc<dyn RecordStore> = Arc::new(
        kiwicaptcha_verifier::store::RedisStore::connect(&url, &prefix).expect("handle B"),
    );

    let addr_a = spawn_with(|c| {
        c.store = Arc::clone(&store_a);
        c.max_pending = 1;
        c.max_live_records = 1;
    });
    let nonce = issue_nonce(addr_a);

    // A second state with its OWN handle on the same keyspace: the
    // server-side admission must refuse it against handle A's record.
    let addr_b = spawn_with(|c| {
        c.store = Arc::clone(&store_b);
        c.max_pending = 1;
        c.max_live_records = 1;
    });
    let (status, body) = post_json(
        addr_b,
        "/issue",
        r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
    );
    assert_eq!(
        status, 503,
        "the ceiling is one transaction across handles: {body}"
    );
    assert!(body.contains("challenge_store_full"), "{body}");

    // Take the record template while it is still pending, then burn
    // through handle A: the tombstone leaves pending but keeps
    // occupying the total-live bound (shared index).
    let now = unix_now();
    let template = match store_a.peek(&nonce, now) {
        kiwicaptcha_verifier::PeekOutcome::Pending(record) => (*record).clone(),
        other => panic!("the issued record is pending: {other:?}"),
    };
    let won = store_a.consume(&nonce, now, None);
    assert!(
        matches!(won, kiwicaptcha_verifier::ConsumeOutcome::Won { .. }),
        "the record consumes: {won:?}"
    );
    let (pending, live) = store_b.live_counts(now);
    assert_eq!(
        (pending, live),
        (0, 1),
        "handle B sees the tombstone through the shared index"
    );

    // Full of tombstones at the live bound: another admission at the
    // real clock is refused with the live ceiling.
    let refused = store_b.try_put_pending(
        &template,
        Default::default(),
        CapacityLimits {
            max_pending: 1,
            max_live: 1,
        },
        now,
    );
    assert_eq!(
        refused,
        AdmissionOutcome::LiveFull,
        "the tombstone occupies the live bound across handles"
    );

    // Once the tombstone's expiry score is in the past, the same
    // admission reopens — the prune runs inside the transaction.
    let future = now + 10_000;
    let (pending, live) = store_a.live_counts(future);
    assert_eq!(
        (pending, live),
        (0, 0),
        "the score-prune reaps the tombstone"
    );
    let mut fresh = template.clone();
    fresh.nonce = format!("adv-adm-fresh-{stamp:x}");
    fresh.issued_at = future;
    fresh.expires_at = future + 90;
    let admitted = store_b.try_put_pending(
        &fresh,
        Default::default(),
        CapacityLimits {
            max_pending: 1,
            max_live: 1,
        },
        future,
    );
    assert_eq!(
        admitted,
        AdmissionOutcome::Admitted,
        "expiry reopens the shared ceiling"
    );

    // Best-effort cleanup of this test's keyspace.
    if let Ok(mut conn) = redis::Client::open(url)
        .expect("redis url parses")
        .get_connection()
    {
        let keys = [
            format!("{prefix}admission:pending"),
            format!("{prefix}admission:live"),
            format!("{prefix}{nonce}"),
            format!("{prefix}{nonce}:smeta"),
            format!("{prefix}{}", fresh.nonce),
            format!("{prefix}{}:smeta", fresh.nonce),
            format!("{prefix}{}", template.nonce),
            format!("{prefix}{}:smeta", template.nonce),
        ];
        let _: redis::RedisResult<i64> = redis::cmd("UNLINK").arg(&keys).query(&mut conn);
    }
}

/// The legacy/foreign companion shape: presentation fields stored
/// WITHOUT the sidecar's companion MAC (an old node's smeta during a
/// rolling upgrade, or any writer that never held the secret). The
/// success stands — the record and its proof are authentic — but the
/// unsigned fields are dropped, never echoed: absence of a tag is not
/// a license to trust the values.
#[test]
fn unsigned_companion_fields_are_dropped_on_success() {
    let store: Arc<dyn RecordStore> = Arc::new(kiwicaptcha_verifier::MemoryStore::new());
    let addr = spawn_with(|c| {
        c.store = Arc::clone(&store);
    });
    let token = issue_and_solve(addr, "login");
    let nonce = kiwicaptcha_solver::Challenge::from_json(
        &post_json(
            addr,
            "/issue",
            r#"{"scope":"login","remoteip":"198.51.100.7"}"#,
        )
        .1,
    )
    .expect("wire parses")
    .nonce;
    let _ = nonce;

    // Replace the stored companion with an unsigned one carrying
    // presentation fields (the pre-MAC sidecar shape). Take the record
    // from the store so the challenge bytes stay identical.
    let now = unix_now();
    let issued_nonce = kiwicaptcha::SolutionToken::decode(&token)
        .expect("token decodes")
        .nonce;
    let record = match store.peek(&issued_nonce, now) {
        kiwicaptcha_verifier::PeekOutcome::Pending(record) => (*record).clone(),
        other => panic!("pending after issue: {other:?}"),
    };
    store
        .put_pending(
            &record,
            kiwicaptcha_verifier::RecordMeta {
                action: Some("legacy-action".to_string()),
                cdata: Some("legacy-cdata".to_string()),
                scope: Some("login".to_string()),
                ..Default::default()
            },
        )
        .expect("the unsigned rewrite lands");

    let (status, body) = post_json(addr, "/verify", &verify_body(&token, "login", None));
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(r#""kiwi-code":"ok""#),
        "the authentic proof still succeeds: {body}"
    );
    assert!(
        !body.contains("legacy-action") && !body.contains("legacy-cdata"),
        "unsigned companion fields must never surface on the success: {body}"
    );
    assert!(
        body.contains(r#""action":null"#),
        "the presentation slot is null, not attacker-populated: {body}"
    );
}
