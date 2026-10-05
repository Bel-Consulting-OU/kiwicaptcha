//! The solver's proof of equivalence: golden vectors pinned to shared
//! fixtures, cross-checks against the core crate's own test solver, and
//! the end-to-end chain this crate exists to serve — solve, pack the
//! token, and have the workspace's real verifier accept it.
//!
//! Every fixed vector below states its provenance in a comment, per the
//! repository's cross-language fixture discipline.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kiwicaptcha::challenge::issue_challenge_with_capabilities;
use kiwicaptcha::challenge::EmissionCapabilities;
use kiwicaptcha::{
    issue_challenge, now_epoch_micros, verify_solution, BindingMode, ChallengeConfig,
    ChallengeRecord, PoWAlgorithm, RequestBindingExpectation, SolutionToken, VerifyContext,
    VerifyOutcome,
};
use kiwicaptcha_solver::{
    solve, CancellationToken, Challenge, SolveError, SolveOptions, SOLVER_MAX_ARGON2_TARGET_BITS,
    SOLVER_MAX_HASHES, SOLVER_MAX_TARGET_BITS,
};
use sha2::{Digest, Sha256};

/// The shared cross-language signing secret (kid 1) the core suite's
/// harness also configures.
const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// A deterministic sha256 challenge: the fixed nonce is the standard
/// base64 of 32 zero bytes, the salt the base64 of 16 constant bytes, the
/// prefix the issuer's `challenge|salt|` shape with fixed content. The
/// winning counter under a fixed target is therefore a golden number.
const GOLDEN_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const GOLDEN_SALT_B64: &str = "c2FsdDEyMzQ1Njc4OWFiY2RlZg==";
const GOLDEN_PREFIX: &str = "Z29sZGVuLWNoYWxsZW5nZQ==.deadbeef|c2FsdDEyMzQ1Njc4OWFiY2RlZg==|";
/// The pinned first counter of the golden sha256 challenge at 12 target
/// bits. Provenance: derived by this solver and cross-checked against the
/// independent recomputation in the test below (which the core verifier's
/// derive_hash shares a preimage contract with); re-pin only together with
/// that recomputation.
const GOLDEN_COUNTER_12_BITS: u64 = 1386;

fn golden_challenge(target_bits: u32) -> Challenge {
    golden_challenge_with_nonce(target_bits, GOLDEN_NONCE)
}

fn golden_challenge_with_nonce(target_bits: u32, nonce: &str) -> Challenge {
    serde_json::from_value(serde_json::json!({
        "nonce": nonce,
        "challenge": "Z29sZGVuLWNoYWxsZW5nZQ==.deadbeef",
        "salt": GOLDEN_SALT_B64,
        "algorithm": "sha256",
        "mKib": 0,
        "t": 1,
        "p": 1,
        "targetBits": target_bits,
        "ttlSecs": 300,
        "minDurationMs": 0,
        "prefix": GOLDEN_PREFIX,
    }))
    .expect("the golden challenge document is well formed")
}

/// The challenge-response wire the reference endpoint emits: the PHP
/// Challenge::toArray key set (camelCase mKib/targetBits/ttlSecs/
/// minDurationMs beside the snake_case optional keys).
fn wire_json(issued: &kiwicaptcha::Issued) -> String {
    let c = &issued.challenge;
    let mut document = serde_json::json!({
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
        document["decoy_field"] = serde_json::json!(decoy);
    }
    if let Some(program) = &c.execution_program {
        document["execution_program"] = serde_json::json!(program);
    }
    if let Some(modulus) = &c.rsw_modulus {
        document["rsw_modulus"] = serde_json::json!(modulus);
    }
    document.to_string()
}

fn sha_config(target_bits: u32) -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.to_string(),
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits,
        argon2_target_bits: 2,
        ttl_secs: 300,
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
        rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
        tenant: None,
    }
}

fn argon_config(m_kib: u32, t: u32, argon2_target_bits: u32) -> ChallengeConfig {
    ChallengeConfig {
        algorithm: PoWAlgorithm::Argon2id,
        m_kib,
        t,
        p: 1,
        argon2_target_bits,
        ..sha_config(8)
    }
}

fn rsw_config(modulus: &str, lambda: &str, rsw_t: u32) -> ChallengeConfig {
    ChallengeConfig {
        algorithm: PoWAlgorithm::Rsw,
        m_kib: 0,
        t: 1,
        p: 1,
        rsw_modulus_n: Some(modulus.to_string()),
        rsw_lambda: Some(lambda.to_string()),
        rsw_t,
        ..sha_config(8)
    }
}

fn issue(config: &ChallengeConfig) -> kiwicaptcha::Issued {
    let now_ns = now_epoch_micros();
    let now_unix = now_ns / 1_000_000;
    issue_challenge(config, "login", "198.51.100.7", now_unix, now_ns, 0, None)
        .expect("issuance succeeds")
}

fn issue_rsw(config: &ChallengeConfig) -> kiwicaptcha::Issued {
    let now_ns = now_epoch_micros();
    let now_unix = now_ns / 1_000_000;
    issue_challenge_with_capabilities(
        EmissionCapabilities::confirmed(kiwicaptcha::challenge::RSW_IDENTITY_PROTOCOL_VERSION)
            .expect("the rsw identity ceiling is a valid confirmed ceiling"),
        config,
        "login",
        "198.51.100.7",
        now_unix,
        now_ns,
        0,
        None,
    )
    .expect("rsw issuance succeeds")
}

/// Verify a wire token against the workspace's real verifier, mirroring
/// the core quick-start context (bound IP, floor off, scope enforced).
fn verify_with_core(
    record: &mut ChallengeRecord,
    token: &str,
    rsw: Option<(&str, &str)>,
) -> VerifyOutcome {
    let decoded = SolutionToken::decode(token).expect("the solver's token decodes");
    let now_ns = record.issued_at_ns + 1_000_000;
    let now_unix_value = record.issued_at + 1;
    let mut now_unix = move || now_unix_value;
    let mut ctx = VerifyContext {
        record,
        secret_key: SECRET,
        tenant: None,
        secrets_by_kid: None,
        revoked_kids: None,
        counter: decoded.counter,
        duration_ms: decoded.duration_ms,
        now_unix: Some(&mut now_unix),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        policy_version_floor: None,
        client_ip: Some("198.51.100.7"),
        execution_digest: None,
        execution_trace: None,
        telemetry: Some(&decoded.telemetry),
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
        rsw_proof: decoded.rsw_proof.as_deref(),
        rsw_modulus_n: rsw.map(|(n, _)| n),
        rsw_lambda: rsw.map(|(_, l)| l),
        rsw_keyring: None,
    };
    verify_solution(&mut ctx)
}

fn plain_solve(challenge: &Challenge) -> kiwicaptcha_solver::Solution {
    let mut opts = SolveOptions::default();
    solve(challenge, &mut opts).expect("the solve succeeds")
}

/// The independent recomputation: the verifier's preimage contract,
/// spelled out in the test so the solver's loop is checked against
/// something written twice.
fn independent_sha256(prefix: &str, counter: u64, salt: &[u8]) -> [u8; 32] {
    let input = format!("{prefix}{counter}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.update(salt);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

// ── the load-bearing chain: solve → token → the real verifier ────────

#[test]
fn sha256_solve_token_and_verify_end_to_end() {
    let issued = issue(&sha_config(8));
    let challenge = Challenge::from_json(&wire_json(&issued)).expect("the wire parses");
    let solution = plain_solve(&challenge);

    // The counter is the FIRST one that meets the target, per an
    // independent recomputation of the preimage contract.
    let salt = B64.decode(&challenge.salt).unwrap();
    for counter in 0..solution.counter {
        assert!(
            leading_zero_bits(&independent_sha256(&challenge.prefix, counter, &salt)) < 8,
            "no counter below the solution may meet the target"
        );
    }
    assert!(
        leading_zero_bits(&independent_sha256(
            &challenge.prefix,
            solution.counter,
            &salt
        )) >= 8,
        "the winning counter must meet the target"
    );
    assert_eq!(
        solution.hash_hex,
        hex_of(&independent_sha256(
            &challenge.prefix,
            solution.counter,
            &salt
        )),
        "the reported digest is the winning hash"
    );
    // The core crate's own solver agrees on the counter (it drives the
    // verifier's derive_hash, the byte-equivalence that matters).
    assert_eq!(
        kiwicaptcha::solve_for_test(&issued.record),
        Some(solution.counter)
    );

    let token = solution.token(&challenge);
    let decoded = SolutionToken::decode(&token).expect("the wire token decodes");
    assert_eq!(decoded.nonce, challenge.nonce);
    assert_eq!(decoded.counter, solution.counter);
    assert_eq!(decoded.telemetry, serde_json::json!({}));

    let mut record = issued.record;
    assert!(
        matches!(
            verify_with_core(&mut record, &token, None),
            VerifyOutcome::Valid { .. }
        ),
        "the core verifier must accept the solver's token end to end"
    );
}

#[test]
fn argon2id_solve_token_and_verify_end_to_end() {
    // The smallest issued parameters (m_kib 8, t 3, p 1) at 2 target bits
    // keep the memory-hard loop test-fast while exercising the real path.
    let issued = issue(&argon_config(8, 3, 2));
    let challenge = Challenge::from_json(&wire_json(&issued)).expect("the wire parses");
    let solution = plain_solve(&challenge);

    // Cross-check against the core crate's own solver (its derive_hash is
    // the verifier's Argon2id path).
    assert_eq!(
        kiwicaptcha::solve_for_test(&issued.record),
        Some(solution.counter)
    );
    // The derived digest meets the issued target.
    assert!(solution.hash_hex.len() == 64, "a 32-byte digest is 64 hex");

    let token = solution.token(&challenge);
    let mut record = issued.record;
    assert!(
        matches!(
            verify_with_core(&mut record, &token, None),
            VerifyOutcome::Valid { .. }
        ),
        "the core verifier must accept the argon2id token"
    );
}

#[test]
fn rsw_solve_matches_the_trapdoor_and_verifies() {
    // Provenance: the shared 2048-bit fixture pair every language suite
    // uses (protocol/rsw-identity-v1/fixtures.json, mirrored by the core
    // crate's rsw::fixtures under the test-fixtures feature).
    let fixture = kiwicaptcha::rsw::fixtures::trapdoor();
    let modulus = kiwicaptcha::rsw::fixtures::MODULUS_N_B64;
    let lambda = kiwicaptcha::rsw::fixtures::LAMBDA_B64;
    let t = kiwicaptcha::challenge::MIN_RSW_T;
    let issued = issue_rsw(&rsw_config(modulus, lambda, t));
    let challenge = Challenge::from_json(&wire_json(&issued)).expect("the wire parses");
    assert_eq!(challenge.algorithm, PoWAlgorithm::Rsw);
    assert_eq!(challenge.t, t);

    let solution = plain_solve(&challenge);
    let proof = solution
        .rsw_proof
        .as_deref()
        .expect("an rsw solve carries the proof");

    // The public sequential path equals the trapdoor expectation, the
    // exact comparison the verifier performs.
    assert_eq!(
        proof,
        fixture.expected_proof_hex(&challenge.prefix, &challenge.nonce, u64::from(t)),
        "the sequential proof must equal the trapdoor expectation"
    );
    // ... and the core suite's own browser-equivalent solver agrees.
    assert_eq!(
        proof,
        kiwicaptcha::rsw::fixtures::sequential_proof(
            &challenge.prefix,
            &challenge.nonce,
            u64::from(t)
        ),
        "two spellings of the same sequential loop must agree"
    );

    let token = solution.token(&challenge);
    let decoded = SolutionToken::decode(&token).expect("the rsw token decodes");
    assert_eq!(decoded.counter, 0, "an rsw proof carries no search counter");
    let mut record = issued.record;
    assert!(
        matches!(
            verify_with_core(&mut record, &token, Some((modulus, lambda))),
            VerifyOutcome::Valid { .. }
        ),
        "the core verifier must accept the rsw token through the trapdoor"
    );
}

// ── golden vectors pinned to shared fixtures ──────────────────────────

#[test]
fn sha256_golden_challenge_pins_the_first_counter() {
    let challenge = golden_challenge(12);
    let solution = plain_solve(&challenge);
    assert_eq!(
        solution.counter, GOLDEN_COUNTER_12_BITS,
        "the golden challenge's first winning counter is pinned"
    );
    // The independent recomputation confirms the pin, both below and at
    // the counter, so a drifted preimage fails here first.
    let salt = B64.decode(&challenge.salt).unwrap();
    for counter in 0..solution.counter {
        assert!(leading_zero_bits(&independent_sha256(&challenge.prefix, counter, &salt)) < 12);
    }
    assert!(
        leading_zero_bits(&independent_sha256(
            &challenge.prefix,
            solution.counter,
            &salt
        )) >= 12
    );
}

#[test]
fn token_wire_bytes_match_the_shared_protocol_fixtures() {
    // Provenance: protocol/solution-token-v1/fixtures.json, the shared
    // boundary fixture generated by the PHP encoder and decoded
    // byte-for-byte by both language suites (PHP
    // TokenSolverLimitFixtureTest, Rust token_limits). The nonce below is
    // the fixture's nonce_b64 (32 bytes of 'a'), the duration its
    // duration_ms, the telemetry its telemetry_json, and the expected
    // strings its accepted rows verbatim.
    let fixture_nonce = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
    let challenge = golden_challenge_with_nonce(1, fixture_nonce);
    let accepted: &[(u64, &str)] = &[
        (
            4_999_999,
            "WVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRT0uNDk5OTk5OS4xMjM0LnsibWUiOjF9",
        ),
        (
            19_999_999,
            "WVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRT0uMTk5OTk5OTkuMTIzNC57Im1lIjoxfQ==",
        ),
    ];
    for (counter, expected) in accepted {
        let solution = kiwicaptcha_solver::Solution {
            counter: *counter,
            duration_ms: 1234,
            hashes: *counter,
            hash_hex: String::new(),
            rsw_proof: None,
            telemetry: serde_json::json!({"me": 1}),
        };
        let token = solution.token(&challenge);
        assert_eq!(
            &token, expected,
            "counter {counter} must encode to the fixture bytes"
        );
        assert!(SolutionToken::decode(&token).is_ok());
    }
    // The fixture's rejected rows stay rejected: a counter at the cap was
    // never minted by a real solve, and the decoder refuses it.
    let rejected = "WVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRT0uMjAwMDAwMDAuMTIzNC57Im1lIjoxfQ==";
    assert!(matches!(
        SolutionToken::decode(rejected),
        Err(kiwicaptcha::DecodeError::InvalidCounter)
    ));
    // The default telemetry is the off-widget empty object.
    let solved = plain_solve(&golden_challenge(4));
    let decoded = SolutionToken::decode(&solved.token(&golden_challenge(4))).unwrap();
    assert_eq!(decoded.telemetry, serde_json::json!({}));
}

// ── challenge document parsing ────────────────────────────────────────

#[test]
fn challenge_parsing_accepts_bare_and_wrapped_documents() {
    let bare = golden_challenge(8);
    let wrapped =
        serde_json::json!({ "challenge": serde_json::to_value(&bare).unwrap() }).to_string();
    assert_eq!(
        Challenge::from_json(&serde_json::to_string(&bare).unwrap()).unwrap(),
        Challenge::from_json(&wrapped).unwrap(),
        "the bare object and the wrapped envelope parse to the same challenge"
    );
    // Unknown keys are tolerated (a newer deployment may add one).
    let extended = serde_json::json!({
        "challenge": serde_json::to_value(&bare).unwrap(),
        "issued": "2026-10-04T00:00:00Z",
    })
    .to_string();
    assert!(Challenge::from_json(&extended).is_ok());
    // Garbage is refused cleanly.
    assert!(Challenge::from_json("not json").is_err());
    assert!(Challenge::from_json("{}").is_err());
    let mut bad_nonce = bare.clone();
    bad_nonce.nonce = "short".to_string();
    let mut solved = SolveOptions::default();
    assert!(matches!(
        solve(&bad_nonce, &mut solved),
        Err(SolveError::MalformedChallenge(_))
    ));
}

// ── cap enforcement: the browser's price is the maximum on offer ──────

#[test]
fn difficulties_beyond_the_browser_ceilings_are_refused_before_work() {
    let mut opts = SolveOptions::default();
    let sha = golden_challenge(SOLVER_MAX_TARGET_BITS + 1);
    assert_eq!(
        solve(&sha, &mut opts),
        Err(SolveError::DifficultyBeyondCap {
            algorithm: PoWAlgorithm::Sha256,
            target_bits: SOLVER_MAX_TARGET_BITS + 1,
            cap: SOLVER_MAX_TARGET_BITS,
        })
    );
    let argon = serde_json::from_value(serde_json::json!({
        "nonce": GOLDEN_NONCE,
        "challenge": "Z29sZGVuLWNoYWxsZW5nZQ==.deadbeef",
        "salt": GOLDEN_SALT_B64,
        "algorithm": "argon2id",
        "mKib": 8,
        "t": 3,
        "p": 1,
        "targetBits": SOLVER_MAX_ARGON2_TARGET_BITS + 1,
        "ttlSecs": 300,
        "minDurationMs": 0,
        "prefix": GOLDEN_PREFIX,
    }))
    .unwrap();
    assert_eq!(
        solve(&argon, &mut opts),
        Err(SolveError::DifficultyBeyondCap {
            algorithm: PoWAlgorithm::Argon2id,
            target_bits: SOLVER_MAX_ARGON2_TARGET_BITS + 1,
            cap: SOLVER_MAX_ARGON2_TARGET_BITS,
        })
    );
}

#[test]
fn an_over_cap_hash_budget_is_refused_outright() {
    let challenge = golden_challenge(8);
    let mut opts = SolveOptions {
        max_hashes: SOLVER_MAX_HASHES + 1,
        ..SolveOptions::default()
    };
    assert_eq!(
        solve(&challenge, &mut opts),
        Err(SolveError::CapTooLarge {
            requested: SOLVER_MAX_HASHES + 1,
            cap: SOLVER_MAX_HASHES,
        })
    );
    // The exact cap is the default budget and stays acceptable.
    opts.max_hashes = SOLVER_MAX_HASHES;
    assert!(solve(&challenge, &mut opts).is_ok());
}

#[test]
fn an_exhausted_search_stops_at_the_cap_never_beyond() {
    // The golden 12-bit challenge's first winner sits at the pinned
    // counter; a budget equal to that counter (the search is half-open)
    // deterministically exhausts at exactly that many hashes.
    let challenge = golden_challenge(12);
    let mut opts = SolveOptions {
        max_hashes: GOLDEN_COUNTER_12_BITS,
        ..SolveOptions::default()
    };
    assert_eq!(
        solve(&challenge, &mut opts),
        Err(SolveError::Exhausted {
            attempted: GOLDEN_COUNTER_12_BITS
        })
    );
    // One more hash finds the winner: the boundary is exact.
    opts.max_hashes = GOLDEN_COUNTER_12_BITS + 1;
    assert_eq!(
        solve(&challenge, &mut opts)
            .expect("the boundary solve succeeds")
            .counter,
        GOLDEN_COUNTER_12_BITS
    );
}

#[test]
fn out_of_contract_parameters_are_refused_before_work() {
    let mut opts = SolveOptions::default();
    let base = serde_json::json!({
        "nonce": GOLDEN_NONCE,
        "challenge": "Z29sZGVuLWNoYWxsZW5nZQ==.deadbeef",
        "salt": GOLDEN_SALT_B64,
        "ttlSecs": 300,
        "minDurationMs": 0,
        "prefix": GOLDEN_PREFIX,
    });
    // Argon2id memory above the 64 MiB ceiling the browser wasm enforces.
    let over_memory = serde_json::json!({"algorithm": "argon2id", "mKib": 65_537, "t": 3, "p": 1, "targetBits": 4});
    let doc = merge(&base, &over_memory);
    assert!(matches!(
        solve(&doc, &mut opts),
        Err(SolveError::UnsupportedArgon2Params { .. })
    ));
    // An issuance-range violation (t below 3).
    let bad_t =
        serde_json::json!({"algorithm": "argon2id", "mKib": 8, "t": 2, "p": 1, "targetBits": 4});
    assert!(matches!(
        solve(&merge(&base, &bad_t), &mut opts),
        Err(SolveError::UnsupportedArgon2Params { .. })
    ));
    // rsw: a squaring count below the protocol floor, and a short modulus.
    let fixture_modulus = kiwicaptcha::rsw::fixtures::MODULUS_N_B64;
    let short_t = serde_json::json!({"algorithm": "rsw", "mKib": 0, "t": 9_999, "p": 1, "targetBits": 1, "rsw_modulus": fixture_modulus});
    assert!(matches!(
        solve(&merge(&base, &short_t), &mut opts),
        Err(SolveError::UnsupportedRswParams(_))
    ));
    let short_modulus = serde_json::json!({"algorithm": "rsw", "mKib": 0, "t": kiwicaptcha::challenge::MIN_RSW_T, "p": 1, "targetBits": 1, "rsw_modulus": B64.encode([0u8; 8])});
    assert!(matches!(
        solve(&merge(&base, &short_modulus), &mut opts),
        Err(SolveError::UnsupportedRswParams(_))
    ));
    // An execution-armed challenge needs the browser interpreter.
    let armed = serde_json::json!({"algorithm": "sha256", "mKib": 0, "t": 1, "p": 1, "targetBits": 4, "execution_program": "AAAAAA=="});
    assert_eq!(
        solve(&merge(&base, &armed), &mut opts),
        Err(SolveError::ExecutionUnsupported)
    );
}

fn merge(base: &serde_json::Value, extra: &serde_json::Value) -> Challenge {
    let mut document = base.clone();
    if let (Some(map), Some(extra)) = (document.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            map.insert(key.clone(), value.clone());
        }
    }
    serde_json::from_value(document).expect("the merged document is well formed")
}

// ── cancellation and progress ─────────────────────────────────────────

#[test]
fn a_precancelled_solve_stops_immediately() {
    let challenge = golden_challenge(8);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut opts = SolveOptions {
        cancel: Some(&cancel),
        ..SolveOptions::default()
    };
    assert_eq!(
        solve(&challenge, &mut opts),
        Err(SolveError::Cancelled { attempted: 0 })
    );
}

#[test]
fn cancellation_from_the_progress_callback_stops_promptly() {
    // The golden 12-bit challenge's winner sits far past the stop point,
    // so the cancel path is the only way this solve ends.
    let challenge = golden_challenge(12);
    let cancel = CancellationToken::new();
    let mut seen = Vec::new();
    let outcome = {
        let cancel_ref = &cancel;
        let mut sink = |event: kiwicaptcha_solver::ProgressEvent| {
            seen.push(event.attempted);
            if event.attempted >= 128 {
                cancel_ref.cancel();
            }
        };
        let mut opts = SolveOptions {
            progress_interval: 128,
            cancel: Some(&cancel),
            on_progress: Some(&mut sink),
            ..SolveOptions::default()
        };
        solve(&challenge, &mut opts)
    };
    match outcome {
        Err(SolveError::Cancelled { attempted }) => {
            // The loop checks every 256 hashes, so the stop lands at the
            // first check after the 128-hash event: prompt and exact.
            assert_eq!(attempted, 256);
        }
        other => panic!("a cancelled solve must not finish: {other:?}"),
    }
    assert!(
        seen.contains(&128),
        "progress events must be observed: {seen:?}"
    );
    assert_eq!(
        seen.last(),
        Some(&256),
        "the events are monotonic up to the stop"
    );
}

#[test]
fn rsw_cancellation_and_progress_follow_the_squaring_cadence() {
    let fixture_modulus = kiwicaptcha::rsw::fixtures::MODULUS_N_B64;
    let challenge: Challenge = serde_json::from_value(serde_json::json!({
        "nonce": GOLDEN_NONCE,
        "challenge": "Z29sZGVuLWNoYWxsZW5nZQ==.deadbeef",
        "salt": GOLDEN_SALT_B64,
        "algorithm": "rsw",
        "mKib": 0,
        "t": kiwicaptcha::challenge::MIN_RSW_T,
        "p": 1,
        "targetBits": 1,
        "ttlSecs": 300,
        "minDurationMs": 0,
        "prefix": GOLDEN_PREFIX,
        "rsw_modulus": fixture_modulus,
    }))
    .unwrap();
    let cancel = CancellationToken::new();
    let mut events = 0u32;
    let outcome = {
        let cancel_ref = &cancel;
        let mut sink = |_event: kiwicaptcha_solver::ProgressEvent| {
            events += 1;
            cancel_ref.cancel();
        };
        let mut opts = SolveOptions {
            progress_interval: 1024,
            cancel: Some(&cancel),
            on_progress: Some(&mut sink),
            ..SolveOptions::default()
        };
        solve(&challenge, &mut opts)
    };
    match outcome {
        Err(SolveError::Cancelled { attempted }) => {
            // The loop polls every squaring, so it stops exactly at the
            // cadence boundary that fired the callback.
            assert_eq!(attempted, 1024);
        }
        other => panic!("a cancelled rsw solve must not finish: {other:?}"),
    }
    assert_eq!(
        events, 1,
        "exactly one progress event fires before the stop"
    );
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
