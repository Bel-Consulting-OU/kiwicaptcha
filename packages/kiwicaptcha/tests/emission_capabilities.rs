//! The protocol-v5 emission-capability matrix: the RSW modulus identity is
//! a feature of the writer, not an implicit consequence of issuing an RSW
//! challenge. The capability-free default and any confirmed ceiling below
//! [`RSW_IDENTITY_PROTOCOL_VERSION`] emit the legacy identityless v2 shape
//! (which every pre-v5 reader accepts), and only a confirmed ceiling at the
//! feature version (or above — a later protocol maximum must not shut the
//! feature off) arms the identity and stamps v5.

use kiwicaptcha::challenge::{
    issue_challenge, issue_challenge_with_capabilities, BindingMode, ChallengeConfig,
    EmissionCapabilities, PoWAlgorithm, BASE_PROTOCOL_VERSION, RSW_IDENTITY_PROTOCOL_VERSION,
};
use kiwicaptcha::rsw::fixtures::{LAMBDA_B64, MODULUS_N_B64};
use kiwicaptcha::verify::{
    verify_solution, RequestBindingExpectation, VerifyContext, VerifyOutcome,
};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const NOW_UNIX: u64 = 1_800_000_000;
const NOW_NS: u64 = NOW_UNIX * 1_000_000;

fn rsw_config() -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.into(),
        kid: 1,
        execution_key: None,
        rsw_modulus_n: Some(MODULUS_N_B64.into()),
        rsw_lambda: Some(LAMBDA_B64.into()),
        rsw_t: kiwicaptcha::challenge::MIN_RSW_T,
        tenant: None,
        algorithm: PoWAlgorithm::Rsw,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 8,
        ttl_secs: 120,
        min_duration_ms: Some(0),
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    }
}

fn issue_with_ceiling(ceiling: u8) -> kiwicaptcha::challenge::Issued {
    issue_challenge_with_capabilities(
        EmissionCapabilities::confirmed(ceiling),
        &rsw_config(),
        "login",
        "198.51.100.7",
        NOW_UNIX,
        NOW_NS,
        0,
        None,
    )
    .expect("rsw issuance")
}

fn verify_record(record: &mut kiwicaptcha::ChallengeRecord, proof: &str) -> VerifyOutcome {
    verify_solution(&mut VerifyContext {
        record,
        secret_key: SECRET,
        tenant: None,
        secrets_by_kid: None,
        revoked_kids: None,
        counter: 0,
        duration_ms: 5000,
        now_unix: Some(&mut || NOW_UNIX + 1),
        now_ns: NOW_NS + 1_000_000,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("198.51.100.7"),
        execution_digest: None,
        execution_trace: None,
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
        rsw_proof: Some(proof),
        rsw_modulus_n: Some(MODULUS_N_B64),
        rsw_lambda: Some(LAMBDA_B64),
        rsw_keyring: None,
    })
}

#[test]
fn the_default_capability_is_capability_free() {
    assert_eq!(
        EmissionCapabilities::default().max_protocol_version(),
        BASE_PROTOCOL_VERSION
    );
    assert!(!EmissionCapabilities::default().admits_rsw_identity());
    assert!(EmissionCapabilities::confirmed(RSW_IDENTITY_PROTOCOL_VERSION).admits_rsw_identity());
    assert!(!EmissionCapabilities::confirmed(4).admits_rsw_identity());
    assert!(EmissionCapabilities::confirmed(6).admits_rsw_identity());
}

#[test]
fn a_capped_rsw_writer_emits_the_identityless_v2_shape() {
    // The plain entry point keeps the capability-free default: a direct
    // caller in a rolling-upgrade-capable deployment must NOT see v5
    // records appear implicitly.
    let default_issued = issue_challenge(
        &rsw_config(),
        "login",
        "198.51.100.7",
        NOW_UNIX,
        NOW_NS,
        0,
        None,
    )
    .expect("rsw issuance");
    assert_eq!(
        default_issued.record.protocol_version,
        BASE_PROTOCOL_VERSION
    );
    assert_eq!(default_issued.record.rsw_modulus_sha256, None);

    // An old-reader-compatible ceiling (4) stays on the legacy shape.
    let capped = issue_with_ceiling(4);
    assert_eq!(capped.record.protocol_version, BASE_PROTOCOL_VERSION);
    assert_eq!(capped.record.rsw_modulus_sha256, None);
    // The client-facing response still carries the public modulus: the
    // identity-less shape is the pre-v5 wire, not a broken challenge.
    assert_eq!(capped.challenge.rsw_modulus.as_deref(), Some(MODULUS_N_B64));

    // An in-range v4 reader accepts the capped record: v2 is inside every
    // reader's range, and the sequential proof verifies under the active
    // pair exactly like before the identity feature.
    let proof = kiwicaptcha::rsw::fixtures::sequential_proof(
        &capped.record.prefix,
        &capped.record.nonce,
        capped.record.t as u64,
    );
    let mut record = capped.record;
    assert!(matches!(
        verify_record(&mut record, &proof),
        VerifyOutcome::Valid { .. }
    ));
}

#[test]
fn the_feature_ceiling_arms_v5_and_a_later_maximum_does_not_revoke_it() {
    for ceiling in [RSW_IDENTITY_PROTOCOL_VERSION, 6] {
        let issued = issue_with_ceiling(ceiling);
        assert_eq!(
            issued.record.protocol_version, RSW_IDENTITY_PROTOCOL_VERSION,
            "a confirmed ceiling {ceiling} arms the identity-bearing shape"
        );
        assert_eq!(
            issued.record.rsw_modulus_sha256.as_deref(),
            Some(
                kiwicaptcha::rsw::modulus_fingerprint_hex(MODULUS_N_B64)
                    .expect("the fixture modulus is canonical")
                    .as_str()
            ),
        );
        let proof = kiwicaptcha::rsw::fixtures::sequential_proof(
            &issued.record.prefix,
            &issued.record.nonce,
            issued.record.t as u64,
        );
        let mut record = issued.record;
        assert!(matches!(
            verify_record(&mut record, &proof),
            VerifyOutcome::Valid { .. }
        ));
    }
}

#[test]
fn a_non_rsw_writer_is_unaffected_by_the_ceiling() {
    let mut config = rsw_config();
    config.algorithm = PoWAlgorithm::Sha256;
    config.rsw_modulus_n = None;
    config.rsw_lambda = None;
    let issued = issue_challenge_with_capabilities(
        EmissionCapabilities::confirmed(6),
        &config,
        "login",
        "198.51.100.7",
        NOW_UNIX,
        NOW_NS,
        0,
        None,
    )
    .expect("sha issuance");
    assert_eq!(issued.record.protocol_version, BASE_PROTOCOL_VERSION);
    assert_eq!(issued.record.rsw_modulus_sha256, None);
}
