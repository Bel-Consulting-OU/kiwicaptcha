//! The ABI integration test: load the built cdylib exactly the way the
//! Dart bindings do (dlopen by file name, late-bound symbols) and solve
//! the shared golden PHP vectors through the EXPORTED C ABI, then hand
//! every solution to the workspace's real verifier.
//!
//! The golden vectors are the repo's shared server-SDK fixture
//! (`packages/kiwicaptcha-jvm/testdata/golden/golden-php-vectors.json`),
//! minted live by the canonical PHP Issuer: the same records the JVM
//! and Elixir suites pin. Every solve runs through `kiwi_solve_*` — no
//! in-process shortcut — and every verification runs
//! `kiwicaptcha::verify_solution`, the code the server deploys.

use std::path::PathBuf;
use std::process::Command;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kiwicaptcha::{
    verify_solution, ChallengeRecord, RequestBindingExpectation, VerifyContext, VerifyOutcome,
};
use libloading::{Library, Symbol};

/// The shared cross-language signing secret (kid 1) the golden fixture
/// was minted with (the JSON's provenance block).
const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// The Dart-side default hash budget (KiwiLimits.maxHashes, the
/// protocol/limits.json solver_max_hashes).
const MAX_HASHES: u64 = 20_000_000;

// ── the Dart-shaped signatures (mirror of ffi_bindings.dart) ─────────

type SolveSha256 = unsafe extern "C" fn(*const u8, u32, *const u8, u32, u32, u64, *mut u64) -> i32;
type SolveRsw =
    unsafe extern "C" fn(*const u8, u32, *const u8, u32, *const u8, u32, u64, *mut u8) -> i32;
type SolveArgon2id =
    unsafe extern "C" fn(*const u8, u32, *const u8, u32, u32, u32, u32, u32, *mut u64) -> i32;
type SolveSha256Range =
    unsafe extern "C" fn(*const u8, u32, *const u8, u32, u32, u64, u64, *mut u64) -> i32;
type SolveArgon2idRange = unsafe extern "C" fn(
    *const u8,
    u32,
    *const u8,
    u32,
    u32,
    u32,
    u32,
    u32,
    u64,
    u64,
    *mut u64,
) -> i32;
type RswBegin =
    unsafe extern "C" fn(*const u8, u32, *const u8, u32, *const u8, u32, *mut u8) -> i32;
type RswSquare = unsafe extern "C" fn(*const u8, u32, *mut u8, u32) -> i32;

const KIWI_OK: i32 = 0;
const KIWI_ERR_MALFORMED: i32 = 1;
const KIWI_ERR_CAP: i32 = 2;
const KIWI_ERR_EXHAUSTED: i32 = 5;

/// The loaded library plus its late-bound symbols, held the way Dart
/// holds them: the DynamicLibrary stays open while the functions are
/// called.
struct Abi {
    _lib: Library,
    solve_sha256: SolveSha256,
    solve_rsw: SolveRsw,
    solve_argon2id: SolveArgon2id,
    solve_sha256_range: SolveSha256Range,
    solve_argon2id_range: SolveArgon2idRange,
    rsw_begin: RswBegin,
    rsw_square: RswSquare,
}

impl Abi {
    fn load() -> Abi {
        let path = dylib_path();
        // SAFETY: the artifact is this crate's own cdylib built just
        // above; the symbols are the #[no_mangle] exports of src/lib.rs.
        let lib = unsafe { Library::new(&path) }.expect("the cdylib loads");
        let solve_sha256 = unsafe {
            let sym: Symbol<SolveSha256> = lib.get(b"kiwi_solve_sha256\0").expect("sha256 export");
            *sym
        };
        let solve_rsw = unsafe {
            let sym: Symbol<SolveRsw> = lib.get(b"kiwi_solve_rsw\0").expect("rsw export");
            *sym
        };
        let solve_argon2id = unsafe {
            let sym: Symbol<SolveArgon2id> =
                lib.get(b"kiwi_solve_argon2id\0").expect("argon2id export");
            *sym
        };
        let solve_sha256_range = unsafe {
            let sym: Symbol<SolveSha256Range> = lib
                .get(b"kiwi_solve_sha256_range\0")
                .expect("sha256 range export");
            *sym
        };
        let solve_argon2id_range = unsafe {
            let sym: Symbol<SolveArgon2idRange> = lib
                .get(b"kiwi_solve_argon2id_range\0")
                .expect("argon2id range export");
            *sym
        };
        let rsw_begin = unsafe {
            let sym: Symbol<RswBegin> = lib.get(b"kiwi_rsw_begin\0").expect("rsw begin export");
            *sym
        };
        let rsw_square = unsafe {
            let sym: Symbol<RswSquare> = lib.get(b"kiwi_rsw_square\0").expect("rsw square export");
            *sym
        };
        Abi {
            _lib: lib,
            solve_sha256,
            solve_rsw,
            solve_argon2id,
            solve_sha256_range,
            solve_argon2id_range,
            rsw_begin,
            rsw_square,
        }
    }

    /// The exact call the Dart `sha256Search` performs.
    fn sha256(&self, prefix: &[u8], salt: &[u8], target_bits: u32, max_hashes: u64) -> (i32, u64) {
        let mut out_counter = 0u64;
        // SAFETY: valid buffers and lengths, as the Dart caller builds them.
        let code = unsafe {
            (self.solve_sha256)(
                prefix.as_ptr(),
                prefix.len() as u32,
                salt.as_ptr(),
                salt.len() as u32,
                target_bits,
                max_hashes,
                &mut out_counter,
            )
        };
        (code, out_counter)
    }

    /// The exact call the Dart `rswSquarings` performs: a
    /// caller-allocated 256-byte proof buffer.
    fn rsw(&self, modulus: &[u8], prefix: &[u8], nonce: &[u8], t: u64) -> (i32, Vec<u8>) {
        let mut out_proof = vec![0u8; 256];
        // SAFETY: valid buffers and lengths, as the Dart caller builds them.
        let code = unsafe {
            (self.solve_rsw)(
                modulus.as_ptr(),
                modulus.len() as u32,
                prefix.as_ptr(),
                prefix.len() as u32,
                nonce.as_ptr(),
                nonce.len() as u32,
                t,
                out_proof.as_mut_ptr(),
            )
        };
        (code, out_proof)
    }

    /// The exact call the Dart `argon2id` performs.
    fn argon2id(
        &self,
        prefix: &[u8],
        salt: &[u8],
        m_kib: u32,
        t: u32,
        p: u32,
        target_bits: u32,
    ) -> (i32, u64) {
        let mut out_counter = 0u64;
        // SAFETY: valid buffers and lengths, as the Dart caller builds them.
        let code = unsafe {
            (self.solve_argon2id)(
                prefix.as_ptr(),
                prefix.len() as u32,
                salt.as_ptr(),
                salt.len() as u32,
                m_kib,
                t,
                p,
                target_bits,
                &mut out_counter,
            )
        };
        (code, out_counter)
    }

    /// The exact call the Dart cancellation loop performs per 2048-
    /// candidate sha256 batch.
    fn sha256_range(
        &self,
        prefix: &[u8],
        salt: &[u8],
        target_bits: u32,
        start_counter: u64,
        max_hashes: u64,
    ) -> (i32, u64) {
        let mut out_counter = 0u64;
        // SAFETY: valid buffers and lengths, as the Dart caller builds them.
        let code = unsafe {
            (self.solve_sha256_range)(
                prefix.as_ptr(),
                prefix.len() as u32,
                salt.as_ptr(),
                salt.len() as u32,
                target_bits,
                start_counter,
                max_hashes,
                &mut out_counter,
            )
        };
        (code, out_counter)
    }

    /// The exact call the Dart cancellation loop performs per argon2id
    /// derivation batch.
    #[allow(clippy::too_many_arguments)]
    fn argon2id_range(
        &self,
        prefix: &[u8],
        salt: &[u8],
        m_kib: u32,
        t: u32,
        p: u32,
        target_bits: u32,
        start_counter: u64,
        max_hashes: u64,
    ) -> (i32, u64) {
        let mut out_counter = 0u64;
        // SAFETY: valid buffers and lengths, as the Dart caller builds them.
        let code = unsafe {
            (self.solve_argon2id_range)(
                prefix.as_ptr(),
                prefix.len() as u32,
                salt.as_ptr(),
                salt.len() as u32,
                m_kib,
                t,
                p,
                target_bits,
                start_counter,
                max_hashes,
                &mut out_counter,
            )
        };
        (code, out_counter)
    }

    /// The exact call the Dart cancellation loop performs to start an
    /// rsw solve: derive the squaring base into a 256-byte buffer.
    fn rsw_begin(&self, modulus: &[u8], prefix: &[u8], nonce: &[u8]) -> (i32, Vec<u8>) {
        let mut out_value = vec![0u8; 256];
        // SAFETY: valid buffers and lengths, as the Dart caller builds them.
        let code = unsafe {
            (self.rsw_begin)(
                modulus.as_ptr(),
                modulus.len() as u32,
                prefix.as_ptr(),
                prefix.len() as u32,
                nonce.as_ptr(),
                nonce.len() as u32,
                out_value.as_mut_ptr(),
            )
        };
        (code, out_value)
    }

    /// The exact call the Dart cancellation loop performs per 256-
    /// squaring rsw batch: square in place.
    fn rsw_square(&self, modulus: &[u8], value: &mut [u8], squarings: u32) -> i32 {
        // SAFETY: valid buffers and lengths, as the Dart caller builds them.
        unsafe {
            (self.rsw_square)(
                modulus.as_ptr(),
                modulus.len() as u32,
                value.as_mut_ptr(),
                squarings,
            )
        }
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The file name Dart opens on this platform (the mirror of
/// `KiwiFfi._open`).
fn dylib_file_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libkiwicaptcha_solver.dylib"
    } else if cfg!(target_os = "windows") {
        "kiwicaptcha_solver.dll"
    } else {
        "libkiwicaptcha_solver.so"
    }
}

/// Build the cdylib (`cargo test` does not build cdylib artifacts by
/// itself) and return its path. The crate is a workspace member, so the
/// artifact lands in the workspace target directory; a standalone
/// checkout would put it beside the crate.
fn dylib_path() -> PathBuf {
    let manifest = manifest_dir();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(&cargo)
        .current_dir(&manifest)
        .args(["build"])
        .status()
        .expect("spawn cargo to build the cdylib");
    assert!(status.success(), "cargo build of the cdylib failed");
    let name = dylib_file_name();
    let mut candidates = Vec::new();
    for base in [
        manifest.join("../../../target"), // the workspace target directory
        manifest.join("target"),          // a standalone (non-workspace) build
    ] {
        for profile in ["debug", "release"] {
            candidates.push(base.join(profile).join(name));
        }
    }
    candidates
        .into_iter()
        .find(|path| path.exists())
        .unwrap_or_else(|| panic!("the built cdylib ({name}) was not found"))
}

// ── the shared golden fixture ─────────────────────────────────────────

fn golden() -> serde_json::Value {
    let path = manifest_dir().join("../../kiwicaptcha-jvm/testdata/golden/golden-php-vectors.json");
    let json = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the shared golden vectors are missing ({}): {error}",
            path.display()
        )
    });
    serde_json::from_str(&json).expect("the golden document parses")
}

fn golden_record<'a>(golden: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    golden["records"]
        .as_array()
        .expect("the golden document lists records")
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("the golden document carries a {name} record"))
}

/// The wire token's plain spelling: nonce.counter.duration.telemetry
/// (with the rsw proof riding as the final 512-hex segment).
fn token_parts(token_b64: &str) -> Vec<String> {
    let plain = B64
        .decode(token_b64)
        .expect("the golden token is standard base64");
    String::from_utf8(plain)
        .expect("the golden token is UTF-8")
        .split('.')
        .map(str::to_string)
        .collect()
}

/// Verify through the workspace's real verifier — the same context
/// shape the solver and JVM suites drive, floors off, scope enforced,
/// now inside the issued window.
fn verify_with_core(
    record: &mut ChallengeRecord,
    counter: u64,
    now_ns: u64,
    expected_region: Option<&str>,
    rsw: Option<(&str, &str)>,
    rsw_proof: Option<&str>,
) -> VerifyOutcome {
    let now_unix_value = record.issued_at + 1;
    let mut now_unix = move || now_unix_value;
    let mut ctx = VerifyContext {
        record,
        secret_key: SECRET,
        tenant: None,
        secrets_by_kid: None,
        revoked_kids: None,
        counter,
        duration_ms: 1500,
        now_unix: Some(&mut now_unix),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region,
        expected_issuer: None,
        expected_policy_version: None,
        policy_version_floor: None,
        client_ip: None,
        execution_digest: None,
        execution_trace: None,
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
        rsw_proof,
        rsw_modulus_n: rsw.map(|(n, _)| n),
        rsw_lambda: rsw.map(|(_, l)| l),
        rsw_keyring: None,
    };
    verify_solution(&mut ctx)
}

// ── the three golden solves through the exported C ABI ────────────────

#[test]
fn sha256_golden_vector_solves_through_the_abi_and_verifies() {
    let golden = golden();
    let entry = golden_record(&golden, "sha_plain");
    let record_json = &entry["record"];
    let prefix = record_json["prefix"].as_str().unwrap();
    let salt = B64.decode(record_json["salt"].as_str().unwrap()).unwrap();
    let target_bits = record_json["target_bits"].as_u64().unwrap() as u32;
    let expected_counter = token_parts(entry["token_b64"].as_str().unwrap())[1]
        .parse::<u64>()
        .unwrap();

    let abi = Abi::load();
    let (code, counter) = abi.sha256(prefix.as_bytes(), &salt, target_bits, MAX_HASHES);
    assert_eq!(code, KIWI_OK, "the ABI solve answers KIWI_OK");
    assert_eq!(
        counter, expected_counter,
        "the ABI finds the same first counter the canonical PHP issuer's solve found"
    );

    // The workspace's real verifier accepts the ABI's solution.
    let mut record: ChallengeRecord =
        serde_json::from_value(record_json.clone()).expect("the golden record deserializes");
    let now_ns = record.issued_at_ns + 3_000_000;
    let region = entry["verify_opts"]["region"].as_str();
    assert!(matches!(
        verify_with_core(&mut record, counter, now_ns, region, None, None),
        VerifyOutcome::Valid { .. }
    ));
}

#[test]
fn argon2id_golden_vector_solves_through_the_abi_and_verifies() {
    let golden = golden();
    let entry = golden_record(&golden, "argon2id");
    let record_json = &entry["record"];
    let prefix = record_json["prefix"].as_str().unwrap();
    let salt = B64.decode(record_json["salt"].as_str().unwrap()).unwrap();
    let m_kib = record_json["m_kib"].as_u64().unwrap() as u32;
    let t = record_json["t"].as_u64().unwrap() as u32;
    let p = record_json["p"].as_u64().unwrap() as u32;
    let target_bits = record_json["target_bits"].as_u64().unwrap() as u32;
    let expected_counter = token_parts(entry["token_b64"].as_str().unwrap())[1]
        .parse::<u64>()
        .unwrap();

    let abi = Abi::load();
    let (code, counter) = abi.argon2id(prefix.as_bytes(), &salt, m_kib, t, p, target_bits);
    assert_eq!(code, KIWI_OK, "the ABI solve answers KIWI_OK");
    assert_eq!(
        counter, expected_counter,
        "the ABI finds the same first counter the sodium-gated PHP solve found"
    );

    // The core verifier re-derives the argon2id rungs and accepts.
    let mut record: ChallengeRecord =
        serde_json::from_value(record_json.clone()).expect("the golden record deserializes");
    let now_ns = record.issued_at_ns + 3_000_000;
    assert!(matches!(
        verify_with_core(&mut record, counter, now_ns, None, None, None),
        VerifyOutcome::Valid { .. }
    ));
}

#[test]
fn rsw_golden_vector_solves_through_the_abi_and_verifies() {
    let golden = golden();
    let entry = golden_record(&golden, "rsw");
    let record_json = &entry["record"];
    let prefix = record_json["prefix"].as_str().unwrap();
    let nonce = record_json["nonce"].as_str().unwrap();
    let t = record_json["t"].as_u64().unwrap();
    let modulus_b64 = entry["verify_opts"]["rsw"]["modulus_n"].as_str().unwrap();
    let lambda_b64 = entry["verify_opts"]["rsw"]["lambda"].as_str().unwrap();
    let modulus = B64.decode(modulus_b64).unwrap();
    assert_eq!(modulus.len(), 256, "the canonical 2048-bit modulus");
    let parts = token_parts(entry["token_b64"].as_str().unwrap());
    let expected_proof = parts
        .last()
        .expect("the golden rsw token carries the 512-hex proof");

    let abi = Abi::load();
    let (code, proof) = abi.rsw(&modulus, prefix.as_bytes(), nonce.as_bytes(), t);
    assert_eq!(code, KIWI_OK, "the ABI solve answers KIWI_OK");
    let proof_hex: String = proof.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        proof_hex, *expected_proof,
        "the sequential squarings produce the PHP-solved 512-hex proof"
    );

    // The trapdoor verifier accepts the ABI's proof.
    let mut record: ChallengeRecord =
        serde_json::from_value(record_json.clone()).expect("the golden record deserializes");
    let now_ns = record.issued_at_ns + 3_000_000;
    assert!(matches!(
        verify_with_core(
            &mut record,
            0,
            now_ns,
            None,
            Some((modulus_b64, lambda_b64)),
            Some(&proof_hex),
        ),
        VerifyOutcome::Valid { .. }
    ));
}

// ── the batched entry points, through the ABI ─────────────────────────

#[test]
fn sha256_range_windows_reach_the_golden_counter_through_the_abi() {
    let golden = golden();
    let entry = golden_record(&golden, "sha_plain");
    let record_json = &entry["record"];
    let prefix = record_json["prefix"].as_str().unwrap();
    let salt = B64.decode(record_json["salt"].as_str().unwrap()).unwrap();
    let target_bits = record_json["target_bits"].as_u64().unwrap() as u32;
    let expected_counter = token_parts(entry["token_b64"].as_str().unwrap())[1]
        .parse::<u64>()
        .unwrap();

    let abi = Abi::load();
    // The window below the winner exhausts; the one-counter window at
    // the winner finds it — the exact shape the Dart cancellation
    // batches issue.
    if expected_counter > 0 {
        let (code, _) =
            abi.sha256_range(prefix.as_bytes(), &salt, target_bits, 0, expected_counter);
        assert_eq!(code, KIWI_ERR_EXHAUSTED);
    }
    let (code, counter) =
        abi.sha256_range(prefix.as_bytes(), &salt, target_bits, expected_counter, 1);
    assert_eq!(code, KIWI_OK);
    assert_eq!(counter, expected_counter);
    // The Dart cadence's 2048-counter batch spanning the winner finds
    // the same first hit (no counter below the winner qualifies).
    let batch_start = expected_counter / 2048 * 2048;
    let (code, counter) =
        abi.sha256_range(prefix.as_bytes(), &salt, target_bits, batch_start, 2048);
    assert_eq!(code, KIWI_OK);
    assert_eq!(counter, expected_counter);
}

#[test]
fn rsw_begin_and_square_batches_reproduce_the_golden_proof_through_the_abi() {
    let golden = golden();
    let entry = golden_record(&golden, "rsw");
    let record_json = &entry["record"];
    let prefix = record_json["prefix"].as_str().unwrap();
    let nonce = record_json["nonce"].as_str().unwrap();
    let t = record_json["t"].as_u64().unwrap();
    let modulus = B64
        .decode(entry["verify_opts"]["rsw"]["modulus_n"].as_str().unwrap())
        .unwrap();
    let parts = token_parts(entry["token_b64"].as_str().unwrap());
    let expected_proof = parts
        .last()
        .expect("the golden rsw token carries the 512-hex proof");

    let abi = Abi::load();
    let (code, mut value) = abi.rsw_begin(&modulus, prefix.as_bytes(), nonce.as_bytes());
    assert_eq!(code, KIWI_OK, "the rsw base derives through the ABI");
    // The Dart loop's shape: 256-squaring batches until t is spent.
    let mut remaining = t;
    while remaining > 0 {
        let step = remaining.min(256) as u32;
        assert_eq!(
            abi.rsw_square(&modulus, &mut value, step),
            KIWI_OK,
            "the squaring batch advances through the ABI"
        );
        remaining -= step as u64;
    }
    let proof_hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        proof_hex, *expected_proof,
        "batched squarings land on the golden proof"
    );
}

#[test]
#[cfg(feature = "argon")]
fn argon2id_range_windows_reach_the_golden_counter_through_the_abi() {
    let golden = golden();
    let entry = golden_record(&golden, "argon2id");
    let record_json = &entry["record"];
    let prefix = record_json["prefix"].as_str().unwrap();
    let salt = B64.decode(record_json["salt"].as_str().unwrap()).unwrap();
    let m_kib = record_json["m_kib"].as_u64().unwrap() as u32;
    let t = record_json["t"].as_u64().unwrap() as u32;
    let p = record_json["p"].as_u64().unwrap() as u32;
    let target_bits = record_json["target_bits"].as_u64().unwrap() as u32;
    let expected_counter = token_parts(entry["token_b64"].as_str().unwrap())[1]
        .parse::<u64>()
        .unwrap();

    let abi = Abi::load();
    if expected_counter > 0 {
        let (code, _) = abi.argon2id_range(
            prefix.as_bytes(),
            &salt,
            m_kib,
            t,
            p,
            target_bits,
            0,
            expected_counter,
        );
        assert_eq!(code, KIWI_ERR_EXHAUSTED);
    }
    let (code, counter) = abi.argon2id_range(
        prefix.as_bytes(),
        &salt,
        m_kib,
        t,
        p,
        target_bits,
        expected_counter,
        1,
    );
    assert_eq!(code, KIWI_OK);
    assert_eq!(counter, expected_counter);
}

// ── the refusal codes, through the ABI ────────────────────────────────

#[test]
fn abi_refusal_codes_match_the_dart_error_map() {
    let abi = Abi::load();
    let salt = b"0123456789abcdef";
    let prefix = "golden-prefix|".as_bytes();

    // Over-cap difficulty → KIWI_ERR_CAP (2).
    let (code, _) = abi.sha256(prefix, salt, 21, MAX_HASHES);
    assert_eq!(code, KIWI_ERR_CAP);
    // A budget above the documented cap → KIWI_ERR_CAP (2).
    let (code, _) = abi.sha256(prefix, salt, 8, MAX_HASHES + 1);
    assert_eq!(code, KIWI_ERR_CAP);
    // A tiny budget at an unreachable target → KIWI_ERR_EXHAUSTED (5).
    let (code, _) = abi.sha256(prefix, salt, 20, 3);
    assert_eq!(code, KIWI_ERR_EXHAUSTED);
    // A short modulus → KIWI_ERR_MALFORMED (1).
    let (code, _) = abi.rsw(&[0u8; 255], prefix, &[b'A'; 44], 10_000);
    assert_eq!(code, KIWI_ERR_MALFORMED);
    // An out-of-contract squaring count → KIWI_ERR_MALFORMED (1).
    let (code, _) = abi.rsw(&[0xffu8; 256], prefix, &[b'A'; 44], 9_999);
    assert_eq!(code, KIWI_ERR_MALFORMED);
    // Argon2id parameters outside the issued contract → KIWI_ERR_MALFORMED (1).
    let (code, _) = abi.argon2id(prefix, salt, 4, 3, 1, 4);
    assert_eq!(code, KIWI_ERR_MALFORMED);
}

/// Leading zero bits of a digest, big-endian bit order — the shared
/// notion, spelled out locally so the check is independent of the
/// library under test.
fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in digest {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

#[test]
fn the_abi_matches_an_independent_recomputation_of_the_preimage() {
    // The load-bearing check, written twice: the winning digest of the
    // sha_plain golden vector, recomputed here with sha2 directly (the
    // verifier's preimage contract spelled out), must hash to a digest
    // with the issued leading zero bits at the ABI's counter.
    let golden = golden();
    let entry = golden_record(&golden, "sha_plain");
    let record_json = &entry["record"];
    let prefix = record_json["prefix"].as_str().unwrap();
    let salt = B64.decode(record_json["salt"].as_str().unwrap()).unwrap();
    let target_bits = record_json["target_bits"].as_u64().unwrap() as u32;

    let abi = Abi::load();
    let (code, counter) = abi.sha256(prefix.as_bytes(), &salt, target_bits, MAX_HASHES);
    assert_eq!(code, KIWI_OK);

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(counter.to_string().as_bytes());
    hasher.update(&salt);
    let digest = hasher.finalize();
    assert!(
        leading_zero_bits(&digest) >= target_bits,
        "the winning counter meets the target"
    );
    // ... and no earlier counter does (the FIRST-hit contract).
    for earlier in 0..counter {
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(earlier.to_string().as_bytes());
        hasher.update(&salt);
        let digest = hasher.finalize();
        assert!(
            leading_zero_bits(&digest) < target_bits,
            "counter {earlier} must not meet the target"
        );
    }
}
