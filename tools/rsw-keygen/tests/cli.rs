//! End-to-end tests of the rsw-keygen binary: a full keygen run, the
//! diagnostic gate around the primes, the fingerprint modes and the
//! --check rule list against committed fixture material.

use num_bigint::BigUint;
use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rsw-keygen"))
}

/// The shared fixture pair of the kiwicaptcha suites, in hex.
const FIXTURE_N_HEX: &str = "b0bd4c936619e019f39c18167b6601dee399f8a14dfd51139754f41fdcee5a43f9e3f9c037cb203e1aa8cc3ad109543174973920382487d11e9801b362392efb3aafd9f76bc9fcb98876ed4048641c956dfb97ffeb2c6b643bc750c8600d10262deeeb463108642f06a9c7dc6d0c95102831ccd7dddc513e0137aec5cf3029a7e352d43faef8b3141242a392f4af853aec90e8a1756de324cbb51b2814add664138a20e499f84d2f6490edd9d75e0d296e4bfa9aa99e42ddd49579a4b269e957f1d1a99a8bebf310a50bef522ac16731cfba9bd581a360ac092a491a4dcb64cdbce3b1cce7faf681f98d74de7345e723118e4c2cb110ff7e098a7b8cb4c269bb";

const FIXTURE_LAMBDA_HEX: &str = "585ea649b30cf00cf9ce0c0b3db300ef71ccfc50a6fea889cbaa7a0fee772d21fcf1fce01be5901f0d54661d6884aa18ba4b9c901c1243e88f4c00d9b11c977d9d57ecfbb5e4fe5cc43b76a024320e4ab6fdcbfff59635b21de3a8643006881316f775a3188432178354e3ee36864a881418e66beeee289f009bd762e79814d31c130309747422f2580d14124cc0d37edbaee8562b8d76f5d1b422f1d0c78e4a220f3af0cd9cb53405ae1b260e664d72d8f6594830fb4eb8753906237c13b218f24282758969253806aaffaebb968d4bf48f425dec311f1d228df39fbc1985cb0ccb32759ff74b647352c17b37417e97414f81c7c395cf9a662583d325476c10";

/// A real 2048-bit probable prime, shared with the core suites.
const PROBABLE_PRIME_N_HEX: &str = "dd007bd3d23ae90f08be9d8fe51b600f8f9c8b7f1d1ee02e5dfcc62f82ad0a4df85065fdb8e1b5160355f7607d05c552d625f824261da8df5c1e0eb6b2a116c7ea747e7eeb502b8f619485a67c1c5a95631cc6e2833cf6c235adda6864a8bb5b819ffe9daaffa6d42eeda1ca3ab418540a6961fd2dc667f0b6751b1d25a9c8c66152fd742529cd3d1b8f2fac2b6f4707f138c77b1d96f748ac95cdea3c0c22f6501976d5fff8e7a91412c39268e7138ca2d92c8167be641d69febdeee75e0d37e76cdb3ed2f7828b3ae7c949b1555db7721ba9e55fd48f709d5891629212f846072b9a255a6dfeb0ec7065f6e2c6580b874a7725a7d0a029d9a641768fef46cf";

const FIXTURE_FINGERPRINT: &str =
    "8aa0239a5d27b93ceff3317fcee8ef9ac59510685178e6f34d0f07decc075fc2";

fn output_of(args: &[&str]) -> std::process::Output {
    binary().args(args).output().expect("the binary runs")
}

fn stdout_of(args: &[&str]) -> String {
    let out = output_of(args);
    assert!(
        out.status.success(),
        "args {args:?} must succeed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

fn line_value<'a>(stdout: &'a str, key: &str) -> &'a str {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .unwrap_or_else(|| panic!("{key} missing from: {stdout}"))
        .trim()
}

#[test]
fn full_keygen_run_emits_the_canonical_shapes() {
    let out = binary()
        .arg("--diagnostic")
        .output()
        .expect("the binary runs");
    assert!(out.status.success(), "keygen must succeed");
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");

    let n_hex = line_value(&stdout, "rsw_modulus_n_hex=");
    assert_eq!(n_hex.len(), 512, "n is exactly 512 hex chars");
    assert!(n_hex
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    assert!(
        n_hex.starts_with(|c: char| ('8'..='f').contains(&c)),
        "the top nibble of a 2048-bit modulus is 8..f"
    );

    // Lambda is emitted as minimal hex: no leading zeros, so the
    // length is even when the top nibble reaches the fourth bit and
    // odd below it. The --check mode accepts both forms.
    let lambda_hex = line_value(&stdout, "rsw_lambda_hex=");
    assert!(lambda_hex
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    assert!(!lambda_hex.starts_with('0'), "the lambda hex is minimal");

    let fingerprint = line_value(&stdout, "rsw_modulus_n_sha256=");
    assert_eq!(fingerprint.len(), 64);
    assert!(fingerprint
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));

    // The primes appear only under --diagnostic.
    let p_hex = line_value(&stdout, "rsw_p_hex=");
    let q_hex = line_value(&stdout, "rsw_q_hex=");
    assert_eq!(p_hex.len(), 256, "a 1024-bit prime is 256 hex chars");
    assert_eq!(q_hex.len(), 256);
    assert_ne!(p_hex, q_hex);

    let plain = stdout_of(&[]);
    assert!(
        !plain.contains("rsw_p_hex="),
        "the default run never shows p"
    );
    assert!(
        !plain.contains("rsw_q_hex="),
        "the default run never shows q"
    );
    assert_eq!(line_value(&plain, "rsw_modulus_n_sha256=").len(), 64);
}

#[test]
fn generated_pair_passes_check_and_fingerprint() {
    let out = binary()
        .arg("--diagnostic")
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let n_hex = line_value(&stdout, "rsw_modulus_n_hex=");
    let lambda_hex = line_value(&stdout, "rsw_lambda_hex=");
    let fingerprint = line_value(&stdout, "rsw_modulus_n_sha256=");

    let checked = stdout_of(&["--check", n_hex, lambda_hex]);
    assert!(checked.contains("OK:"));
    assert_eq!(line_value(&checked, "rsw_modulus_n_sha256="), fingerprint);

    let fp = stdout_of(&["--fingerprint", n_hex]);
    assert_eq!(fp.trim(), fingerprint);
}

#[test]
fn fixture_pair_passes_check() {
    let out = output_of(&["--check", FIXTURE_N_HEX, FIXTURE_LAMBDA_HEX]);
    assert!(out.status.success(), "the fixture pair must pass --check");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        line_value(&stdout, "rsw_modulus_n_sha256="),
        FIXTURE_FINGERPRINT
    );

    let fp = stdout_of(&["--fingerprint", FIXTURE_N_HEX]);
    assert_eq!(fp.trim(), FIXTURE_FINGERPRINT);
}

#[test]
fn check_rejects_weak_material_with_explicit_reasons() {
    // Even n.
    let even_n = format!("{}0", &FIXTURE_N_HEX[..511]);
    let out = output_of(&["--check", &even_n, FIXTURE_LAMBDA_HEX]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.is_empty(), "reasons ride stdout: {stderr}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("REJECT: n is even"));

    // A modulus with a small prime factor: 3 * (2^2046 + 1), shaped
    // exactly like a genuine 2048-bit modulus.
    let weak_value = BigUint::from(3u8) * ((BigUint::from(1u8) << 2046usize) + BigUint::from(1u8));
    let weak = format!("{:x}", weak_value);
    assert_eq!(weak.len(), 512, "the weak modulus is 2048 bits");
    let out = output_of(&["--check", &weak, FIXTURE_LAMBDA_HEX]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("REJECT: n is divisible by the small prime 3"));

    // A probable-prime modulus.
    let out = output_of(&["--check", PROBABLE_PRIME_N_HEX, FIXTURE_LAMBDA_HEX]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("REJECT: n is a probable prime"));

    // A mismatched lambda (lambda - 2): even and correctly shaped,
    // but no longer a multiple of the Carmichael value.
    let shifted_lambda =
        BigUint::parse_bytes(FIXTURE_LAMBDA_HEX.as_bytes(), 16).unwrap() - BigUint::from(2u8);
    let lambda_minus_two = format!("{:x}", shifted_lambda);
    let out = output_of(&["--check", FIXTURE_N_HEX, &lambda_minus_two]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("REJECT: lambda is not a matching trapdoor"));
}

#[test]
fn usage_errors_exit_two() {
    let out = output_of(&["--check", "not-hex", "also-not-hex"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a malformed pair is a rejection"
    );
    let out = output_of(&["--bogus-flag"]);
    assert_eq!(out.status.code(), Some(2));
    let out = output_of(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
}
