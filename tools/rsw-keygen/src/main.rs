//! The rsw-keygen command line: generate a fresh KiwiCaptcha rsw
//! trapdoor pair, check an existing pair, or fingerprint a deployed
//! modulus.
//!
//! Exit codes: 0 on success (a checked pair is valid), 1 when a
//! generated pair fails its self-test or a checked pair is rejected,
//! 2 on usage or parse errors.

use rsw_keygen::{check_pair, fingerprint_of_hex, generate_pair, selftest, KeyPair};

fn usage() -> String {
    "rsw-keygen: first-party generator and checker for the KiwiCaptcha rsw trapdoor pair

USAGE:
  rsw-keygen [--diagnostic]                generate n and lambda (default)
  rsw-keygen --check N_HEX LAMBDA_HEX      reject weak or inconsistent pairs
  rsw-keygen --fingerprint N_HEX           print the sha256 of the canonical n
  rsw-keygen --help

A fresh pair is self-tested against the shipped trapdoor math before
anything is emitted; the primes p and q appear only under --diagnostic.
Both hex values are lowercase: n is exactly 512 chars, lambda is the
minimal form without leading zeros."
        .to_string()
}

fn emit(pair: &KeyPair, diagnostic: bool) {
    println!("rsw_modulus_n_hex={}", pair.n_hex());
    println!("rsw_modulus_n_base64={}", pair.n_base64());
    println!("rsw_lambda_hex={}", pair.lambda_hex());
    println!("rsw_lambda_base64={}", pair.lambda_base64());
    println!("rsw_modulus_n_sha256={}", pair.fingerprint_hex());
    if diagnostic {
        println!("rsw_p_hex={}", pair.p_hex());
        println!("rsw_q_hex={}", pair.q_hex());
    }
}

fn run_generate(diagnostic: bool) -> i32 {
    match generate_pair() {
        Err(message) => {
            eprintln!("rsw-keygen: {message}");
            1
        }
        Ok(pair) => match selftest(&pair) {
            Err(message) => {
                eprintln!("rsw-keygen: {message}");
                eprintln!("rsw-keygen: no key material was emitted");
                1
            }
            Ok(()) => {
                emit(&pair, diagnostic);
                0
            }
        },
    }
}

fn run_check(n_hex: &str, lambda_hex: &str) -> i32 {
    let reasons = check_pair(n_hex, lambda_hex);
    if reasons.is_empty() {
        println!("OK: the pair passes the shipped rsw validation");
        if let Ok(fingerprint) = fingerprint_of_hex(n_hex) {
            println!("rsw_modulus_n_sha256={fingerprint}");
        }
        return 0;
    }
    for reason in &reasons {
        println!("REJECT: {reason}");
    }
    1
}

fn run_fingerprint(n_hex: &str) -> i32 {
    match fingerprint_of_hex(n_hex) {
        Ok(fingerprint) => {
            println!("{fingerprint}");
            0
        }
        Err(message) => {
            eprintln!("rsw-keygen: {message}");
            2
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => {
            println!("{}", usage());
            0
        }
        [flag] if flag == "--diagnostic" => run_generate(true),
        [] => run_generate(false),
        [flag, n_hex, lambda_hex] if flag == "--check" => run_check(n_hex, lambda_hex),
        [flag, n_hex] if flag == "--fingerprint" => run_fingerprint(n_hex),
        _ => {
            eprintln!("rsw-keygen: unrecognized arguments");
            eprintln!("{}", usage());
            2
        }
    };
    std::process::exit(code);
}
