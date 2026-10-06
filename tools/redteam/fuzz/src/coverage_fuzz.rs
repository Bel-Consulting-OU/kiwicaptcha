//! coverage_fuzz.rs — the local coverage-guided substitute for the
//! D4.1 row when cargo-fuzz/libfuzzer cannot build in this
//! environment (no network for libfuzzer-sys). It executes the same
//! no-panic property over the same parse surfaces as the cargo-fuzz
//! targets (SolutionToken::decode, ChallengeRecord deserialization)
//! with a coverage feedback loop: the "coverage" signal is the
//! distinct parse-outcome signature (error discriminant / Ok shape)
//! of each input, and the corpus grows whenever a mutation hits a
//! signature never seen before. Panics abort the run with a nonzero
//! exit and a machine-readable CRASH line — never a quiet pass.
//!
//! Scale honesty: the run is bounded by --runs (the gate records the
//! measured n). The specification's 24 h budget is the CI job's; this
//! substitute is explicitly a reduced-scale local check.

use kiwicaptcha::challenge::ChallengeRecord;
use kiwicaptcha::token::SolutionToken;
use std::collections::HashSet;
use std::env;
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn signature_of(data: &[u8]) -> String {
    let mut sig = String::new();
    match std::str::from_utf8(data) {
        Ok(s) => match SolutionToken::decode(s) {
            Ok(_) => sig.push_str("token:ok"),
            Err(e) => sig.push_str(&format!("token:err:{:?}", std::mem::discriminant(&e))),
        },
        Err(_) => {
            let lossy = String::from_utf8_lossy(data);
            match SolutionToken::decode(&lossy) {
                Ok(_) => sig.push_str("token:lossy:ok"),
                Err(e) => sig.push_str(&format!("token:lossy:err:{:?}", std::mem::discriminant(&e))),
            }
        }
    }
    match serde_json::from_slice::<ChallengeRecord>(data) {
        Ok(_) => sig.push_str("|record:ok"),
        Err(e) => {
            // The error class (syntax vs data vs eof) is the coverage
            // edge; the absolute column is noise.
            let class = if e.is_syntax() {
                "syntax"
            } else if e.is_data() {
                "data"
            } else if e.is_eof() {
                "eof"
            } else {
                "other"
            };
            sig.push_str(&format!("|record:err:{class}"));
        }
    }
    sig
}

fn mutate(seed: u64, parent: &[u8], out: &mut Vec<u8>) {
    // A deterministic xorshift mutator: byte flip, byte insert, byte
    // delete, and a splice of two corpus entries' tails. Seeded from
    // the run seed so the campaign is reproducible.
    let mut state = seed | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    out.clear();
    out.extend_from_slice(parent);
    if out.is_empty() {
        out.push((next() & 0xff) as u8);
        return;
    }
    let op = next() % 4;
    let idx = (next() as usize) % out.len();
    match op {
        0 => out[idx] ^= 0xff,
        1 => out[idx] = (next() & 0xff) as u8,
        2 => {
            if out.len() > 1 {
                out.remove(idx);
            }
        }
        _ => {
            out.insert(idx, (next() & 0xff) as u8);
        }
    }
    // Occasional length churn so parse paths see short and long docs.
    if next() % 5 == 0 {
        let keep = 1 + (next() as usize) % out.len().max(1);
        out.truncate(keep);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut runs: usize = 10_000;
    let mut seed: u64 = 0x6b77_6d74;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--runs" => {
                i += 1;
                runs = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(runs);
            }
            "--seed" => {
                i += 1;
                seed = args
                    .get(i)
                    .and_then(|v| v.trim_start_matches("0x").parse().ok())
                    .unwrap_or(seed);
            }
            _ => {}
        }
        i += 1;
    }

    let mut corpus: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"x".to_vec(),
        b"{}".to_vec(),
        br#"{"nonce":"n","counter":1,"duration_ms":1,"telemetry":{}}"#.to_vec(),
        br#"{"nonce":"a","kid":1,"scope":"login","issued_at_ns":1,"attempts_used":0,"algorithm":"sha256","target_bits":4,"ttl_secs":1,"policy_version":1,"binding_mode":"bound"}"#.to_vec(),
        (0u8..=255).collect(),
    ];
    let mut seen: HashSet<String> = HashSet::new();
    for entry in &corpus {
        seen.insert(signature_of(entry));
    }

    let mut executed = 0usize;
    let mut crashes = 0usize;
    let mut unique_edges = seen.len();
    let mut child = Vec::new();
    let mut rng = seed;
    while executed < runs {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let parent = &corpus[(rng as usize) % corpus.len()];
        mutate(rng, parent, &mut child);
        let outcome = catch_unwind(AssertUnwindSafe(|| signature_of(&child)));
        executed += 1;
        match outcome {
            Ok(sig) => {
                if seen.insert(sig) {
                    unique_edges += 1;
                    corpus.push(child.clone());
                }
            }
            Err(_) => {
                crashes += 1;
                let hex: String = child.iter().map(|b| format!("{:02x}", b)).collect();
                println!("CRASH: panic on input {hex}");
                let _ = std::io::stdout().flush();
                std::process::exit(1);
            }
        }
    }

    println!(
        "COVERAGE-FUZZ: substitute=local-no-libfuzzer runs={} corpus={} unique_parse_signatures={} crashes={} (cargo-fuzz/libfuzzer-sys unavailable: offline; same no-panic property over SolutionToken::decode and ChallengeRecord)",
        executed,
        corpus.len(),
        unique_edges,
        crashes
    );
    if crashes == 0 {
        std::process::exit(0);
    }
    std::process::exit(1);
}
