//! The kiwicaptcha-solver CLI: the supported automation path.
//!
//! It walks the documented JSON flow against a deployment's own endpoints:
//! fetch the challenge, perform the proof of work at the browser's price
//! (the same caps the widget enforces), and post the token to the verify
//! endpoint when a siteverify secret is supplied. Without a secret it
//! solves and prints the token for the caller to carry in the protected
//! form POST, exactly like the widget does.
//!
//! Exit codes: 0 verified (or solved, in the no-secret mode), 1 refused or
//! rejected (the server's error codes are printed), 2 usage or transport
//! errors. Progress goes to stderr; the machine-readable result is one
//! JSON object on stdout.

use kiwicaptcha_solver::bench::{
    ladder, parse_reference_costs, render_dollars, render_measurements, render_references,
    render_verdicts, run_rung, value_class_verdicts, BenchError, DEFAULT_SAMPLES, DEFAULT_SEED,
    EMBEDDED_REFERENCE_COSTS,
};
use kiwicaptcha_solver::http::post_json;
use kiwicaptcha_solver::{solve, CancellationToken, Challenge, SolveOptions};
use std::process::ExitCode;

/// The top-level help: the flow, the price, and the honest rationale.
const USAGE: &str = "\
kiwicaptcha-solver — the supported automation path at the browser's price

Solver secrecy was never part of KiwiCaptcha's model, and well-behaved
unauthenticated automation deserves a supported tool instead of a scraped
widget. This CLI pays exactly what a browser pays: the same caps (at most
20,000,000 hashes, at most 20 target bits for SHA-256, 10 for Argon2id,
64 MiB of Argon2id memory, the protocol rsw bounds), the same challenge
JSON, and the same wire token. No telemetry is claimed: a native client
has no browser signals, and the verifier never gates on telemetry alone.

Usage:
  kiwicaptcha-solver challenge --endpoint URL --scope SCOPE
                              [--algorithm sha256|argon2id|rsw]
                              [--header \"Name: value\"]...
  kiwicaptcha-solver solve --endpoint URL --scope SCOPE
                           [--algorithm sha256|argon2id|rsw]
                           [--header \"Name: value\"]...
                           [--verify-endpoint URL] [--secret SECRET]
                           [--remoteip IP] [--max-hashes N]
                           [--progress-interval N]
  kiwicaptcha-solver bench  [--samples N] [--seed N] [--rungs LIST]
                           [--rsw-t T] [--reference-costs PATH]

The challenge endpoint is the widget's own route (an HTTP POST carrying
{\"scope\": ...} JSON); --endpoint is its absolute http:// URL. The verify
endpoint defaults to the same prefix with /siteverify in place of
/challenge, or set it explicitly with --verify-endpoint. The verify body is
the provider-shaped {\"secret\", \"response\", \"remoteip\"} document the
symfony /siteverify route documents; pass --secret to verify end to end,
or omit it to solve only and print the token for the protected form POST.
https:// endpoints are unsupported by the std-only client: pipe them
through a local plaintext proxy or a CONNECT tunnel.

bench measures the native attacker cost of every difficulty-ladder rung
(sha16, sha18, sha20, argon16, argon32, argon64, rsw) on this CPU: it
solves N instances per rung (default 50, times are single-threaded wall
time) and prints the rung table, the published hardware reference
classes from reference-costs.json with their provenance, the dollar
cost per 1000 solves, and a doctor-style verdict per value class.
--rungs filters the ladder (a comma list); --rsw-t overrides the rsw
squaring count inside the protocol bounds; --reference-costs loads a
refreshed table over the embedded copy. Expect the default run to take
a minute or two on a laptop: the higher sha rungs alone are 50 expected
million-hash searches.

Exit codes: 0 verified (or solved with no --secret), 1 refused/rejected
(the server's error codes print on stdout), 2 usage or transport error.";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        None | Some("-h") | Some("--help") | Some("help") => {
            println!("{USAGE}");
            if argv.is_empty() {
                eprintln!("no subcommand given; run with --help for usage");
                return exit_code(2);
            }
            exit_code(0)
        }
        Some("-V") | Some("--version") => {
            println!(
                "kiwicaptcha-solver {} (protocol caps: {} hashes, sha {} bits, argon2id {} bits)",
                env!("CARGO_PKG_VERSION"),
                kiwicaptcha_solver::SOLVER_MAX_HASHES,
                kiwicaptcha_solver::SOLVER_MAX_TARGET_BITS,
                kiwicaptcha_solver::SOLVER_MAX_ARGON2_TARGET_BITS
            );
            exit_code(0)
        }
        Some("challenge") => run_challenge(&argv[1..]),
        Some("solve") => run_solve(&argv[1..]),
        Some("bench") => run_bench(&argv[1..]),
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            eprintln!("run with --help for usage");
            exit_code(2)
        }
    }
}

/// Map a bool to the process exit code with stdout flushed first.
fn exit_code(code: u8) -> ExitCode {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    ExitCode::from(code)
}

/// One parsed `--name value` (or flag-less) option.
struct Options {
    endpoint: Option<String>,
    scope: Option<String>,
    algorithm: Option<String>,
    verify_endpoint: Option<String>,
    secret: Option<String>,
    remoteip: Option<String>,
    max_hashes: Option<u64>,
    progress_interval: Option<u64>,
    headers: Vec<(String, String)>,
}

impl Options {
    fn new() -> Self {
        Options {
            endpoint: None,
            scope: None,
            algorithm: None,
            verify_endpoint: None,
            secret: None,
            remoteip: None,
            max_hashes: None,
            progress_interval: None,
            headers: Vec::new(),
        }
    }
}

/// Parse `--name value` pairs. `value_flags` names the options that take a
/// value; --header may repeat; everything else must appear at most once.
fn parse_options(args: &[String], value_flags: &[&str]) -> Result<Options, String> {
    let mut opts = Options::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let Some(name) = arg.strip_prefix("--") else {
            return Err(format!("unexpected argument: {arg}"));
        };
        if !value_flags.contains(&name) {
            return Err(format!("unknown option: {arg}"));
        }
        let Some(value) = args.get(i + 1) else {
            return Err(format!("option {arg} needs a value"));
        };
        match name {
            "endpoint" => set_once(&mut opts.endpoint, value)?,
            "scope" => set_once(&mut opts.scope, value)?,
            "algorithm" => set_once(&mut opts.algorithm, value)?,
            "verify-endpoint" => set_once(&mut opts.verify_endpoint, value)?,
            "secret" => set_once(&mut opts.secret, value)?,
            "remoteip" => set_once(&mut opts.remoteip, value)?,
            "max-hashes" => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("--max-hashes needs a number: {value}"))?;
                set_once(&mut opts.max_hashes, &parsed)?
            }
            "progress-interval" => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("--progress-interval needs a number: {value}"))?;
                set_once(&mut opts.progress_interval, &parsed)?
            }
            "header" => {
                let (head, tail) = value
                    .split_once(':')
                    .ok_or_else(|| format!("--header needs \"Name: value\", got: {value}"))?;
                let head = head.trim().to_string();
                if head.is_empty() {
                    return Err(format!("--header needs a name: {value}"));
                }
                opts.headers.push((head, tail.trim_start().to_string()));
            }
            _ => unreachable!("the value_flags gate already filtered the name"),
        }
        i += 2;
    }
    Ok(opts)
}

fn set_once<T>(slot: &mut Option<T>, value: &T) -> Result<(), String>
where
    T: Clone,
{
    if slot.is_some() {
        return Err("an option was given twice".to_string());
    }
    *slot = Some(value.clone());
    Ok(())
}

/// `kiwicaptcha-solver challenge`: fetch and print the raw challenge JSON.
fn run_challenge(args: &[String]) -> ExitCode {
    let opts = match parse_options(args, &["endpoint", "scope", "algorithm", "header"]) {
        Ok(o) => o,
        Err(err) => {
            eprintln!("usage error: {err}");
            return exit_code(2);
        }
    };
    let (Some(endpoint), Some(scope)) = (opts.endpoint.as_deref(), opts.scope.as_deref()) else {
        eprintln!("usage error: --endpoint and --scope are required");
        return exit_code(2);
    };
    let body = challenge_request_body(scope, opts.algorithm.as_deref());
    let response = match post_json(endpoint, &body, &opts.headers) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("challenge fetch failed: {err}");
            return exit_code(2);
        }
    };
    let text = String::from_utf8_lossy(&response.body);
    println!("{text}");
    if (200..300).contains(&response.status) {
        exit_code(0)
    } else {
        eprintln!("challenge endpoint answered HTTP {}", response.status);
        exit_code(1)
    }
}

/// `kiwicaptcha-solver solve`: fetch, solve, optionally verify, print JSON.
fn run_solve(args: &[String]) -> ExitCode {
    let opts = match parse_options(
        args,
        &[
            "endpoint",
            "scope",
            "algorithm",
            "header",
            "verify-endpoint",
            "secret",
            "remoteip",
            "max-hashes",
            "progress-interval",
        ],
    ) {
        Ok(o) => o,
        Err(err) => {
            eprintln!("usage error: {err}");
            return exit_code(2);
        }
    };
    let (Some(endpoint), Some(scope)) = (opts.endpoint.as_deref(), opts.scope.as_deref()) else {
        eprintln!("usage error: --endpoint and --scope are required");
        return exit_code(2);
    };

    // 1. Fetch the challenge (the widget's own JSON flow).
    let body = challenge_request_body(scope, opts.algorithm.as_deref());
    let response = match post_json(endpoint, &body, &opts.headers) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("challenge fetch failed: {err}");
            return exit_code(2);
        }
    };
    if !(200..300).contains(&response.status) {
        println!("{}", String::from_utf8_lossy(&response.body));
        eprintln!("challenge endpoint answered HTTP {}", response.status);
        return exit_code(1);
    }
    let raw = match String::from_utf8(response.body) {
        Ok(text) => text,
        Err(_) => {
            eprintln!("challenge response is not UTF-8");
            return exit_code(2);
        }
    };
    let challenge = match Challenge::from_json(&raw) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("challenge content failure: {err}");
            return exit_code(2);
        }
    };
    eprintln!(
        "challenge algorithm={} target_bits={} t={} m_kib={}",
        challenge.algorithm.as_str(),
        challenge.target_bits,
        challenge.t,
        challenge.m_kib
    );

    // 2. Solve at the browser's price.
    let cancel = CancellationToken::new();
    let mut options = SolveOptions {
        max_hashes: opts.max_hashes.unwrap_or(0),
        progress_interval: opts.progress_interval.unwrap_or(0),
        cancel: Some(&cancel),
        on_progress: None,
    };
    let solution = {
        // A scoped borrow so the solution outlives the closure.
        let mut on_progress = |event: kiwicaptcha_solver::ProgressEvent| {
            eprintln!("at {}", event.attempted);
        };
        options.on_progress = Some(&mut on_progress);
        match solve(&challenge, &mut options) {
            Ok(s) => s,
            Err(err) => {
                let code = refusal_code(&err);
                eprintln!("solve failed: {err}");
                match code {
                    None => return exit_code(2),
                    Some(code) => {
                        println!(
                            "{}",
                            serde_json::json!({
                                "solved": false,
                                "verified": null,
                                "error-codes": [code],
                            })
                        );
                        return exit_code(1);
                    }
                }
            }
        }
    };
    eprintln!(
        "found counter={} hashes={} duration_ms={}",
        solution.counter, solution.hashes, solution.duration_ms
    );
    let token = solution.token(&challenge);

    // 3. Verify when a secret is given; otherwise the token is the result.
    let (verified, error_codes) = match opts.secret.as_deref() {
        None => (None, Vec::new()),
        Some(secret) => {
            let verify_url = match opts
                .verify_endpoint
                .clone()
                .or_else(|| derive_verify_endpoint(endpoint))
            {
                Some(url) => url,
                None => {
                    eprintln!(
                        "usage error: --endpoint does not end in /challenge, so --verify-endpoint is required"
                    );
                    return exit_code(2);
                }
            };
            let body = kiwicaptcha_solver::verify_endpoint_request(
                secret,
                &token,
                opts.remoteip.as_deref(),
            );
            let response = match post_json(&verify_url, &body, &opts.headers) {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("verify request failed: {err}");
                    return exit_code(2);
                }
            };
            let parsed: serde_json::Value = match serde_json::from_slice(&response.body) {
                Ok(v) => v,
                Err(_) => {
                    println!("{}", String::from_utf8_lossy(&response.body));
                    eprintln!("verify endpoint answered non-JSON HTTP {}", response.status);
                    return exit_code(1);
                }
            };
            let success = parsed
                .get("success")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let codes = parsed
                .get("error-codes")
                .and_then(serde_json::Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(|c| c.as_str().map(str::to_string))
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default();
            (Some(success), codes)
        }
    };

    println!(
        "{}",
        serde_json::json!({
            "solved": true,
            "verified": verified,
            "error-codes": error_codes,
            "nonce": challenge.nonce,
            "token": token,
            "counter": solution.counter,
            "hashes": solution.hashes,
            "duration_ms": solution.duration_ms,
        })
    );
    match verified {
        Some(true) | None => exit_code(0),
        Some(false) => exit_code(1),
    }
}

/// `kiwicaptcha-solver bench`: measure the ladder rungs on this CPU,
/// print the tables and verdicts. No network is touched.
fn run_bench(args: &[String]) -> ExitCode {
    let mut samples = DEFAULT_SAMPLES;
    let mut seed = DEFAULT_SEED;
    let mut rungs: Option<Vec<String>> = None;
    let mut rsw_t = kiwicaptcha::challenge::DEFAULT_RSW_T;
    let mut reference_path: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let Some(value) = args.get(i + 1) else {
            eprintln!("usage error: option {arg} needs a value");
            return exit_code(2);
        };
        match arg.as_str() {
            "--samples" => match value.parse::<u32>() {
                Ok(n) if n >= 1 => samples = n,
                _ => {
                    eprintln!("usage error: --samples needs a number >= 1, got {value}");
                    return exit_code(2);
                }
            },
            "--seed" => match value.parse::<u64>() {
                Ok(n) => seed = n,
                _ => {
                    eprintln!("usage error: --seed needs a number, got {value}");
                    return exit_code(2);
                }
            },
            "--rsw-t" => match value.parse::<u32>() {
                Ok(n) => rsw_t = n,
                _ => {
                    eprintln!("usage error: --rsw-t needs a number, got {value}");
                    return exit_code(2);
                }
            },
            "--rungs" => {
                let list: Vec<String> = value
                    .split(',')
                    .map(str::trim)
                    .map(str::to_string)
                    .collect();
                if list.is_empty() || list.iter().any(String::is_empty) {
                    eprintln!("usage error: --rungs needs a comma list of rung names");
                    return exit_code(2);
                }
                rungs = Some(list);
            }
            "--reference-costs" => reference_path = Some(value),
            other => {
                eprintln!("usage error: unknown bench option {other}");
                return exit_code(2);
            }
        }
        i += 2;
    }

    // The reference table: the embedded copy, or a refreshed file.
    let table_raw = match reference_path {
        None => EMBEDDED_REFERENCE_COSTS.to_string(),
        Some(path) => match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) => {
                eprintln!("usage error: cannot read the reference-costs file {path}: {err}");
                return exit_code(2);
            }
        },
    };
    let table = match parse_reference_costs(&table_raw) {
        Ok(table) => table,
        Err(err) => {
            eprintln!("usage error: {err}");
            return exit_code(2);
        }
    };

    // The ladder, filtered and rsw-adjusted.
    let mut specs = ladder();
    if let Some(wanted) = &rungs {
        for name in wanted {
            if !specs.iter().any(|spec| spec.name == *name) {
                eprintln!("usage error: {}", BenchError::UnknownRung(name.clone()));
                return exit_code(2);
            }
        }
        specs.retain(|spec| wanted.iter().any(|name| *name == spec.name));
    }
    // The rsw squaring count is refused before any work is spent, the
    // same discipline the solver's own contract checks apply.
    if !(kiwicaptcha::challenge::MIN_RSW_T..=kiwicaptcha::challenge::MAX_RSW_T).contains(&rsw_t) {
        eprintln!(
            "usage error: {}",
            BenchError::RswTOutOfBounds(
                rsw_t,
                kiwicaptcha::challenge::MIN_RSW_T,
                kiwicaptcha::challenge::MAX_RSW_T
            )
        );
        return exit_code(2);
    }
    for spec in &mut specs {
        if spec.algorithm == kiwicaptcha::PoWAlgorithm::Rsw {
            spec.t = rsw_t;
        }
    }

    eprintln!(
        "bench: {} rungs x {} samples on this CPU (single-threaded, seed {}, times in microseconds)",
        specs.len(),
        samples,
        seed
    );
    let mut measurements = Vec::with_capacity(specs.len());
    for spec in &specs {
        eprintln!("  measuring {} ...", spec.name);
        match run_rung(spec, samples, seed) {
            Ok(measurement) => measurements.push(measurement),
            Err(err) => {
                eprintln!("bench failed: {err}");
                return exit_code(2);
            }
        }
    }

    println!(
        "kiwicaptcha-solver bench — native attacker cost per ladder rung, measured on this CPU"
    );
    println!();
    print!("{}", render_measurements(&measurements));
    println!();
    print!("{}", render_references(&table));
    println!();
    print!("{}", render_dollars(&measurements, &table));
    println!();
    print!(
        "{}",
        render_verdicts(&value_class_verdicts(&measurements, &table))
    );
    exit_code(0)
}

/// The refusal code a solve error prints, or None when the failure is a
/// usage-class error instead (a caller's bad option, a malformed
/// document): refusals exit 1, usage and transport exit 2.
fn refusal_code(err: &kiwicaptcha_solver::SolveError) -> Option<&'static str> {
    use kiwicaptcha_solver::SolveError;
    match err {
        SolveError::MalformedChallenge(_) => None,
        SolveError::CapTooLarge { .. } => None,
        SolveError::DifficultyBeyondCap { .. } => Some("difficulty-beyond-solver-cap"),
        SolveError::UnsupportedArgon2Params { .. } => Some("unsupported-argon2-params"),
        SolveError::UnsupportedRswParams(_) => Some("unsupported-rsw-params"),
        SolveError::ExecutionUnsupported => Some("execution-unsupported"),
        SolveError::Exhausted { .. } => Some("exhausted"),
        SolveError::Cancelled { .. } => Some("cancelled"),
    }
}

/// The challenge POST body: the scope always, the algorithm only when a
/// non-default profile is requested (the widget's own body grammar).
fn challenge_request_body(scope: &str, algorithm: Option<&str>) -> String {
    match algorithm {
        None => serde_json::json!({ "scope": scope }).to_string(),
        Some(alg) => serde_json::json!({ "scope": scope, "algorithm": alg }).to_string(),
    }
}

/// Derive the default verify endpoint: the challenge URL with the trailing
/// /challenge segment replaced by /siteverify, the bundle's own route
/// layout. None when the challenge endpoint does not end in /challenge.
fn derive_verify_endpoint(endpoint: &str) -> Option<String> {
    let suffix = "/challenge";
    let stem = endpoint.strip_suffix(suffix)?;
    Some(format!("{stem}/siteverify"))
}
