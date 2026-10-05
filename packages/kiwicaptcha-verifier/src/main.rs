//! The sidecar binary entry: environment and argument parsing, then the
//! blocking serve loop. One process fronts one node's verifications.

use std::process::ExitCode;
use std::sync::Arc;

use kiwicaptcha_verifier::{parse_listen, serve, ListenAddr, SidecarState, DEFAULT_LISTEN};

const USAGE: &str = "kiwicaptcha-verifier — the language-neutral KiwiCaptcha verifier sidecar

Usage:
  kiwicaptcha-verifier [--listen ADDR] [--secret KEY] [--bearer TOKEN] [--scopes LIST]

Options:
  --listen ADDR    http://127.0.0.1:7371 (default) or unix:///path/to/socket
                   (env KIWI_LISTEN; loopback only — the sidecar is a localhost service)
  --secret KEY     the HMAC verification secret, 32 bytes recommended
                   (env KIWI_SECRET; required)
  --bearer TOKEN   the sidecar's own credential on /verify, /issue,
                   /metrics and /doctor, compared in constant time
                   (env KIWI_BEARER; absent = the loopback boundary is the auth)
  --scopes LIST    comma-separated allowed scope values (env KIWI_SCOPES;
                   default login)
  --help           this text
  --version        the crate version

Once running, any stack verifies a solved token with one local call:
  curl -s http://127.0.0.1:7371/verify \\
    -H 'content-type: application/json' \\
    -d '{\"token\":\"...\",\"scope\":\"login\"}'

The response is the provider siteverify JSON (success, challenge_ts,
hostname, action, cdata, error-codes) plus the additive kiwi-code core
wire code. GET /metrics, /healthz and /doctor expose the observability
plane. The process makes no outbound connections.
";

struct Args {
    listen: Option<String>,
    secret: Option<String>,
    bearer: Option<String>,
    scopes: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        listen: None,
        secret: None,
        bearer: None,
        scopes: None,
    };
    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        match flag.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("kiwicaptcha-verifier {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--listen" => {
                args.listen = Some(raw.next().ok_or("--listen needs a value".to_string())?);
            }
            "--secret" => {
                args.secret = Some(raw.next().ok_or("--secret needs a value".to_string())?);
            }
            "--bearer" => {
                args.bearer = Some(raw.next().ok_or("--bearer needs a value".to_string())?);
            }
            "--scopes" => {
                args.scopes = Some(raw.next().ok_or("--scopes needs a value".to_string())?);
            }
            other => return Err(format!("unknown argument: {other} (try --help)")),
        }
    }
    Ok(args)
}

fn env_or(flag: Option<String>, name: &str) -> Option<String> {
    flag.or_else(|| std::env::var(name).ok().filter(|v| !v.is_empty()))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(secret) = env_or(args.secret, "KIWI_SECRET") else {
        eprintln!(
            "kiwicaptcha-verifier: no secret configured (set KIWI_SECRET or pass --secret; try --help)"
        );
        return ExitCode::FAILURE;
    };
    let bearer = env_or(args.bearer, "KIWI_BEARER");
    let listen_raw =
        env_or(args.listen, "KIWI_LISTEN").unwrap_or_else(|| DEFAULT_LISTEN.to_string());
    let listen: ListenAddr = match parse_listen(&listen_raw) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };
    let scopes: Vec<String> = env_or(args.scopes, "KIWI_SCOPES")
        .map(|list| {
            list.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let state = Arc::new(SidecarState::new(secret, bearer, scopes, &listen_raw));
    let described = match &listen {
        ListenAddr::Http(addr) => format!("http://{addr}"),
        ListenAddr::Unix(path) => format!("unix://{}", path.display()),
    };
    println!(
        "kiwicaptcha-verifier listening on {described} (verify: POST /verify; metrics: GET /metrics; health: GET /healthz; doctor: GET /doctor)"
    );
    match serve(&listen, Arc::clone(&state)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            ExitCode::FAILURE
        }
    }
}
