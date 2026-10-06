//! The sidecar binary entry: environment and argument parsing, startup
//! validation in fail-fast order, then the blocking serve loop. One
//! process fronts one node's verifications.

use std::process::ExitCode;
use std::sync::Arc;

use kiwicaptcha_verifier::{
    open_store, parse_binding, parse_listen, parse_rung, parse_scopes, parse_store,
    parse_timeout_ms, parse_workers, validate_rsw_trapdoor, validate_secret, BindingConfig,
    ListenAddr, ServerOptions, SidecarConfig, SidecarState, DEFAULT_LISTEN, DEFAULT_PROFILE,
};

const USAGE: &str = "kiwicaptcha-verifier: the language-neutral KiwiCaptcha verifier sidecar

Usage:
  kiwicaptcha-verifier [--listen ADDR] [--secret KEY] [--bearer TOKEN]
                       [--scopes MAP] [--profile RUNG] [--store BACKEND]
                       [--workers N] [--timeout-ms MS] [--binding MODE]
                       [--risk] [--risk-url URL] [--risk-namespace NAME]
                       [--allow-no-remoteip]
                       [--allow-insecure-example-secret]

Options:
  --listen ADDR    http://127.0.0.1:7371 (default) or unix:///path/to/socket
                   (env KIWI_LISTEN; loopback only, the sidecar is a
                   localhost service)
  --secret KEY     the HMAC verification secret, at least 32 bytes,
                   generated locally (env KIWI_SECRET; required;
                   published example values are refused)
  --bearer TOKEN   the sidecar's own credential on /verify, /issue,
                   /metrics and /doctor, compared in constant time
                   (env KIWI_BEARER; absent = the loopback boundary is
                   the auth)
  --scopes MAP     comma-separated scope to rung pairs, each
                   \"scope=rung\" or a bare scope at the default rung;
                   rung names sha16, sha18, sha20, argon16, argon32,
                   argon64, rsw, and the value classes low, standard,
                   high, critical (env KIWI_SCOPES; default \"login\")
  --profile RUNG   the default rung for scopes without an explicit
                   entry (env KIWI_PROFILE; default sha18)
  --store BACKEND  memory (volatile, the default), file=DIR (durable,
                   atomic rename plus fsync, single node) or a redis://
                   URL (the core crate's fused verifier store; needs the
                   redis-store build feature) (env KIWI_STORE)
  --workers N      the bounded worker pool size, 1..=1024
                   (env KIWI_WORKERS; default 16)
  --timeout-ms MS  the per-connection read and write timeout, 1..=60000
                   (env KIWI_TIMEOUT_MS; default 5000)
  --binding MODE   bound (the default: challenges bind to remoteip and
                   both endpoints require it) or none
                   (env KIWI_BINDING)
  --risk           wire the adaptive risk plane (env KIWI_RISK=1);
                   requires --risk-url
  --risk-url URL   the Redis URL the risk state lives in
                   (env KIWI_RISK_URL)
  --risk-namespace NAME  the risk state namespace (env
                   KIWI_RISK_NAMESPACE; default sidecar)
  --allow-no-remoteip  development escape hatch: accept a missing
                   remoteip as loopback while binding is on (env
                   KIWI_ALLOW_NO_REMOTEIP=1)
  --allow-insecure-example-secret  development escape hatch: accept a
                   published example secret with a warning (env
                   KIWI_ALLOW_INSECURE_EXAMPLE_SECRET=1)
  --rsw-modulus B64, --rsw-lambda B64, --rsw-t N
                   the rsw time-lock trapdoor, required when any scope
                   maps to the rsw rung (env KIWI_RSW_MODULUS,
                   KIWI_RSW_LAMBDA, KIWI_RSW_T; generate with
                   tools/rsw-keygen)
  --help           this text
  --version        the crate version

Once running, any stack verifies a solved token with one local call:
  curl -s http://127.0.0.1:7371/verify \\
    -H 'content-type: application/json' \\
    -d '{\"token\":\"...\",\"scope\":\"login\",\"remoteip\":\"203.0.113.9\"}'

The response is the provider siteverify JSON (success, challenge_ts,
hostname, action, cdata, error-codes) plus the additive kiwi-code core
wire code. GET /metrics, /healthz and /doctor expose the observability
plane. The risk plane is optional: without it this binary runs with no
abuse-risk telemetry, which is the single-node small-site trade; the
bundle is the full plane.
";

struct Args {
    listen: Option<String>,
    secret: Option<String>,
    bearer: Option<String>,
    scopes: Option<String>,
    profile: Option<String>,
    store: Option<String>,
    workers: Option<String>,
    timeout_ms: Option<String>,
    binding: Option<String>,
    allow_no_remoteip: bool,
    risk: bool,
    risk_url: Option<String>,
    risk_namespace: Option<String>,
    allow_insecure_example_secret: bool,
    rsw_modulus: Option<String>,
    rsw_lambda: Option<String>,
    rsw_t: Option<String>,
    execution_key: Option<String>,
    execution_version: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        listen: None,
        secret: None,
        bearer: None,
        scopes: None,
        profile: None,
        store: None,
        workers: None,
        timeout_ms: None,
        binding: None,
        allow_no_remoteip: false,
        risk: false,
        risk_url: None,
        risk_namespace: None,
        allow_insecure_example_secret: false,
        rsw_modulus: None,
        rsw_lambda: None,
        rsw_t: None,
        execution_key: None,
        execution_version: None,
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
                args.listen = Some(raw.next().ok_or("--listen needs a value")?);
            }
            "--secret" => {
                args.secret = Some(raw.next().ok_or("--secret needs a value")?);
            }
            "--bearer" => {
                args.bearer = Some(raw.next().ok_or("--bearer needs a value")?);
            }
            "--scopes" => {
                args.scopes = Some(raw.next().ok_or("--scopes needs a value")?);
            }
            "--profile" => {
                args.profile = Some(raw.next().ok_or("--profile needs a value")?);
            }
            "--store" => {
                args.store = Some(raw.next().ok_or("--store needs a value")?);
            }
            "--workers" => {
                args.workers = Some(raw.next().ok_or("--workers needs a value")?);
            }
            "--timeout-ms" => {
                args.timeout_ms = Some(raw.next().ok_or("--timeout-ms needs a value")?);
            }
            "--binding" => {
                args.binding = Some(raw.next().ok_or("--binding needs a value")?);
            }
            "--allow-no-remoteip" => args.allow_no_remoteip = true,
            "--risk" => args.risk = true,
            "--risk-url" => {
                args.risk_url = Some(raw.next().ok_or("--risk-url needs a value")?);
            }
            "--risk-namespace" => {
                args.risk_namespace = Some(raw.next().ok_or("--risk-namespace needs a value")?);
            }
            "--allow-insecure-example-secret" => args.allow_insecure_example_secret = true,
            "--rsw-modulus" => {
                args.rsw_modulus = Some(raw.next().ok_or("--rsw-modulus needs a value")?);
            }
            "--rsw-lambda" => {
                args.rsw_lambda = Some(raw.next().ok_or("--rsw-lambda needs a value")?);
            }
            "--rsw-t" => {
                args.rsw_t = Some(raw.next().ok_or("--rsw-t needs a value")?);
            }
            "--execution-key" => {
                args.execution_key = Some(raw.next().ok_or("--execution-key needs a value")?);
            }
            "--execution-version" => {
                args.execution_version =
                    Some(raw.next().ok_or("--execution-version needs a value")?);
            }
            other => return Err(format!("unknown argument: {other} (try --help)")),
        }
    }
    Ok(args)
}

/// The value a flag carries, or the environment variable of the same
/// contract, or nothing.
fn env_or(flag: Option<String>, name: &str) -> Option<String> {
    flag.or_else(|| std::env::var(name).ok().filter(|v| !v.is_empty()))
}

fn env_flag(flag: bool, name: &str) -> bool {
    flag || std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn main() -> ExitCode {
    // The feature-gated cross-language test surface, dispatched before
    // any server state exists.
    #[cfg(feature = "test-fixtures")]
    {
        let raw: Vec<String> = std::env::args().skip(1).collect();
        if raw.first().map(String::as_str) == Some("exec-evidence") {
            return match exec_evidence::run(&raw[1..]) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("kiwicaptcha-verifier exec-evidence: {e}");
                    ExitCode::FAILURE
                }
            };
        }
    }
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };

    // 1. The secret, validated before any socket exists: the length
    //    floor and the published-example refusal, with the explicit
    //    development escape hatch.
    let Some(raw_secret) = env_or(args.secret, "KIWI_SECRET") else {
        eprintln!(
            "kiwicaptcha-verifier: no secret configured (set KIWI_SECRET or pass --secret; generate one with: openssl rand -base64 48; try --help)"
        );
        return ExitCode::FAILURE;
    };
    let allow_example = env_flag(
        args.allow_insecure_example_secret,
        "KIWI_ALLOW_INSECURE_EXAMPLE_SECRET",
    );
    let (secret, insecure_example) = match validate_secret(&raw_secret, allow_example) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };
    if insecure_example {
        eprintln!(
            "kiwicaptcha-verifier: WARNING the secret is a published example value, accepted only through the development escape hatch; never expose this process beyond loopback"
        );
    }

    // 2. Listen, profile, scopes, binding.
    let listen_raw =
        env_or(args.listen, "KIWI_LISTEN").unwrap_or_else(|| DEFAULT_LISTEN.to_string());
    let listen: ListenAddr = match parse_listen(&listen_raw) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };
    let default_rung = match env_or(args.profile, "KIWI_PROFILE")
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(parse_rung)
    {
        None => parse_rung(DEFAULT_PROFILE),
        Some(Ok(rung)) => Ok(rung),
        Some(Err(e)) => Err(e),
    };
    let default_rung = match default_rung {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };
    let plan = match parse_scopes(env_or(args.scopes, "KIWI_SCOPES").as_deref(), default_rung) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };
    let binding = match parse_binding(env_or(args.binding, "KIWI_BINDING").as_deref()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };
    let allow_no_remoteip = env_flag(args.allow_no_remoteip, "KIWI_ALLOW_NO_REMOTEIP");

    // 3. The rsw trapdoor when the plan needs it.
    let rsw = if kiwicaptcha_verifier::config::plan_needs_rsw(&plan) {
        match validate_rsw_trapdoor(
            env_or(args.rsw_modulus, "KIWI_RSW_MODULUS").as_deref(),
            env_or(args.rsw_lambda, "KIWI_RSW_LAMBDA").as_deref(),
            env_or(args.rsw_t, "KIWI_RSW_T").as_deref(),
        ) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("kiwicaptcha-verifier: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    // 4. The store backend.
    let store_config = match parse_store(env_or(args.store, "KIWI_STORE").as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };
    let store = match open_store(&store_config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };

    // 5. The optional risk plane: a Redis-backed state store is part of
    //    the contract (the engine's adaptive state has no other
    //    production backend).
    let risk_on = env_flag(args.risk, "KIWI_RISK");
    let risk = if risk_on {
        #[cfg(feature = "redis-store")]
        {
            let Some(url) = env_or(args.risk_url, "KIWI_RISK_URL") else {
                eprintln!(
                    "kiwicaptcha-verifier: the risk plane needs a Redis state store (pass --risk-url or set KIWI_RISK_URL)"
                );
                return ExitCode::FAILURE;
            };
            let namespace = env_or(args.risk_namespace, "KIWI_RISK_NAMESPACE")
                .unwrap_or_else(|| "sidecar".to_string());
            match kiwicaptcha_verifier::riskplane::connect_redis_plane(
                &url, &namespace, &plan, &secret,
            ) {
                Ok(plane) => Some(plane),
                Err(e) => {
                    eprintln!("kiwicaptcha-verifier: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        #[cfg(not(feature = "redis-store"))]
        {
            let _ = (&args.risk_url, &args.risk_namespace);
            eprintln!(
                "kiwicaptcha-verifier: KIWI_RISK=1 needs the redis-store build feature (rebuild with: cargo build --features redis-store); the risk plane's state store is Redis-backed"
            );
            return ExitCode::FAILURE;
        }
    } else {
        if let Some(url) = env_or(args.risk_url, "KIWI_RISK_URL") {
            let _ = url;
            eprintln!(
                "kiwicaptcha-verifier: note: KIWI_RISK_URL is set but the risk plane is off (set KIWI_RISK=1 to wire it)"
            );
        }
        None
    };

    // 6. The pool options.
    let workers = match parse_workers(env_or(args.workers, "KIWI_WORKERS").as_deref()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };
    let timeout = match parse_timeout_ms(env_or(args.timeout_ms, "KIWI_TIMEOUT_MS").as_deref()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The execution arming knobs: a key below the core's byte floor is
    // refused at startup, never silently disarmed, and the version must
    // sit inside the core's live grammar range.
    let execution_key = match env_or(args.execution_key, "KIWI_EXECUTION_KEY") {
        Some(key) => {
            if key.len() < kiwicaptcha::keys::MIN_EXECUTION_KEY_BYTES {
                eprintln!(
                    "kiwicaptcha-verifier: the execution key needs at least {} bytes",
                    kiwicaptcha::keys::MIN_EXECUTION_KEY_BYTES
                );
                return ExitCode::FAILURE;
            }
            Some(key)
        }
        None => None,
    };
    let execution_version = match env_or(args.execution_version, "KIWI_EXECUTION_VERSION") {
        Some(raw) => match raw.parse::<u8>() {
            Ok(v) if (1..=kiwicaptcha::execution::MAX_EXECUTION_VERSION).contains(&v) => v,
            _ => {
                eprintln!(
                    "kiwicaptcha-verifier: --execution-version must be 1..={}",
                    kiwicaptcha::execution::MAX_EXECUTION_VERSION
                );
                return ExitCode::FAILURE;
            }
        },
        None => 1,
    };

    let config = SidecarConfig {
        secret_key: secret,
        bearer: env_or(args.bearer, "KIWI_BEARER"),
        plan,
        listen_label: listen_raw.clone(),
        store,
        risk,
        binding,
        allow_no_remoteip,
        rsw,
        execution_key,
        execution_version,
    };
    let rungs: Vec<String> = config
        .plan
        .entries()
        .iter()
        .map(|(name, rung)| format!("{name}={}", rung.as_str()))
        .collect();
    let state = Arc::new(SidecarState::build(config));
    let store_label = match &store_config {
        kiwicaptcha_verifier::StoreConfig::Memory => "memory (volatile)".to_string(),
        kiwicaptcha_verifier::StoreConfig::File(path) => format!("file ({})", path.display()),
        kiwicaptcha_verifier::StoreConfig::Redis(url) => format!("redis ({url})"),
    };
    let binding_label = match binding {
        BindingConfig::Bound if allow_no_remoteip => "bound (loopback dev fallback)",
        BindingConfig::Bound => "bound (remoteip required)",
        BindingConfig::None => "none",
    };
    let risk_label = if risk_on {
        "on (adaptive)"
    } else {
        "off (no abuse-risk telemetry)"
    };
    let options = ServerOptions { workers, timeout };
    // Bind first so the startup line carries the real port (the
    // operator may pass port 0).
    let serve_result = match &listen {
        ListenAddr::Http(addr) => {
            let listener = match std::net::TcpListener::bind(*addr) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("kiwicaptcha-verifier: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let bound = listener
                .local_addr()
                .map(|a| format!("http://{a}"))
                .unwrap_or_else(|_| listen_raw.clone());
            println!(
                "kiwicaptcha-verifier listening on {bound} (store: {store_label}; binding: {binding_label}; risk: {risk_label}; workers: {workers}; timeout: {}ms)",
                timeout.as_millis()
            );
            println!("kiwicaptcha-verifier scopes: {}", rungs.join(", "));
            println!(
                "kiwicaptcha-verifier verify: POST /verify; issue: POST /issue; metrics: GET /metrics; health: GET /healthz; doctor: GET /doctor"
            );
            kiwicaptcha_verifier::serve_http_with(listener, state, options)
        }
        ListenAddr::Unix(path) => {
            println!(
                "kiwicaptcha-verifier listening on unix://{} (store: {store_label}; binding: {binding_label}; risk: {risk_label}; workers: {workers}; timeout: {}ms)",
                path.display(),
                timeout.as_millis()
            );
            println!("kiwicaptcha-verifier scopes: {}", rungs.join(", "));
            println!(
                "kiwicaptcha-verifier verify: POST /verify; issue: POST /issue; metrics: GET /metrics; health: GET /healthz; doctor: GET /doctor"
            );
            kiwicaptcha_verifier::serve_unix_with(path, state, options)
        }
    };
    match serve_result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kiwicaptcha-verifier: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The cross-language evidence helper behind the `test-fixtures`
/// feature: mints one execution-armed challenge exactly as the armed
/// issuance path does, optionally writes its pending envelope into a
/// sidecar file store, and prints the record wire JSON beside the
/// browser-equivalent executed trace and its digest. Test suites and
/// fixtures only: a production build never compiles this module, and
/// nothing in the serve loop reaches it.
#[cfg(feature = "test-fixtures")]
mod exec_evidence {
    use kiwicaptcha::challenge::{
        issue_challenge_with_execution, BindingMode, ChallengeConfig, PoWAlgorithm,
    };
    use kiwicaptcha::execution;

    pub fn run(args: &[String]) -> Result<(), String> {
        let mut secret: Option<String> = None;
        let mut scope = String::from("login");
        let mut action = String::from("default");
        let mut version: u8 = 1;
        let mut store_dir: Option<String> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--secret" => {
                    i += 1;
                    secret = Some(args.get(i).ok_or("--secret needs a value")?.clone());
                }
                "--scope" => {
                    i += 1;
                    scope = args.get(i).ok_or("--scope needs a value")?.clone();
                }
                "--action" => {
                    i += 1;
                    action = args.get(i).ok_or("--action needs a value")?.clone();
                }
                "--version" => {
                    i += 1;
                    version = args
                        .get(i)
                        .ok_or("--version needs a value")?
                        .parse::<u8>()
                        .map_err(|_| "--version must be 1..=MAX")?;
                }
                "--store-dir" => {
                    i += 1;
                    store_dir = Some(args.get(i).ok_or("--store-dir needs a value")?.clone());
                }
                other => return Err(format!("unknown argument: {other}")),
            }
            i += 1;
        }
        let secret = secret.ok_or("--secret is required (32 bytes or more)")?;
        if secret.len() < kiwicaptcha::keys::MIN_MASTER_BYTES {
            return Err(format!(
                "the secret needs at least {} bytes",
                kiwicaptcha::keys::MIN_MASTER_BYTES
            ));
        }

        let config = ChallengeConfig {
            secret_key: secret.clone(),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 8,
            argon2_target_bits: 8,
            ttl_secs: 240,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 8,
            binding_mode: BindingMode::None,
            policy_version: 1,
            region: None,
            issuer: None,
            kid: 1,
            execution_key: Some(secret.clone()),
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: 0,
            tenant: None,
        };
        let issued = issue_challenge_with_execution(
            &config,
            &scope,
            "",
            kiwicaptcha::challenge::now_epoch_micros() / 1_000_000,
            kiwicaptcha::challenge::now_epoch_micros(),
            0,
            None,
            true,
            Some(&action),
            Some(version),
            false,
        )
        .map_err(|e| e.to_string())?;
        let record = &issued.record;
        let program = record
            .execution_program
            .clone()
            .ok_or("the armed issuance produced no program")?;

        // The pending envelope into a sidecar file store, written by
        // the store's own code so the layout can never drift.
        if let Some(dir) = store_dir {
            use kiwicaptcha_verifier::RecordStore;
            let store = kiwicaptcha_verifier::FileStore::open(std::path::Path::new(&dir))?;
            store.put_pending(record, kiwicaptcha_verifier::RecordMeta::default())?;
        }

        // The browser-equivalent executed trace of the program and its
        // digest, the evidence a real driver would present.
        let decoded = execution::decode(&program).ok_or("the minted program does not decode")?;
        let trace = execution::fixtures::executed_trace_for(&decoded);
        let digest = execution::expected_digest_over_trace(&program, &record.nonce, &trace)
            .ok_or("the digest did not derive")?;
        // The wire trace is the canonical unpadded base64url of the
        // trace string, the form the token's evidence segment carries
        // and the verifier's strict decode accepts.
        const B64URL: base64::engine::GeneralPurpose =
            base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let trace_wire: String = B64URL.encode(trace.as_bytes());

        let record_json = serde_json::to_value(record).map_err(|e| e.to_string())?;
        let doc = serde_json::json!({
            "record": record_json,
            "program": program,
            "nonce": record.nonce,
            "trace": trace_wire,
            "digest": digest,
            "version": version,
        });
        println!("{doc}");
        Ok(())
    }
}
