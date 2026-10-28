//! Sidecar configuration: the challenge rungs, the scope plan, the store
//! selection, the server limits and the secret policy.
//!
//! Every knob parses through a typed, unit-tested function here, so the
//! binary's startup path only wires validated values. A malformed knob is
//! a startup refusal with an actionable message, never a silent default.

use std::path::PathBuf;
use std::time::Duration;

use kiwicaptcha::challenge::{
    PoWAlgorithm, DEFAULT_RSW_T, MAX_RSW_T, MIN_RSW_T, RSW_TARGET_BITS_PIN,
};
use kiwicaptcha::profile::ChallengeProfile;

/// The HMAC secret floor, byte-identical to the core crate's
/// `kiwicaptcha::keys::MIN_MASTER_BYTES` and the PHP bundle's
/// `Config::MIN_SECRET_BYTES`. A shorter secret cannot even derive the
/// purpose keys, so it is refused before the socket opens.
pub const MIN_SECRET_BYTES: usize = kiwicaptcha::keys::MIN_MASTER_BYTES;

/// The shipped live-pending-challenge ceiling: about 833 issues/s at a
/// 120 s TTL before issuance refuses with `challenge_store_full`. TTL
/// bounds age, not cardinality, so the generic store needs its own
/// bound; `--max-pending-challenges` / `KIWI_MAX_PENDING_CHALLENGES`
/// raise it (0 disables the ceiling explicitly).
pub const DEFAULT_MAX_PENDING_CHALLENGES: u64 = 100_000;

/// The default total-live-record ceiling (pending + consumed
/// tombstones): four times the pending bound, so the default pending
/// window can be fully burned (every pending record consumed into a
/// tombstone) without hitting the total bound, while a
/// burn-and-reissue churn is still capped at a fixed multiple of the
/// pending window until records expire. `--max-live-records` /
/// `KIWI_MAX_LIVE_RECORDS` raise it (0 disables the ceiling
/// explicitly; when both ceilings are on, a total bound below the
/// pending bound is refused at startup).
pub const DEFAULT_MAX_LIVE_RECORDS: u64 = 400_000;

/// The placeholder secret the documentation shows. It is a label, not a
/// credential: startup refuses it unless the operator passes the explicit
/// development escape hatch.
pub const EXAMPLE_SECRET: &str = "change-me-32-bytes-of-random-entropy";

/// Secrets that appear in published examples and must never guard a real
/// deployment. Each exact value is refused at startup unless
/// `KIWI_ALLOW_INSECURE_EXAMPLE_SECRET=1` is set (which prints a warning).
pub const EXAMPLE_SECRETS: [&str; 2] = ["0123456789abcdef0123456789abcdef", EXAMPLE_SECRET];

/// Secret prefixes that mark a placeholder: any secret starting with one
/// is an example value by construction (every "change-me-*" string is a
/// label an operator was meant to replace, never a credential). Refused
/// exactly like the exact list above.
pub const EXAMPLE_SECRET_PREFIXES: [&str; 1] = ["change-me-"];

/// Whether a secret is a published example: an exact [`EXAMPLE_SECRETS`]
/// entry or a value carrying an [`EXAMPLE_SECRET_PREFIXES`] prefix.
pub fn is_example_secret(raw: &str) -> bool {
    EXAMPLE_SECRETS.contains(&raw)
        || EXAMPLE_SECRET_PREFIXES
            .iter()
            .any(|prefix| raw.starts_with(prefix))
}

/// The default listen address: loopback only.
pub const DEFAULT_LISTEN: &str = "http://127.0.0.1:7371";

/// The default challenge rung: SHA-256 at 18 leading zero bits, the
/// bundle's balanced-profile difficulty.
pub const DEFAULT_PROFILE: &str = "sha18";

/// The default worker count for the connection pool.
pub const DEFAULT_WORKERS: usize = 16;

/// The default per-connection read and write timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// The largest request body the reader accepts. A solution token is a few
/// hundred bytes; anything near this bound is misuse or an attack.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// The maximum request line plus header block the reader buffers.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The challenge lifetime in seconds (the bundle's balanced default, well
/// inside the protocol's 300 s cap).
pub const CHALLENGE_TTL_SECS: u64 = 120;

/// A challenge rung: one entry of the risk ladder plus the rsw time-lock
/// surface. The names match the risk engine's action vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    Sha16,
    Sha18,
    Sha20,
    Argon16,
    Argon32,
    Argon64,
    Rsw,
}

impl Rung {
    /// The wire name of the rung (the risk action vocabulary; `rsw` is
    /// the sidecar's own name for the time-lock surface).
    pub fn as_str(self) -> &'static str {
        match self {
            Rung::Sha16 => "sha16",
            Rung::Sha18 => "sha18",
            Rung::Sha20 => "sha20",
            Rung::Argon16 => "argon16",
            Rung::Argon32 => "argon32",
            Rung::Argon64 => "argon64",
            Rung::Rsw => "rsw",
        }
    }

    /// True for the memory-hard rungs. Argon derivations are the
    /// sidecar's dominant memory consumers (up to 64 MiB each); the
    /// verify path admits them through a memory-weighted semaphore so
    /// `workers * 64 MiB` can never become the process's working set.
    pub fn is_argon(self) -> bool {
        matches!(self, Rung::Argon16 | Rung::Argon32 | Rung::Argon64)
    }

    /// The memory cost in KiB the rung's derivation requires.
    pub fn argon_m_kib(self) -> u32 {
        match self {
            Rung::Argon16 => 65536,
            Rung::Argon32 => 65536,
            Rung::Argon64 => 65536,
            _ => 0,
        }
    }

    /// The proof-of-work profile the rung issues. The rsw rung carries no
    /// profile knobs (the trapdoor lives on the challenge config), so its
    /// profile pins the protocol values issuance expects.
    pub fn profile(self) -> ChallengeProfile {
        match self {
            Rung::Sha16 => ChallengeProfile::sha(16),
            Rung::Sha18 => ChallengeProfile::sha(18),
            Rung::Sha20 => ChallengeProfile::sha(20),
            Rung::Argon16 => ChallengeProfile::argon16(),
            Rung::Argon32 => ChallengeProfile::argon32(),
            Rung::Argon64 => ChallengeProfile::argon64(),
            Rung::Rsw => ChallengeProfile {
                algorithm: PoWAlgorithm::Rsw,
                target_bits: RSW_TARGET_BITS_PIN as u8,
                m_kib: 0,
                t: 0,
                p: 1,
            },
        }
    }

    /// The minimum plausible solve time the profile derives, in
    /// milliseconds. Never zero: every rung carries a timing floor that
    /// verification enforces against the server clock.
    pub fn min_duration_ms(self) -> u64 {
        self.profile_min_duration_ms(DEFAULT_RSW_T)
    }

    /// The floor under an explicit rsw sequential cost (the caller's
    /// configured `rsw_t`), so an rsw deployment's floor matches the
    /// configured trapdoor cost.
    pub fn profile_min_duration_ms(self, rsw_t: u32) -> u64 {
        let profile = self.profile();
        match profile.algorithm {
            PoWAlgorithm::Sha256 => sha_floor(profile.target_bits as u32),
            PoWAlgorithm::Argon2id => argon_floor(profile.target_bits as u32),
            PoWAlgorithm::Rsw => rsw_floor(rsw_t),
        }
    }
}

fn sha_floor(target_bits: u32) -> u64 {
    // The core's derivation: expected hashes over the solver hash rate,
    // with a 5 ms absolute floor.
    let expected = 1u64 << target_bits.min(32);
    let ms = (expected as f64 / kiwicaptcha::challenge::SHA256_SOLVER_HASHES_PER_SEC * 1000.0)
        .ceil() as u64;
    ms.max(5)
}

fn argon_floor(target_bits: u32) -> u64 {
    let expected = 1u64 << target_bits.min(32);
    let ms = (expected as f64 / kiwicaptcha::challenge::ARGON2_SOLVER_HASHES_PER_SEC * 1000.0)
        .ceil() as u64;
    ms.max(50)
}

fn rsw_floor(rsw_t: u32) -> u64 {
    let ms = (rsw_t as f64 / kiwicaptcha::challenge::RSW_SOLVER_SQUARINGS_PER_SEC * 1000.0).ceil()
        as u64;
    ms.max(50)
}

/// Parse a rung name or a value class. The value classes are the bundle's
/// pricing vocabulary (`AgentPriceTier`, the scope value-class table):
/// low, standard, high and critical.
pub fn parse_rung(raw: &str) -> Result<Rung, String> {
    match raw.trim() {
        "sha16" | "low" => Ok(Rung::Sha16),
        "sha18" | "standard" => Ok(Rung::Sha18),
        "sha20" | "high" => Ok(Rung::Sha20),
        "argon16" | "critical" => Ok(Rung::Argon16),
        "argon32" => Ok(Rung::Argon32),
        "argon64" => Ok(Rung::Argon64),
        "rsw" => Ok(Rung::Rsw),
        other => Err(format!(
            "unknown rung or value class \"{other}\" (want sha16, sha18, sha20, argon16, argon32, argon64, rsw, or the value classes low, standard, high, critical)"
        )),
    }
}

/// The per-scope rung plan: every scope the sidecar issues for, with its
/// rung. The mapping mirrors the bundle's value-class table (each scope's
/// `value_class` prices onto a challenge rung) with the direct rung names
/// accepted as shorthand.
#[derive(Debug, Clone)]
pub struct ScopePlan {
    entries: Vec<(String, Rung)>,
}

impl ScopePlan {
    /// The rung configured for `scope`, if the plan lists it.
    pub fn rung_of(&self, scope: &str) -> Option<Rung> {
        self.entries
            .iter()
            .find(|(name, _)| name == scope)
            .map(|(_, rung)| *rung)
    }

    /// The configured scope names (the `/doctor` summary reads them).
    pub fn names(&self) -> Vec<String> {
        self.entries.iter().map(|(name, _)| name.clone()).collect()
    }

    /// The scope, rung pairs in configuration order.
    pub fn entries(&self) -> &[(String, Rung)] {
        &self.entries
    }
}

/// Parse the scope plan. Entries are comma separated; each entry is
/// `scope=rung` or a bare scope name (which takes `default_rung`). An
/// empty list yields the single `login` scope at the default rung.
pub fn parse_scopes(raw: Option<&str>, default_rung: Rung) -> Result<ScopePlan, String> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(ScopePlan {
            entries: vec![("login".to_string(), default_rung)],
        });
    };
    let mut entries: Vec<(String, Rung)> = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (scope, rung) = match part.split_once('=') {
            Some((scope, value)) => {
                let scope = scope.trim();
                if scope.is_empty() {
                    return Err(format!("scope entry \"{part}\" names no scope"));
                }
                (scope, parse_rung(value)?)
            }
            None => (part, default_rung),
        };
        if !valid_scope_name(scope) {
            return Err(format!(
                "scope \"{scope}\" must be 1..=128 bytes of [A-Za-z0-9._:-]"
            ));
        }
        if entries.iter().any(|(name, _)| name == scope) {
            return Err(format!("scope \"{scope}\" is configured twice"));
        }
        entries.push((scope.to_string(), rung));
    }
    if entries.is_empty() {
        return Ok(ScopePlan {
            entries: vec![("login".to_string(), default_rung)],
        });
    }
    Ok(ScopePlan { entries })
}

fn valid_scope_name(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 128
        && scope
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// The store backend selection: `memory` (the default, volatile), `file`
/// (durable, atomic rename plus fsync) or `redis` (the core crate's Redis
/// verifier store, behind the `redis-store` feature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreConfig {
    Memory,
    File(PathBuf),
    Redis(String),
}

/// Parse the store selection: `memory`, `file=/path` or a `redis://` URL.
pub fn parse_store(raw: Option<&str>) -> Result<StoreConfig, String> {
    let raw = match raw {
        None => return Ok(StoreConfig::Memory),
        Some(v) => v.trim(),
    };
    if raw.is_empty() || raw == "memory" {
        return Ok(StoreConfig::Memory);
    }
    if let Some(path) = raw.strip_prefix("file=") {
        let path = path.trim();
        if path.is_empty() {
            return Err("store \"file=\" needs a directory path".to_string());
        }
        return Ok(StoreConfig::File(PathBuf::from(path)));
    }
    if raw.starts_with("rediss://") || raw.starts_with("REDISS://") {
        // Honest rejection instead of pretended support: this build's
        // redis crate carries no TLS feature, and the bounded liveness
        // probe cannot speak TLS. Managed-Redis deployments terminate
        // TLS in front (stunnel / mesh / platform sidecar) and hand the
        // sidecar a redis:// URL, including ACL credentials.
        return Err("store rediss:// (TLS Redis) is not supported by this build: terminate TLS in front of Redis (stunnel, service mesh, or the platform's local proxy) and pass redis:// — optionally with ACL credentials — or rebuild with a Redis TLS backend before advertising rediss://".to_string());
    }
    // Schemes compare case-insensitively (url/redis-rs lowercase them
    // too); the stored string keeps the operator's spelling.
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("redis://")
        || lower.starts_with("unix://")
        || lower.starts_with("redis+unix://")
    {
        return Ok(StoreConfig::Redis(raw.to_string()));
    }
    Err(format!(
        "unknown store \"{}\" (want memory, file=DIR, redis:// with optional ACL credentials, or unix://)",
        redact_store_url(raw)
    ))
}

/// The store/risk URL as it may be printed in logs, startup lines and
/// operator-facing errors: the userinfo component (`user:password@`)
/// becomes `***@` so an ACL credential never lands in stdout, a journal
/// or a crash report. Query credentials (`pass=`, `password=`, … — the
/// unix:// form redis-rs actually honors) are stripped to `***` too.
/// Wire address, database and non-secret query stay visible.
/// Works on well-formed `scheme://` URLs and on single-slash typos
/// (`rediss:/user:pass@host`) so a malformed scheme cannot leak either.
pub fn redact_store_url(raw: &str) -> String {
    let without_query_secrets = redact_query_secrets(raw);
    // Prefer the structured authority after `://`; fall back to the
    // first `:/` so `rediss:/user:pass@host` redacts too.
    let (scheme_end, sep) = if let Some(i) = without_query_secrets.find("://") {
        (i, 3)
    } else if let Some(i) = without_query_secrets.find(":/") {
        (i, 2)
    } else {
        return strip_log_controls(&redact_bare_userinfo(&without_query_secrets));
    };
    let (scheme, rest) = without_query_secrets.split_at(scheme_end + sep);
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let redacted = match authority.rfind('@') {
        Some(at) => format!("{scheme}***@{}{tail}", &authority[at + 1..]),
        None => redact_bare_userinfo(&without_query_secrets),
    };
    strip_log_controls(&redacted)
}

/// Drop C0 controls (and DEL) so a DSN/path printed on the startup
/// line or in an error cannot inject fake log lines or terminal escapes.
pub fn strip_log_controls(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>()
}

/// Query parameters that carry credentials (redis-rs reads `user`/`pass`
/// from the query on `unix://` URLs) become `***` so a socket DSN with
/// `?pass=secret` cannot leak through the userinfo-only redaction.
fn redact_query_secrets(raw: &str) -> String {
    let Some(q) = raw.find('?') else {
        return raw.to_string();
    };
    let (head, query) = raw.split_at(q);
    let mut parts = Vec::new();
    for part in query[1..].split_inclusive('&') {
        let bare = part.trim_end_matches('&');
        let key = bare.split('=').next().unwrap_or("");
        if key.eq_ignore_ascii_case("pass")
            || key.eq_ignore_ascii_case("password")
            || key.eq_ignore_ascii_case("auth")
            || key.eq_ignore_ascii_case("token")
        {
            parts.push(if part.ends_with('&') {
                format!("{key}=***&")
            } else {
                format!("{key}=***")
            });
        } else {
            parts.push(part.to_string());
        }
    }
    format!("{head}?{}", parts.concat())
}

/// Last-resort pass for strings with no scheme separator at all: drop
/// `anything:password@` userinfo wherever it appears.
fn redact_bare_userinfo(raw: &str) -> String {
    match raw.find('@') {
        None => raw.to_string(),
        Some(at) => {
            let head = &raw[..at];
            match head.rfind([':', '/']) {
                Some(i) if head[i..].contains(':') && !head[i + 1..].contains('/') => {
                    format!("{}***@{}", &raw[..i + 1], &raw[at + 1..])
                }
                _ => raw.to_string(),
            }
        }
    }
}

/// The IP binding posture. `Bound` (the default, the core's issuance
/// default) demands `remoteip` on both endpoints; `None` drops the
/// nonce-bound IP tag entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingConfig {
    Bound,
    None,
}

/// Parse the binding posture: `bound` or `none`.
pub fn parse_binding(raw: Option<&str>) -> Result<BindingConfig, String> {
    match raw.map(str::trim) {
        None | Some("") | Some("bound") | Some("nonce_ip_hmac") => Ok(BindingConfig::Bound),
        Some("none") => Ok(BindingConfig::None),
        Some(other) => Err(format!(
            "unknown binding mode \"{other}\" (want bound or none)"
        )),
    }
}

/// The server limits: the bounded worker pool and the per-connection
/// timeouts.
#[derive(Debug, Clone, Copy)]
pub struct ServerLimits {
    pub workers: usize,
    pub timeout: Duration,
}

/// Parse the worker count: at least one worker, at most 1024.
pub fn parse_workers(raw: Option<&str>) -> Result<usize, String> {
    let raw = match raw {
        None => return Ok(DEFAULT_WORKERS),
        Some(v) => v.trim(),
    };
    if raw.is_empty() {
        return Ok(DEFAULT_WORKERS);
    }
    let n: usize = raw
        .parse()
        .map_err(|_| format!("workers \"{raw}\" is not a number"))?;
    if n == 0 || n > 1024 {
        return Err(format!("workers must be within 1..=1024 (got {n})"));
    }
    Ok(n)
}

/// Parse the per-connection timeout in milliseconds: 1 ms..=60 s.
pub fn parse_timeout_ms(raw: Option<&str>) -> Result<Duration, String> {
    let raw = match raw {
        None => return Ok(Duration::from_millis(DEFAULT_TIMEOUT_MS)),
        Some(v) => v.trim(),
    };
    if raw.is_empty() {
        return Ok(Duration::from_millis(DEFAULT_TIMEOUT_MS));
    }
    let n: u64 = raw
        .parse()
        .map_err(|_| format!("timeout \"{raw}\" is not a number"))?;
    if n == 0 || n > 60_000 {
        return Err(format!("timeout ms must be within 1..=60000 (got {n})"));
    }
    Ok(Duration::from_millis(n))
}

/// The secret policy. Refuses secrets under [`MIN_SECRET_BYTES`] and the
/// published example secrets unless the operator passes the explicit
/// development escape hatch. The hatch is reported to the caller so the
/// startup line can carry the warning.
pub fn validate_secret(raw: &str, allow_insecure_example: bool) -> Result<(String, bool), String> {
    if raw.len() < MIN_SECRET_BYTES {
        return Err(format!(
            "the HMAC secret is {} bytes; the minimum is {MIN_SECRET_BYTES} (generate one with: openssl rand -base64 48)",
            raw.len()
        ));
    }
    if is_example_secret(raw) {
        if !allow_insecure_example {
            return Err(
                "the configured secret is a published example value and is refused; generate a real secret (openssl rand -base64 48) or set the environment variable KIWI_ALLOW_INSECURE_EXAMPLE_SECRET=1 to accept it for local development"
                    .to_string(),
            );
        }
        return Ok((raw.to_string(), true));
    }
    Ok((raw.to_string(), false))
}

/// The rsw trapdoor material a deployment must supply when any scope maps
/// to the `rsw` rung. Both halves are required; the cost defaults to the
/// protocol default and is validated against the issuance bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RswTrapdoorConfig {
    pub modulus_n: String,
    pub lambda: String,
    pub t: u32,
}

/// Validate the rsw trapdoor knobs: both halves present, the cost within
/// the issuance bounds. The deep shape checks (canonical base64, modulus
/// primality guards) run in the core issuer at issuance time.
pub fn validate_rsw_trapdoor(
    modulus: Option<&str>,
    lambda: Option<&str>,
    t: Option<&str>,
) -> Result<RswTrapdoorConfig, String> {
    let modulus_n = modulus.map(str::trim).filter(|v| !v.is_empty()).ok_or(
        "the rsw rung needs a modulus: set KIWI_RSW_MODULUS (the tools/rsw-keygen public half)",
    )?;
    let lambda = lambda.map(str::trim).filter(|v| !v.is_empty()).ok_or(
        "the rsw rung needs a trapdoor: set KIWI_RSW_LAMBDA (the tools/rsw-keygen secret half)",
    )?;
    let t = match t.map(str::trim).filter(|v| !v.is_empty()) {
        None => DEFAULT_RSW_T,
        Some(raw) => raw
            .parse()
            .map_err(|_| format!("rsw t \"{raw}\" is not a number"))?,
    };
    if !(MIN_RSW_T..=MAX_RSW_T).contains(&t) {
        return Err(format!(
            "rsw t must be within {MIN_RSW_T}..={MAX_RSW_T} (got {t})"
        ));
    }
    Ok(RswTrapdoorConfig {
        modulus_n: modulus_n.to_string(),
        lambda: lambda.to_string(),
        t,
    })
}

/// True when the plan lists the rsw rung anywhere.
pub fn plan_needs_rsw(plan: &ScopePlan) -> bool {
    plan.entries().iter().any(|(_, rung)| *rung == Rung::Rsw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rung_table_carries_the_core_profiles() {
        assert_eq!(Rung::Sha16.profile().target_bits, 16);
        assert_eq!(Rung::Sha18.profile().target_bits, 18);
        assert_eq!(Rung::Sha20.profile().target_bits, 20);
        assert_eq!(Rung::Argon16.profile().m_kib, 16 * 1024);
        assert_eq!(Rung::Argon32.profile().m_kib, 32 * 1024);
        assert_eq!(Rung::Argon64.profile().m_kib, 64 * 1024);
        assert_eq!(Rung::Argon16.profile().t, 3);
        assert_eq!(Rung::Argon16.profile().p, 1);
        for rung in [
            Rung::Sha16,
            Rung::Sha18,
            Rung::Sha20,
            Rung::Argon16,
            Rung::Argon32,
            Rung::Argon64,
            Rung::Rsw,
        ] {
            rung.profile().validate().expect("the profile validates");
            assert!(rung.min_duration_ms() > 0, "the floor is never zero");
        }
        assert_eq!(Rung::Sha18.min_duration_ms(), 5);
        assert_eq!(Rung::Argon16.min_duration_ms(), 50);
        assert_eq!(Rung::Rsw.min_duration_ms(), 50);
    }

    #[test]
    fn value_classes_map_to_the_bundle_rungs() {
        assert_eq!(parse_rung("low").unwrap(), Rung::Sha16);
        assert_eq!(parse_rung("standard").unwrap(), Rung::Sha18);
        assert_eq!(parse_rung("high").unwrap(), Rung::Sha20);
        assert_eq!(parse_rung("critical").unwrap(), Rung::Argon16);
        assert!(parse_rung("sha12").is_err());
        assert!(parse_rung("urgent").is_err());
    }

    #[test]
    fn scope_plan_parses_pairs_bare_names_and_defaults() {
        let plan = parse_scopes(Some("login=critical,comment=low"), Rung::Sha18).unwrap();
        assert_eq!(plan.rung_of("login"), Some(Rung::Argon16));
        assert_eq!(plan.rung_of("comment"), Some(Rung::Sha16));
        assert_eq!(plan.rung_of("admin"), None);

        let bare = parse_scopes(Some("login,signup"), Rung::Sha18).unwrap();
        assert_eq!(bare.rung_of("login"), Some(Rung::Sha18));
        assert_eq!(bare.rung_of("signup"), Some(Rung::Sha18));

        let empty = parse_scopes(None, Rung::Sha18).unwrap();
        assert_eq!(empty.names(), vec!["login".to_string()]);
        assert_eq!(empty.rung_of("login"), Some(Rung::Sha18));

        assert!(parse_scopes(Some("login=nope"), Rung::Sha18).is_err());
        assert!(parse_scopes(Some("login=sha18,login=sha20"), Rung::Sha18).is_err());
        assert!(parse_scopes(Some("=sha18"), Rung::Sha18).is_err());
        assert!(parse_scopes(Some("bad scope=sha18"), Rung::Sha18).is_err());
    }

    #[test]
    fn store_config_parses_the_three_backends() {
        assert_eq!(parse_store(None), Ok(StoreConfig::Memory));
        assert_eq!(parse_store(Some("memory")), Ok(StoreConfig::Memory));
        assert_eq!(
            parse_store(Some("file=/var/lib/kiwi")),
            Ok(StoreConfig::File(PathBuf::from("/var/lib/kiwi")))
        );
        assert_eq!(
            parse_store(Some("redis://127.0.0.1:6379")),
            Ok(StoreConfig::Redis("redis://127.0.0.1:6379".to_string()))
        );
        assert!(parse_store(Some("sqlite=/tmp/x")).is_err());
        assert!(parse_store(Some("file=")).is_err());
        // TLS is refused honestly instead of pretended: this build
        // carries no Redis TLS backend and the liveness probe speaks
        // plain RESP only.
        let tls = parse_store(Some("rediss://user:secret@redis.internal:6380/0"))
            .expect_err("rediss:// must be refused at configuration");
        assert!(
            tls.to_string().contains("not supported"),
            "the refusal names the unsupported scheme: {tls}"
        );
        // ACL-credentialed and unix forms stay first-class.
        assert!(parse_store(Some("redis://appuser:secret@redis.internal:6379/0")).is_ok());
        assert!(parse_store(Some("unix:///var/run/kiwi-redis.sock")).is_ok());
        // Schemes compare case-insensitively (url/redis-rs lowercase
        // them); upper-case rediss is still refused as TLS.
        assert_eq!(
            parse_store(Some("REDIS://127.0.0.1:6379")),
            Ok(StoreConfig::Redis("REDIS://127.0.0.1:6379".to_string()))
        );
        let tls_case = parse_store(Some("REDISS://user:secret@redis.internal:6380/0"))
            .expect_err("upper-case rediss:// must be refused");
        assert!(
            tls_case.to_string().contains("not supported"),
            "the refusal names the unsupported scheme: {tls_case}"
        );
        // A mistyped scheme with credentials must not echo the password.
        let leak = parse_store(Some("rediss:/user:secret@redis.internal:6380"))
            .expect_err("malformed scheme is refused");
        assert!(
            !leak.to_string().contains("secret"),
            "the refusal redacts userinfo: {leak}"
        );
        assert!(
            leak.to_string().contains("***@"),
            "the redaction marker is visible: {leak}"
        );
        let leak2 = parse_store(Some("http://user:secret@redis.internal:6379"))
            .expect_err("foreign scheme is refused");
        assert!(
            !leak2.to_string().contains("secret"),
            "the foreign-scheme refusal redacts userinfo: {leak2}"
        );
    }

    #[test]
    fn store_url_redaction_keeps_wire_shape_and_drops_password() {
        assert_eq!(
            redact_store_url("redis://appuser:secret@redis.internal:6379/0"),
            "redis://***@redis.internal:6379/0"
        );
        assert_eq!(
            redact_store_url("redis://:only-password@[2001:db8::1]:6379/2?protocol=resp2"),
            "redis://***@[2001:db8::1]:6379/2?protocol=resp2"
        );
        assert_eq!(
            redact_store_url("redis://cache.example.com:6379"),
            "redis://cache.example.com:6379"
        );
        assert_eq!(
            redact_store_url("unix:///var/run/kiwi-redis.sock"),
            "unix:///var/run/kiwi-redis.sock"
        );
        // A bare host:port with no scheme is left alone.
        assert_eq!(redact_store_url("127.0.0.1:6379"), "127.0.0.1:6379");
        // Single-slash scheme typo still redacts.
        let typo = redact_store_url("rediss:/user:secret@redis.internal:6380");
        assert!(!typo.contains("secret"), "typo form redacts: {typo}");
        assert!(typo.contains("***@"), "typo form marks redaction: {typo}");
        // Query credentials (the unix:// form redis-rs honors) never leak.
        let sock = redact_store_url("unix:///var/run/kiwi.sock?user=app&pass=TopSecret99&db=2");
        assert!(!sock.contains("TopSecret99"), "query pass redacted: {sock}");
        assert!(sock.contains("pass=***"), "query pass marked: {sock}");
        assert!(sock.contains("db=2"), "non-secret query kept: {sock}");
        assert!(sock.contains("user=app"), "username kept: {sock}");
        let pw = redact_store_url("redis://cache:6379/0?password=TopSecret99");
        assert!(
            !pw.contains("TopSecret99"),
            "password= query redacted: {pw}"
        );
        // Control characters never survive into a log line.
        let injected = redact_store_url("redis://user:secret@host:6379/0\nFAKE ok=true\r");
        assert!(
            !injected.contains('\n') && !injected.contains('\r'),
            "newline injection stripped: {injected:?}"
        );
        assert!(
            !injected.contains("secret"),
            "password still redacted: {injected}"
        );
        assert_eq!(strip_log_controls("a\nb\r\nc\u{7}"), "abc");
    }

    #[test]
    fn parse_store_accepts_the_redis_plus_unix_alias() {
        assert!(parse_store(Some("redis+unix:///var/run/kiwi.sock")).is_ok());
    }

    #[test]
    fn binding_workers_and_timeout_parse() {
        assert_eq!(parse_binding(None), Ok(BindingConfig::Bound));
        assert_eq!(parse_binding(Some("none")), Ok(BindingConfig::None));
        assert!(parse_binding(Some("loose")).is_err());
        assert_eq!(parse_workers(None), Ok(16));
        assert_eq!(parse_workers(Some("1")), Ok(1));
        assert!(parse_workers(Some("0")).is_err());
        assert!(parse_workers(Some("2000")).is_err());
        assert_eq!(
            parse_timeout_ms(Some("250")),
            Ok(Duration::from_millis(250))
        );
        assert!(parse_timeout_ms(Some("0")).is_err());
        assert!(parse_timeout_ms(Some("huge")).is_err());
    }

    #[test]
    fn secret_floor_refuses_short_and_example_secrets() {
        assert!(validate_secret("short", false).is_err());
        assert!(validate_secret("0123456789abcdef0123456789abcdef", false).is_err());
        assert!(validate_secret(EXAMPLE_SECRET, false).is_err());
        // The change-me prefix is refused for any suffix, not only the
        // one documented example string.
        assert!(validate_secret("change-me-for-the-demo-deployment", false).is_err());
        let (secret, warned) =
            validate_secret(EXAMPLE_SECRET, true).expect("the hatch accepts the example");
        assert_eq!(secret, EXAMPLE_SECRET);
        assert!(warned);
        let (secret, warned) = validate_secret("change-me-for-the-demo-deployment", true)
            .expect("the hatch accepts a prefixed placeholder too");
        assert_eq!(secret, "change-me-for-the-demo-deployment");
        assert!(warned);
        let strong = "a-locally-generated-secret-of-48-bytes!!";
        let (secret, warned) = validate_secret(strong, false).expect("a real secret passes");
        assert_eq!(secret, strong);
        assert!(!warned);
    }

    #[test]
    fn rsw_trapdoor_requires_both_halves_and_bounded_cost() {
        assert!(validate_rsw_trapdoor(None, None, None).is_err());
        assert!(validate_rsw_trapdoor(Some("n"), None, None).is_err());
        let cfg = validate_rsw_trapdoor(Some(" n "), Some(" l "), None)
            .expect("both halves present, default t");
        assert_eq!(cfg.modulus_n, "n");
        assert_eq!(cfg.lambda, "l");
        assert_eq!(cfg.t, DEFAULT_RSW_T);
        assert!(validate_rsw_trapdoor(Some("n"), Some("l"), Some("1")).is_err());
    }

    #[test]
    fn server_limits_bundles_the_validated_worker_and_timeout_knobs() {
        // The public knob pair the server options consume: the defaults
        // are the documented 16 workers / 5 s timeout, and explicit
        // values pass through unchanged (bounded by the parsers above).
        let defaults = ServerLimits {
            workers: parse_workers(None).expect("the default parses"),
            timeout: parse_timeout_ms(None).expect("the default parses"),
        };
        assert_eq!(defaults.workers, DEFAULT_WORKERS);
        assert_eq!(defaults.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));

        let explicit = ServerLimits {
            workers: parse_workers(Some("4")).expect("bounded workers"),
            timeout: parse_timeout_ms(Some("250")).expect("bounded timeout"),
        };
        assert_eq!(explicit.workers, 4);
        assert_eq!(explicit.timeout, Duration::from_millis(250));
        // Copy is part of the contract: ServerOptions stores it by value.
        let copied = explicit;
        assert_eq!(copied.workers, explicit.workers);
        assert_eq!(copied.timeout, explicit.timeout);
    }
}
