//! The KiwiCaptcha language-neutral verifier sidecar.
//!
//! A single static binary that exposes the provider-shaped siteverify
//! surface over localhost HTTP or a Unix socket, so any stack without a
//! native SDK integrates with one local call:
//!
//! ```text
//! KIWI_SECRET=<48 random bytes, base64> kiwicaptcha-verifier
//! curl -s http://127.0.0.1:7371/verify \
//!   -H 'content-type: application/json' \
//!   -d '{"token":"...","scope":"login","remoteip":"203.0.113.9"}'
//! ```
//!
//! The HTTP surface is std-only: a hand-rolled HTTP/1.1 reader on the
//! standard library's TCP and Unix sockets, served by a bounded worker
//! pool with per-connection read and write timeouts. No framework
//! dependency exists. The process opens no outbound connection beyond
//! the store backend the operator selects (file or redis).
//!
//! # Endpoints
//!
//! - `POST /verify` `{token, scope, remoteip}` — the provider JSON
//!   shape (`success`, `challenge_ts`, `hostname`, `action`, `cdata`,
//!   `error-codes`), built by the core crate's siteverify mapper, plus
//!   the additive `kiwi-code` field carrying the precise core wire code
//!   (`ok`, `wrong_scope`, ...). While IP binding is on (the default)
//!   `remoteip` is required: its absence is a typed 400
//!   (`remoteip_required`). The loopback-only development escape hatch
//!   is `--allow-no-remoteip`.
//! - `POST /issue` `{scope, remoteip, action?, cdata?}` — mints through
//!   the core crate's real issuer under a challenge profile: the rung
//!   table maps `--profile` (`KIWI_PROFILE`, default `sha18`) and the
//!   per-scope plan (`KIWI_SCOPES "login=critical,comment=low"`, the
//!   bundle's value classes or direct rung names) onto the core's
//!   `ChallengeProfile`. The derived timing floor (never zero) is
//!   enforced at verification against the server clock.
//! - `GET /metrics` — Prometheus text: verify outcomes, store gauges,
//!   risk-denied issues, pool counters.
//! - `GET /healthz` — always `ok` while the process runs.
//! - `GET /doctor` — a JSON config/store/secret/binding/risk summary.
//!
//! # Authentication and secrets
//!
//! `KIWI_BEARER` (or `--bearer`) enables the sidecar's own bearer
//! credential on `/verify`, `/issue`, `/metrics` and `/doctor`,
//! compared in constant time. The HMAC secret must be at least
//! [`config::MIN_SECRET_BYTES`] bytes and published example values are
//! refused at startup; the development escape hatch
//! `KIWI_ALLOW_INSECURE_EXAMPLE_SECRET=1` accepts them with a warning.
//!
//! # Storage scope
//!
//! `KIWI_STORE` selects the backend. `memory` (the default) is volatile
//! single-node state: a restart loses outstanding challenges, and the
//! replay protection with them; that is the documented single-node
//! small-site trade. `file=DIR` persists every record through an atomic
//! rename with fsync (one JSON envelope per nonce, the peer of the PHP
//! filesystem storage's discipline, single node and single process).
//! `redis://URL` uses the core crate's fused Redis verifier store
//! behind the `redis-store` build feature, which is the multi-node
//! capable backend: several sidecar nodes may then share one store and
//! one secret, and a token minted on one node verifies on another.
//!
//! # Risk involvement
//!
//! With `--risk` (`KIWI_RISK=1`) and a Redis URL (`KIWI_RISK_URL`),
//! issuance runs the adaptive risk engine's pre-issue assessment over
//! the inputs the server holds (source IP, scope, the store's aggregate
//! history) and the disposition gates issuance: deny refuses with 429,
//! the ladder rungs compose onto the issued challenge, step-up carries
//! its disposition in the response, and a valid solve confirms the
//! recorded decision in the risk store's outcome ledger. Without the
//! plane this binary runs with no abuse-risk telemetry: purely
//! cryptographic issuance and verification, the single-node small-site
//! trade made deliberately. The bundle is the full plane.

pub mod config;
pub mod riskplane;
pub mod server;
pub mod state;
pub mod store;

pub use config::{
    parse_binding, parse_rung, parse_scopes, parse_store, parse_timeout_ms, parse_workers,
    validate_rsw_trapdoor, validate_secret, BindingConfig, Rung, ScopePlan, StoreConfig,
    CHALLENGE_TTL_SECS, DEFAULT_LISTEN, DEFAULT_PROFILE, DEFAULT_TIMEOUT_MS, DEFAULT_WORKERS,
    EXAMPLE_SECRET, EXAMPLE_SECRETS, MAX_BODY_BYTES, MAX_HEAD_BYTES, MIN_SECRET_BYTES,
};
pub use riskplane::{compose_rung, scope_id, RiskPlane};
pub use server::{
    parse_listen, serve, serve_http, serve_http_with, serve_unix, serve_unix_with, serve_with,
    ListenAddr, PoolMetrics, ServerOptions,
};
pub use state::{default_profile, issue_wire_of, open_store, SidecarConfig, SidecarState};
pub use store::{ConsumeOutcome, FileStore, MemoryStore, RecordMeta, RecordStore};

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(scopes: &[&str]) -> SidecarState {
        SidecarState::new(
            "a-locally-generated-secret-of-48-bytes!!".to_string(),
            None,
            scopes.iter().map(|s| s.to_string()).collect(),
            "http://127.0.0.1:0",
        )
    }

    fn req(method: &str, path: &str, body: &str) -> server::Request {
        server::Request {
            method: method.to_string(),
            path: path.to_string(),
            authorization: None,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn healthz_answers_ok_without_credentials() {
        let state = state_with(&[]);
        let res = state.handle(&req("GET", "/healthz", ""));
        assert_eq!(res.status, 200);
        assert_eq!(res.body, "ok\n");
    }

    #[test]
    fn verify_requires_the_configured_bearer() {
        let mut config = SidecarConfig::minimal(
            "a-locally-generated-secret-of-48-bytes!!".to_string(),
            vec![],
            "x",
        );
        config.bearer = Some("tok".to_string());
        let state = SidecarState::build(config);
        assert_eq!(state.handle(&req("POST", "/verify", "{}")).status, 401);
        let mut authorized = req("POST", "/verify", "{}");
        authorized.authorization = Some("Bearer tok".to_string());
        let res = state.handle(&authorized);
        assert_eq!(res.status, 400);
        assert!(res.body.contains("remoteip_required"), "{}", res.body);
    }

    #[test]
    fn unknown_routes_answer_not_found() {
        let state = state_with(&[]);
        assert_eq!(state.handle(&req("GET", "/nope", "")).status, 404);
    }

    #[test]
    fn issue_and_verify_demand_remoteip_while_binding_is_on() {
        let state = state_with(&["login"]);
        let issue = state.handle(&req("POST", "/issue", "{\"scope\":\"login\"}"));
        assert_eq!(issue.status, 400);
        assert!(issue.body.contains("remoteip_required"), "{}", issue.body);
        let verify = state.handle(&req(
            "POST",
            "/verify",
            "{\"token\":\"x\",\"scope\":\"login\"}",
        ));
        assert_eq!(verify.status, 400);
        assert!(verify.body.contains("remoteip_required"), "{}", verify.body);
    }

    #[test]
    fn the_escape_hatch_restores_the_loopback_fallback() {
        let mut config = SidecarConfig::minimal(
            "a-locally-generated-secret-of-48-bytes!!".to_string(),
            vec![],
            "x",
        );
        config.allow_no_remoteip = true;
        let state = SidecarState::build(config);
        let issue = state.handle(&req("POST", "/issue", "{\"scope\":\"login\"}"));
        assert_eq!(issue.status, 200, "{}", issue.body);
        let wire: serde_json::Value = serde_json::from_str(issue.body.trim_end()).unwrap();
        assert_eq!(wire["profile"], "sha18");
        assert!(wire["minDurationMs"].as_u64().unwrap() > 0);
    }

    #[test]
    fn an_unknown_scope_is_a_typed_400() {
        let state = state_with(&["login"]);
        let res = state.handle(&req(
            "POST",
            "/issue",
            "{\"scope\":\"admin\",\"remoteip\":\"198.51.100.7\"}",
        ));
        assert_eq!(res.status, 400);
        assert!(res.body.contains("scope_not_allowed"), "{}", res.body);
    }

    #[test]
    fn issue_runs_on_the_configured_profile_and_floor() {
        let plan = parse_scopes(Some("login=argon16"), Rung::Argon16).expect("plan");
        let mut config = SidecarConfig::minimal(
            "a-locally-generated-secret-of-48-bytes!!".to_string(),
            vec![],
            "x",
        );
        config.plan = plan;
        let state = SidecarState::build(config);
        let res = state.handle(&req(
            "POST",
            "/issue",
            "{\"scope\":\"login\",\"remoteip\":\"198.51.100.7\"}",
        ));
        assert_eq!(res.status, 200, "{}", res.body);
        let wire: serde_json::Value = serde_json::from_str(res.body.trim_end()).unwrap();
        assert_eq!(wire["profile"], "argon16");
        assert_eq!(wire["mKib"], 16 * 1024);
        assert_eq!(wire["minDurationMs"], 50);
        assert_eq!(wire["targetBits"], 1);
    }
}
