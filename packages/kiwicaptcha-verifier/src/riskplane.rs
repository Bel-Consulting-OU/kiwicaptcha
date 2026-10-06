//! The sidecar's optional risk plane: the adaptive risk engine wired to
//! issuance and verification.
//!
//! Enabled by `--risk` (env `KIWI_RISK=1`) with a Redis URL. When on, every
//! `/issue` runs the engine's pre-issue assessment over the inputs the
//! server really holds (the source IP, the scope, the aggregate history
//! the store carries) and the disposition gates issuance: a deny refuses
//! with 429, a step-up and every ladder rung compose onto the issued
//! challenge, and a valid solve confirms the recorded decision in the
//! risk store's outcome ledger.
//!
//! When the plane is off, this binary runs without abuse-risk telemetry:
//! issuance and verification stay purely cryptographic. That is the
//! single-node small-site trade, made deliberately; the BUNDLE is the
//! full plane with the Redis state, the pricing stage and the outcome
//! bridge.

use std::net::IpAddr;
use std::sync::Arc;

use kiwicaptcha_risk::action::RiskAction;
use kiwicaptcha_risk::context::RiskContext;
use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::keyspace::fnv1a32;
use kiwicaptcha_risk::network::{CidrNetworkClassifier, NetworkFlags};
use kiwicaptcha_risk::policy::RiskPolicy;
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::store::{
    AssessV2Reply, Observed, OutcomeRegistration, RiskStateStore, RiskStoreError,
    SessionContextTagStore, SessionTlsTagStore,
};
use kiwicaptcha_risk::{RiskDecision, RiskEngine};

use crate::config::{Rung, ScopePlan};

/// The risk engine's ladder action for a configured rung. The rsw rung
/// has no ladder entry (the risk ladder tops out at argon64), so the
/// policy floor for an rsw scope is the strongest challenge rung.
fn risk_action_of(rung: Rung) -> RiskAction {
    match rung {
        Rung::Sha16 => RiskAction::Sha16,
        Rung::Sha18 => RiskAction::Sha18,
        Rung::Sha20 => RiskAction::Sha20,
        Rung::Argon16 => RiskAction::Argon16,
        Rung::Argon32 => RiskAction::Argon32,
        Rung::Argon64 => RiskAction::Argon64,
        Rung::Rsw => RiskAction::Argon64,
    }
}

/// The rung a ladder action issues at. StepUp has no challenge rung: the
/// sidecar issues its strongest challenge and carries the step-up
/// disposition in the response for the application to answer.
fn rung_of_action(action: RiskAction) -> Option<Rung> {
    match action {
        RiskAction::Sha16 => Some(Rung::Sha16),
        RiskAction::Sha18 => Some(Rung::Sha18),
        RiskAction::Sha20 => Some(Rung::Sha20),
        RiskAction::Argon16 => Some(Rung::Argon16),
        RiskAction::Argon32 => Some(Rung::Argon32),
        RiskAction::Argon64 | RiskAction::StepUp => Some(Rung::Argon64),
        RiskAction::Allow | RiskAction::Deny => None,
    }
}

/// The scope id the risk state is keyed under: the workspace keyspace's
/// FNV-1a 32 of the scope name with the sign bit dropped, stable for the
/// life of a deployment. Zero is not a legal scope id and is bumped to 1.
pub fn scope_id(name: &str) -> u32 {
    let id = fnv1a32(name.as_bytes()) & 0x7fff_ffff;
    if id == 0 {
        1
    } else {
        id
    }
}

/// Compose the configured scope rung with a decision's ladder action: the
/// risk ladder only ever raises. StepUp issues the strongest challenge
/// rung; Allow keeps the configuration.
pub fn compose_rung(base: Rung, action: RiskAction) -> Rung {
    match action {
        RiskAction::Allow => base,
        RiskAction::Deny => base,
        RiskAction::StepUp => Rung::Argon64,
        other => match rung_of_action(other) {
            Some(rung) if risk_action_of(rung).rank() > risk_action_of(base).rank() => rung,
            _ => base,
        },
    }
}

/// The object-safe store wrapper: any [`RiskStateStore`] behind an arc,
/// with the neutral risk-v2 capability surfaces (the sidecar collects no
/// session context or TLS tags).
struct AnyRiskStore(Arc<dyn RiskStateStore + Send + Sync>);

impl RiskStateStore for AnyRiskStore {
    fn observe(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        self.0.observe(o)
    }

    fn register_outcome(
        &self,
        decision_id: &str,
        scope: u32,
        decision_hour: i64,
        score: u32,
    ) -> Result<bool, RiskStoreError> {
        self.0
            .register_outcome(decision_id, scope, decision_hour, score)
    }

    fn confirm_outcome(&self, decision_id: &str, legitimate: bool) -> Result<u8, RiskStoreError> {
        self.0.confirm_outcome(decision_id, legitimate)
    }

    fn correct_outcome(&self, decision_id: &str, legitimate: bool) -> Result<bool, RiskStoreError> {
        self.0.correct_outcome(decision_id, legitimate)
    }

    fn assess_v2(
        &self,
        o: &RiskObservation,
        context_tag: Option<&str>,
        tls_tag: Option<&str>,
        registration: Option<&OutcomeRegistration>,
    ) -> Result<Option<AssessV2Reply>, RiskStoreError> {
        self.0.assess_v2(o, context_tag, tls_tag, registration)
    }
}

impl SessionContextTagStore for AnyRiskStore {}
impl SessionTlsTagStore for AnyRiskStore {}

/// The wired risk plane: one engine over one state store, with the
/// policy derived from the scope plan (each scope's rung becomes the
/// policy's hard minimum, mirroring the bundle's scope floors).
pub struct RiskPlane {
    engine: RiskEngine<AnyRiskStore, CidrNetworkClassifier>,
}

impl RiskPlane {
    /// Build the plane over `store`. The policy: per scope, base risk 100
    /// and the configured rung as the hard minimum; the contract default
    /// weights and global floors; the unconfigured-scope row stays the
    /// contract default (base 100, minimum sha20, never Allow).
    pub fn new(
        store: Arc<dyn RiskStateStore + Send + Sync>,
        plan: &ScopePlan,
        master_secret: &str,
    ) -> Result<Self, String> {
        let keys = RiskKeys::try_from_master(master_secret.as_bytes())
            .map_err(|e| format!("cannot derive the risk keys: {e}"))?;
        let mut scopes = serde_json::Map::new();
        for (name, rung) in plan.entries() {
            let row = serde_json::json!({
                "base_risk": 100,
                "minimum": risk_action_of(*rung).as_str(),
                "post_solve_check": false,
                "degraded": "allow",
            });
            scopes.insert(scope_id(name).to_string(), row);
        }
        let config = serde_json::json!({
            "version": 1,
            "weights": {},
            "scopes": scopes,
            "global_floors": {"0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20"},
        });
        let policy = RiskPolicy::from_config(1, &config)
            .map_err(|e| format!("the derived risk policy is invalid: {e}"))?;
        let classifier = CidrNetworkClassifier::from_entries(Vec::new());
        let engine = RiskEngine::new(AnyRiskStore(store), classifier, Arc::new(policy), keys);
        Ok(RiskPlane { engine })
    }

    /// The pre-issue assessment over the server-side inputs.
    pub fn assess_pre_issue(&self, scope: &str, source_ip: IpAddr) -> Result<RiskDecision, String> {
        let ctx = RiskContext::new(
            scope_id(scope),
            source_ip,
            None,
            None,
            RiskEventKind::PreIssue,
            NetworkFlags::default(),
            ResourcePressure::default(),
        );
        self.engine
            .assess_pre_issue(ctx, None)
            .map_err(|e| format!("risk assessment failed: {e}"))
    }

    /// Book the confirmed-legitimate outcome for the decision an issue
    /// recorded. Best effort: a risk store outage never fails a valid
    /// solve.
    pub fn confirm_legitimate(
        &self,
        scope: &str,
        source_ip: IpAddr,
        decision_id: &str,
        nonce: &str,
    ) {
        let ctx = RiskContext::new(
            scope_id(scope),
            source_ip,
            None,
            None,
            RiskEventKind::ConfirmedLegitimate,
            NetworkFlags::default(),
            ResourcePressure::default(),
        );
        let idempotency = format!("kiwi-verifier:confirm:{nonce}");
        let _ = self
            .engine
            .confirmed_legitimate(ctx, Some(idempotency), decision_id, None);
    }

    /// Book the invalid-proof outcome. Best effort, same contract.
    pub fn report_invalid_proof(&self, scope: &str, source_ip: IpAddr, nonce: &str) {
        let ctx = RiskContext::new(
            scope_id(scope),
            source_ip,
            None,
            None,
            RiskEventKind::InvalidProof,
            NetworkFlags::default(),
            ResourcePressure::default(),
        );
        let idempotency = format!("kiwi-verifier:invalid:{nonce}");
        let _ =
            self.engine
                .record_feedback(RiskEventKind::InvalidProof, ctx, Some(idempotency), None);
    }

    /// The policy version the plane runs under (for `/doctor`).
    pub fn policy_version(&self) -> u32 {
        self.engine.policy_version()
    }
}

#[cfg(feature = "redis-store")]
/// Wire the plane over the production Redis state store (the binary's
/// `--risk` path). The namespace isolates the keyspace; the master
/// secret derives the risk identity keys.
pub fn connect_redis_plane(
    url: &str,
    namespace: &str,
    plan: &ScopePlan,
    master_secret: &str,
) -> Result<RiskPlane, String> {
    use kiwicaptcha_risk::redis::RedisRiskStateStore;
    let client = redis::Client::open(url.to_string())
        .map_err(|e| format!("cannot parse the risk Redis url {url}: {e}"))?;
    let store = RedisRiskStateStore::new(client, namespace);
    RiskPlane::new(
        Arc::new(store) as Arc<dyn RiskStateStore + Send + Sync>,
        plan,
        master_secret,
    )
}

/// The disposition JSON the `/issue` response carries when the risk plane
/// is on (additive; the challenge wire fields are untouched). The
/// decision id is a random handle the risk store keys outcomes under,
/// never a secret.
pub fn disposition_json(decision: &RiskDecision) -> serde_json::Value {
    serde_json::to_value(decision).unwrap_or_else(|_| serde_json::json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwicaptcha_risk::signals::SignalVector;
    use std::sync::Mutex as StdMutex;

    /// A store stub whose observation is fixed, so a test crafts the
    /// deny or the step-up condition through the engine's own decision
    /// path.
    struct StubStore {
        vector: SignalVector,
        confirms: StdMutex<Vec<(String, bool)>>,
        registrations: StdMutex<Vec<String>>,
    }

    impl StubStore {
        fn saturated(field: fn(&mut SignalVector)) -> Self {
            let mut vector = SignalVector::default();
            field(&mut vector);
            StubStore {
                vector,
                confirms: StdMutex::new(Vec::new()),
                registrations: StdMutex::new(Vec::new()),
            }
        }
    }

    impl RiskStateStore for StubStore {
        fn observe(&self, _o: &RiskObservation) -> Result<Observed, RiskStoreError> {
            Ok(Observed {
                vector: self.vector,
                global_level: 0,
                cooldown_until_ms: 0,
                is_duplicate: false,
            })
        }

        fn register_outcome(
            &self,
            decision_id: &str,
            _scope: u32,
            _decision_hour: i64,
            _score: u32,
        ) -> Result<bool, RiskStoreError> {
            self.registrations
                .lock()
                .unwrap()
                .push(decision_id.to_string());
            Ok(true)
        }

        fn confirm_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<u8, RiskStoreError> {
            self.confirms
                .lock()
                .unwrap()
                .push((decision_id.to_string(), legitimate));
            Ok(1)
        }

        fn correct_outcome(
            &self,
            _decision_id: &str,
            _legitimate: bool,
        ) -> Result<bool, RiskStoreError> {
            Ok(false)
        }
    }

    fn plan() -> ScopePlan {
        crate::config::parse_scopes(Some("login=critical"), crate::config::Rung::Argon16).unwrap()
    }

    #[test]
    fn scope_ids_are_stable_and_nonzero() {
        assert_eq!(scope_id("login"), scope_id("login"));
        assert_ne!(scope_id("login"), scope_id("comment"));
        assert!(scope_id("login") > 0);
    }

    #[test]
    fn compose_rung_only_raises() {
        assert_eq!(compose_rung(Rung::Sha18, RiskAction::Allow), Rung::Sha18);
        assert_eq!(compose_rung(Rung::Sha18, RiskAction::Sha20), Rung::Sha20);
        assert_eq!(
            compose_rung(Rung::Argon16, RiskAction::Sha20),
            Rung::Argon16
        );
        assert_eq!(compose_rung(Rung::Sha16, RiskAction::StepUp), Rung::Argon64);
    }

    #[test]
    fn a_saturated_replay_signal_denies_issuance() {
        let store = Arc::new(StubStore::saturated(|v| v.replay = 1000));
        let plane = RiskPlane::new(
            store as Arc<dyn RiskStateStore + Send + Sync>,
            &plan(),
            "kiwi-verifier-unit-test-secret-0123456789",
        )
        .unwrap();
        let decision = plane
            .assess_pre_issue("login", "198.51.100.7".parse().unwrap())
            .unwrap();
        assert_eq!(decision.action, RiskAction::Deny);
        assert!(decision.has_reason(kiwicaptcha_risk::policy::RiskReason::ReplayTraffic));
    }

    #[test]
    fn a_confirmed_solve_books_the_ledger_outcome() {
        let stub = Arc::new(StubStore::saturated(|_| {}));
        let plane = RiskPlane::new(
            Arc::clone(&stub) as Arc<dyn RiskStateStore + Send + Sync>,
            &plan(),
            "kiwi-verifier-unit-test-secret-0123456789",
        )
        .unwrap();
        let decision = plane
            .assess_pre_issue("login", "198.51.100.7".parse().unwrap())
            .unwrap();
        assert!(!decision.decision_id.is_empty());
        plane.confirm_legitimate(
            "login",
            "198.51.100.7".parse().unwrap(),
            &decision.decision_id,
            "nonce-1",
        );
        let confirms = stub.confirms.lock().unwrap();
        assert_eq!(confirms.len(), 1);
        assert_eq!(confirms[0].0, decision.decision_id);
        assert!(confirms[0].1);
    }
}
