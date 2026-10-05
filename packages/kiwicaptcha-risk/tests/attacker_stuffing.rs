//! The credential-stuffing simulator: the done-when of decisive
//! attacker handling (change.md 3.3.3). One victim account; K attacker
//! identities (distinct session dimensions, three groups sharing an ASN
//! bucket) attempt M logins against the victim. Every attacker identity
//! must be denied within N = 3 attempts of its own traffic, while the
//! victim logs in with exactly one step-up and zero lockouts end-to-end.
//!
//! The simulation is deterministic and policy-layer only: attempt j of
//! an attacker carries the accumulated invalid-proof evidence
//! `bad_proof = min(1000, 250 * j)` through the real scorer and policy,
//! the outcome plane writes the attacker's abuse marks (session plus
//! ASN bucket) once its evidence corroborates (bad_proof at the
//! corroboration floor, attempt 2), and the target-attack state is the
//! reader-side view derived from the target's rolling failure count. A
//! denied attempt never reaches authentication, so it adds no target
//! failure. The marks store is in-memory; with the Redis url variable
//! set the identical simulation runs over the real marks surface.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use kiwicaptcha_risk::action::RiskAction;
use kiwicaptcha_risk::context::RiskContext;
use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::marks::MarksView;
use kiwicaptcha_risk::network::CidrNetworkClassifier;
use kiwicaptcha_risk::network::NetworkFlags;
use kiwicaptcha_risk::outcomes::{
    KiwiOutcomes, MarkDimension, MarkRecord, Outcome, OutcomeHandle, OutcomeMarksStore,
};
use kiwicaptcha_risk::policy::{RiskPolicy, RiskReason};
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::score::{score as compute_score, RiskWeights};
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::RiskStoreError;
use kiwicaptcha_risk::store::{
    Observed, RiskStateStore, SessionContextTagStore, SessionTlsTagStore,
};
use kiwicaptcha_risk::{marks, RiskEngine, RiskError};
use serde_json::json;

const K: usize = 24;
const M: u32 = 6;
/// Documented bound: every attacker identity is denied at attempt 2 or 3.
const N: u32 = 3;
const GROUPS: usize = 3;
const T0: u64 = 1_700_000_000_000;
const TARGET_ATTACK_THRESHOLD: u32 = 5;
const QUIET_WINDOW_MS: u64 = 900_000;

fn policy() -> Arc<RiskPolicy> {
    Arc::new(
        RiskPolicy::from_config(
            3,
            &json!({
                "version": 3,
                "weights": {
                    "source_fast": 190, "source_slow": 110, "subnet_fast": 80,
                    "issue_debt": 150, "bad_proof": 220, "malformed": 260,
                    "replay": 320, "action_failure": 120, "scope_switch": 60,
                    "global_pressure": 170, "network_risk": 100,
                    "trust_credit": 130, "principal_credit": 100
                },
                "scopes": {
                    "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" }
                },
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
            }),
        )
        .expect("config parses"),
    )
}

fn attacker_sessions() -> Vec<String> {
    (0..K).map(|i| format!("{:032x}", i + 1)).collect()
}

fn asn_buckets() -> Vec<String> {
    (0..GROUPS)
        .map(|group| format!("a{}", 64496 + group))
        .collect()
}

/// The deterministic stuffing storm over one marks surface; the credit
/// closure reports the victim's stepUpCompleted outcome through the
/// typed outcomes facade and answers (channel_booked, marks_written).
fn run_simulation(marks: &dyn OutcomeMarksStore, report_step_up_credit: &dyn Fn() -> (bool, u32)) {
    let weights = RiskWeights::default();
    let policy = policy();
    let healthy = ResourcePressure::default();
    let ttl = marks::DEFAULT_MARK_TTL_MS;

    // Hex-only 32-char pseudonyms (the handle contract's shape).
    let victim_session = "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5".to_string();
    let victim_principal = "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6".to_string();
    let sessions = attacker_sessions();
    let buckets = asn_buckets();

    let mut target_failures = 0u32;
    let mut last_failure_at = 0u64;
    let mut attack_started_at = 0u64;
    let mut step_up_completed = false;
    let mut marked = [false; K];
    let mut denied_at: Vec<Option<u32>> = vec![None; K];
    let mut victim_step_ups = 0u32;
    let mut victim_denies = 0u32;

    // The reader-side target view: while the target's rolling failure
    // count is at or above the attack threshold, a login claiming the
    // target sees the attacked-target record.
    let target_record = |failures: u32, started_at: u64, last_at: u64| {
        (failures >= TARGET_ATTACK_THRESHOLD).then(|| MarkRecord {
            kind: "targetUnderAttack".to_string(),
            count: failures as i64,
            first_ms: started_at as i64,
            last_ms: last_at as i64,
        })
    };

    // Round-robin attempts: round j runs attacker 0..K-1 in order, so
    // each group's first attacker writes the shared ASN bucket mark
    // before its group-mates attempt in the same round.
    for j in 1..=M {
        for i in 0..K {
            let now = T0 + (((j - 1) as u64 * K as u64) + i as u64) * 1000;
            let bad_proof = (250 * j).min(1000) as u16;
            let signals = SignalVector {
                bad_proof,
                ..Default::default()
            };
            let score = compute_score(100, &signals, &weights);
            let plain = policy.decide(1, score, &signals, &healthy, 0, now, 0);
            if j == 1 {
                // The pre-mark floor check: the attacker's own plain
                // evidence lands it in the Sha16 band, nothing weaker.
                assert_eq!(plain.action.as_str(), "sha16");
            }
            let bucket = &buckets[i * GROUPS / K];
            let view = MarksView::read(
                marks,
                &[
                    (MarkDimension::Session, sessions[i].clone()),
                    (MarkDimension::Asn, bucket.clone()),
                ],
                None,
            )
            .expect("marks read")
            .with_target(target_record(
                target_failures,
                attack_started_at,
                last_failure_at,
            ));
            let decision = marks::apply(
                plain,
                &view,
                marks::corroborated(&signals, false),
                now,
                ttl,
                &healthy,
                false,
            );
            if decision.action == RiskAction::Deny {
                denied_at[i].get_or_insert(j);
            } else {
                // The attempt proceeds and fails authentication: one more
                // target failure.
                target_failures += 1;
                if target_failures == TARGET_ATTACK_THRESHOLD {
                    attack_started_at = now;
                }
                last_failure_at = now;
            }
            if !marked[i] && bad_proof >= marks::CORROBORATION_FLOOR {
                // The outcome plane confirms the abuse: long-memory marks
                // on the attacker's session and ASN bucket.
                marks
                    .write_mark("session", &sessions[i], "accountBanned", now)
                    .expect("session mark");
                marks
                    .write_mark("asn", bucket, "accountBanned", now)
                    .expect("asn mark");
                marked[i] = true;
            }
        }

        if j == 2 {
            // The victim logs in while the target is under attack:
            // exactly the interactive step-up, never a lockout.
            let now = T0 + (K as u64 * 2) * 1000;
            let plain = policy.decide(1, 100, &SignalVector::zero(), &healthy, 0, now, 0);
            let view = MarksView::read(
                marks,
                &[
                    (MarkDimension::Session, victim_session.clone()),
                    (MarkDimension::Principal, victim_principal.clone()),
                ],
                None,
            )
            .expect("marks read")
            .with_target(target_record(
                target_failures,
                attack_started_at,
                last_failure_at,
            ));
            let decision = marks::apply(plain, &view, false, now, ttl, &healthy, false);
            assert_eq!(decision.action.as_str(), "step_up");
            assert!(decision.has_reason(RiskReason::TargetUnderAttack));
            victim_step_ups += 1;
            if decision.action == RiskAction::Deny {
                victim_denies += 1;
            }

            // The victim completes the step-up: the outcome credit
            // through the typed outcomes facade over the same surface.
            let (channel_booked, marks_written) = report_step_up_credit();
            assert!(channel_booked, "the credit books its trust channel");
            assert_eq!(marks_written, 0, "a trust outcome never writes a mark");
            step_up_completed = true;
        }
    }

    // (a) every attacker identity is denied within N attempts, and the
    // deny arrives only after corroborated evidence exists (attempt 2
    // at the earliest).
    let mut leaders = Vec::new();
    for (i, attempt) in denied_at.iter().enumerate() {
        let attempt = attempt.expect("every attacker identity reaches a deny");
        assert!(
            attempt >= 2,
            "attacker {i} denied at {attempt} (before evidence)"
        );
        assert!(attempt <= N, "attacker {i} denied at {attempt} (beyond N)");
        if attempt == N {
            leaders.push(i);
        }
    }
    // Each group's first attacker is denied at attempt 3 (its own marks
    // land after its second attempt); its group-mates ride the shared
    // ASN bucket mark and are denied at attempt 2.
    assert_eq!(leaders, vec![0, 8, 16]);

    // The attack subsides: denied attempts add no target failures, so a
    // quiet window decays the rolling count back below the threshold.
    let quiet_at = last_failure_at + QUIET_WINDOW_MS;
    assert!(quiet_at > attack_started_at);
    assert!(
        step_up_completed,
        "the victim completed its step-up before relief"
    );
    target_failures = 0;

    // (b) the victim's next login is the plain allow again: no step-up,
    // no lockout, and exactly one step-up happened overall.
    let plain = policy.decide(1, 100, &SignalVector::zero(), &healthy, 0, quiet_at, 0);
    let view = MarksView::read(
        marks,
        &[
            (MarkDimension::Session, victim_session),
            (MarkDimension::Principal, victim_principal),
        ],
        None,
    )
    .expect("marks read")
    .with_target(target_record(
        target_failures,
        attack_started_at,
        last_failure_at,
    ));
    let decision = marks::apply(plain, &view, false, quiet_at, ttl, &healthy, false);
    assert_eq!(decision.action.as_str(), "allow");
    assert!(!decision.has_reason(RiskReason::TargetUnderAttack));
    assert_eq!(victim_step_ups, 1, "the victim saw exactly one step-up");
    assert_eq!(victim_denies, 0, "the victim is never locked out");
}

/// The in-memory marks-and-state twin of the PHP RiskStateStoreStub:
/// cloning shares the state, so the engine owns one clone while the
/// simulation drives another.
#[derive(Default, Clone)]
struct SimStore {
    observed: Arc<Mutex<Vec<RiskObservation>>>,
    marks: Arc<Mutex<HashMap<(String, String), MarkRecord>>>,
}

impl RiskStateStore for SimStore {
    fn observe(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        self.observed.lock().unwrap().push(o.clone());
        Ok(Observed {
            vector: SignalVector::zero(),
            global_level: 0,
            cooldown_until_ms: 0,
            is_duplicate: false,
        })
    }
    fn register_outcome(
        &self,
        _decision_id: &str,
        _scope: u32,
        _decision_hour: i64,
        _score: u32,
    ) -> Result<bool, RiskStoreError> {
        Ok(true)
    }
    fn confirm_outcome(&self, _decision_id: &str, _legitimate: bool) -> Result<u8, RiskStoreError> {
        Ok(1)
    }
    fn correct_outcome(
        &self,
        _decision_id: &str,
        _legitimate: bool,
    ) -> Result<bool, RiskStoreError> {
        Ok(true)
    }
}

impl SessionContextTagStore for SimStore {}
impl SessionTlsTagStore for SimStore {}

impl OutcomeMarksStore for SimStore {
    fn mark_key(&self, dimension: &str, id: &str) -> Result<String, RiskError> {
        Ok(format!("mark:{{kiwi:test}}:{dimension}:{id}"))
    }
    fn write_mark(
        &self,
        dimension: &str,
        id: &str,
        kind: &str,
        now_ms: u64,
    ) -> Result<i64, RiskError> {
        let mut marks = self.marks.lock().unwrap();
        let entry = marks
            .entry((dimension.to_string(), id.to_string()))
            .or_insert(MarkRecord {
                kind: kind.to_string(),
                count: 0,
                first_ms: now_ms as i64,
                last_ms: now_ms as i64,
            });
        entry.kind = kind.to_string();
        entry.count += 1;
        entry.last_ms = now_ms as i64;
        Ok(entry.count)
    }
    fn read_mark(&self, dimension: &str, id: &str) -> Result<Option<MarkRecord>, RiskError> {
        Ok(self
            .marks
            .lock()
            .unwrap()
            .get(&(dimension.to_string(), id.to_string()))
            .cloned())
    }
    fn forget_marks(&self, dimension: &str, id: &str) -> Result<u32, RiskError> {
        Ok(self
            .marks
            .lock()
            .unwrap()
            .remove(&(dimension.to_string(), id.to_string()))
            .map_or(0, |_| 1))
    }
}

fn victim_context() -> RiskContext<'static> {
    RiskContext::new(
        1,
        "203.0.113.7".parse().unwrap(),
        None,
        None,
        RiskEventKind::PreIssue,
        NetworkFlags::default(),
        ResourcePressure::default(),
    )
}

#[test]
fn stuffing_storm_denies_attackers_and_saves_the_victim() {
    let store = SimStore::default();
    let engine = RiskEngine::new(
        store.clone(),
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    );
    let outcomes = KiwiOutcomes::new(&engine, &store);
    let victim_principal = "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6".to_string();
    let report = || {
        let receipt = outcomes
            .report(
                Outcome::StepUpCompleted,
                &OutcomeHandle::principal(&victim_principal).unwrap(),
                Some("victim-step-up-credit".to_string()),
                Some(victim_context()),
            )
            .expect("the credit report succeeds");
        (receipt.channel_booked, receipt.marks_written)
    };
    run_simulation(&store, &report);
    assert!(
        !store.observed.lock().unwrap().is_empty(),
        "the credit booked its feedback observation"
    );
}

/// The identical simulation against the real Redis marks surface
/// (marks.lua writes and reads).
#[test]
fn stuffing_storm_over_real_redis_marks() {
    let Ok(raw_url) = std::env::var("RISK_REDIS_URL") else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let url = raw_url
        .strip_prefix("tcp://")
        .map(|rest| format!("redis://{rest}"))
        .unwrap_or(raw_url);
    let client = ::redis::Client::open(url.clone()).expect("url parses");
    let mut suffix = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut suffix);
    let namespace = format!("stuffing{}", hex::encode(suffix));
    let engine_store =
        kiwicaptcha_risk::redis::RedisRiskStateStore::new(client.clone(), &namespace)
            .with_io_timeouts(2_000, 2_000);
    let marks_store = kiwicaptcha_risk::redis::RedisRiskStateStore::new(client, &namespace)
        .with_io_timeouts(2_000, 2_000);

    let engine = RiskEngine::new(
        engine_store,
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    );
    let outcomes = KiwiOutcomes::new(&engine, &marks_store);
    let victim_principal = "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6".to_string();
    let report = || {
        let receipt = outcomes
            .report(
                Outcome::StepUpCompleted,
                &OutcomeHandle::principal(&victim_principal).unwrap(),
                Some("victim-step-up-credit".to_string()),
                Some(victim_context()),
            )
            .expect("the credit report succeeds");
        (receipt.channel_booked, receipt.marks_written)
    };
    run_simulation(&marks_store, &report);

    // Cleanup: the exact mark keys of the run.
    let mut keys = Vec::new();
    for session in attacker_sessions() {
        keys.push(marks_store.mark_key("session", &session).unwrap());
    }
    for bucket in asn_buckets() {
        keys.push(marks_store.mark_key("asn", &bucket).unwrap());
    }
    let mut conn = ::redis::Client::open(url)
        .unwrap()
        .get_connection()
        .unwrap();
    use ::redis::Commands;
    let _: i64 = conn.del(keys).unwrap();
}
