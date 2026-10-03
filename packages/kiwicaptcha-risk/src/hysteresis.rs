//! Per-process, bounded, TTL'd map of the last score-selected action per
//! scope and client pseudonym, giving the scope action selection enter/exit
//! hysteresis: a score hovering at a band boundary (449/451/449…) can no
//! longer flip the challenge profile on every request.
//!
//! Rules (behaviorally mirrored by the PHP `ScopeActionHysteresis`):
//!   - entries are keyed by `(scope, client)`: the client key is the
//!     session pseudonym when present, else the source pseudonym;
//!   - thresholds reuse the plain band boundaries: `enter[i] = upper[i] +
//!     10`, `exit[i] = lower[i] − 10`;
//!   - a request whose own score clears the target band margin selects the
//!     plain action directly: escalation when `score >= lower[plain] + 10`,
//!     drop when `score <= upper[plain] − 10`;
//!   - otherwise a previous ladder action at band `i` escalates to band
//!     `i+1` only when `score >= enter[i]`, de-escalates to band `i−1`
//!     only when `score < exit[i]`, and otherwise stays in band `i`;
//!   - a fresh key (no previous action, or an expired entry) uses the
//!     plain band mapping;
//!   - the hard actions (StepUp/Deny) are not hysteresis-affected: when
//!     the previous or the plain action is StepUp/Deny the plain mapping
//!     wins;
//!   - entries expire after [`TTL_MS`] (300 s); the map is bounded at
//!     1024 entries, the least-recently-used entry evicted when a new
//!     key arrives at capacity (expired entries are purged first).
//!
//! The map is intentionally per-process: worker-mode deployments and the
//! Rust engine keep it across requests. PHP-FPM workers are long-lived,
//! but the engine (and with it this map) is normally rebuilt per request,
//! so the map does not smooth across requests; worker, preload or
//! singleton setups that keep the engine keep the map. The authoritative
//! global state stays in Redis.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::action::RiskAction;

#[derive(Debug, Clone, Copy)]
struct Entry {
    action: RiskAction,
    updated_ms: u64,
}

/// See the module docs for the exact hysteresis rules.
#[derive(Debug, Default)]
pub struct ScopeActionHysteresis {
    inner: Mutex<HashMap<(u32, Vec<u8>), Entry>>,
}

impl ScopeActionHysteresis {
    /// Entry lifetime: 300 s.
    pub const TTL_MS: u64 = 300_000;

    /// Bounded map: at most 1024 entries; the least-recently-used entry is evicted.
    pub const MAX_ENTRIES: usize = 1024;

    /// The hysteresis ladder (ranks 0..6): StepUp and Deny are hard actions
    /// and never participate in the hold logic.
    const LADDER: [RiskAction; 7] = [
        RiskAction::Allow,
        RiskAction::Sha16,
        RiskAction::Sha18,
        RiskAction::Sha20,
        RiskAction::Argon16,
        RiskAction::Argon32,
        RiskAction::Argon64,
    ];

    /// Plain band boundaries `(lower, upper)` per ladder rank, mirroring
    /// [`RiskAction::action_for_score`] (pinned by a parity test).
    const BANDS: [(u16, u16); 7] = [
        (0, 150),
        (150, 300),
        (300, 450),
        (450, 600),
        (600, 750),
        (750, 850),
        (850, 930),
    ];

    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Selects the action for one client in one scope with enter/exit
    /// hysteresis and remembers the selection as that key's new last
    /// action. The stored action is the score-selected one: a later
    /// Deny/StepUp hard override never poisons the profile.
    pub fn select(
        &self,
        scope: u32,
        client: &[u8],
        score: u16,
        plain: RiskAction,
        now_ms: u64,
    ) -> RiskAction {
        let key = (scope, client.to_vec());
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let previous = map
            .get(&key)
            .copied()
            .filter(|e| now_ms.saturating_sub(e.updated_ms) <= Self::TTL_MS);
        let action = match previous {
            Some(prev)
                if (prev.action.rank() as usize) < Self::LADDER.len()
                    && (plain.rank() as usize) < Self::LADDER.len() =>
            {
                let prev_rank = prev.action.rank() as usize;
                let plain_rank = plain.rank() as usize;
                if plain_rank > prev_rank && score >= Self::BANDS[plain_rank].0 + 10 {
                    // The score clears the target band margin: jump.
                    plain
                } else if plain_rank < prev_rank && score <= Self::BANDS[plain_rank].1 - 10 {
                    // The score clears the target band exit margin: jump.
                    plain
                } else {
                    let (lower, upper) = Self::BANDS[prev_rank];
                    if prev_rank < Self::LADDER.len() - 1 && score >= upper + 10 {
                        Self::LADDER[prev_rank + 1]
                    } else if prev_rank > 0 && score < lower - 10 {
                        Self::LADDER[prev_rank - 1]
                    } else {
                        prev.action
                    }
                }
            }
            _ => plain,
        };
        if !map.contains_key(&key) && map.len() >= Self::MAX_ENTRIES {
            Self::evict(&mut map, now_ms);
        }
        map.insert(
            key,
            Entry {
                action,
                updated_ms: now_ms,
            },
        );
        action
    }

    /// Current number of tracked entries (tests/metrics).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
    }

    /// Purges expired entries; when still at capacity, evicts the single
    /// oldest entry.
    fn evict(map: &mut HashMap<(u32, Vec<u8>), Entry>, now_ms: u64) {
        map.retain(|_, e| now_ms.saturating_sub(e.updated_ms) <= Self::TTL_MS);
        if map.len() < Self::MAX_ENTRIES {
            return;
        }
        let oldest = map
            .iter()
            .min_by_key(|(_, e)| e.updated_ms)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000_000;
    const CLIENT_A: &[u8] = b"client-a";
    const CLIENT_B: &[u8] = b"client-b";
    const CLIENT_C: &[u8] = b"client-c";

    #[test]
    fn bands_mirror_action_for_score() {
        for (rank, (lower, upper)) in ScopeActionHysteresis::BANDS.iter().enumerate() {
            assert_eq!(
                RiskAction::action_for_score(*lower),
                ScopeActionHysteresis::LADDER[rank],
                "lower boundary of rank {rank}"
            );
            if rank < ScopeActionHysteresis::LADDER.len() - 1 {
                assert_eq!(
                    RiskAction::action_for_score(upper - 1),
                    ScopeActionHysteresis::LADDER[rank],
                    "inside band of rank {rank}"
                );
                assert_eq!(
                    RiskAction::action_for_score(*upper),
                    ScopeActionHysteresis::LADDER[rank + 1],
                    "upper boundary of rank {rank} enters the next band"
                );
            }
        }
    }

    #[test]
    fn oscillating_score_produces_stable_action() {
        // The canonical example: 49/51/49/51 — entirely inside the
        // Allow band [0,150): no flip-flop possible, always Allow.
        let h = ScopeActionHysteresis::new();
        for (i, score) in [49u16, 51, 49, 51].iter().enumerate() {
            assert_eq!(
                h.select(
                    1,
                    CLIENT_A,
                    *score,
                    RiskAction::action_for_score(*score),
                    T0 + i as u64
                ),
                RiskAction::Allow
            );
        }

        // The real boundary oscillation (the 450 edge): 449 is Sha18,
        // 451 would be Sha20 under the plain mapping — the previous action
        // must hold Sha18 (451 < enter[Sha18] = 460) so the profile never
        // flips.
        let h = ScopeActionHysteresis::new();
        for (i, score) in [449u16, 451, 449, 451, 449, 451].iter().enumerate() {
            assert_eq!(
                h.select(
                    1,
                    CLIENT_A,
                    *score,
                    RiskAction::action_for_score(*score),
                    T0 + i as u64
                ),
                RiskAction::Sha18,
                "iteration {i}: an oscillating boundary score must not flip the profile"
            );
        }
    }

    #[test]
    fn sustained_crossing_enters_the_higher_action() {
        let h = ScopeActionHysteresis::new();
        let mut now = T0;
        // 449 -> Sha18; a brief tick to 455 (plain Sha20) is still inside
        // [exit[Sha18]=290, enter[Sha18]=460): held.
        assert_eq!(
            h.select(1, CLIENT_A, 449, RiskAction::Sha18, now),
            RiskAction::Sha18
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 455, RiskAction::Sha20, now),
            RiskAction::Sha18
        );
        now += 1;
        // Sustained crossing: 480 >= enter[Sha18]=460 -> Sha20, then held.
        assert_eq!(
            h.select(1, CLIENT_A, 480, RiskAction::Sha20, now),
            RiskAction::Sha20
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 480, RiskAction::Sha20, now),
            RiskAction::Sha20
        );
        now += 1;
        // Still inside [exit[Sha20]=440, enter[Sha20]=610): held even at
        // 590 (plain Argon16) — escalation needs a sustained crossing.
        assert_eq!(
            h.select(1, CLIENT_A, 590, RiskAction::Argon16, now),
            RiskAction::Sha20
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 590, RiskAction::Argon16, now),
            RiskAction::Sha20
        );
        now += 1;
        // 620 >= enter[Sha20]=610 -> Argon16, then held.
        assert_eq!(
            h.select(1, CLIENT_A, 620, RiskAction::Argon16, now),
            RiskAction::Argon16
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 620, RiskAction::Argon16, now),
            RiskAction::Argon16
        );
    }

    #[test]
    fn sustained_drop_exits_the_higher_action() {
        let h = ScopeActionHysteresis::new();
        let mut now = T0;
        // Climb to Sha20 (480), then drop: 441 is still above the drop
        // margin -> held; 439 -> Sha18; 250 -> Sha16, then held.
        assert_eq!(
            h.select(1, CLIENT_A, 480, RiskAction::Sha20, now),
            RiskAction::Sha20
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 441, RiskAction::Sha18, now),
            RiskAction::Sha20
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 439, RiskAction::Sha18, now),
            RiskAction::Sha18
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 250, RiskAction::Sha16, now),
            RiskAction::Sha16
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 250, RiskAction::Sha16, now),
            RiskAction::Sha16
        );
        now += 1;
        // Below the Sha16 drop margin (140) -> Allow.
        assert_eq!(
            h.select(1, CLIENT_A, 100, RiskAction::Allow, now),
            RiskAction::Allow
        );
    }

    #[test]
    fn fresh_scope_uses_plain_mapping() {
        // Every score on a fresh key must equal RiskAction::action_for_score.
        for score in 0..=1000u16 {
            let fresh = ScopeActionHysteresis::new();
            assert_eq!(
                fresh.select(1, CLIENT_A, score, RiskAction::action_for_score(score), T0),
                RiskAction::action_for_score(score),
                "fresh key must use the plain mapping at score {score}"
            );
        }
    }

    #[test]
    fn hard_override_actions_are_not_hysteresis_affected() {
        let h = ScopeActionHysteresis::new();
        let mut now = T0;
        // Deny (plain, score 980) then a 500: the previous action is Deny —
        // not hysteresis-affected, the plain mapping applies (Sha20).
        assert_eq!(
            h.select(1, CLIENT_A, 980, RiskAction::Deny, now),
            RiskAction::Deny
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 500, RiskAction::Sha20, now),
            RiskAction::Sha20
        );
        now += 1;
        // StepUp (plain, score 930) then a 500: plain mapping again.
        assert_eq!(
            h.select(1, CLIENT_A, 930, RiskAction::StepUp, now),
            RiskAction::StepUp
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 500, RiskAction::Sha20, now),
            RiskAction::Sha20
        );
        now += 1;
        // A ladder previous action with a hard plain action: the hard
        // action wins immediately (never held in the lower band).
        assert_eq!(
            h.select(1, CLIENT_A, 500, RiskAction::Sha20, now),
            RiskAction::Sha20
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 980, RiskAction::Deny, now),
            RiskAction::Deny
        );
        now += 1;
        assert_eq!(
            h.select(1, CLIENT_A, 930, RiskAction::StepUp, now),
            RiskAction::StepUp
        );
    }

    #[test]
    fn multi_band_escalation_jumps_immediately() {
        // Regression: a bot on a fresh key after another client held
        // Allow in the same scope gets Argon64 at once, instead of the
        // one-band step a scope-wide memory would force.
        let h = ScopeActionHysteresis::new();
        assert_eq!(
            h.select(1, CLIENT_A, 100, RiskAction::Allow, T0),
            RiskAction::Allow
        );
        assert_eq!(
            h.select(1, CLIENT_B, 900, RiskAction::Argon64, T0 + 1),
            RiskAction::Argon64,
            "a fresh client's own score clears every band margin"
        );
        // The same key jumps from Allow to Argon64 in one request too.
        assert_eq!(
            h.select(1, CLIENT_A, 900, RiskAction::Argon64, T0 + 2),
            RiskAction::Argon64
        );
    }

    #[test]
    fn legitimate_client_score_after_bot_stays_allow() {
        // Regression: the bot's Argon64 memory must not leak into a
        // different client's key in the same scope.
        let h = ScopeActionHysteresis::new();
        assert_eq!(
            h.select(1, CLIENT_B, 900, RiskAction::Argon64, T0),
            RiskAction::Argon64
        );
        assert_eq!(
            h.select(1, CLIENT_C, 100, RiskAction::Allow, T0 + 1),
            RiskAction::Allow,
            "a client with no history maps 100 to Allow"
        );
        assert_eq!(
            h.select(1, CLIENT_A, 449, RiskAction::Sha18, T0 + 2),
            RiskAction::Sha18
        );
    }

    #[test]
    fn multi_band_drop_jumps_immediately() {
        let h = ScopeActionHysteresis::new();
        assert_eq!(
            h.select(1, CLIENT_A, 900, RiskAction::Argon64, T0),
            RiskAction::Argon64
        );
        assert_eq!(
            h.select(1, CLIENT_A, 100, RiskAction::Allow, T0 + 1),
            RiskAction::Allow,
            "the score clears the target band exit margin"
        );
        // Just above the drop margin the client steps down one band only.
        let h = ScopeActionHysteresis::new();
        assert_eq!(
            h.select(1, CLIENT_A, 900, RiskAction::Argon64, T0),
            RiskAction::Argon64
        );
        assert_eq!(
            h.select(1, CLIENT_A, 141, RiskAction::Allow, T0 + 1),
            RiskAction::Argon32
        );
    }

    #[test]
    fn boundary_hover_within_ten_holds_one_band() {
        // Enter edge of the Sha18 band: 459 holds, 460 escalates.
        let h = ScopeActionHysteresis::new();
        assert_eq!(
            h.select(1, CLIENT_A, 449, RiskAction::Sha18, T0),
            RiskAction::Sha18
        );
        assert_eq!(
            h.select(1, CLIENT_A, 451, RiskAction::Sha20, T0 + 1),
            RiskAction::Sha18
        );
        assert_eq!(
            h.select(1, CLIENT_A, 455, RiskAction::Sha20, T0 + 2),
            RiskAction::Sha18
        );
        assert_eq!(
            h.select(1, CLIENT_A, 459, RiskAction::Sha20, T0 + 3),
            RiskAction::Sha18
        );
        assert_eq!(
            h.select(1, CLIENT_A, 460, RiskAction::Sha20, T0 + 4),
            RiskAction::Sha20
        );
        // Exit edge of the Sha20 band: 441 holds, 440 drops.
        let h = ScopeActionHysteresis::new();
        assert_eq!(
            h.select(1, CLIENT_A, 480, RiskAction::Sha20, T0),
            RiskAction::Sha20
        );
        assert_eq!(
            h.select(1, CLIENT_A, 441, RiskAction::Sha18, T0 + 1),
            RiskAction::Sha20
        );
        assert_eq!(
            h.select(1, CLIENT_A, 440, RiskAction::Sha18, T0 + 2),
            RiskAction::Sha18
        );
    }

    #[test]
    fn different_clients_keep_independent_histories() {
        let h = ScopeActionHysteresis::new();
        // Client A climbs to Sha20 under the 450 edge.
        assert_eq!(
            h.select(1, CLIENT_A, 449, RiskAction::Sha18, T0),
            RiskAction::Sha18
        );
        assert_eq!(
            h.select(1, CLIENT_A, 480, RiskAction::Sha20, T0 + 1),
            RiskAction::Sha20
        );
        // Client B on the same scope starts fresh: 100 -> Allow, then the
        // 449 edge uses the plain mapping.
        assert_eq!(
            h.select(1, CLIENT_B, 100, RiskAction::Allow, T0 + 2),
            RiskAction::Allow
        );
        assert_eq!(
            h.select(1, CLIENT_B, 449, RiskAction::Sha18, T0 + 3),
            RiskAction::Sha18
        );
        // Client A still holds its own Sha20 memory.
        assert_eq!(
            h.select(1, CLIENT_A, 449, RiskAction::Sha18, T0 + 4),
            RiskAction::Sha20
        );
        assert_eq!(h.len(), 2, "one entry per scope and client key");
    }

    #[test]
    fn ttl_expiry_forgets_the_scope() {
        // Inside TTL the previous action holds (no flip).
        let h = ScopeActionHysteresis::new();
        assert_eq!(
            h.select(1, CLIENT_A, 449, RiskAction::Sha18, T0),
            RiskAction::Sha18
        );
        assert_eq!(
            h.select(
                1,
                CLIENT_A,
                451,
                RiskAction::Sha20,
                T0 + ScopeActionHysteresis::TTL_MS - 1
            ),
            RiskAction::Sha18,
            "inside TTL the previous action must hold"
        );

        // Past TTL (300 s since the last decision): the entry is gone, the
        // key is fresh again and the plain mapping applies (Sha20).
        let h = ScopeActionHysteresis::new();
        assert_eq!(
            h.select(1, CLIENT_A, 449, RiskAction::Sha18, T0),
            RiskAction::Sha18
        );
        assert_eq!(
            h.select(
                1,
                CLIENT_A,
                451,
                RiskAction::Sha20,
                T0 + ScopeActionHysteresis::TTL_MS + 1
            ),
            RiskAction::Sha20,
            "after TTL the boundary score must fall back to the plain mapping"
        );
        assert_eq!(h.len(), 1, "the fresh selection re-inserts one entry");
    }

    #[test]
    fn bounded_map_evicts_the_oldest_entry() {
        let h = ScopeActionHysteresis::new();
        for scope in 1..=ScopeActionHysteresis::MAX_ENTRIES as u32 {
            h.select(scope, CLIENT_A, 100, RiskAction::Allow, T0 + scope as u64);
        }
        assert_eq!(h.len(), ScopeActionHysteresis::MAX_ENTRIES);

        // A NEW key at capacity evicts the least-recently-used entry (scope 1).
        let new_scope = ScopeActionHysteresis::MAX_ENTRIES as u32 + 1;
        h.select(new_scope, CLIENT_A, 100, RiskAction::Allow, T0 + 100_000);
        assert_eq!(
            h.len(),
            ScopeActionHysteresis::MAX_ENTRIES,
            "the map must stay bounded"
        );
        // Scope 1 was evicted: it is fresh again (plain mapping at 449 =
        // Sha18), while the new key is tracked.
        assert_eq!(
            h.select(1, CLIENT_A, 449, RiskAction::Sha18, T0 + 100_001),
            RiskAction::Sha18,
            "the least-recently-used entry must be evicted"
        );
        assert_eq!(h.len(), ScopeActionHysteresis::MAX_ENTRIES);
    }

    #[test]
    fn expired_entries_are_purged_before_eviction() {
        let h = ScopeActionHysteresis::new();
        for scope in 1..=ScopeActionHysteresis::MAX_ENTRIES as u32 {
            h.select(scope, CLIENT_A, 100, RiskAction::Allow, T0 + scope as u64);
        }
        // All entries expired long ago: the purge alone makes room.
        let new_scope = ScopeActionHysteresis::MAX_ENTRIES as u32 + 1;
        h.select(new_scope, CLIENT_A, 100, RiskAction::Allow, T0 + 10_000_000);
        assert_eq!(h.len(), 1, "expired entries are purged before eviction");
        assert_eq!(
            h.select(1, CLIENT_A, 100, RiskAction::Allow, T0 + 10_000_001),
            RiskAction::Allow
        );
    }
}
