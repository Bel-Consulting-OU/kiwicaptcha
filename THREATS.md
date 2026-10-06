# THREATS

The living output of the automated red-team engine (change.md Part 10).
Generated from the runs ledger by `tools/redteam/engine/ledger.mjs`;
regenerate with the orchestrator. Status GREEN means the campaign's
required result held on the current repo state, RED means it did not,
NO-DATA means the campaign has not run into this ledger yet.

Seed: `0x6b776d74` · Ledger entries: 17

## Method note

the engine ran fully offline: no local model was configured (KIWI_RT_LOCAL_LLM_URL unset), so the synthesis corpus is the deterministic seeded grammar and the novelty ordering is the documented no-op scorer

The self-escalation mandate: run 2: no new finding this run: the synthesis escalates (combined forged-token + framing-ambiguity, synthesis budget raised to 38)

The closed synthesis loop: the synthesis corpus was consumed end to end: 39 candidates triaged, 39 refuted deterministically (two-run hash gate), 0 findings filed, 0 unstable harnesses, 0 classes without a harness

| Attack class | Current economic result | Status |
| --- | --- | --- |
| D3.1 commodity no-JS bots | cost_per_accepted_abuse=unbounded accepted=0 | GREEN |
| D3.10 infrastructure attacker | cost_per_accepted_abuse=unbounded accepted=0 backend=redis | GREEN |
| D3.11 denial of service | garbage_verify_marginal_cost=cheap_phase_p99_0.79ms amplification_return=negative accepted_abuses=0 | GREEN |
| D3.12 protocol and parser | cost_per_differential=infinite differentials=0 desyncs=0 sdk_green=7 | GREEN |
| D3.13 supply chain | tampered_driver_executions=0 mitm_yield=0 cost_per_accepted_supply_abuse=unbounded | GREEN |
| D3.14 privacy adversary | reidentification_cost=infinite raw_hits=0 | GREEN |
| D3.15 multi-tenant | cross_tenant_reads_accepted=0 cross_tenant_replays_accepted=0 cost_per_accepted_cross_tenant_abuse=unbounded | GREEN |
| D3.16 accessibility and compatibility | autofill_decoy_fills=0 escalations=0 | GREEN |
| D3.17 cross-SDK parity attack | weakest_link=none rejection_divergences=0 | GREEN |
| D3.2 stealth headless | cost_per_accepted_abuse=unbounded accepted_abuses=0 solve_p95_ms=283 | GREEN |
| D3.3 PoW farm economics | cost_per_accepted_abuse=unbounded value_class_fails=low,standard,high,critical table=/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone/tools/redteam/runs/env/d33-economics-redis.json | GREEN |
| D3.4 proxy pools | cost_per_accepted_abuse=unbounded accepted=0 pool_ips=10000 | GREEN |
| D3.5 credential stuffing | cost_per_compromised_account=0.0003 spend_usd=0.093613 blocked_valid_prevented=645 cost_per_prevented_compromise=0.000145 | GREEN |
| D3.6 token brokering | cost_per_accepted_relayed_abuse=unbounded accepted_relays=0 resale_value_of_solved_token=0 | GREEN |
| D3.7 human solver farms | relayed_code_resale_value=single_use webauthn_phish_yield=0 cost_per_accepted_relayed_abuse_beyond_first=unbounded | GREEN |
| D3.8 AI agents | unauth_agent_cost=browser_price_per_solve verified_agent_within_quota=5 post_revocation_accepted=0 | GREEN |
| D3.9 risk-engine gaming | gaming_yield=zero farmed_offhome_credit=0 poisoned_bias_points=0 churned_escapes=0 | GREEN |

## The bounds the engine holds itself to

- Every campaign states its environment downscale openly.
- Every finding is reproduced deterministically before it gates.
- Every committed repro is a reviewable test under tools/redteam/findings/.
- The engine targets loopback and private addresses only.
