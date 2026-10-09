# THREATS

The living output of the automated red-team engine (change.md Part 10).
Generated from the runs ledger by `tools/redteam/engine/ledger.mjs`;
regenerate with the orchestrator. Status GREEN means a real recorded
run of the campaign's required result held, RED means it did not,
NOT RUN means this environment has no run document for the campaign
(that is not a pass and is never omitted from this table).

Seed: `0x6b776d74` · Campaign slots: 17 ·
Recorded runs: 17

## Method note

the engine method is recorded per run: offline-grammar (no local model consulted)

The self-escalation mandate: run 4: no new finding this run: the synthesis escalates (combined scope-confusable + clock-skew, synthesis budget raised to 60)

The closed synthesis loop: the synthesis corpus was consumed end to end: 61 candidates triaged, 61 refuted deterministically (two-run hash gate), 0 findings filed, 0 unstable harnesses, 0 inconclusive, 0 harness errors, 0 classes without a harness

| Attack class | Current economic result | Status | Evidence (actual measured scale) |
| --- | --- | --- | --- |
| D3.1 commodity no-JS bots | cost_per_accepted_abuse=unbounded accepted=0 | GREEN | measured: attempts=600 downscaled_from=100000; wall 2s |
| D3.2 stealth headless | cost_per_accepted_abuse=unbounded accepted_abuses=0 solve_p95_ms=282 whitebox_pass_rate=1 | GREEN | measured: whitebox_attempted=25 whitebox_passed=25 whitebox_pass_rate=1 whitebox_class=full_knowledge_envelope_forger; wall 8s |
| D3.3 PoW farm economics | cost_per_accepted_abuse=unbounded accepted_abuses=0 honest_solves_verified=3 value_class_fails=low,standard,high,critical table=tools/redteam/runs/env/d33-economics-redis.json | GREEN | measured: table_complete=true honest_solves_verified=3 accepted_abuses=0 fail_rows=low,standard,high,critical; wall 18s |
| D3.4 proxy pools | cost_per_accepted_abuse=unbounded accepted=0 pool_ips=10000 | GREEN | measured: downscale=10000_of_1000000 factor=100x wire_sample=66_requests; downscale stated: 10000_of_1000000; wall 2s |
| D3.5 credential stuffing | compromised_valid_rate=0.0000 (threshold 0.0) cost_per_compromised_account=unbounded (critical threshold 50000.000000 usd) blocked_valid_prevented=1000 | GREEN | measured: downscale=rows_are_100000 engine=AdaptiveRiskEngine.reassess(AuthenticationSuccess) novelty=enforce breach_checker=not_shipped_not_credited valid_rate=1percent verdict=PASS cost_per_compromised_account=unbounded critical_threshold=50000.000000 compromised_valid_rate=0.0000 rate_threshold=0.0 compromised=0 valid=1000 spend_usd=0.091329; downscale stated: rows_are_100000; wall 23s |
| D3.6 token brokering | cost_per_accepted_relayed_abuse=unbounded accepted_relays=0 resale_value_of_solved_token=0 | GREEN | measured: relays_refused=4 stock_issued=30 embed_token_reads=; wall 2s |
| D3.7 human solver farms | relayed_code_resale_value=single_use webauthn_phish_yield=0 cost_per_accepted_relayed_abuse_beyond_first=unbounded | GREEN | measured: totp_begin_rate_limited=9 of 10; wall 0s |
| D3.8 AI agents | unauth_agent_cost=browser_price_per_solve verified_agent_within_quota=5 post_revocation_accepted=0 | GREEN | measured: unauth_solves=10 accepted=10 ladder_escalated=true verified_in_quota=5 quota_refused=3 revoked_accepted=0; wall 2s |
| D3.9 risk-engine gaming | gaming_yield=zero farmed_offhome_credit=0 poisoned_bias_points=0 churned_escapes=0 | GREEN | measured: downscale=labels_are_the_full_100000 mechanisms_exact; downscale stated: labels_are_the_full_100000; wall 11s |
| D3.10 infrastructure attacker | cost_per_accepted_abuse=unbounded accepted=0 backend=redis | GREEN | wall 1s |
| D3.11 denial of service | garbage_verify_marginal_cost=cheap_phase_p99_0.77ms amplification_return=negative accepted_abuses=0 | GREEN | measured: bounds=5x_measured_baseline floors=2000ms_challenge_1000ms_probe; wall 11s |
| D3.12 protocol and parser | cost_per_differential=infinite differentials=0 desyncs=0 sdk_green=7 | GREEN | wall 16s |
| D3.13 supply chain | tampered_driver_executions=0 mitm_yield=0 cost_per_accepted_supply_abuse=unbounded | GREEN | measured: tamper_legs=2 pollution_leg=1 csp_suites=4 page_errors_under_pollution=0 tampered_bytes=1_per_response; wall 52s |
| D3.14 privacy adversary | reidentification_cost=infinite raw_hits=0 | GREEN | measured: canary=canary-dbb1205a8d23 dumps=2 files; wall 92s |
| D3.15 multi-tenant | cross_tenant_reads_accepted=0 cross_tenant_replays_accepted=0 cost_per_accepted_cross_tenant_abuse=unbounded | GREEN | measured: tenants=2 namespace_corpus=8 cross_reads=3 replay_legs=3 shared_secret=yes; wall 1s |
| D3.16 accessibility and compatibility | autofill_decoy_fills=0 escalations=0 | GREEN | measured: engines=chromium specs=autofill-evidence.spec.mjs a11y.spec.mjs adversarial-portable.spec.mjs; wall 29s |
| D3.17 cross-SDK parity attack | weakest_link=none rejection_divergences=0 | GREEN | measured: sdks=7 adversarial_vectors=2; wall 10s |

## The bounds the engine holds itself to

- Every campaign states its environment downscale openly; the evidence
  column records the scale that actually ran, and a hash budget is
  never restated as a solve count.
- A campaign without a recorded run is listed NOT RUN with its reason.
  Green is never claimed without a run document.
- Known tiny-scale facts from the recorded evidence, stated honestly
  (transcribed from the run documents and runs/env/gate logs, not
  invented): the D3.5 wire sample paid 13,215,184 proof-of-work hashes
  for 200 wire solves (that figure is a hash budget, not a solve
  count) while the engine loop decided 100,000 leaked-list rows; D3.2
  solved 25 challenges (a 4000x downscale of one farm-day); D3.4
  walked 10,000 pool addresses over 66 wire requests (100x downscale).
  The specification volumes are not claimed to have been replayed.
- Every finding is reproduced deterministically before it gates.
- Every committed repro is a reviewable test under tools/redteam/findings/.
- The engine targets loopback and private addresses only.
