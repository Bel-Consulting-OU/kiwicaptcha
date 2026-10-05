# THREATS

The living output of the automated red-team engine (change.md Part 10).
Generated from the runs ledger by `tools/redteam/engine/ledger.mjs`;
regenerate with the orchestrator. Status GREEN means the campaign's
required result held on the current repo state, RED means it did not,
NO-DATA means the campaign has not run into this ledger yet.

Seed: `0x6b776d74` · Ledger entries: 6

| Attack class | Current economic result | Status |
| --- | --- | --- |
| D3.1 commodity no-JS bots | cost_per_accepted_abuse=unbounded accepted=0 | GREEN |
| D3.10 infrastructure attacker | cost_per_accepted_abuse=unbounded accepted=0 backend=redis | GREEN |
| D3.12 protocol and parser | cost_per_differential=infinite differentials=0 desyncs=0 sdk_green=7 | GREEN |
| D3.14 privacy adversary | reidentification_cost=infinite raw_hits=0 | GREEN |
| D3.17 cross-SDK parity attack | weakest_link=none rejection_divergences=0 | GREEN |
| D3.5 credential stuffing | cost_per_compromised_account=unbounded compromised=0 attacker_solve_hashes=5138972 | GREEN |

## The bounds the engine holds itself to

- Every campaign states its environment downscale openly.
- Every finding is reproduced deterministically before it gates.
- Every committed repro is a reviewable test under tools/redteam/findings/.
- The engine targets loopback and private addresses only.
