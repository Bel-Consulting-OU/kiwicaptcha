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

the engine method is recorded per run (see the run documents)

The self-escalation mandate: run 2: no new finding this run: the synthesis escalates (combined forged-token + framing-ambiguity, synthesis budget raised to 38)

The closed synthesis loop: the synthesis corpus was consumed end to end: 39 candidates triaged, 39 refuted deterministically (two-run hash gate), 0 findings filed, 0 unstable harnesses, 0 inconclusive, 0 harness errors, 0 classes without a harness

| Attack class | Current economic result | Status | Evidence (actual measured scale) |
| --- | --- | --- | --- |
| D3.1 commodity no-JS bots | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.2 stealth headless | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.3 PoW farm economics | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.4 proxy pools | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.5 credential stuffing | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document's source fingerprint does not match the current tree. Re-run the campaign. |
| D3.6 token brokering | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.7 human solver farms | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.8 AI agents | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.9 risk-engine gaming | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.10 infrastructure attacker | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.11 denial of service | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.12 protocol and parser | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.13 supply chain | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.14 privacy adversary | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.15 multi-tenant | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.16 accessibility and compatibility | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.17 cross-SDK parity attack | stale run: the recorded evidence predates the source it measures | RED | STALE: the run document is older than the packages/protocol sources. Re-run the campaign against the current tree; a leftover run is never a pass. |

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
