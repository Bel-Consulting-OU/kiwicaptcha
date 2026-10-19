# THREATS

The living output of the automated red-team engine (change.md Part 10).
Generated from the runs ledger by `tools/redteam/engine/ledger.mjs`;
regenerate with the orchestrator. Status GREEN means a recorded run of
the campaign's required result holds under the current seed, the
current target profile and topology, and the current product, harness
and campaign digests; the digests prove which tree a run measured and
the profile and topology prove which deployment shape it measured,
and the recorded result, metrics and economics
are trusted as written (they are not re-measured or signed here) while binding the CURRENT
product, harness and campaign digests (engine/fingerprint.mjs), RED
means it did not, NOT RUN means this environment has no run document
for the campaign (that is not a pass and is never omitted from this
table).

Seed: `0x6b776d74` · Profile: `redis` ·
Topology: `single-primary` · Campaign slots: 17 ·
Recorded runs: 17 · Satisfying the current seed, profile
and digest contract: 0

## Method note

the engine method is recorded per run (see the run documents)

The self-escalation mandate: run 8: no new finding this run: the synthesis escalates (combined clock-skew + scope-confusable, synthesis budget raised to 148)

The closed synthesis loop: the synthesis corpus was consumed end to end: 61 candidates triaged, 61 refuted deterministically (two-run hash gate), 0 findings filed, 0 unstable harnesses, 0 inconclusive, 0 harness errors, 0 classes without a harness

| Attack class | Current economic result | Status | Evidence (actual measured scale) |
| --- | --- | --- | --- |
| D3.1 commodity no-JS bots | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.2 stealth headless | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.3 PoW farm economics | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.4 proxy pools | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5; campaign_fingerprint c6873e1fd14adc4e7d219c372ed16239 != current 63e8c35ca6bfc10dffd9de58c615f229 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5; campaign_fingerprint c6873e1fd14adc4e7d219c372ed16239 != current 63e8c35ca6bfc10dffd9de58c615f229. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.5 credential stuffing | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.6 token brokering | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.7 human solver farms | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.8 AI agents | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.9 risk-engine gaming | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.10 infrastructure attacker | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.11 denial of service | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.12 protocol and parser | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.13 supply chain | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.14 privacy adversary | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.15 multi-tenant | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.16 accessibility and compatibility | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |
| D3.17 cross-SDK parity attack | stale run: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5 | RED | STALE: product_fingerprint 00aab9de9a5492e292b9a7cb7fc6c3cd != current 2c85760ad9a736b0e1fe6b383fb93153; harness_fingerprint 53ec51426e5b9b143e6164239f7a64cc != current 215c2e1673edb7177c37b5f0bbddd5e5. Re-run the campaign against the current tree; a leftover run is never a pass. |

## The bounds the engine holds itself to

- Every campaign states its environment downscale openly; the evidence
  column records the scale that actually ran, and a hash budget is
  never restated as a solve count.
- A campaign without a recorded run is listed NOT RUN with its reason.
  Green is never claimed without a run document.
- Evidence is bound to three digests recorded at run time (product,
  harness, campaign). A run whose digests do not match the current
  tree is STALE, never a pass — a campaign or harness edit invalidates
  old PASS evidence exactly as a product edit does — and the ledger
  never falls back to an older passing run of a different seed or
  shape. A document that predates the digest binding never satisfies.
- Evidence is bound to the deployment shape too: every run document
  records the target profile and the replication topology it measured,
  and the ledger selects only runs recorded under its own profile and
  topology. A document missing those fields predates the binding and
  never satisfies; a mismatch is refused with both values named.
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
