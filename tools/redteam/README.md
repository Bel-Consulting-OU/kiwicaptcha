# The red-team program and the LLM engine

The executable harness of change.md Part 9 (the automated red-team
program), Part 10 (the self-hosted LLM red-team engine), and the
keeper of Part 12 (the consistency ledger). This program gates
releases; every campaign is a runnable script with a required-result
assertion and an economic metric against the real repo surfaces.

## Layout

    target.sh                  the 9.2 target environment (five profiles)
    cluster.sh                 the B7.2 leg: a real three-primary cluster
                               and the gated cluster suites
    target/router-storage.php  the storage-matrix deployment (sqlite, files)
    target/dual-read-proxy.mjs the stdlib CL/TE dual-read harness
    campaigns/*.sh             one runnable campaign per attack class,
                               all seventeen slots of the 9.3 list
    campaigns/lib/             drivers: wire client, store tamper, the
                               stealth browser harness, the risk-engine
                               drivers, the supply-chain legs, the
                               step-up and verified-agent drivers
    engine/orchestrator.sh     the Part 10 controller (allowlist, budget,
                               escalation, triage)
    engine/recon.mjs           deterministic attack-surface enumeration
    engine/synth.mjs           seeded grammar synthesis, offline first
    engine/model-adapter.mjs   the local-model contract plus the
                               documented CI no-op novelty scorer
    engine/harness-library.mjs the candidate class to harness mapping
    engine/repros/             the deterministic repro harnesses the
                               triage gate drives twice per candidate
    engine/escalate.mjs        the self-escalation mandate, provable
                               from engine/runs/escalations.json
    engine/triage.mjs          the two-run reproduction gate over the
                               consumed candidate corpus
    engine/regression.mjs      the nightly replay of committed findings
    engine/prompts/            pinned prompts (committed, never inline)
    engine/runs/               the runs ledger (one json per run), the
                               triage reports, the escalation ledger
    findings/                  committed reproducible findings as tests
    tla/                       the PlusCal-checked consume/commit spec,
                               the vendored tla2tools, the TLC runner
    exit-criteria.sh           the 9.5 gate: every criterion measured,
                               the honest table, no excuse rows

## The target environment

    tools/redteam/target.sh up redis      # the reference deployment
    tools/redteam/target.sh up sentinel   # master + replica + sentinel
    tools/redteam/target.sh up sqlite     # the sqlite adapter path
    tools/redteam/target.sh up files      # the filesystem fallback
    tools/redteam/target.sh up sidecar    # the Rust verifier sidecar
    tools/redteam/cluster.sh suites       # the three-primary cluster leg

Every profile is production-equivalent: the same core issuer and
verifier the bundle ships, the same wire contract, real stores. No
profile is a fixture. The sqlite and files profiles run with no Redis
at all (the deployment's budget-0 setting is the limiter off switch).

## The campaigns

| Campaign | Class | Required result (asserted) |
| --- | --- | --- |
| d3.1-commodity-nojs.sh | D3.1 | zero forged, replayed or omitted tokens accepted; cap admits exactly the budget; honest human control accepted |
| d3.2-stealth-headless.sh | D3.2 | the stealth bootstrap solves at scale through the real verifier; the decoy is never in page source and stays per-challenge polymorphic; spoofed telemetry scores as evidence; marked sessions are denied |
| d3.3-pow-economics.sh | D3.3 | the measured value-class table with per-row verdicts against the declared abuse values (the rows feed the gate verbatim); the RSW suite pins sequential squaring |
| d3.4-proxy-pools.sh | D3.4 | 10^4 addresses over 512 listed ASNs plus the unknown buckets: ASN and target dimensions catch it, the scope failure ratio fires, per-source budgets hold, CGNAT neighbors stay bounded by their own price |
| d3.5-credential-stuffing.sh | D3.5 | 10^5 leaked-list rows, one attempt each: step-up within 5 spread failures, zero lockouts, attackers denied within 3 of their own attempts, the local breached-password corpus blocks every breached-valid login |
| d3.6-token-brokering.sh | D3.6 | zero cross-scope, cross-binding or cross-node acceptance; the in-TTL replay dies at the consumed marker; stockpiles hit exactly the cap; the hostile embed reads nothing |
| d3.7-solver-farms.sh | D3.7 | the relayed TOTP code completes exactly once (stated residual), the replay guard and rate bounds cap the farm; WebAuthn refuses the phishing origin end to end |
| d3.8-ai-agents.sh | D3.8 | the scripted agent priced and escalated; the RFC 9421 verified agent 100% within quota and 0% after revocation |
| d3.9-risk-gaming.sh | D3.9 | farmed trust never crosses ASNs; edge riding selects the stable action; the forged label flood moves the bias at most 1 point; churn starts untrusted; the shared-network victim stays at its own price |
| d3.10-infrastructure.sh | D3.10 | eleven tamper classes rejected on every backend; retained marker refuses replay; sentinel failover continuity and stale primary read-only |
| d3.11-dos.sh | D3.11 | the argon verifier never overspends on garbage (cheap-phase p99 stated); floods and probe storms bounded at 5x baseline; oversized records refused; the hysteresis map stays bounded |
| d3.12-protocol-parser.sh | D3.12 | no desync through the nginx chain or the dual-read harness; every parser rejection code; all seven SDK runners green on the shared corpus |
| d3.13-supply-chain.sh | D3.13 | the byte-flipped driver never executes on either interception layer; the widget survives prototype pollution and clobbering; the CSP suites re-driven green |
| d3.14-privacy.sh | D3.14 | zero raw identity occurrences in everything persisted; transaction binding only inside records |
| d3.15-multi-tenant.sh | D3.15 | the digest namespace derivation injective over the crafted corpus; zero cross-tenant reads, zero cross-tenant replay with the same secret; the legacy fold asserted as the documented hazard |
| d3.16-accessibility.sh | D3.16 | validators and their mutation corpora green; Playwright a11y lane green; registry truthfulness holds |
| d3.17-cross-sdk-parity.sh | D3.17 | identical rejection across all seven SDKs, direct adversarial drives included |

## Running the battery

    tools/redteam/engine/orchestrator.sh            # full run
    tools/redteam/engine/orchestrator.sh --synth    # with synthesis and triage
    tools/redteam/engine/orchestrator.sh --regression
    tools/redteam/exit-criteria.sh                  # the release gate

Knobs: `KIWI_RT_SEED` (ledger and synthesis pin), `KIWI_RT_SCALE`
(environment downscale multiplier), `KIWI_RT_PROFILE` (target),
`KIWI_RT_BUDGET_MINUTES` and `KIWI_RT_CAMPAIGN_TIMEOUT` (budget),
`KIWI_RT_CAMPAIGNS` (subset). Campaigns state their downscale openly;
the default battery is a laptop-scale envelope of the 9.3 volumes.

Every campaign reserves its own loopback ports; the auxiliaries live
in the 6470-6479 band (the campaign headers carry the exact map) and
never touch the product's ports.

## The local-model adapter (change.md Part 10.1)

The engine is deterministic offline first: nothing calls a model
unless the operator explicitly exports `KIWI_RT_LOCAL_LLM_URL`. The
adapter (engine/model-adapter.mjs) speaks four shapes:

| `KIWI_RT_LOCAL_LLM_KIND` | Runtime | Endpoint | Response field |
| --- | --- | --- | --- |
| `llamacpp` | llama.cpp server | POST `{url}/completion` | `content` |
| `vllm` | vLLM OpenAI-compatible | POST `{url}/v1/completions` | `choices[0].text` |
| `ollama` | Ollama | POST `{url}/api/generate` | `response` |
| `openai` | any OpenAI-compatible chat host you own | POST `{url}/v1/chat/completions` | `choices[0].message.content` |

`KIWI_RT_LOCAL_LLM_MODEL` names the local model where the runtime
needs one. Temperature is pinned to 0 and the seed to the run seed;
the prompt is the pinned file under engine/prompts/ with the seed
substituted. The adapter resolves the host and refuses anything
outside the loopback and private ranges, as does the orchestrator
before it starts anything. Model output is parsed as candidate
descriptions and never executed; the deterministic triage gate still
decides what becomes a finding.

In CI mode (no `KIWI_RT_LOCAL_LLM_URL`) the adapter is the documented
no-op: candidate novelty is scored deterministically from the surface
map and the run history, the orchestrator logs that no model is
configured, and THREATS.md's method note carries the same honest line.

## The closed synthesis loop

synth.mjs emits the structured candidate corpus; triage.mjs consumes
every candidate, maps its class through engine/harness-library.mjs to
the real repro harness, runs the harness twice, and files a finding
only when a REPRODUCED verdict survives the two-run transcript hash
gate. Refutations are recorded with their evidence hash. When a run
files nothing, engine/escalate.mjs combines two prior technique
labels (seeded) and raises the synthesis budget knob; the escalation
ledger at engine/runs/escalations.json makes the mandate provable.

## Guardrails

- The orchestrator refuses to start unless every target host is
  loopback or private range. There is no override flag.
- A finding gates only after the repro ran twice with an identical
  transcript hash (engine/triage.mjs); flaky never gates.
- Findings live under tools/redteam/findings/ as reviewable pairs
  (manifest plus executable repro). The regression agent replays the
  corpus; exit-criteria carries the row.
- The runs ledger under engine/runs/ is the auditable record; the
  aggregator (engine/ledger.mjs) generates THREATS.md at the repo root
  and docs/cost-to-abuse.md from it. Both are regenerated artifacts.

## The honest gate

exit-criteria.sh fails on any red, including the repository's own
gates; there are no RED-REPO excuse rows. A criterion the toolchain
cannot run prints TOOLCHAIN-ABSENT with the exact blocker and closes
the gate (that is non-green by default). The table it prints carries
the measured values: the value-class verdicts, the D3.5 outcomes, the
live confirmed-legitimate probe (100 honest solves), the verified
agent facts, the TLC model-checking result, the bounded fuzz passes
(N stated), the real cluster leg, and the campaign battery results.
