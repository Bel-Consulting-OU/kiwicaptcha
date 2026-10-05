# The red-team program and the LLM engine

The executable harness of change.md Part 9 (the automated red-team
program), Part 10 (the self-hosted LLM red-team engine), and the
keeper of Part 12 (the consistency ledger). This program gates
releases; every campaign is a runnable script with a required-result
assertion and an economic metric against the real repo surfaces.

## Layout

    target.sh                  the 9.2 target environment (five profiles)
    target/router-storage.php  the storage-matrix deployment (sqlite, files)
    target/dual-read-proxy.mjs the stdlib CL/TE dual-read harness
    campaigns/*.sh             one runnable campaign per attack class
    campaigns/lib/             drivers: wire client, store tamper, stuffing
    engine/orchestrator.sh     the Part 10 controller (allowlist, budget)
    engine/recon.mjs           deterministic attack-surface enumeration
    engine/synth.mjs           seeded grammar synthesis, offline first
    engine/model-adapter.mjs   the local-model contract (see below)
    engine/triage.mjs          deterministic two-run reproduction gate
    engine/regression.mjs      the nightly replay of committed findings
    engine/prompts/            pinned prompts (committed, never inline)
    engine/runs/               the runs ledger (one json per campaign run)
    findings/                  committed reproducible findings as tests
    exit-criteria.sh           the 9.5 locally checkable gate, printed

## The target environment

    tools/redteam/target.sh up redis      # the reference deployment
    tools/redteam/target.sh up sentinel   # master + replica + sentinel
    tools/redteam/target.sh up sqlite     # the sqlite adapter path
    tools/redteam/target.sh up files      # the filesystem fallback
    tools/redteam/target.sh up sidecar    # the Rust verifier sidecar
    tools/redteam/target.sh matrix campaigns/d3.10-infrastructure.sh

Every profile is production-equivalent: the same core issuer and
verifier the bundle ships, the same wire contract, real stores. No
profile is a fixture. The sqlite and files profiles run with no Redis
at all (the deployment's budget-0 setting is the limiter off switch).

## Running the battery

    tools/redteam/engine/orchestrator.sh            # full run
    tools/redteam/engine/orchestrator.sh --synth    # with synthesis
    tools/redteam/engine/orchestrator.sh --regression
    tools/redteam/exit-criteria.sh                  # the release gate

Knobs: `KIWI_RT_SEED` (ledger and synthesis pin), `KIWI_RT_SCALE`
(environment downscale multiplier), `KIWI_RT_PROFILE` (target),
`KIWI_RT_BUDGET_MINUTES` and `KIWI_RT_CAMPAIGN_TIMEOUT` (budget),
`KIWI_RT_CAMPAIGNS` (subset). Campaigns state their downscale openly;
the default battery is a laptop-scale envelope of the 9.3 volumes.

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

## Guardrails

- The orchestrator refuses to start unless every target host is
  loopback or private range. There is no override.
- A finding gates only after the repro ran twice with an identical
  transcript hash (engine/triage.mjs); flaky never gates.
- Findings live under tools/redteam/findings/ as reviewable pairs
  (manifest plus executable repro). The regression agent replays the
  corpus; exit-criteria carries the row.
- The runs ledger under engine/runs/ is the auditable record; the
  aggregator (engine/ledger.mjs) generates THREATS.md at the repo root
  and docs/cost-to-abuse.md from it. Both are regenerated artifacts.

## The campaigns

| Campaign | Class | Required result (asserted) |
| --- | --- | --- |
| d3.1-commodity-nojs.sh | D3.1 | zero forged, replayed or omitted tokens accepted; cap admits exactly the budget; honest human control accepted |
| d3.5-credential-stuffing.sh | D3.5 | every attacker denied within 3 of its own attempts; victim step-up exactly once; zero lockouts; wire honest |
| d3.10-infrastructure.sh | D3.10 | eleven tamper classes rejected on every backend; retained marker refuses replay; sentinel failover continuity and stale primary read-only |
| d3.12-protocol-parser.sh | D3.12 | no desync through the nginx chain or the dual-read harness; every parser rejection code; all seven SDK runners green on the shared corpus |
| d3.14-privacy.sh | D3.14 | zero raw identity occurrences in everything persisted; transaction binding only inside records |
| d3.16-accessibility.sh | D3.16 | validators and their mutation corpora green; Playwright a11y lane green; registry truthfulness holds |
| d3.17-cross-sdk-parity.sh | D3.17 | identical rejection across all seven SDKs, direct adversarial drives included |
