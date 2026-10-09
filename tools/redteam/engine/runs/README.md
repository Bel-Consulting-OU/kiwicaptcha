# runs/ — per-invocation campaign evidence

Each campaign writes one JSON document per run:
`<UTC timestamp>-<campaign>-seed-<seed>.json`. The ledger
(`../ledger.mjs`) reads the latest document per campaign and
regenerates `THREATS.md` and `docs/cost-to-abuse.md`.

These documents are **CI artifacts, not source**:

- A fresh battery stamps a new timestamp on every campaign.
- Every commit that touches `packages/`, `protocol/`, or
  `integrations-platforms/` changes the source fingerprint, which
  makes every previously written document STALE (see
  `../fingerprint.mjs`).

Day to day the directory stays out of the index (`.gitignore`). A
tagged release force-adds the single battery that ships with it:

```sh
git add -f tools/redteam/engine/runs/<timestamp>-*.json
```

`escalations.json` is cumulative engine state (the self-escalation
knob the exit-criteria gate reads) and is tracked.

The writer (`../write-run.mjs`) refuses to write outside this
directory: a shifted argv must never scatter campaign-named files
across the working directory.
