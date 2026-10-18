# Kiwi-CI pipelines

Kiwi-CI is the repository's continuous-integration engine. The
pipelines are plain YAML under this directory:

| File | Trigger | Contents |
|------|---------|----------|
| `pipeline.yaml` | push, pull request | The functional matrix: lint, the PHP core matrix, Symfony, risk, Rust, browser, Redis lanes, cross-language interop, build reproducibility, packaging, the reference deployment, every server SDK, every browser wrapper, the platform integrations, the verifier Redis feature, WASM, iOS compile, Flutter, the feature inventory, and the aggregate `promotion-gate` job. |
| `release.yaml` | tags matching `v*` | The strict rebuild, committed-byte equality, release manifests, the asset contract and the three release-validator gates. The GitHub token is the `github_token` step secret, exposed as `KIWI_SECRET_GITHUB_TOKEN`. |
| `manual.yaml` | none (run explicitly) | Asset regeneration, public-install (crates.io and Packagist), quiet latency and paired latency-regression lanes. Run one with `kiwi run -f .kiwi/manual.yaml --job <name>`. |

## Running

```sh
kiwi validate -f .kiwi/pipeline.yaml
kiwi validate -f .kiwi/release.yaml
kiwi validate -f .kiwi/manual.yaml
kiwi run -f .kiwi/pipeline.yaml --job feature-inventory
kiwi run -f .kiwi/pipeline.yaml --max-parallel 4
```

Each job runs in an isolated workspace snapshot, so a local run never
touches the working tree.

## By-design constraints

- **Container jobs never see `docker.sock`.** The reference deployment
  uses `runtime: native` and needs a runner with a working Docker CLI.
- **macOS Docker needs a shared temporary root.** Set
  `TMPDIR=$HOME/kiwi-tmp` (or another Docker-shared path) and run with
  `--no-inherit-env`, otherwise the container's workspace mount is
  empty and the host `TMPDIR` leaks into the job.
- **Alpine jobs default to `sh`.** Non-Alpine images use `bash`.
- **iOS XCTest stays on the macOS GitHub lane.** The Kiwi job compiles
  the package and parses the XCTest target; a local CommandLineTools
  runner has no XCTest.

## Pipeline construction notes

- The Woodpecker importer merges every step of a workflow into one job
  and, when the steps name different images, keeps the first image and
  warns. Mixed-image workflows (the PHP matrix, Symfony, risk, Redis 8,
  packaging, release tools and the SDKs) are therefore built per step;
  same-image workflows are one job with several steps so they keep the
  shared workspace.
- Services keep their image and optional `command` list; the Redis
  sidecars keep their explicit `redis-server` command.
- Woodpecker's `$$` escape is normalized to `$`.
- Kiwi injects `CI_COMMIT_SHA` and `CI_REPO` (owner/name). The
  remaining legacy names are synthesized per step: `CI_WORKSPACE` is the
  container's `$PWD`, `CI_COMMIT_TAG` is derived from `KIWI_GIT_REF`,
  and the before/target SHAs are empty so the baseline-integrity lane
  uses `HEAD^` when history is available.
- The local snapshot includes tracked `target/` and `dist/` paths but
  carries a `.git` worktree pointer to an unmounted host path, so git
  history is unavailable in local container jobs. The docs-lint
  integrity lane skips with an explicit message when git is unusable;
  the n1-compatibility lane clones the repository from `CI_REPO` in that
  case.
- `when.event` filters for `tag` and `manual` have no direct Kiwi
  trigger equivalent, so the release and manual lanes live in their own
  files rather than sharing `pipeline.yaml`.
