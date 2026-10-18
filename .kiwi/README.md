# Kiwi-CI pipelines

Kiwi-CI is the repository's continuous-integration engine. The
pipelines are plain YAML under this directory:

| File | Trigger | Contents |
|------|---------|----------|
| `pipeline.yaml` | push, pull request | The functional matrix: lint, the PHP core matrix, Symfony, risk, Rust, browser, Redis lanes, cross-language interop, build reproducibility, packaging, the reference deployment, every server SDK, every browser wrapper, the platform integrations, the verifier Redis feature, WASM, iOS compile, Flutter, the feature inventory, and the aggregate `promotion-gate` job. |
| `release.yaml` | tags matching `v*` | The strict rebuild, committed-byte equality, release manifests, the asset contract and the three release-validator gates. The GitHub token is declared as the `github_token` step secret, which Kiwi exposes as `KIWI_SECRET_GITHUB_TOKEN`. |
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

## Local-run notes

- **Container workspaces must be on a Docker-shared path.** On macOS,
  Docker Desktop does not share `/var/folders`, so Kiwi's default
  temporary workspace appears empty inside the container. Point the
  temporary directory at the home directory (or another shared path):

  ```sh
  mkdir -p "$HOME/kiwi-tmp"
  TMPDIR="$HOME/kiwi-tmp" kiwi run -f .kiwi/pipeline.yaml --job <name>
  ```

- **Use `--no-inherit-env` for a clean job environment.** With the
  default environment inheritance, the host `TMPDIR` reaches the
  container, where that path does not exist.
- **Workspace metadata.** Kiwi exposes `KIWI_GIT_SHA`, `KIWI_GIT_REF`,
  `KIWI_GIT_BRANCH`, `KIWI_WORKSPACE`, `KIWI_REPO` and
  `KIWI_REPO_FULL`. The generated pipeline maps them onto the legacy
  `CI_*` names the imported scripts read; `CI_WORKSPACE` is the
  container's `$PWD`, never the host workspace path.

## Pipeline construction notes

- The Woodpecker importer merges every step of a workflow into one job
  and, when the steps name different images, keeps the first image and
  warns. Mixed-image workflows (the PHP matrix, Symfony, risk, Redis 8,
  packaging, release tools and the SDKs) are therefore built per step;
  same-image workflows are one job with several steps so they keep the
  shared workspace.
- Services are converted with their image and optional `command` list.
  The Redis sidecars keep their explicit `redis-server` command.
- Woodpecker's `$$` escape is normalized to `$`; the container shells
  are `sh` on Alpine images and `bash` elsewhere.
- The reference-deployment lane runs with `runtime: native` because a
  container job cannot reach the host Docker socket. It requires a
  runner with a working Docker CLI.
- The local snapshot omits tracked paths under build-looking directory
  names (`target/`, `dist/`) and normalizes a few files. The lint lane
  restores the tracked tree with `git checkout -- .` before the
  release-asset contract's deletion guard runs.
- The iOS job compiles the package and parses the XCTest target. XCTest
  execution needs a full Xcode, which a local CommandLineTools runner
  does not have; the macOS GitHub lane runs the tests.
- `when.event` filters for `tag` and `manual` have no direct Kiwi
  trigger equivalent, so the release and manual lanes live in their own
  files rather than sharing `pipeline.yaml`.
