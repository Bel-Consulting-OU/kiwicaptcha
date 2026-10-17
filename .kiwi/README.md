# Kiwi-CI pipelines

Kiwi-CI is the repository's continuous-integration engine. The
pipelines are plain YAML under this directory:

| File | Trigger | Contents |
|------|---------|----------|
| `pipeline.yaml` | push, pull request | The functional matrix: lint, PHP core and matrix, Symfony, risk, Rust, browser, Redis lanes, cross-language, build reproducibility, packaging, the reference deployment, every server SDK, every browser wrapper, the platform integrations, the verifier Redis feature, WASM, iOS compile, Flutter, the feature inventory, and the aggregate `promotion-gate` job. |
| `release.yaml` | tags matching `v*` | The strict rebuild, committed-byte equality, release manifests, the asset contract and the three release-validator gates. It needs `GITHUB_TOKEN` and `GITHUB_REPOSITORY` for the two remote release checks. |
| `manual.yaml` | none (run explicitly) | The asset regeneration, public-install (crates.io and Packagist), quiet latency and paired latency-regression lanes. Run one with `kiwi run -f .kiwi/manual.yaml --job <name>`. |

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

- **`kiwi run` inherits the host environment by default.** Use
  `--no-inherit-env` for a clean-environment run; with inheritance, a
  host locale that the image does not carry produces a harmless
  `setlocale` warning.
- **Repo metadata in local runs.** `KIWI_GIT_SHA`, `KIWI_GIT_REF` and
  `KIWI_GIT_BRANCH` are populated; `KIWI_REPO` and `KIWI_REPO_FULL` are
  empty for a local run. The release pipeline therefore takes
  `GITHUB_REPOSITORY` and `GITHUB_TOKEN` from the environment.

## Migration notes from the Woodpecker pipelines

The push/PR and release pipelines were imported from the former
Woodpecker workflows and then adapted:

- The importer does not expand YAML anchors/aliases, so the repeated PHP
  matrix steps imported empty. The source workflows were pre-expanded
  before import.
- The importer maps every Woodpecker step to a separate Kiwi job, but
  Kiwi jobs have isolated workspaces. Workflows whose steps pass files
  to one another (cross-language interop, the reference deployment, the
  public-install journeys, the release build, latency lanes) are single
  Kiwi jobs with several steps.
- Services are converted by image only; custom service `commands` are
  not. The Redis sidecars use the image's default entrypoint, which
  serves the same port and data directory the workflows need.
- Woodpecker's `$$` escape is preserved by the importer. The pipeline
  text normalizes it to a single `$` because Kiwi hands the command to
  the shell unchanged (a literal `$$` would be the shell's PID).
- The local workspace snapshot omits tracked paths under a directory
  named `target/`, which collides with `tools/redteam/target/`. The
  lint lane restores that path from the checkout before the
  tracked-deletion guard runs. A runner that snapshots from git does not
  need the restoration.
- The lint lane excludes the local Elixir `deps/` tree from the prose
  scan: it is third-party source and absent on a clean checkout.
- The reference-deployment lane runs with `runtime: native` because a
  container job cannot reach the host Docker socket (Kiwi's local
  workflow guard refuses Docker-socket mounts). It therefore requires a
  runner with a working Docker CLI.
- The iOS job compiles the package and parses the XCTest target. The
  XCTest execution needs a full Xcode, which a local CommandLineTools
  runner does not have; the macOS GitHub lane runs the tests.
- The Woodpecker `when.event` filters for `tag` and `manual` have no
  direct Kiwi trigger equivalent, which is why the release and manual
  lanes live in their own files rather than sharing `pipeline.yaml`.
