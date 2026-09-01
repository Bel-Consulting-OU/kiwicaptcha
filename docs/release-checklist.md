# Release checklist

This checklist is the complete sequence for releasing the public
installation path: publishing the package chain, validating clean-room
Composer resolution, landing the Symfony Flex recipe, and proving the
one-command install on an empty application. Every step states its pass
criteria and its current status. Statuses: not started, in progress,
blocked, done. It also tracks the governance and operations milestones
that sit outside the publication sequence.

## Step 1. Publish the package chain to Packagist

The chain is four packages: `kiwicaptcha/kiwicaptcha-php` (the
framework-neutral PHP core), `kiwicaptcha/kiwicaptcha-risk-php` (the
risk-engine PHP mirror, which requires the PHP core),
`bel-consulting/kiwicaptcha-symfony` (the bundle, which requires both),
and `kiwicaptcha-risk` (the Rust crate, whose registry is crates.io
rather than Packagist). The Rust crates are published separately on
crates.io (step 2).

Composer release-readiness checks, run on all three Composer packages:

- Version fields: `composer validate --strict` passes; the published
  tag series matches the branch alias (1.0.x for all three Composer
  packages). The bundle-to-risk-mirror constraint is aligned:
  `bel-consulting/kiwicaptcha-symfony` requires
  `kiwicaptcha/kiwicaptcha-risk-php` at `^1.0`, matching the mirror's
  declared 1.0.x-dev branch alias, so a published 1.0.0 satisfies the
  constraint and no second tag series is needed. The path-repository
  version override in this repository pins the risk mirror at 1.0.0,
  the version the Packagist publication will carry; verify the
  released tags satisfy every constraint in the require graph.
- Repository and autoload validity: the PSR-4 roots map to existing
  directories, the `autoload.files` entry
  (`src/Storage/ProcessEmergencyCap.php`) exists, and the path
  repositories under `repositories` are dev-only, never part of the
  published metadata.
- Require graph: the graph resolves from Packagist alone, without any
  path repository. `kiwicaptcha/kiwicaptcha-risk-php` requires
  `kiwicaptcha/kiwicaptcha-php` at `^1.0` and `predis/predis` at
  `^3.5`. `bel-consulting/kiwicaptcha-symfony` requires the PHP core at
  `^1.0`, the risk mirror at `^1.0`, and the Symfony packages. Publish
  the Composer packages bottom-up so every constraint resolves at
  install time.

Pass criteria: each package is listed on Packagist at the expected
version, `composer show -a` returns the release, and the require graph
resolves from Packagist alone. `composer validate --strict` passes on
all three Composer packages.

Status: not started. Publication is a maintainer action on
packagist.org.

## Step 2. Publish the Rust crates to crates.io

The Rust core `kiwicaptcha` declares version 1.7.0 in its Cargo.toml
and has never been published to crates.io; the registry still reports
the name unknown. `kiwicaptcha-risk` declares 0.1.0 and depends on
`kiwicaptcha` at exactly 1.7.0. Publish the core first, then the risk
crate, so the versioned dependency resolves from crates.io alone.

Pass criteria: `cargo publish` succeeds for both crates, the
dependency `kiwicaptcha = { version = "1.7.0" }` resolves from
crates.io without a path override, and docs.rs serves the published
documentation.

Status: not started. Publication is a maintainer action on
crates.io.

## Step 3. Validate clean-room Composer resolution

In an empty application that shares no files with this repository,
install only from the published packages: remove the path repositories
and run `composer require bel-consulting/kiwicaptcha-symfony`. The
resolution must come entirely from Packagist.

Pass criteria: `composer install` succeeds with no path repositories
and no un-met constraints, and the lock file references the published
packages only.

Status: blocked on step 1.

## Step 4. Get the Symfony recipe QA green

The recipes-contrib validation (Symfony Bot) installs the published
package into the recipe's fixture application, so the upstream QA check
needs the bundle to exist on Packagist first. PR #2038 in
`symfony/recipes-contrib` carries the recipe and is open with
auto-merge enabled; its QA check must turn green.

Pass criteria: the QA check on PR #2038 is green, and the recipe
applies cleanly to the fixture application.

Status: blocked on step 1.

## Step 5. Merge recipes-contrib PR #2038

Merging is a Symfony maintainer action. The PR is open with auto-merge
enabled; it is blocked on Packagist publication (step 1) and on the
upstream QA check (step 4). Once merged, a plain
`composer require bel-consulting/kiwicaptcha-symfony` registers the
bundle, installs the routes, and writes the starter configuration and
the environment placeholders.

Pass criteria: the PR is merged and the recipe is live in
`symfony/recipes-contrib`.

Status: blocked on steps 1 and 4.

## Step 6. Test an empty application through the public instructions

Create a completely empty current Symfony application and follow only
the public instructions. Run
`composer require bel-consulting/kiwicaptcha-symfony` and confirm Flex
registers the bundle and applies the recipe. Run
`bin/console kiwicaptcha:doctor`. Render a form with the widget; issue,
solve and verify a challenge. Then uninstall, reinstall and update the
package.

Pass criteria: every step works from the public instructions alone,
with no repository-local knowledge. The doctor reports a clean
environment, the issue-solve-verify round trip ends in a valid
outcome, and the uninstall, reinstall and update cycle leaves a
working installation.

Status: blocked on step 5.

## Tracked governance and operations milestones

These three milestones sit outside the package publication sequence
but are tracked here so the checklist is the complete record of the
open work. Each lists its pass criteria and its current status.

### Milestone A. Dedicated latency runner

Provision the dedicated, isolated latency runner (fixed CPU class,
pinned PHP and Redis, warm-up, p50/p90/p95 recording, variance
limits, base-commit comparison) and flip the hard-latency gate from
the manual dispatch-only job to a required check context on
protected `main`. The stable end state and the operational steps are
documented in the latency-runner sections of
`docs/performance-analysis.md`; the manual job remains the one CI job
skipped on every push and pull_request until then.

Pass criteria: the runner is provisioned and validated, the baselines
are re-recorded on it, and the latency job runs on every push and
pull_request as a required context that blocks only on confident
regressions.

Status: not started.

### Milestone B. Organization-admin bypass hardening

Narrow the protected-main and protected-tag `OrganizationAdmin`
always-bypass to a scoped emergency break-glass identity, with
hardware-backed authentication, audit-log coverage and bypass
alerting, through the rulesets API. The current governance reality,
the recommendation and the concrete narrowing steps are documented
in the governance section of `SECURITY.md`.

Pass criteria: no routine actor holds a permanent always-bypass, the
break-glass identity is scoped and hardware-authenticated, and every
use is audited and alerted.

Status: not started. This is a governance hardening recommendation,
not evidence that releases are currently unsafe; signed release tags
and the release workflow's independent provenance checks remain in
force.

### Milestone C. Independent external security audit

Commission an independent external security audit attacking the full
production surface, with the 100/100 acceptance criterion: every item
of the scope checklist in `SECURITY.md` is attacked, and no finding
rated high or critical is open at closure.

Pass criteria: the audit report covers the full checklist, every
finding has a disposition, and the high and critical bands are
closed.

Status: not started.
