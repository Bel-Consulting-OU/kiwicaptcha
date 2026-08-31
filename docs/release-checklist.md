# Release checklist

This checklist is the complete sequence for releasing the public
installation path: publishing the package chain, validating clean-room
Composer resolution, landing the Symfony Flex recipe, and proving the
one-command install on an empty application. Every step states its pass
criteria and its current status. Statuses: not started, in progress,
blocked, done.

## Step 1. Publish the package chain to Packagist

The chain is four packages: `kiwicaptcha/kiwicaptcha-php` (the
framework-neutral PHP core), `kiwicaptcha/kiwicaptcha-risk-php` (the
risk-engine PHP mirror, which requires the PHP core),
`bel-consulting/kiwicaptcha-symfony` (the bundle, which requires both),
and `kiwicaptcha-risk` (the Rust crate, whose registry is crates.io
rather than Packagist).

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

## Step 2. Validate clean-room Composer resolution

In an empty application that shares no files with this repository,
install only from the published packages: remove the path repositories
and run `composer require bel-consulting/kiwicaptcha-symfony`. The
resolution must come entirely from Packagist.

Pass criteria: `composer install` succeeds with no path repositories
and no un-met constraints, and the lock file references the published
packages only.

Status: blocked on step 1.

## Step 3. Get the Symfony recipe QA green

The recipes-contrib validation (Symfony Bot) installs the published
package into the recipe's fixture application, so the upstream QA check
needs the bundle to exist on Packagist first. PR #2038 in
`symfony/recipes-contrib` carries the recipe and is open with
auto-merge enabled; its QA check must turn green.

Pass criteria: the QA check on PR #2038 is green, and the recipe
applies cleanly to the fixture application.

Status: blocked on step 1.

## Step 4. Merge recipes-contrib PR #2038

Merging is a Symfony maintainer action. The PR is open with auto-merge
enabled; it is blocked on Packagist publication (step 1) and on the
upstream QA check (step 3). Once merged, a plain
`composer require bel-consulting/kiwicaptcha-symfony` registers the
bundle, installs the routes, and writes the starter configuration and
the environment placeholders.

Pass criteria: the PR is merged and the recipe is live in
`symfony/recipes-contrib`.

Status: blocked on steps 1 and 3.

## Step 5. Test an empty application through the public instructions

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

Status: blocked on step 4.
