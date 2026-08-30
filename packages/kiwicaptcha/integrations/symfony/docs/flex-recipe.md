# Flex recipe (template)

This directory is the template of the Symfony Flex recipe for
`bel-consulting/kiwicaptcha-symfony`. A published recipe lets a plain
`composer require bel-consulting/kiwicaptcha-symfony` register the
bundle, install the routes, drop in a starter configuration with a
protection profile, and add the environment placeholders.

## What the template contains

| Path | Purpose |
|------|---------|
| `manifest.json` | The recipe manifest: the bundle registration (`bundles`), the files copied into the app (`copy-from-recipe`) and the environment placeholders (`env`). |
| `config/packages/kiwicaptcha.yaml` | Starter configuration: `protection_profile: balanced`, the `KIWI_SECRET_KEY` placeholder, the canonical `KIWI_PUBLIC_URL` origin, and the commented production storage lines. |
| `config/routes/kiwicaptcha.yaml` | Explicit import of the bundle's routes (the extension also auto-prepends them on apps that never configured `framework.router` themselves). |
| `.env` | The environment placeholders as a reference for manual setups (the recipe itself declares them in `manifest.json` under `env`). |

## How recipes work

Symfony Flex fetches recipes from two public repositories:
[`symfony/recipes`](https://github.com/symfony/recipes) (official) and
[`symfony/recipes-contrib`](https://github.com/symfony/recipes-contrib)
(community, opt-in via `extra.symfony.allow-contrib`). A recipe lives at
`<vendor>/<package>/<version>/manifest.json` in the repository, next to
the files it installs. When the package is installed, Flex reads the
matching manifest, registers the bundles, copies the recipe files into
the app, and appends the declared environment variables to `.env`.

## Publishing (maintainer action)

Until the recipe is merged into `symfony/recipes-contrib`, it is a
template: `composer require` alone applies nothing. Publishing is a
maintainer action:

1. Create a pull request against `symfony/recipes-contrib` adding
   `bel-consulting/kiwicaptcha-symfony/<version>/` containing this
   `manifest.json` plus the `config/` tree.
2. Keep the version directory in sync with the package releases; a new
   recipe version is only needed when the files or the env keys change.
3. Mention the package's `type: symfony-bundle` and the PSR-4 namespace
   in the PR description so the reviewer can verify the auto-generated
   fallback (see below) against the recipe.

Recipes are reviewed by the Symfony maintainers. Until publication, the
recipe's effect is the same as the manual steps below.

## Bundle auto-registration

The bundle does not need a composer `extra` key for registration. Flex
generates an "auto-generated recipe" for bundles without a published
recipe: it scans the package's PSR-4 namespaces and registers the class
`BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle` (a file named
`KiwiCaptchaBundle.php` in `src/` extending
`Symfony\Component\HttpKernel\Bundle\Bundle`). The published recipe
declares the same registration explicitly in `manifest.json`, which is
the canonical route once the recipe exists.

## Manual equivalent

Without the recipe, the steps are the same as
[docs/getting-started.md](getting-started.md):

1. `composer require bel-consulting/kiwicaptcha-symfony` (adds the
   bundle; Flex registers it via the auto-generated recipe).
2. Copy the `.env` placeholders into your `.env` and set a real random
   value for `KIWI_SECRET_KEY` (`openssl rand -hex 32`).
3. Copy `config/packages/kiwicaptcha.yaml` into your app, or write the
   configuration by hand: choose a `protection_profile`, point
   `secret_key` at `%env(KIWI_SECRET_KEY)%`, set `public_base_url` to
   your canonical origin, and wire a shared Redis storage for
   production.
4. Import the routes (`config/routes/kiwicaptcha.yaml`) if your app
   configures `framework.router` itself.
5. Include the widget on a form or in a template
   (see getting-started).
6. Run `bin/console kiwicaptcha:doctor` and resolve every failed check before
   going live.
