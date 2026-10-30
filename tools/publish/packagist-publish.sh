#!/usr/bin/env bash
# Publish the monorepo's three Composer packages to Packagist via
# dedicated GitHub repositories under Bel-Consulting-OU.
#
# Packagist resolves packages from a public Git repository whose ROOT
# contains composer.json. This monorepo keeps packages in subdirectories
# (and path repositories for local development), so each package is
# exported with `git archive`, path repositories are stripped for the
# published metadata, and the result is pushed as its own repo tagged
# v1.0.0.
#
# Publish order (dependency bottom-up, release-checklist.md step 1):
#   1. kiwicaptcha/kiwicaptcha-php
#   2. kiwicaptcha/kiwicaptcha-risk-php
#   3. bel-consulting/kiwicaptcha-symfony
#
# Requires: gh (authenticated to Bel-Consulting-OU), git, jq, tar.
# Does not require Packagist credentials: after the public repos exist
# with composer.json at the root and a v1.0.0 tag, each package is
# submitted once on packagist.org (or auto-picked up if already
# submitted).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ORG="Bel-Consulting-OU"
VERSION="1.0.0"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kiwi-packagist.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

log() { printf '==> %s\n' "$*"; }

# Strip monorepo path repositories and force stable minimum-stability
# for the published composer.json (path repos are local-dev only per
# release-checklist.md).
sanitize_composer() {
  local file="$1"
  jq '
    del(.repositories)
    | .["minimum-stability"] = "stable"
    | del(.["prefer-stable"])
  ' "$file" > "${file}.tmp"
  mv "${file}.tmp" "$file"
}

# Ensure a LICENSE file exists in the export root.
ensure_license() {
  local dir="$1"
  if [[ ! -f "$dir/LICENSE" ]]; then
    cp "$ROOT/LICENSE" "$dir/LICENSE"
  fi
}

# Export one package: archive from HEAD, sanitize, init git, tag, push.
publish_package() {
  local prefix="$1"
  local repo_name="$2"
  local description="$3"
  local repo="${ORG}/${repo_name}"
  local export_dir="$WORK/$repo_name"

  log "export ${prefix} → ${repo}@${VERSION}"

  mkdir -p "$export_dir"
  git -C "$ROOT" archive "HEAD:${prefix}" | tar -x -C "$export_dir"
  sanitize_composer "$export_dir/composer.json"
  ensure_license "$export_dir"

  # Fail closed: the published root must be a valid composer package.
  (cd "$export_dir" && composer validate --strict --no-check-publish)

  # Create or reuse the public GitHub repository.
  if ! gh repo view "$repo" >/dev/null 2>&1; then
    gh repo create "$repo" \
      --public \
      --description "$description" \
      --homepage "https://github.com/${ORG}/kiwicaptcha"
  fi

  gh repo edit "$repo" \
    --description "$description" \
    --homepage "https://github.com/${ORG}/kiwicaptcha" \
    --add-topic packagist \
    --add-topic composer \
    --add-topic captcha \
    --add-topic proof-of-work \
    --add-topic php \
    --delete-branch-on-merge=false >/dev/null 2>&1 || true

  git -C "$export_dir" init -b main >/dev/null
  git -C "$export_dir" config user.name "sbelakho2"
  git -C "$export_dir" config user.email "sbelakho2@users.noreply.github.com"
  git -C "$export_dir" add -A
  git -C "$export_dir" commit -m "Release ${VERSION}" >/dev/null
  git -C "$export_dir" tag -a "v${VERSION}" -m "v${VERSION}"

  git -C "$export_dir" push -f "https://github.com/${repo}.git" main "v${VERSION}"

  log "published ${repo} v${VERSION}"
  log "submit: https://packagist.org/packages/submit?url=https://github.com/${repo}"
}

log "working tree: $(git -C "$ROOT" rev-parse --short HEAD)"

publish_package \
  "packages/kiwicaptcha-php" \
  "kiwicaptcha-php" \
  "KiwiCaptcha PHP core: privacy-first, self-hosted proof-of-work anti-abuse engine for PHP 8.1+"

publish_package \
  "packages/kiwicaptcha-risk-php" \
  "kiwicaptcha-risk-php" \
  "KiwiCaptcha Adaptive Risk Engine for PHP: self-hosted risk scoring for proof-of-work issuance"

publish_package \
  "packages/kiwicaptcha/integrations/symfony" \
  "kiwicaptcha-symfony" \
  "Self-contained Symfony bundle for KiwiCaptcha proof-of-work CAPTCHA (no external services, no tracking)"

log "all three package repositories are public and tagged v${VERSION}"
log "next: submit each repo on packagist.org (or confirm auto-update once submitted)"
