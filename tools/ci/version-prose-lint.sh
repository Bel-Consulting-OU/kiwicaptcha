#!/usr/bin/env bash
# tools/ci/version-prose-lint.sh - stale execution-version and bypass
# governance prose ratchet
#
# Usage:
#   bash tools/ci/version-prose-lint.sh
#
# Scans SECURITY.md, packages/ and docs/ (any CHANGELOG* is excluded,
# as are vendor, node_modules and target trees) and exits 1 on any
# match of the banned stale claims:
#
#   - the maximum execution-program version is claimed to be 2
#     (live value is higher; the canonical constant is the authority),
#   - the readiness floor is claimed as min_protocol_version <= 3
#     (the live floor contract is the v4-capable binary max),
#   - a version-2 capability is claimed to be the strongest grammar,
#   - prose asserts that an OrganizationAdmin always-bypass is live
#     (the rulesets carry empty bypass lists; a present-tense claim
#     that an org-admin bypass is in place is a stale claim; explicit
#     negations and removal records such as "is REMOVED" or "no actor
#     holds a bypass" are not claims of a live bypass).
#
# The ratchet is calibrated to the exact stale strings the governance
# review found, so any reintroduction anywhere in the scan roots fails
# CI immediately.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

# Optional ripgrep for multiline-capable searching; plain grep -rE
# otherwise (the patterns below are single-line by construction).
if command -v rg >/dev/null 2>&1; then
  search() { rg -n -i --glob '!**/vendor/**' --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/CHANGELOG*' "$@" || true; }
else
  search() {
    local pattern="$1"
    shift
    grep -rInE "$pattern" "$@" --exclude-dir=vendor --exclude-dir=node_modules --exclude-dir=target --exclude='*CHANGELOG*' || true
  }
fi

hits=0
report() {
  hits=1
  echo "version-prose-lint: $1"
}

# 1. maximum execution-program version claimed as 2.
matches="$(
  search 'maximum[[:space:]]+execution-?program[[:space:]]+version:[[:space:]]+2([^0-9]|$)' \
    "$repo_root/SECURITY.md" "$repo_root/packages" "$repo_root/docs"
)"
if [ -n "$matches" ]; then
  report "stale claim: the maximum execution-program version is 2 (the live max is higher)"
  printf '%s\n' "$matches"
fi

# 2. readiness floor claimed as min_protocol_version <= 3.
matches="$(
  search 'min_protocol_version[[:space:]]*<=[[:space:]]*3([^0-9]|$)' \
    "$repo_root/SECURITY.md" "$repo_root/packages" "$repo_root/docs"
)"
if [ -n "$matches" ]; then
  report "stale claim: min_protocol_version <= 3 (the live floor contract is the v4-capable binary max)"
  printf '%s\n' "$matches"
fi

# 3. a version-2 capability claimed as the strongest grammar.
matches="$(
  search 'version[- ]2[- ]capability.*strongest' \
    "$repo_root/SECURITY.md" "$repo_root/packages" "$repo_root/docs"
)"
if [ -n "$matches" ]; then
  report "stale claim: a version-2 capability is the strongest grammar (version 2 is not the strongest any more)"
  printf '%s\n' "$matches"
fi

# 4. prose asserting a live OrganizationAdmin always-bypass: the line
# must pair an org-admin actor with a bypass term AND carry a
# present-tense liveness marker, and must not itself negate the claim
# (no, not, without, removed, empty, never, none) on the same line.
# The liveness and negation filters run on the content portion only
# (after the path:line prefix), so file names never decide a verdict.
candidates="$(
  search '(OrganizationAdmin|organization[[:space:]-]?admin|org[[:space:]-]?admin).*(always[- ]?bypass|bypass)' \
    "$repo_root/SECURITY.md" "$repo_root/packages" "$repo_root/docs"
)"
while IFS= read -r line; do
  [ -n "$line" ] || continue
  content="${line#*:*:}"
  if ! grep -qiE '(^|[^A-Za-z])no[[:space:]]|not[[:space:]]|without|removed?|removal|empty|never|none|no-?one|must[[:space:]]' <<<"$content"; then
    if grep -qiE '(^|[^A-Za-z])(is|are|remains?|remained|still|currently|holds?|hold|granted|live|active|enabled|present|in place|exists?|kept|retained|permanent|always)([^A-Za-z]|$)' <<<"$content"; then
      report "stale claim: an OrganizationAdmin always-bypass is described as live"
      printf '%s\n' "$line"
    fi
  fi
done <<<"$candidates"

if [ "$hits" -ne 0 ]; then
  echo "version prose lint FAILED: stale claims found (see above)" >&2
  exit 1
fi

echo "version prose lint PASS: no stale execution-version or bypass-governance claims in SECURITY.md, packages/, docs/"
