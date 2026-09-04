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
# Group 5 bans stale CURRENT claims about the live execution-grammar
# ladder (the generator's maximum is ExecutionChallengeGenerator::
# MAX_EXECUTION_VERSION / execution::MAX_EXECUTION_VERSION, today 4):
#
#   - "execution version ... exactly 1" (also spelled as
#     "execution_version ... exactly 1"), e.g. "the canonical numeric
#     byte: exactly 1",
#   - "execution_version ... 1 or 2",
#   - "maximum execution version 2" / "maximum execution version 3",
#   - "future version-4" / "future v4" (version 4 is live),
#   - bare "versions? 1..3" describing the supported set,
#   - "v1/v2/v3" describing the supported set.
#
# A file whose content carries the marker
#   historical-compat fixture:
# in any line comment is exempt from group 5: that marker is the
# convention for deliberately frozen N-1 compatibility fixtures whose
# prose must keep describing an older ladder (e.g. a fixture that pins
# the v1..v3 decode fences). Historical narrative in CHANGELOGs is
# excluded by the CHANGELOG glob above; past-tense history elsewhere
# must stay clear of the group-5 phrases, which are reserved for
# present-tense claims about the supported set.
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

# The scan roots shared by every group.
scan_roots=("$repo_root/SECURITY.md" "$repo_root/packages" "$repo_root/docs")

# File-level historical-compat marker: a file carrying this string in
# its content is a deliberately frozen compatibility fixture and is
# exempt from the group-5 ladder patterns only (groups 1-4 still
# apply). See the header for the convention.
compat_marker='historical-compat fixture:'

# Drop every match whose file carries the historical-compat marker.
drop_compat_files() {
  local line file
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    file="${line%%:*}"
    if [ -n "$file" ] && [ -f "$file" ] && ! grep -qF "$compat_marker" "$file"; then
      printf '%s\n' "$line"
    fi
  done
}

# 1. maximum execution-program version claimed as 2.
matches="$(
  search 'maximum[[:space:]]+execution-?program[[:space:]]+version:[[:space:]]+2([^0-9]|$)' "${scan_roots[@]}"
)"
if [ -n "$matches" ]; then
  report "stale claim: the maximum execution-program version is 2 (the live max is higher)"
  printf '%s\n' "$matches"
fi

# 2. readiness floor claimed as min_protocol_version <= 3.
matches="$(
  search 'min_protocol_version[[:space:]]*<=[[:space:]]*3([^0-9]|$)' "${scan_roots[@]}"
)"
if [ -n "$matches" ]; then
  report "stale claim: min_protocol_version <= 3 (the live floor contract is the v4-capable binary max)"
  printf '%s\n' "$matches"
fi

# 3. a version-2 capability claimed as the strongest grammar.
matches="$(
  search 'version[- ]2[- ]capability.*strongest' "${scan_roots[@]}"
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
  search '(OrganizationAdmin|organization[[:space:]-]?admin|org[[:space:]-]?admin).*(always[- ]?bypass|bypass)' "${scan_roots[@]}"
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

# 5. stale CURRENT claims about the live execution-grammar ladder
# (version 4 is live; the generator maximum is the authority). Files
# carrying the historical-compat marker are exempt.
ladder_matches="$(
  search \
    -e 'future[[:space:]]+version-4' \
    -e 'future[[:space:]]+v4' \
    -e 'execution[-_ ]version[^.!?]{0,80}exactly[[:space:]]+1([^0-9]|$)' \
    -e 'execution_version[^.!?]{0,60}1 or 2([^0-9]|$)' \
    -e 'execution-dimension[^.!?]{0,60}exactly[[:space:]]+1([^0-9]|$)' \
    -e 'the canonical numeric byte[^.!?]{0,30}exactly[[:space:]]+1([^0-9]|$)' \
    -e 'maximum[[:space:]]+execution[[:space:]]+version[[:space:]]+2([^0-9]|$)' \
    -e 'maximum[[:space:]]+execution[[:space:]]+version[[:space:]]+3([^0-9]|$)' \
    -e '(versions?|version)[[:space:]]+1\.\.3([^0-9.]|$)' \
    -e 'v1/v2/v3' \
    "${scan_roots[@]}"
)"
ladder_matches="$(printf '%s\n' "$ladder_matches" | drop_compat_files)"
if [ -n "$ladder_matches" ]; then
  report "stale claim: the live execution-grammar ladder is described with a frozen 1..3-era phrase (the live maximum is MAX_EXECUTION_VERSION, today 4; mark frozen N-1 fixtures with 'historical-compat fixture:' to exempt them)"
  printf '%s\n' "$ladder_matches"
fi

if [ "$hits" -ne 0 ]; then
  echo "version prose lint FAILED: stale claims found (see above)" >&2
  exit 1
fi

echo "version prose lint PASS: no stale execution-version or bypass-governance claims in SECURITY.md, packages/, docs/"
