#!/usr/bin/env bash
# tools/ci/version-prose-lint.sh - stale execution-version and bypass
# governance prose ratchet
#
# Usage:
#   bash tools/ci/version-prose-lint.sh
#
# The live execution-grammar maximum is DERIVED at runtime from the
# protocol manifest (protocol/execution-v1.json, the max_execution_version
# row), never hardcoded: the manifest row is the single authored
# authority the parity lanes pin against the PHP and Rust constants
# (ExecutionChallengeGenerator::MAX_EXECUTION_VERSION and
# execution::MAX_EXECUTION_VERSION), so every ladder numeral in this
# tool's patterns and reports comes from that row and can never
# describe yesterday's maximum.
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
# ladder. Two families of patterns run under it:
#
#   - static frozen-era calibrations, the exact stale strings the
#     earlier governance reviews found: "execution version ... exactly
#     1" (also spelled "execution_version ... exactly 1" or "the
#     canonical numeric byte: exactly 1"), "execution_version ... 1 or
#     2", bare "versions? 1..3" describing the supported set, and
#     "v1/v2/v3" describing the supported set; and
#   - derived below-maximum families, generated for every execution
#     grammar numeral n below the manifest maximum, so the current top
#     rung can never be claimed stale while it is live, and any rung
#     the register has moved past is banned the moment it is no longer
#     the maximum:
#       - "future v4" / "future version 4" / "future version-4"
#         (the rung is live, so a future-tense claim is stale),
#       - "future grammar beyond version 4"
#         (a rung already inside the live ladder is never beyond it),
#       - "version 4 is the current boundary" and "version 4 is live"
#         (the boundary and the live top are the manifest maximum),
#       - "the current maximum ... version 4" / "the live maximum is 4"
#         / "today 4" / "version 4 today"
#         (the maximum is the manifest row, never a frozen numeral),
#       - "maximum execution version 2" style claims and a "versions
#         1..4" supported-set claim.
#
# Group 6 bans stale claims that the driver's execution-capability
# advertisement carries a value below the manifest maximum. The live
# widget driver sends the `Kiwi-Execution-Max-Version` request header
# with its current maximum (the generator's MAX_EXECUTION_VERSION),
# pinned by an executable parity test (WidgetDriverCapabilityParityTest
# reads the driver literal and asserts it equals the generator
# maximum), so prose pairing the header name or the "execution
# capability" term with a below-maximum value on the same line is a
# stale claim:
#
#   - 'Kiwi-Execution-Max-Version ... value 2'
#   - 'execution capability ... value 2'
#
# A file whose content carries the marker
#   historical-compat fixture:
# in any line comment is exempt from groups 5 and 6: that marker is
# the convention for deliberately frozen N-1 compatibility fixtures
# whose prose must keep describing an older ladder (e.g. a fixture
# that pins the v1..v3 decode fences). Historical narrative in
# CHANGELOGs is excluded by the CHANGELOG glob above; past-tense
# history elsewhere must stay clear of the group-5 and group-6
# phrases, which are reserved for present-tense claims about the
# supported set.
#
# The ratchet is calibrated to the exact stale strings the governance
# review found, so any reintroduction anywhere in the scan roots fails
# CI immediately.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

# The live execution-grammar maximum comes from the protocol manifest,
# the canonical register the parity lanes read (see
# tools/ci/protocol-manifest-check.sh). A missing or unreadable row is
# a hard failure: the ratchet must never silently disarm itself.
manifest="$repo_root/protocol/execution-v1.json"
live_max="$(sed -n -E 's/^  "max_execution_version": ([0-9]+),?$/\1/p' "$manifest" | head -n 1)"
if [ -z "$live_max" ] || ! [ "$live_max" -ge 1 ] 2>/dev/null; then
  echo "version prose lint FAILED: cannot read max_execution_version from $manifest" >&2
  exit 1
fi

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

# 5. stale CURRENT claims about the live execution-grammar ladder: the
# static frozen-era calibrations plus one derived family per numeral
# below the manifest maximum. Files carrying the historical-compat
# marker are exempt.
ladder_patterns=(
  -e 'execution[-_ ]version[^.!?]{0,80}exactly[[:space:]]+1([^0-9]|$)'
  -e 'execution_version[^.!?]{0,60}1 or 2([^0-9]|$)'
  -e 'execution-dimension[^.!?]{0,60}exactly[[:space:]]+1([^0-9]|$)'
  -e 'the canonical numeric byte[^.!?]{0,30}exactly[[:space:]]+1([^0-9]|$)'
  -e '(versions?|version)[[:space:]]+1\.\.3([^0-9.]|$)'
  -e 'v1/v2/v3'
)
for n in $(seq 2 $((live_max - 1))); do
  ladder_patterns+=(
    -e "future[[:space:]]+(version[[:space:]-]?|v)${n}([^0-9]|$)"
    -e "future[[:space:]]+grammar[^.!?\n]{0,40}beyond[^.!?\n]{0,20}version[[:space:]-]?${n}([^0-9]|$)"
    -e "version[[:space:]-]?${n}[[:space:]]+is[[:space:]]+the[[:space:]]+current[[:space:]]+boundary([^A-Za-z0-9]|$)"
    -e "version[[:space:]-]?${n}[[:space:]]+is[[:space:]]+live([^A-Za-z0-9]|$)"
    -e "version[[:space:]-]?${n}[[:space:]]+today([^A-Za-z0-9]|$)"
    -e "current[[:space:]]+maximum[^.!?\n]{0,60}version[[:space:]-]?${n}([^0-9]|$)"
    -e "(current|live)[[:space:]]+maximum[^.!?\n]{0,50}(is|remains)[[:space:]]+${n}([^0-9]|$)"
    -e "([^A-Za-z0-9]|^)today[[:space:]]+${n}([^0-9]|$)"
    -e "maximum[[:space:]]+execution[[:space:]]+version[[:space:]]+${n}([^0-9]|$)"
  )
done
ladder_matches="$(
  search "${ladder_patterns[@]}" "${scan_roots[@]}"
)"
ladder_matches="$(printf '%s\n' "$ladder_matches" | drop_compat_files)"
if [ -n "$ladder_matches" ]; then
  report "stale claim: the live execution-grammar ladder is described with a below-maximum or frozen phrase (the live maximum is MAX_EXECUTION_VERSION, manifest max_execution_version = ${live_max}; mark frozen N-1 fixtures with 'historical-compat fixture:' to exempt them)"
  printf '%s\n' "$ladder_matches"
fi

# 6. the driver's execution-capability advertisement claimed as a
# value below the manifest maximum (the live driver sends
# Kiwi-Execution-Max-Version with its current maximum, pinned by the
# executable WidgetDriverCapabilityParityTest). Files carrying the
# historical-compat marker are exempt, like group 5.
capability_patterns=()
for n in $(seq 2 $((live_max - 1))); do
  capability_patterns+=(
    -e "Kiwi-Execution-Max-Version[^.!?\n]{0,100}value[[:space:]]+${n}([^0-9]|$)"
    -e "execution capability[^.!?\n]{0,100}value[[:space:]]+${n}([^0-9]|$)"
  )
done
capability_matches="$(
  search "${capability_patterns[@]}" "${scan_roots[@]}"
)"
capability_matches="$(printf '%s\n' "$capability_matches" | drop_compat_files)"
if [ -n "$capability_matches" ]; then
  report "stale claim: the driver's execution-capability advertisement is described with a below-maximum value (the live driver sends the header with its current maximum, manifest max_execution_version = ${live_max}; mark frozen N-1 fixtures with 'historical-compat fixture:' to exempt them)"
  printf '%s\n' "$capability_matches"
fi

if [ "$hits" -ne 0 ]; then
  echo "version prose lint FAILED: stale claims found (see above)" >&2
  exit 1
fi

echo "version prose lint PASS: no stale execution-version, capability-header or bypass-governance claims in SECURITY.md, packages/, docs/ (live execution maximum derived from the protocol manifest: ${live_max})"
