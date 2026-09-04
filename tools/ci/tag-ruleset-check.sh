#!/usr/bin/env bash
# tools/ci/tag-ruleset-check.sh - enforce the v* release-tag ruleset contract
#
# Usage:
#   bash tools/ci/tag-ruleset-check.sh [expected-ruleset-id] < ruleset.json
#
# Reads exactly one GitHub repository-ruleset JSON document on stdin and
# verifies the contract a release may be published under:
#
#   - the ruleset id matches the expected id (default 20868582),
#   - target == "tag" (the tag ruleset, not a branch ruleset),
#   - enforcement == "active" (never "evaluate" or "disabled"),
#   - the rules include creation, deletion and non_fast_forward,
#   - conditions.ref_name.include covers refs/tags/v* (shell-glob
#     match against the include entries, with no exclude entry carving
#     v* back out),
#   - bypass_actors is empty or limited to Integration actors: the
#     documented release identity is a dedicated GitHub App, so an
#     OrganizationAdmin or any other actor type in the bypass list is a
#     refusal.
#
# Exit 0 with one PASS line on stdout when the contract holds; exit 1
# with a failing-clause message on stderr otherwise. The script is pure
# (no network): the release workflow fetches the ruleset with gh api
# and pipes it in, and tools/ci/release-governance-fixture.sh proves
# the exact same logic with fixture documents.
set -euo pipefail

expected_id="${1:-20868582}"

input="$(cat)"
if [[ -z "$input" ]]; then
  echo "tag-ruleset-check: refusing an empty ruleset document (fail closed)" >&2
  exit 1
fi

fail() {
  echo "tag-ruleset-check: FAIL: $1" >&2
  exit 1
}

doc="$(jq -c . <<<"$input" 2>/dev/null)" || fail "the ruleset document is not valid JSON"

id="$(jq -r '.id // empty' <<<"$doc")"
[[ "$id" == "$expected_id" ]] || fail "ruleset id is '$id', expected '$expected_id'"

target="$(jq -r '.target // empty' <<<"$doc")"
[[ "$target" == "tag" ]] || fail "ruleset target is '$target', expected 'tag'"

enforcement="$(jq -r '.enforcement // empty' <<<"$doc")"
[[ "$enforcement" == "active" ]] || fail "ruleset enforcement is '$enforcement', expected 'active'"

for rule in creation deletion non_fast_forward; do
  present="$(jq -r --arg rule "$rule" '[.rules[]? | select(.type == $rule)] | length' <<<"$doc")"
  [[ "$present" -ge 1 ]] || fail "the ruleset lacks the '$rule' rule"
done

# Ref coverage: an empty include set would silently mean "all refs" in
# the platform semantics, so the include list must exist AND contain an
# entry that shell-glob matches refs/tags/v* (probed with
# refs/tags/v1.0.0). An exclude entry matching the probe removes the
# coverage again.
probe_ref="refs/tags/v1.0.0"
include_ok="no"
while IFS= read -r pat; do
  [[ -n "$pat" ]] || continue
  # shellcheck disable=SC2254 # the unquoted pattern is the deliberate shell-glob match
  case "$probe_ref" in
    $pat) include_ok="yes" ;;
  esac
done < <(jq -r '.conditions.ref_name.include[]?' <<<"$doc")
if [[ "$include_ok" != "yes" ]]; then
  fail "the ref include list does not cover refs/tags/v* (include: $(jq -c '.conditions.ref_name.include // []' <<<"$doc"))"
fi
while IFS= read -r pat; do
  [[ -n "$pat" ]] || continue
  # shellcheck disable=SC2254 # the unquoted pattern is the deliberate shell-glob match
  case "$probe_ref" in
    $pat)
      fail "the ref exclude list carves refs/tags/v* out of the ruleset (exclude: $(jq -c '.conditions.ref_name.exclude // []' <<<"$doc"))"
      ;;
  esac
done < <(jq -r '.conditions.ref_name.exclude[]?' <<<"$doc")

# Bypass posture: empty is the live state; the only actor type that may
# ever appear is Integration (the dedicated release GitHub App).
bad_bypass="$(jq -r '[.bypass_actors[]? | select(.actor_type != "Integration") | .actor_type] | unique | join(",")' <<<"$doc")"
if [[ -n "$bad_bypass" ]]; then
  fail "bypass_actors contains non-Integration actor types: $bad_bypass (only the dedicated release GitHub App may bypass)"
fi

echo "PASS: v* tag ruleset $id active: creation + deletion + non_fast_forward on refs/tags/v*, bypass empty-or-Integration"
