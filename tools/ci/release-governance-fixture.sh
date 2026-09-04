#!/usr/bin/env bash
# tools/ci/release-governance-fixture.sh - pure fixture matrix for the
# v* tag-ruleset parser (tools/ci/tag-ruleset-check.sh)
#
# No network is used: each case builds a fixture ruleset JSON document
# and pipes it into the same parser the release workflow preflight step
# runs, asserting the expected verdict. A parser regression (a rule the
# check stops requiring, an include pattern check that stops biting, an
# enforcement state that slips through, a bypass actor that is
# accepted) fails this fixture matrix.
#
# Expected verdicts, by audit requirement:
#   creation missing        -> refused
#   deletion missing        -> refused
#   non-fast-forward missing -> refused
#   wrong tag pattern       -> refused
#   inactive enforcement    -> refused
#   all present, empty bypass -> accepted
#   all present, Integration-only bypass (dedicated release App) -> accepted
# Extras that must also refuse: OrganizationAdmin in the bypass list, a
# branch-target ruleset, a mismatched ruleset id, malformed JSON.
#
# Prints one PASS/FAIL line per case plus a summary line, and exits 0
# only when every case behaved as expected.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
parser="$script_dir/tag-ruleset-check.sh"
expected_id="20868582"

base_doc() {
  # $1 = enforcement state (active/evaluate)
  jq -n --arg enforcement "$1" --argjson id "$expected_id" '{
    id: $id,
    name: "v* release tags",
    target: "tag",
    source_type: "Repository",
    enforcement: $enforcement,
    bypass_actors: [],
    conditions: { ref_name: { include: ["refs/tags/v*"], exclude: [] } },
    rules: [
      { type: "creation" },
      { type: "deletion" },
      { type: "non_fast_forward" }
    ]
  }'
}

failures=0
total=0

# run_case <label> <expected: accept|refuse> <json document>
run_case() {
  local label="$1"
  local expected="$2"
  local json="$3"
  local verdict output rc
  total=$((total + 1))
  # The parser's refusal exit code must not abort the fixture under
  # set -e, so errexit is suspended around the capture.
  set +e
  output="$(printf '%s\n' "$json" | bash "$parser" "$expected_id" 2>&1)"
  rc=$?
  set -e
  if [ "$expected" = "accept" ] && [ "$rc" -eq 0 ]; then
    verdict="PASS"
  elif [ "$expected" = "refuse" ] && [ "$rc" -ne 0 ]; then
    verdict="PASS"
  else
    verdict="FAIL"
    failures=$((failures + 1))
  fi
  echo "$verdict fixture: $label (expected $expected, parser exit $rc)"
  if [ "$verdict" = "FAIL" ]; then
    printf '%s\n' "$output" | sed 's/^/    /'
  fi
}

full="$(base_doc active)"

run_case "creation rule missing -> refused" refuse "$(jq '.rules = [.rules[] | select(.type != "creation")]' <<<"$full")"
run_case "deletion rule missing -> refused" refuse "$(jq '.rules = [.rules[] | select(.type != "deletion")]' <<<"$full")"
run_case "non-fast-forward rule missing -> refused" refuse "$(jq '.rules = [.rules[] | select(.type != "non_fast_forward")]' <<<"$full")"
run_case "wrong tag pattern (refs/tags/stable*) -> refused" refuse "$(jq '.conditions.ref_name.include = ["refs/tags/stable*"]' <<<"$full")"
run_case "inactive enforcement (evaluate) -> refused" refuse "$(base_doc evaluate)"
run_case "all rules present, empty bypass -> accepted" accept "$full"
run_case "all rules present, Integration-only bypass -> accepted" accept "$(jq '.bypass_actors = [{actor_id: 777777, actor_type: "Integration", bypass_mode: "always"}]' <<<"$full")"

# Extras.
run_case "OrganizationAdmin bypass actor -> refused" refuse "$(jq '.bypass_actors = [{actor_id: 1, actor_type: "OrganizationAdmin", bypass_mode: "always"}]' <<<"$full")"
run_case "branch-target ruleset -> refused" refuse "$(jq '.target = "branch"' <<<"$full")"
run_case "ruleset id mismatch -> refused" refuse "$(jq '.id = 99999999' <<<"$full")"
run_case "malformed JSON -> refused" refuse "{ not json"
run_case "empty document -> refused" refuse ""

echo "release governance fixture matrix: $((total - failures))/$total cases behaved as expected"
if [ "$failures" -ne 0 ]; then
  echo "release governance fixture matrix FAILED ($failures case(s))" >&2
  exit 1
fi
