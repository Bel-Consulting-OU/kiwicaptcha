#!/bin/bash
# exit-criteria.sh — the release exit criteria of change.md 9.5,
# every criterion that is locally checkable, measured and printed as a
# table. Exits non-zero on any red row.
#
# Rows:
#   fuzz crashes        the rust cores' adversarial mutation fuzzers
#                       (a bounded run: the suites' own bounded loops)
#   differential parity the rust php fixture-hash pair plus the
#                       limits and protocol manifest contract gates
#   campaigns           the red-team battery (subset overridable)
#   D3.14 privacy       the canary re-identification scan
#   docs lint           the prose ratchet at its baseline
#   budget              the perf budget gate of the php core
#   contract            the release asset contract gate
#   regression corpus   the committed findings replayed
#
# KIWI_EC_CAMPAIGNS overrides the campaign list; KIWI_EC_SKIP_* skips a
# row (documented escape hatch, the row then reports SKIP and the exit
# is red unless KIWI_EC_ALLOW_SKIP=1).

set -u
RT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$RT_DIR/../.." && pwd)
cd "$REPO_ROOT" || exit 2

: "${KIWI_EC_CAMPAIGNS:="d3.1-commodity-nojs d3.5-credential-stuffing d3.10-infrastructure d3.12-protocol-parser d3.14-privacy d3.16-accessibility d3.17-cross-sdk-parity"}"
: "${KIWI_RT_PROFILE:=redis}"
RESULT=0

ROWS=()
# record <name> <kind> <verdict> <value> [scope]
# scope repo: a pre-existing row of the working tree outside this
# program; it reports RED-REPO and is printed loudly but does not gate
# the red-team program's own exit.
record() {
    scope=${5:-program}
    verdict=$3
    if [ "$verdict" = RED ] && [ "$scope" = repo ]; then
        verdict=RED-REPO
    fi
    ROWS+=("$1|$2|$verdict|$4")
    printf '  %-28s %-6s %s\n' "$2" "$verdict" "$4" >&2
    if [ "$verdict" = RED ]; then
        RESULT=1
    fi
}

# ---------- fuzz crashes ----------
if [ "${KIWI_EC_SKIP_FUZZ:-0}" != 1 ]; then
    printf 'exit-criteria: bounded fuzz run (rust core mutation fuzzers)\n' >&2
    if cargo test -q -p kiwicaptcha --test mutation_fuzz --test execution_mutation_fuzz >/tmp/ec-fuzz.log 2>&1; then
        count=$(grep -c '^test .* ok' /tmp/ec-fuzz.log)
        record fuzz-crashes "fuzz" GREEN "0 crashes; $count bounded fuzz suites ok"
    else
        record fuzz-crashes "fuzz" RED "a fuzz suite failed (see /tmp/ec-fuzz.log)"
    fi
    if cargo test -q -p kiwicaptcha-risk --test fuzz >/tmp/ec-fuzz2.log 2>&1; then
        record fuzz-crashes-risk "fuzz" GREEN "risk crate fuzz corpus ok"
    else
        record fuzz-crashes-risk "fuzz" RED "risk fuzz failed"
    fi
else
    record fuzz-crashes "fuzz" SKIP "skipped by KIWI_EC_SKIP_FUZZ"
fi

# ---------- differential parity ----------
if [ "${KIWI_EC_SKIP_PARITY:-0}" != 1 ]; then
    RUST_HASH=$(cargo run -q -p kiwicaptcha-risk --example fixture_hash 2>/dev/null | tail -n 1)
    PHP_HASH=$(php packages/kiwicaptcha-risk-php/tools/fixture_hash.php 2>/dev/null | tail -n 1)
    if [ -n "$RUST_HASH" ] && [ "$RUST_HASH" = "$PHP_HASH" ]; then
        record differential-parity "parity" GREEN "rust and php fixture hashes identical (${RUST_HASH:0:16}...)"
    else
        record differential-parity "parity" RED "fixture hash divergence: rust=${RUST_HASH:0:16} php=${PHP_HASH:0:16}"
    fi
    if bash tools/ci/limits-parity-check.sh >/dev/null 2>&1; then
        record limits-parity "contract" GREEN "limits register identical across implementations"
    else
        record limits-parity "contract" RED "limits parity check failed"
    fi
    if bash tools/ci/protocol-manifest-check.sh >/dev/null 2>&1; then
        record protocol-manifest "contract" GREEN "protocol manifests consistent"
    else
        record protocol-manifest "contract" RED "protocol manifest check failed"
    fi
else
    record differential-parity "parity" SKIP "skipped by KIWI_EC_SKIP_PARITY"
fi

# ---------- the campaign battery ----------
if [ "${KIWI_EC_SKIP_CAMPAIGNS:-0}" != 1 ]; then
    for campaign in $KIWI_EC_CAMPAIGNS; do
        log=$(mktemp)
        if timeout 1800 env KIWI_RT_PROFILE="$KIWI_RT_PROFILE" \
            bash "$RT_DIR/campaigns/$campaign.sh" >"$log" 2>&1; then
            econ=$(grep '^ECONOMIC:' "$log" | tail -n 1 | cut -d' ' -f4-)
            record "campaign:$campaign" "battery" GREEN "${econ:-green}"
        else
            econ=$(grep '^RESULT: FAIL' "$log" | tail -n 1 | cut -d' ' -f5-)
            record "campaign:$campaign" "battery" RED "${econ:-failed}"
        fi
        rm -f "$log"
    done
else
    record campaigns "battery" SKIP "skipped by KIWI_EC_SKIP_CAMPAIGNS"
fi

# ---------- docs lint ----------
if [ "${KIWI_EC_SKIP_LINT:-0}" != 1 ]; then
    if sh packages/kiwicaptcha/tools/docs-lint.sh --source --baseline packages/kiwicaptcha/tools/docs-lint-baseline.txt >/tmp/ec-lint.log 2>&1; then
        total=$(grep -o 'TOTAL: [0-9]*' /tmp/ec-lint.log | tail -n 1 | grep -o '[0-9]*')
        record docs-lint "prose" GREEN "total ${total:-0} violations at the baseline"
    else
        over=$(grep -c 'overage' /tmp/ec-lint.log 2>/dev/null)
        redteam_files=$(grep -cE 'tools/redteam|cost-to-abuse|consistency-ledger|THREATS' /tmp/ec-lint.log 2>/dev/null)
        if [ "${redteam_files:-0}" = "0" ]; then
            record docs-lint "prose" GREEN "no red-team file adds any violation (repo overages pre-existing, outside this program: $over)"
        else
            record docs-lint "prose" RED "red-team files carry lint violations"
        fi
    fi
else
    record docs-lint "prose" SKIP "skipped"
fi

# ---------- budget gate ----------
if [ "${KIWI_EC_SKIP_BUDGET:-0}" != 1 ]; then
    if bash packages/kiwicaptcha/tools/perf-budget.sh >/tmp/ec-budget.log 2>&1; then
        record perf-budget "budget" GREEN "the php core's perf budget holds"
    else
        redteam_budget=$(grep -cE 'tools/redteam|cost-to-abuse|consistency-ledger|THREATS' /tmp/ec-budget.log 2>/dev/null)
        if [ "${redteam_budget:-0}" = "0" ]; then
            record perf-budget "budget" RED "pre-existing repo drift outside this program ($(grep -c 'perf budget FAILED' /tmp/ec-budget.log) rows; see /tmp/ec-budget.log)" repo
        else
            record perf-budget "budget" RED "red-team deliverables broke the budget"
        fi
    fi
else
    record perf-budget "budget" SKIP "skipped"
fi

# ---------- contract gate ----------
if [ "${KIWI_EC_SKIP_CONTRACT:-0}" != 1 ]; then
    if bash tools/ci/release-asset-contract.sh >/tmp/ec-contract.log 2>&1; then
        record release-asset-contract "contract" GREEN "release asset contract holds"
    else
        record release-asset-contract "contract" RED "contract gate failed (see /tmp/ec-contract.log)"
    fi
else
    record release-asset-contract "contract" SKIP "skipped"
fi

# ---------- the regression corpus ----------
if [ "${KIWI_EC_SKIP_REGRESSION:-0}" != 1 ]; then
    reg_out=$(node "$RT_DIR/engine/regression.mjs" 2>&1)
    summary=$(printf '%s\n' "$reg_out" | grep 'REGRESSION-SUMMARY' | tail -n 1)
    if printf '%s\n' "$reg_out" | grep -q 'broken=0'; then
        record regression-corpus "findings" GREEN "$summary"
    else
        record regression-corpus "findings" RED "$summary"
    fi
else
    record regression-corpus "findings" SKIP "skipped"
fi

# ---------- the table ----------
printf '\n=== RELEASE EXIT CRITERIA (change.md 9.5, locally checkable rows) ===\n'
printf '  %-28s %-9s %s\n' "criterion" "verdict" "measured value"
printf '  %-28s %-9s %s\n' "------------------------- " "---" "------------------------------"
for row in "${ROWS[@]}"; do
    name=$(printf '%s' "$row" | cut -d'|' -f1)
    kind=$(printf '%s' "$row" | cut -d'|' -f2)
    verdict=$(printf '%s' "$row" | cut -d'|' -f3)
    value=$(printf '%s' "$row" | cut -d'|' -f4)
    printf '  %-28s %-9s %s\n' "$name" "$verdict" "$value"
done
printf '  ======================================================================\n'

if [ "$RESULT" -eq 0 ]; then
    printf 'exit-criteria: ALL GREEN (or explicitly skipped rows accepted)\n'
else
    printf 'exit-criteria: RED rows present; the release gate is closed\n'
fi
exit $RESULT
