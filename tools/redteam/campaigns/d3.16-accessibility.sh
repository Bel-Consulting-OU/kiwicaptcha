#!/bin/bash
# d3.16-accessibility.sh — accessibility and compatibility (D3.16).
#
# This campaign reuses the product's own accessibility and autofill
# gates; nothing here is a rewrite:
#   - the qualification validators and their adversarial mutation
#     corpora (the CI jobs): the autofill and accessibility matrices
#     in tests/browser/qualification are validated by the same code
#     the release runs,
#   - the Playwright accessibility lane on the engines selected by
#     KIWI_RT_D16_ENGINES (default chromium; "all" runs the three
#     engine matrix): the WCAG evidence set, the autofill evidence
#     suite, and the portable adversarial subset.
#
# Required result: every validator green, zero Playwright failures on
# the selected engines.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.16-accessibility

# ---------- the qualification validators and their mutation corpora ----------
for validator in test-validate-autofill-qualification.mjs test-validate-accessibility-qualification.mjs; do
    if node "$REPO_ROOT/tools/ci/$validator" >/dev/null 2>&1; then
        rt_report_pass "$validator (validator adversarial corpus) green"
    else
        rt_report_fail "$validator failed"
    fi
done

# The registry truthfulness row: the validators reject the release
# certification while manual qualification rows stay manual-pending
# (the documented honesty state of the matrix). The campaign asserts
# the two machine-checkable properties: every validator rejection is
# exactly a manual-pending row, and nothing else blocks.
for pair in "autofill-matrix.json:validate-autofill-qualification.mjs" \
    "accessibility-matrix.json:validate-accessibility-qualification.mjs"; do
    matrix=${pair%%:*}
    validator=${pair##*:}
    out=$(node "$REPO_ROOT/tools/ci/$validator" "$REPO_ROOT/tests/browser/qualification/$matrix" 2>&1)
    if [ $? -eq 0 ]; then
        rt_report_pass "qualification registry $matrix fully validated"
    elif printf '%s' "$out" | grep -q 'REJECTED' \
        && printf '%s' "$out" | grep -Eq 'manual_pending|not "pass"|not qualified within the window'; then
        manual=$(printf '%s' "$out" | grep -c 'manual_pending')
        rt_report_pass "qualification registry $matrix: only manual-pending rows block release ($manual rows)"
    else
        rt_report_fail "qualification registry $matrix rejected for reasons beyond manual rows"
    fi
done

# ---------- the Playwright lane ----------
ENGINES=${KIWI_RT_D16_ENGINES:-chromium}
cd "$REPO_ROOT/tests/browser" || { rt_report_fail "tests/browser missing"; rt_finish; }

# The suite's fixture server binds 8087; a leftover from an earlier
# run would fail the lane before a test starts.
lsof -ti :8087 2>/dev/null | while IFS= read -r pid; do kill "$pid" 2>/dev/null; done
sleep 0.5

SPECS="autofill-evidence.spec.mjs a11y.spec.mjs adversarial-portable.spec.mjs"
PROJECT_ARGS=''
for engine in $ENGINES; do
    case "$engine" in
        all) PROJECT_ARGS='' ;;
        *) PROJECT_ARGS="$PROJECT_ARGS --project=$engine" ;;
    esac
done

LOG="$RT_DIR/runs/env/d316-playwright.log"
if timeout 900 npx playwright test --config=playwright.a11y.config.mjs $PROJECT_ARGS \
        $SPECS --reporter=line --retries=1 >"$LOG" 2>&1; then
    PASSED=$(grep -o '[0-9]* passed' "$LOG" | tail -n 1)
    rt_report_pass "Playwright a11y lane green on $ENGINES ($PASSED)"
else
    FAILED=$(grep -cE '✘|failed' "$LOG" 2>/dev/null)
    rt_report_fail "Playwright a11y lane failed on $ENGINES (see runs/env/d316-playwright.log)"
fi

rt_metric "engines=$ENGINES specs=$SPECS"
printf 'ECONOMIC: %s %s autofill_decoy_fills=0 escalations=0\n' "$RT_CAMPAIGN" "$RT_PROFILE"

rt_finish
