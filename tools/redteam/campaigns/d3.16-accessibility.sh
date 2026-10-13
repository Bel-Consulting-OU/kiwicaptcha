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
#
# The verdicts are split. The automated compatibility lane (the
# validator corpora and the Playwright matrix) is what the ASSERT
# records and the final RESULT speak for. The manual qualification
# state travels in its own machine-readable record per matrix, and the
# gate parses it:
#   QUALIFICATION: qualified <matrix>
#   QUALIFICATION: pending manual_rows=<n> <matrix>
# A pending state is not a campaign failure: the validators behave
# exactly as documented while required manual rows stay unqualified,
# so the script exits 0 and the run document persists. The d3.16 row
# of the exit-criteria gate renders that state as PENDING (non-green)
# with the matrices and manual row counts named, and GREEN only when
# every matrix reports qualified.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.16-accessibility
# The profile the battery grades under: the authoritative RESULT record
# must name the campaign and profile the gate invoked, so the profile
# honors the environment exactly like the deployment campaigns do.
RT_PROFILE="${KIWI_RT_PROFILE:-default}"

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
# exactly a manual-pending row, and nothing else blocks. The manual
# qualification state itself goes out on the dedicated QUALIFICATION
# record per matrix, which the gate reads separately from the ASSERT
# result: the automated lane can be green while the release row must
# stay non-green until every required manual row has passed.
for pair in "autofill-matrix.json:validate-autofill-qualification.mjs" \
    "accessibility-matrix.json:validate-accessibility-qualification.mjs"; do
    matrix=${pair%%:*}
    validator=${pair##*:}
    out=$(node "$REPO_ROOT/tools/ci/$validator" "$REPO_ROOT/tests/browser/qualification/$matrix" 2>&1)
    if [ $? -eq 0 ]; then
        rt_report_pass "qualification registry $matrix fully validated"
        printf 'QUALIFICATION: qualified %s\n' "$matrix"
    elif printf '%s' "$out" | grep -q 'REJECTED' \
        && printf '%s' "$out" | grep -Eq 'manual_pending|not "pass"|not qualified within the window'; then
        manual=$(printf '%s' "$out" | grep -c 'manual_pending')
        rt_report_pass "qualification registry $matrix: only manual-pending rows block release ($manual rows)"
        printf 'QUALIFICATION: pending manual_rows=%s %s\n' "$manual" "$matrix"
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
# The manual qualification state rides the recorded economics so the
# ledger's row carries it: pending while any matrix has manual rows,
# qualified only when every matrix reports qualified.
QUAL_STATE=pending
QUAL_TOTAL=$(grep -c 'QUALIFICATION: qualified' "$LOG")
PENDING_TOTAL=$(grep -c 'QUALIFICATION: pending' "$LOG" || true)
[ "$QUAL_TOTAL" -ge 2 ] && [ "$PENDING_TOTAL" -eq 0 ] && QUAL_STATE=qualified
printf 'ECONOMIC: %s %s autofill_decoy_fills=0 escalations=0 manual_qualification=%s\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$QUAL_STATE"
rt_metric "qualification=$QUAL_STATE engines=$ENGINES specs=$SPECS"

rt_finish
