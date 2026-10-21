# verdict.sh — the shared campaign row verdict contract.
#
# campaign_log_verdict <campaign> <profile> <log> <rc> — extracted
# verbatim from exit-criteria.sh so the per-backend runner applies
# the exact same record contract to every nested run: GREEN
# requires exit 0 AND exactly one final RESULT: PASS record naming
# this campaign and profile AND zero RESULT: FAIL records; anything
# else is RED with the specific reason. Prints "<verdict> <detail>".

# campaign_log_verdict <campaign> <profile> <log> <rc> — the campaign
# row verdict under the record contract. GREEN requires exit 0 AND
# exactly one final authoritative RESULT: PASS record naming this
# campaign and profile AND zero RESULT: FAIL records in the log;
# anything else is RED with the specific reason. Prints
# "<verdict> <detail>" on stdout, detail never empty.
campaign_log_verdict() {
    c=$1
    prof=$2
    logf=$3
    crc=$4
    fail_count=$(grep -c '^RESULT: FAIL' "$logf" 2>/dev/null)
    fail_count=${fail_count:-0}
    fail_detail=$(grep '^RESULT: FAIL' "$logf" 2>/dev/null | tail -n 1 | cut -d' ' -f5-)
    assert_fail=$(grep '^ASSERT: FAIL' "$logf" 2>/dev/null | head -n 1 | cut -d' ' -f5-)
    if [ "$crc" -ne 0 ]; then
        if [ -n "$fail_detail" ]; then
            printf 'RED campaign exited %s: %s (see %s)' "$crc" "$fail_detail" "$logf"
        elif [ -n "$assert_fail" ]; then
            printf 'RED campaign exited %s with a failed assertion and no final record: %s (see %s)' "$crc" "$assert_fail" "$logf"
        else
            printf 'RED campaign exited %s without a RESULT: FAIL record (see %s)' "$crc" "$logf"
        fi
        return 0
    fi
    if [ "$fail_count" -gt 0 ]; then
        printf 'RED %s RESULT: FAIL record(s) in the log: %s' "$fail_count" "$fail_detail"
        return 0
    fi
    pass_pat="^RESULT: PASS $(printf '%s' "$c" | sed 's/[.]/[.]/g') $(printf '%s' "$prof" | sed 's/[.]/[.]/g') "
    pass_count=$(grep -c "$pass_pat" "$logf" 2>/dev/null)
    pass_count=${pass_count:-0}
    if [ "$pass_count" -eq 0 ]; then
        if [ -n "$assert_fail" ]; then
            printf 'RED exit 0 with a failed assertion and no final record: %s' "$assert_fail"
        else
            # A campaign that answered not-applicable measured nothing on
            # the profile the battery runs, where every campaign is
            # applicable: it is RED for the same reason an absent record
            # is, and the reason names which of the two happened.
            na_count=$(grep -c "^RESULT: not-applicable $(printf '%s' "$c" | sed 's/[.]/[.]/g') " "$logf" 2>/dev/null)
            na_count=${na_count:-0}
            if [ "$na_count" -gt 0 ]; then
                na_detail=$(grep "^RESULT: not-applicable " "$logf" | tail -n 1 | cut -d' ' -f5-)
                printf 'RED the campaign declared itself not-applicable on %s, where it must run: %s' "$prof" "$na_detail"
            else
                printf 'RED exit 0 without a RESULT: PASS record for %s %s' "$c" "$prof"
            fi
        fi
        return 0
    fi
    if [ "$pass_count" -gt 1 ]; then
        printf 'RED %s RESULT: PASS records for %s %s; the contract allows exactly one' "$pass_count" "$c" "$prof"
        return 0
    fi
    # The GREEN path enforces the same contract rt_finish does: any
    # ASSERT: FAIL line beside the PASS record is a failure, and the
    # PASS record must be rt_finish's own summary shape (zero of a
    # positive assertion count). A campaign whose driver assertions
    # were captured may legitimately log no ASSERT lines, but the
    # summary shape still proves the record names a real counted run;
    # a hand-printed PASS without the shape is refused.
    logged_assert_fail=$(grep -c '^ASSERT: FAIL' "$logf" 2>/dev/null)
    logged_assert_fail=${logged_assert_fail:-0}
    if [ "$logged_assert_fail" -gt 0 ]; then
        printf 'RED %s ASSERT: FAIL record(s) in the log beside the PASS record: %s' "$logged_assert_fail" "$assert_fail"
        return 0
    fi
    pass_detail=$(grep "$pass_pat" "$logf" | tail -n 1 | cut -d' ' -f5-)
    assert_total=$(printf '%s' "$pass_detail" | sed -n 's/^0 of \([0-9][0-9]*\) assertions failed$/\1/p')
    if [ -n "$assert_total" ] && [ "$assert_total" -ge 1 ]; then
        printf 'GREEN %s' "$pass_detail"
    else
        printf 'RED the PASS record is not an rt_finish summary over a positive assertion count: %s' "$pass_detail"
    fi
}
