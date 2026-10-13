#!/bin/bash
# zz-proof-fail.sh — throwaway proof fixture, deleted after the proof.
# A campaign that records an ASSERT: FAIL but then exits 0 without ever
# calling rt_finish: the broken shape the verdict logic must refuse.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=zz-proof-fail
RT_PROFILE=${KIWI_RT_PROFILE:-redis}

rt_report_fail "the required result did not hold"
exit 0
