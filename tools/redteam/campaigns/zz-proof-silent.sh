#!/bin/bash
# zz-proof-silent.sh — throwaway proof fixture, deleted after the proof.
# The audited fail-open shape: the campaign exits 0 and prints no final
# RESULT record at all.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=zz-proof-silent
RT_PROFILE=${KIWI_RT_PROFILE:-redis}

echo "ASSERT: PASS a fixture assertion that never becomes a verdict"
exit 0
