#!/bin/bash
# repro-common.sh — the shared shape of the triage repro harnesses.
#
# Every harness is a deterministic, self-contained probe against the
# live deployment: when the orchestrator's target answers (state file
# present and healthy) it is reused, otherwise the harness boots the
# redis profile and tears it down itself. The transcript is exactly one
# JSON line of derived facts (verdict plus the wire error code), never
# a server nonce or a timestamp, so the two-run hash gate in triage.mjs
# is stable across back-to-back runs.
#
# This file is deliberately standalone (it does not source
# lib/common.sh, whose paths key off the caller's $0): a harness's $0
# lives under engine/repros/, so the state-file paths are resolved from
# this file's own location instead.

RT_COMMON_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RT_DIR=$(cd "$RT_COMMON_DIR/../.." && pwd)
REPO_ROOT=$(cd "$RT_DIR/../.." && pwd)
RT_RUN_DIR="$RT_DIR/runs/env"

repro_state_get() {
    profile=$1
    key=$2
    file="$RT_RUN_DIR/$profile.env"
    [ -f "$file" ] || return 1
    sed -n "s/^${key}=//p" "$file" | head -n 1
}

# Boot or reuse the target; print the base url on stdout.
repro_target() {
    profile=${KIWI_RT_PROFILE:-redis}
    base=$(repro_state_get "$profile" BASE_URL 2>/dev/null || true)
    if [ -n "$base" ]; then
        probe=$(curl -s --max-time 5 "$base/healthz" 2>/dev/null || true)
        case "$probe" in
            *'"ok":true'*) printf '%s' "$base"; return 0 ;;
        esac
    fi
    sh "$RT_DIR/target.sh" down "$profile" >/dev/null 2>&1
    if ! sh "$RT_DIR/target.sh" up "$profile" >/dev/null 2>&1; then
        return 1
    fi
    repro_state_get "$profile" BASE_URL
}

# The redis url of the target profile (the canary harness scans it).
repro_redis_url() {
    profile=${KIWI_RT_PROFILE:-redis}
    repro_state_get "$profile" REDIS_URL
}

# The stable transcript: verdict + code + the harness name.
repro_verdict() {
    harness=$1
    attack_ok=$2
    code=$3
    if [ "$attack_ok" = "1" ]; then
        verdict=REPRODUCED
    else
        verdict=REFUTED
    fi
    printf '{"harness":"%s","verdict":"%s","wire_code":"%s"}\n' "$harness" "$verdict" "$code"
}
