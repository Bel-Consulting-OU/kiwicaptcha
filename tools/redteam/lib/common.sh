#!/bin/sh
# common.sh — the shared helpers of the red-team harnesses.
#
# Every campaign sources this file. It owns the run directory layout,
# the target state file, the HTTP probe helpers and the required-result
# reporting contract. A campaign that does not print a RESULT line is a
# harness bug and fails in its own right.
#
# Layout under tools/redteam/runs/env/:
#   <profile>.env      the state file target.sh writes on up
#   <profile>.log      the target process log
#   <profile>/         scratch: redis db files, sqlite files, nginx cache
#
# Reporting contract, one line each on stdout:
#   RESULT: PASS|FAIL <campaign> <profile> <detail>
#   METRIC: <campaign> <profile> <key>=<value>
#   ECONOMIC: <campaign> <profile> cost_per_accepted_abuse=<value> <note>

REDETEAM_DIR=$(cd "$(dirname "$0")/.." && pwd)
REPO_ROOT=$(cd "$REDETEAM_DIR/../.." && pwd)
RT_RUN_DIR="$REDETEAM_DIR/runs/env"
RT_STATE="$RT_RUN_DIR/state.env"

# The knobs every harness shares. Campaigns inherit them from the
# orchestrator so a budget knob reaches the deepest script unchanged.
: "${KIWI_RT_BASE_PORT:=6480}"
: "${KIWI_RT_PHP_PORT_OFFSET:=2000}"
: "${KIWI_RT_SCALE:=100}"
: "${KIWI_RT_SEED:=0x6b776d74}"
: "${KIWI_RT_TIMEOUT_SECS:=600}"

export KIWI_RT_BASE_PORT KIWI_RT_SCALE KIWI_RT_SEED

rt_init() {
    mkdir -p "$RT_RUN_DIR"
}

# The absolute path of a profile's state file.
rt_state_file() {
    printf '%s/%s.env' "$RT_RUN_DIR" "$1"
}

# Read one variable out of a profile state file without sourcing it.
rt_state_get() {
    profile=$1
    key=$2
    file=$(rt_state_file "$profile")
    [ -f "$file" ] || return 1
    sed -n "s/^${key}=//p" "$file" | head -n 1
}

rt_base_url() {
    profile=$1
    url=$(rt_state_get "$profile" BASE_URL)
    [ -n "$url" ] && printf '%s' "$url"
}

# POST a JSON document, print the body, set RT_HTTP_STATUS.
rt_post_json() {
    url=$1
    body=$2
    shift 2
    RT_HTTP_STATUS=$(curl -s -o "$RT_TMP_BODY" -w '%{http_code}' \
        -H 'content-type: application/json' "$@" \
        --data "$body" --max-time 30 "$url")
    cat "$RT_TMP_BODY"
}

# GET a URL, print the body, set RT_HTTP_STATUS.
rt_get() {
    url=$1
    shift
    RT_HTTP_STATUS=$(curl -s -o "$RT_TMP_BODY" -w '%{http_code}' \
        --max-time 30 "$@" "$url")
    cat "$RT_TMP_BODY"
}

# Wait until /healthz answers ok true, bounded.
rt_wait_healthy() {
    profile=$1
    base=$(rt_base_url "$profile")
    i=0
    while [ "$i" -lt 100 ]; do
        body=$(rt_get "$base/healthz" 2>/dev/null) || body=''
        case "$body" in
            *'"ok":true'*) return 0 ;;
        esac
        i=$((i + 1))
        sleep 0.2
    done
    return 1
}

# Solve one challenge over HTTP and print the wire token on stdout.
# The native solver pays the browser price; the token it prints is the
# exact wire object a real client carries.
rt_solve_token() {
    profile=$1
    scope=$2
    base=$(rt_base_url "$profile")
    "$REPO_ROOT/target/debug/kiwicaptcha-solver" solve \
        --endpoint "$base/challenge" --scope "$scope" 2>/dev/null |
        python3 -c 'import json, sys; doc = json.load(sys.stdin); print(doc.get("token", ""))'
}

# One POST /verify round trip; prints the response body.
rt_verify_token() {
    profile=$1
    token=$2
    scope=${3:-login}
    base=$(rt_base_url "$profile")
    rt_post_json "$base/verify" \
        "{\"token\":\"$token\",\"scope\":\"$scope\"}"
}

# The reporting helpers. FAIL accumulates; the campaign calls
# rt_finish at the end and exits with the accumulated verdict.
RT_FAILURES=0
RT_CAMPAIGN=unknown
RT_PROFILE=default

rt_report_pass() {
    printf 'RESULT: PASS %s %s %s\n' "$RT_CAMPAIGN" "$RT_PROFILE" "$1"
}

rt_report_fail() {
    RT_FAILURES=$((RT_FAILURES + 1))
    printf 'RESULT: FAIL %s %s %s\n' "$RT_CAMPAIGN" "$RT_PROFILE" "$1"
}

rt_metric() {
    printf 'METRIC: %s %s %s\n' "$RT_CAMPAIGN" "$RT_PROFILE" "$1"
}

rt_assert_eq() {
    got=$1
    want=$2
    what=$3
    if [ "$got" = "$want" ]; then
        return 0
    fi
    rt_report_fail "$what (got '$got', want '$want')"
    return 1
}

rt_assert_contains() {
    haystack=$1
    needle=$2
    what=$3
    case "$haystack" in
        *"$needle"*) return 0 ;;
    esac
    rt_report_fail "$what (missing '$needle')"
    return 1
}

rt_finish() {
    if [ "$RT_FAILURES" -eq 0 ]; then
        exit 0
    fi
    printf 'RESULT: FAIL %s %s %d failed assertions\n' \
        "$RT_CAMPAIGN" "$RT_PROFILE" "$RT_FAILURES" >&2
    exit 1
}

# Boot the profile when no healthy target answers, remembering whether
# this campaign owns it; the trap tears a self-booted target down so a
# standalone campaign run leaves nothing behind.
RT_OWNS_TARGET=0

rt_ensure_profile() {
    profile=$1
    RT_PROFILE=$profile
    boot_profile() {
        sh "$REDETEAM_DIR/target.sh" down "$profile" >/dev/null 2>&1
        sh "$REDETEAM_DIR/target.sh" up "$profile" >/dev/null 2>&1
    }
    base=$(rt_base_url "$profile" 2>/dev/null || true)
    probe=$(curl -s --max-time 5 "$base/healthz" 2>/dev/null || true)
    case "$probe" in
        *'"ok":true'* | ok*) return 0 ;;
    esac
    # A state file with a dead or half-dead target is rebuilt from
    # scratch; the profile's own down cleans the ports first.
    if ! boot_profile; then
        rt_report_fail "target profile $profile failed to boot"
        exit 1
    fi
    base=$(rt_base_url "$profile" 2>/dev/null || true)
    probe=$(curl -s --max-time 5 "$base/healthz" 2>/dev/null || true)
    case "$probe" in
        *'"ok":true'* | ok*) ;;
        *)
            rt_report_fail "target profile $profile never answered healthz after boot"
            exit 1
            ;;
    esac
    RT_OWNS_TARGET=1
    # The orchestrator boots one target for many campaigns and asks for
    # it to be kept; a standalone run tears its own target down.
    if [ "${KIWI_RT_KEEP_TARGET:-0}" != "1" ]; then
        trap 'rt_teardown' EXIT
        RT_TMP_BODY=$(mktemp "${TMPDIR:-/tmp}/kiwi-rt-body.XXXXXX")
    fi
}

rt_teardown() {
    if [ "$RT_OWNS_TARGET" -eq 1 ]; then
        sh "$REDETEAM_DIR/target.sh" down "$RT_PROFILE" >/dev/null 2>&1
    fi
    rm -f "$RT_TMP_BODY" 2>/dev/null
}

rt_init
RT_TMP_BODY=$(mktemp "${TMPDIR:-/tmp}/kiwi-rt-body.XXXXXX")
trap 'rm -f "$RT_TMP_BODY"' EXIT
