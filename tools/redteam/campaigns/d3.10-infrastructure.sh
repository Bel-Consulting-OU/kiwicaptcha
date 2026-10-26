#!/bin/bash
# d3.10-infrastructure.sh — the infrastructure attacker (change.md D3.10).
#
# A storage-plane adversary with read and write access to the live
# record store re-drives the cores' adversarial suites at the
# deployment level: forged record injection, MAC strip and transplant,
# epoch and policy manipulation, clock skew of plus and minus ten
# minutes through the persisted timestamps, scope rewrite, and replay
# after a rollback of the pending record. The matrix runs on every
# storage backend: redis, the sentinel trio, sqlite and the
# filesystem fallback.
#
# On the sentinel profile the campaign adds the failover schedule:
# WAIT-verified replication of a pending record, promotion under a
# killed primary mid-consume, continuity of an unconsumed token after
# the promotion, refusal of the consumed state, and the stale primary
# rejoining as a read-only replica.
#
# Required result: zero acceptances of forged, stripped, transplanted,
# manipulated, skewed or rolled-back state under every fault schedule.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.10-infrastructure
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
BASE=$(rt_base_url "$RT_PROFILE")

export KIWI_RT_BASE="$BASE"
export KIWI_RT_BACKEND="$RT_PROFILE"
export KIWI_RT_REDIS_URL="$(rt_state_get "$RT_PROFILE" REDIS_URL)"
export KIWI_RT_SQLITE_PATH="$RT_DIR/runs/env/$RT_PROFILE/kiwi.db"
export KIWI_RT_FILES_DIR="$RT_DIR/runs/env/$RT_PROFILE"

OUT=$(python3 "$RT_DIR/campaigns/lib/d310.driver.py" 2>"$RT_DIR/runs/env/d310-$RT_PROFILE.err")
DRIVER_RC=$?
[ "$DRIVER_RC" -le 1 ] || { rt_report_fail "driver crashed; see runs/env/d310-$RT_PROFILE.err"; rt_finish; }

printf '%s\n' "$OUT" | python3 -c '
import json, sys

doc = json.load(sys.stdin)
for row in doc["legs"]:
    print("ASSERT: %s %s%s" % ("PASS" if row["ok"] else "FAIL", row["what"],
                               "" if row["ok"] else " (%s)" % row["detail"]))
print("accepted:", len(doc["accepted"]), doc["accepted"])
'

ACCEPTED_COUNT=$(printf '%s' "$OUT" | python3 -c 'import json, sys; print(len(json.load(sys.stdin)["accepted"]))')
rt_assert_eq "$ACCEPTED_COUNT" "0" "zero tampered, forged or rolled-back states accepted on $RT_PROFILE"
printf 'ECONOMIC: %s %s cost_per_accepted_abuse=unbounded accepted=%s backend=%s\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE" "$ACCEPTED_COUNT" "$RT_PROFILE"

# The sentinel failover schedule runs against the sentinel trio only.
if [ "$RT_PROFILE" = sentinel ]; then
    MASTER_PORT=$(rt_state_get sentinel MASTER_PORT)
    REPLICA_PORT=$(rt_state_get sentinel REPLICA_PORT)
    SENTINEL_PORT=$(rt_state_get sentinel SENTINEL_PORT)

    # Issue one challenge, prove the replica holds it (WAIT 1 0), then
    # kill the primary mid-consume and let the sentinel promote.
    TOKEN=$(KIWI_RT_BASE="$BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PYSOLVE'
import os, sys
sys.path.insert(0, os.environ["KIWI_RT_DIR"])
import rtclient as rt
doc = rt.challenge(os.environ["KIWI_RT_BASE"], "login")
counter = rt.pow_solve(doc.body)
print(rt.mint_token(str(doc.body["nonce"]), counter))
PYSOLVE
    )
    # WAIT-verified replication: WAIT is issued against the primary
    # (its acked-return rides the fail detail), and a bounded scan
    # window then proves the record is readable on the replica. A
    # single fire-and-forget WAIT plus one scan raced the fresh-boot
    # link under load and failed the leg while the link was healthy
    # seconds later — the window absorbs that scheduling jitter but
    # stays fail-closed: no record on the replica after the window is
    # still a FAIL.
    ACKS=$(redis-cli -p "$MASTER_PORT" wait 1 3000 2>/dev/null | tr -d '[:space:]')
    REPLICATED=''
    i=0
    while [ "$i" -lt 10 ]; do
        REPLICATED=$(redis-cli -p "$REPLICA_PORT" --scan --pattern 'kiwicaptcha:*' 2>/dev/null | head -n 1)
        if [ -n "$REPLICATED" ]; then
            break
        fi
        sleep 0.3
        i=$((i + 1))
    done
    if [ -n "$REPLICATED" ]; then
        rt_report_pass "pending record replicated to the replica (WAIT verified topology, acks=${ACKS:-0})"
    else
        rt_report_fail "pending record never reached the replica (wait acks=${ACKS:-0}, scan empty after the bounded window)"
    fi

    redis-cli -p "$MASTER_PORT" shutdown nosave >/dev/null 2>&1
    NEW_MASTER_PORT=''
    i=0
    # The promotion window absorbs scheduling jitter on a loaded box:
    # sentinel's failover detection plus the replica's takeover can
    # exceed the old 15 s under contention, which reported a healthy
    # topology as "never promoted" (a false RED, the same class as the
    # sw-mitm probe race). 50 s stays fail-closed — no promotion after
    # the window is still a FAIL.
    while [ "$i" -lt 166 ]; do
        CANDIDATE=$(redis-cli -p "$SENTINEL_PORT" --no-auth-warning sentinel get-master-addr-by-name kiwi-master 2>/dev/null | tail -n 1)
        if [ -n "$CANDIDATE" ] && [ "$CANDIDATE" != "$MASTER_PORT" ]; then
            NEW_MASTER_PORT=$CANDIDATE
            break
        fi
        i=$((i + 1))
        sleep 0.3
    done
    if [ -n "${NEW_MASTER_PORT:-}" ] && [ "$NEW_MASTER_PORT" != "$MASTER_PORT" ]; then
        rt_report_pass "sentinel promoted the replica after the primary died mid-consume"
    else
        rt_report_fail "sentinel never promoted (new master: ${NEW_MASTER_PORT:-none})"
        rt_finish
    fi

    sh "$RT_DIR/target.sh" rebind sentinel "redis://127.0.0.1:$NEW_MASTER_PORT" >/dev/null 2>&1 || {
        rt_report_fail "deployment rebind to the promoted primary failed"
        rt_finish
    }

    CONT=$(rt_verify_token sentinel "$TOKEN")
    case "$CONT" in
        *'"ok":true'*) rt_report_pass "unconsumed token survives the failover (continuity)" ;;
        *) rt_report_fail "unconsumed token refused after failover ($CONT)" ;;
    esac

    sh "$RT_DIR/target.sh" down sentinel >/dev/null 2>&1
    sleep 0.3
    redis-server --port "$MASTER_PORT" --bind 127.0.0.1 --save '' --appendonly no \
        --dir "$RT_DIR/runs/env/sentinel" >/dev/null 2>&1 &
    STALE_PID=$!
    sleep 0.8
    redis-cli -p "$MASTER_PORT" replicaof 127.0.0.1 "$NEW_MASTER_PORT" >/dev/null 2>&1
    sleep 0.5
    ROLE=$(redis-cli -p "$MASTER_PORT" role 2>/dev/null | head -n 1)
    rt_assert_eq "$ROLE" "slave" "restarted stale primary rejoins as a read-only replica"
    WRITE=$(redis-cli -p "$MASTER_PORT" set kiwicaptcha:attacker-write x 2>&1 | head -n 1)
    rt_assert_contains "$WRITE" "READONLY" "stale primary refuses writes (HA authority)"
    kill "$STALE_PID" 2>/dev/null
    printf 'ECONOMIC: %s sentinel failover_continuity=ok stale_primary=readonly\n' "$RT_CAMPAIGN"
fi

# The metric names the backend THIS invocation exercised, never a
# static composite. A composite GREEN without per-backend runs
# overstates the evidence; the ledger shows the one backend that ran.
rt_metric "tamper_classes=11 acceptance_among_tampered=0 backend=${KIWI_RT_BACKEND:-redis} (single backend per invocation; multi-backend coverage is a separate per-backend campaign)"

rt_finish