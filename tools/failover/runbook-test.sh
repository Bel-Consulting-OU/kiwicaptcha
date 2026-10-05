#!/usr/bin/env bash
# runbook-test.sh — the automated test of tools/failover/runbook.sh.
#
# Topology contract (change.md Part 9 / 3.7.4): when redis-sentinel is
# installed, build a real 1-master / 1-replica / 1-sentinel trio on
# ports 6430 / 6431 / 6432, run the runbook against it, assert the
# failover completed and the stale primary refuses writes, then tear
# everything down. When redis-sentinel is absent, run the runbook
# against a single redis with role assertions only and document the gap
# honestly (the promotion and stale-refusal steps are untested there).
#
# Dependencies: redis-server, redis-cli, and redis-sentinel when the
# full trio branch runs. Ports 6430-6432 must be free.

set -u

BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNBOOK="$BASE/runbook.sh"
HOST=127.0.0.1
MASTER_PORT=6430
REPLICA_PORT=6431
SENTINEL_PORT=6432
NAME=kiwi
WORK=""
MASTER_PID=""
REPLICA_PID=""
SENTINEL_PID=""

fail() { printf 'runbook-test FAIL: %s\n' "$1" >&2; cleanup; exit 1; }
note() { printf 'runbook-test: %s\n' "$1"; }

cleanup() {
    for pid in "$SENTINEL_PID" "$REPLICA_PID" "$MASTER_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done
    if [ -n "$WORK" ] && [ -d "$WORK" ]; then
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT INT TERM

start_server() {
    # start_server <port> <extra-config...>: start one redis-server,
    # echo its pid on success.
    local port="$1"; shift
    local dir="$WORK/$port"
    mkdir -p "$dir"
    redis-server --port "$port" --bind "$HOST" --save '' --appendonly no \
        --dir "$dir" --daemonize no --pidfile "$dir/pid" "$@" >/dev/null 2>&1 &
    echo $!
}

wait_ping() {
    local port="$1" waited=0
    while [ "$waited" -lt 30 ]; do
        if redis-cli -h "$HOST" -p "$port" PING >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2 2>/dev/null || sleep 1
        waited=$((waited + 1))
    done
    return 1
}

field_of() {
    # field_of <port> <field>: the value after the named field in the
    # INFO replication section (CRLF stripped). The command words go to
    # redis-cli separately: every argument is one command token.
    redis-cli -h "$HOST" -p "$1" --raw INFO replication 2>/dev/null \
        | awk -F: -v f="$2" '$1 == f { sub("\r", "", $2); print $2; exit }'
}

if ! command -v redis-cli >/dev/null 2>&1 || ! command -v redis-server >/dev/null 2>&1; then
    printf 'runbook-test SKIP: redis-server/redis-cli are not installed\n'
    exit 0
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/kiwi-failover-test.XXXXXX")

if ! command -v redis-sentinel >/dev/null 2>&1; then
    # THE DOCUMENTED GAP: no sentinel binary, so the promotion and
    # stale-refusal steps cannot be exercised here. Run the runbook
    # against a single redis: the role, pin and fence checks run, and
    # the runbook reports the skipped failover steps as an explicit GAP.
    note "redis-sentinel not installed: exercising the single-node branch (the failover steps stay untested on this host)"
    MASTER_PID=$(start_server "$MASTER_PORT")
    wait_ping "$MASTER_PORT" || fail "the single redis on $MASTER_PORT never answered PING"
    out=$("$RUNBOOK" --host "$HOST" --master-port "$MASTER_PORT" --name "$NAME")
    printf '%s\n' "$out"
    printf '%s\n' "$out" | grep -q 'single-node drill complete' \
        || fail "the runbook did not complete the single-node drill"
    printf '%s\n' "$out" | grep -q 'runbook GAP' \
        || fail "the single-node branch must document the failover gap honestly"
    [ "$(field_of "$MASTER_PORT" role)" = "master" ] \
        || fail "role assertion: the node must still be a master"
    note "single-node branch passed with the gap documented"
    cleanup
    trap - EXIT INT TERM
    exit 0
fi

# The full trio: 1 master (6430), 1 replica (6431), 1 sentinel (6432).
note "building the 1-master/1-replica/1-sentinel trio on ports $MASTER_PORT/$REPLICA_PORT/$SENTINEL_PORT"
MASTER_PID=$(start_server "$MASTER_PORT")
wait_ping "$MASTER_PORT" || fail "the master on $MASTER_PORT never answered PING"
REPLICA_PID=$(start_server "$REPLICA_PORT" --replicaof "$HOST" "$MASTER_PORT")
wait_ping "$REPLICA_PORT" || fail "the replica on $REPLICA_PORT never answered PING"

cat > "$WORK/sentinel.conf" <<EOF
port $SENTINEL_PORT
bind $HOST
daemonize no
pidfile "$WORK/$SENTINEL_PORT/pid"
dir "$WORK/$SENTINEL_PORT"
sentinel monitor $NAME $HOST $MASTER_PORT 1
sentinel down-after-milliseconds $NAME 2000
sentinel failover-timeout $NAME 60000
sentinel parallel-syncs $NAME 1
EOF
mkdir -p "$WORK/$SENTINEL_PORT"
redis-sentinel "$WORK/sentinel.conf" >/dev/null 2>&1 &
SENTINEL_PID=$!

wait_role() {
    # wait_role <port> <expected-role> <field> <expected-value> <ticks>
    local port="$1" want_role="$2" field="$3" value="$4" ticks="$5" waited=0 v="" got_role=""
    while [ "$waited" -lt "$ticks" ]; do
        v=$(field_of "$port" "$field")
        got_role=$(field_of "$port" role)
        if [ "$got_role" = "$want_role" ] && [ "$v" = "$value" ]; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

wait_role "$REPLICA_PORT" slave master_link_status up 30 \
    || fail "the replica never synced with the master (master_link_status)"

# The sentinel must discover the monitor before the drill starts.
sentinel_ready=0
for _ in $(seq 1 30); do
    if redis-cli -h "$HOST" -p "$SENTINEL_PORT" --raw SENTINEL get-master-addr-by-name "$NAME" 2>/dev/null | grep -q "$MASTER_PORT"; then
        sentinel_ready=1
        break
    fi
    sleep 1
done
[ "$sentinel_ready" = "1" ] || fail "the sentinel never registered the $NAME monitor"

# The sentinel must also have DISCOVERED the replica before the drill:
# a forced failover with no known replica aborts and parks new attempts
# for the failover-timeout.
replica_seen=0
for _ in $(seq 1 30); do
    if redis-cli -h "$HOST" -p "$SENTINEL_PORT" --raw SENTINEL slaves "$NAME" 2>/dev/null | grep -q "$REPLICA_PORT"; then
        replica_seen=1
        break
    fi
    sleep 1
done
[ "$replica_seen" = "1" ] || fail "the sentinel never discovered the replica on $REPLICA_PORT"

# Sanity: the pre-drill pin keyspace of the runbook is the master.
[ "$(field_of "$MASTER_PORT" role)" = "master" ] \
    || fail "role assertion: $MASTER_PORT must start as the master"

# Run the runbook against the real trio.
if ! out=$("$RUNBOOK" --host "$HOST" --master-port "$MASTER_PORT" \
        --replica-port "$REPLICA_PORT" --sentinel-port "$SENTINEL_PORT" \
        --name "$NAME" --wait 90); then
    printf '%s\n' "$out"
    fail "the runbook exited non-zero against the real trio"
fi
printf '%s\n' "$out"

# Post-drill assertions: the failover happened (the roles flipped) and
# the runbook verified the stale-primary refusal.
new_master_port=$(redis-cli -h "$HOST" -p "$SENTINEL_PORT" --raw SENTINEL get-master-addr-by-name "$NAME" 2>/dev/null | sed -n 2p)
[ -n "$new_master_port" ] || fail "the sentinel lost the $NAME monitor after the drill"
[ "$new_master_port" != "$MASTER_PORT" ] || fail "the failover did not promote the replica (sentinel still points at $MASTER_PORT)"
[ "$(field_of "$new_master_port" role)" = "master" ] \
    || fail "role assertion: the promoted node $new_master_port must be a master"
demoted_role=$(field_of "$MASTER_PORT" role)
[ "$demoted_role" = "slave" ] || [ "$demoted_role" = "replica" ] \
    || fail "role assertion: the demoted node $MASTER_PORT must be a replica"
printf '%s\n' "$out" | grep -q 'the demoted primary refuses writes' \
    || fail "the runbook did not verify the stale-primary refusal"
printf '%s\n' "$out" | grep -q 'pinned-primary guard REFUSES' \
    || fail "the runbook did not verify the authority pin refuse-on-change"
probe="kiwi:failover:probe-readonly-check"
if redis-cli -h "$HOST" -p "$MASTER_PORT" --raw SET "$probe" x 2>&1 | grep -qi 'READONLY'; then
    note "direct stale-primary refusal confirmed after the drill (READONLY on $MASTER_PORT)"
else
    fail "the demoted primary accepted a write after the drill"
fi

note "trio drill passed: failover $MASTER_PORT -> $new_master_port with stale-primary refusal"
cleanup
trap - EXIT INT TERM
exit 0
