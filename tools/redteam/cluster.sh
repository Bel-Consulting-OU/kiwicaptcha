#!/bin/bash
# cluster.sh — the B7.2 scale-target row of the release gate: a real
# three-primary Redis Cluster, booted locally, and the sharded
# keyspace suites run against it with the gated environment.
#
# The cluster: three primaries on ports 6433-6435 (the reference
# deployment the suites document), created with redis-cli --cluster.
# The suites: the rust sharded keyspace cluster leg and the php
# sharded store cluster test, both gated behind KIWI_SHARDING_CLUSTER=1
# with RISK_REDIS_URL pointing at the seed node.
#
# Usage:
#   tools/redteam/cluster.sh up        boot the cluster
#   tools/redteam/cluster.sh down      stop it
#   tools/redteam/cluster.sh suites    boot, run the suites, stop
#
# Exit code 0: both cluster legs green. 3: the cluster toolchain is
# unavailable (no redis with cluster support); the row prints the
# exact blocker and the gate renders TOOLCHAIN-ABSENT.

set -u
RT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$RT_DIR/../.." && pwd)
RUN_DIR="$RT_DIR/runs/env/cluster"
mkdir -p "$RUN_DIR"

PORTS="6433 6434 6435"

cluster_up() {
    command -v redis-server >/dev/null 2>&1 || {
        echo "TOOLCHAIN-ABSENT: redis-server is not installed; the cluster leg cannot run"
        return 3
    }
    # A stale nodes.conf from an earlier run makes the nodes refuse to
    # join a fresh cluster; the boot starts from clean node state.
    rm -f "$RUN_DIR"/nodes-*.conf "$RUN_DIR"/nodes.conf "$RUN_DIR"/dump-*.rdb 2>/dev/null
    local ok=1
    for port in $PORTS; do
        redis-server --port "$port" --bind 127.0.0.1 --save '' --appendonly no \
            --cluster-enabled yes --cluster-config-file "$RUN_DIR/nodes-$port.conf" \
            --cluster-node-timeout 3000 --daemonize no --dir "$RUN_DIR" \
            >"$RUN_DIR/redis-$port.log" 2>&1 &
        echo $! >"$RUN_DIR/redis-$port.pid"
    done
    sleep 1.2
    yes yes | redis-cli --cluster create 127.0.0.1:6433 127.0.0.1:6434 127.0.0.1:6435 \
        --cluster-replicas 0 >"$RUN_DIR/cluster-create.log" 2>&1 || ok=0
    if [ "$ok" != 1 ]; then
        echo "TOOLCHAIN-ABSENT/ERROR: the cluster create failed; see $RUN_DIR/cluster-create.log"
        tail -3 "$RUN_DIR/cluster-create.log"
        cluster_down
        return 3
    fi
    # The cluster must agree it is up before the suites run.
    local info
    info=$(redis-cli -p 6433 cluster info 2>/dev/null | grep cluster_state | tr -d '\r')
    if [ "$info" != "cluster_state:ok" ]; then
        echo "TOOLCHAIN-ABSENT/ERROR: the cluster never reached cluster_state:ok (got ${info:-none})"
        cluster_down
        return 3
    fi
    echo "cluster: up (three primaries 6433-6435, $info)"
}

cluster_down() {
    for port in $PORTS; do
        if [ -f "$RUN_DIR/redis-$port.pid" ]; then
            kill "$(cat "$RUN_DIR/redis-$port.pid")" 2>/dev/null
            rm -f "$RUN_DIR/redis-$port.pid"
        fi
        redis-cli -p "$port" shutdown nosave >/dev/null 2>&1
    done
    echo "cluster: down"
}

cluster_suites() {
    local rc=0
    cluster_up || return $?
    export KIWI_SHARDING_CLUSTER=1
    export RISK_REDIS_URL="redis://127.0.0.1:6433"
    echo "cluster: rust sharded keyspace cluster leg"
    if (cd "$REPO_ROOT" && cargo test -q -p kiwicaptcha-risk --test sharded_keyspace cluster_topology_serves_the_sharded_invariants >"$RUN_DIR/rust-cluster.log" 2>&1); then
        echo "cluster: rust leg green ($(grep -c 'test result: ok' "$RUN_DIR/rust-cluster.log") ok)"
    else
        echo "cluster: RUST LEG FAILED; see $RUN_DIR/rust-cluster.log"
        tail -5 "$RUN_DIR/rust-cluster.log"
        rc=1
    fi
    echo "cluster: php sharded store cluster leg"
    if (cd "$REPO_ROOT/packages/kiwicaptcha-risk-php" && KIWI_SHARDING_CLUSTER=1 RISK_REDIS_URL="redis://127.0.0.1:6433" \
            ./vendor/bin/phpunit --filter 'testShardedClusterTopology' >"$RUN_DIR/php-cluster.log" 2>&1); then
        echo "cluster: php leg green"
    else
        echo "cluster: PHP LEG FAILED; see $RUN_DIR/php-cluster.log"
        tail -5 "$RUN_DIR/php-cluster.log"
        rc=1
    fi
    cluster_down
    return $rc
}

case "${1:-suites}" in
    up) cluster_up ;;
    down) cluster_down ;;
    suites) cluster_suites ;;
    *) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
