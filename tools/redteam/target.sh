#!/bin/bash
# target.sh — the production-equivalent red-team target environment.
#
# change.md Part 9.2 requires a real target: the bundle's reference
# deployment (php -S with deploy/app/router.php, the REAL core issuer
# and verifier over the REAL store), the Rust verifier sidecar, Redis
# single and the sentinel trio, and the storage adapter matrix. This
# script brings every profile up on loopback, tracks the processes, and
# tears them down; campaigns never spawn infrastructure themselves.
#
# Profiles:
#   redis     the reference deployment (deploy/app router) on Redis
#   sentinel  master + replica + sentinel trio, deployment on master,
#             WAIT-verified replication (the 9.2 topology)
#   sqlite    the SQLite adapter path: the same core issuer/verifier
#             behind SqliteStorage, zero Redis at all
#   files     the single-node FilesystemStorage fallback (zero extra
#             infrastructure, the documented small-site path)
#   sidecar   the Rust verifier sidecar on its own port
#   all       every profile at once
#
# Commands:
#   target.sh up <profile>          boot and wait for healthz
#   target.sh down <profile|all>    stop and clean
#   target.sh rebind <profile> <redis-url>   repoint the deployment
#   target.sh status                one line per known profile
#   target.sh matrix <campaign.sh> [profiles...]  run a campaign over
#                                   the storage backend matrix
#
# Every profile writes tools/redteam/runs/env/<profile>.env with the
# ports, pids and the base URL the campaigns read.
#
# Environment knobs:
#   KIWI_RT_BASE_PORT        first redis-family port (default 6480)
#   KIWI_RT_SHA_BITS         challenge target bits (default 16, the
#                            fast end of the real ladder)
#   KIWI_RT_ISSUANCE_LIMIT   per-IP issuance per minute (0 = off)
#   KIWI_RT_TTL_SECS         challenge lifetime (default 120)
#   KIWI_RT_EXTRA_ENV        extra VAR=val pairs for the php process

set -u

RT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$RT_DIR/../.." && pwd)
RT_RUN_DIR="$RT_DIR/runs/env"
: "${KIWI_RT_BASE_PORT:=6480}"
PHP_PORT_OFFSET=2000
SECRET_DEFAULT='51502b24e13a2637325d6b1e505924615ad6fac2b9b17ccf2aa2eb62a2cbe6d1'

log() { printf 'target: %s\n' "$*" >&2; }

mkdir -p "$RT_RUN_DIR"

profile_port() {
    case "$1" in
        redis) echo $((KIWI_RT_BASE_PORT + PHP_PORT_OFFSET)) ;;
        sentinel) echo $((KIWI_RT_BASE_PORT + PHP_PORT_OFFSET + 1)) ;;
        sqlite) echo $((KIWI_RT_BASE_PORT + PHP_PORT_OFFSET + 2)) ;;
        files) echo $((KIWI_RT_BASE_PORT + PHP_PORT_OFFSET + 3)) ;;
        sidecar) echo $((KIWI_RT_BASE_PORT + PHP_PORT_OFFSET + 4)) ;;
        *) return 1 ;;
    esac
}

redis_port() {
    case "$1" in
        redis) echo "$KIWI_RT_BASE_PORT" ;;
        sentinel) echo $((KIWI_RT_BASE_PORT + 1)) ;;
        *) return 1 ;;
    esac
}

stop_pidfile() {
    file=$1
    [ -f "$file" ] || return 0
    pid=$(cat "$file" 2>/dev/null)
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null
    rm -f "$file"
}

wait_php_port() {
    port=$1
    i=0
    while [ "$i" -lt 60 ]; do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.2
    done
    return 1
}

# php -S with workers: the workers hold the listen socket, so killing
# the parent pid is not enough. Kill the whole server command line
# (the trailing space keeps port 848 from matching 8481) and wait for
# the port to be released.
kill_php_port() {
    port=$1
    pkill -f "php -S 127.0.0.1:$port " 2>/dev/null
    i=0
    while [ "$i" -lt 40 ]; do
        nc -z 127.0.0.1 "$port" 2>/dev/null || return 0
        i=$((i + 1))
        sleep 0.2
    done
    return 1
}

# Boot the reference deployment router (deploy/app/router.php) against
# a given redis URL. The env contract is exactly the deployment's own:
# KIWI_SECRET_KEY, KC_REDIS_URL and the documented knobs; nothing else.
start_reference_php() {
    profile=$1
    redis_url=$2
    port=$(profile_port "$profile")
    runprof="$RT_RUN_DIR/$profile"
    mkdir -p "$runprof"
    logfile="$RT_RUN_DIR/$profile.log"
    env KC_REDIS_URL="$redis_url" \
        KIWI_SECRET_KEY="$SECRET_DEFAULT" \
        KIWI_SHA_TARGET_BITS="${KIWI_RT_SHA_BITS:-16}" \
        KIWI_MIN_DURATION_MS=0 \
        KIWI_TTL_SECS="${KIWI_RT_TTL_SECS:-120}" \
        KIWI_ISSUANCE_PER_MINUTE_PER_IP="${KIWI_RT_ISSUANCE_LIMIT:-0}" \
        PHP_CLI_SERVER_WORKERS=8 \
        ${KIWI_RT_EXTRA_ENV:-} \
        php -S "127.0.0.1:$port" -t "$REPO_ROOT/deploy/app" \
            "$REPO_ROOT/deploy/app/router.php" >"$logfile" 2>&1 &
    echo $! >"$runprof/php.pid"
    echo "$port"
}

# Boot the storage-matrix router: the same core issuer and verifier
# with the storage adapter selected by KIWI_STORAGE (sqlite or files).
# No redis exists in these profiles; the issuance limiter is disabled
# (budget 0, the deployment's own documented off switch).
start_storage_php() {
    profile=$1
    port=$(profile_port "$profile")
    runprof="$RT_RUN_DIR/$profile"
    mkdir -p "$runprof"
    logfile="$RT_RUN_DIR/$profile.log"
    env KIWI_STORAGE="$profile" \
        KIWI_STORAGE_PATH="$runprof/kiwi.db" \
        KIWI_STORAGE_DIR="$runprof/records" \
        KC_REDIS_URL="redis://127.0.0.1:1" \
        KIWI_SECRET_KEY="$SECRET_DEFAULT" \
        KIWI_SHA_TARGET_BITS="${KIWI_RT_SHA_BITS:-16}" \
        KIWI_MIN_DURATION_MS=0 \
        KIWI_TTL_SECS="${KIWI_RT_TTL_SECS:-120}" \
        KIWI_ISSUANCE_PER_MINUTE_PER_IP=0 \
        php -S "127.0.0.1:$port" -t "$REPO_ROOT/deploy/app" \
            "$RT_DIR/target/router-storage.php" >"$logfile" 2>&1 &
    echo $! >"$runprof/php.pid"
    echo "$port"
}

start_redis() {
    profile=$1
    port=$(redis_port "$profile")
    runprof="$RT_RUN_DIR/$profile"
    mkdir -p "$runprof"
    logfile="$RT_RUN_DIR/$profile-redis.log"
    redis-server --port "$port" --bind 127.0.0.1 --save '' \
        --appendonly no --daemonize no --dir "$runprof" \
        >"$logfile" 2>&1 &
    echo $! >"$runprof/redis.pid"
}

start_sentinel_trio() {
    master=$((KIWI_RT_BASE_PORT + 1))
    replica=$((KIWI_RT_BASE_PORT + 2))
    sent=$((KIWI_RT_BASE_PORT + 3))
    runprof="$RT_RUN_DIR/sentinel"
    mkdir -p "$runprof"

    redis-server --port "$master" --bind 127.0.0.1 --save '' \
        --appendonly no --daemonize no --dir "$runprof" \
        >"$RT_RUN_DIR/sentinel-master.log" 2>&1 &
    echo $! >"$runprof/master.pid"

    redis-server --port "$replica" --bind 127.0.0.1 --save '' \
        --appendonly no --daemonize no --dir "$runprof" \
        --replicaof 127.0.0.1 "$master" \
        >"$RT_RUN_DIR/sentinel-replica.log" 2>&1 &
    echo $! >"$runprof/replica.pid"

    cat >"$runprof/sentinel.conf" <<EOF
port $sent
bind 127.0.0.1
daemonize no
sentinel monitor kiwi-master 127.0.0.1 $master 1
sentinel down-after-milliseconds kiwi-master 1500
sentinel failover-timeout kiwi-master 10000
sentinel parallel-syncs kiwi-master 1
EOF
    redis-sentinel "$runprof/sentinel.conf" \
        >"$RT_RUN_DIR/sentinel-node.log" 2>&1 &
    echo $! >"$runprof/sentinel.pid"
}

start_sidecar() {
    port=$(profile_port sidecar)
    bin="$REPO_ROOT/target/debug/kiwicaptcha-verifier"
    if [ ! -x "$bin" ]; then
        log "building kiwicaptcha-verifier"
        (cargo build -p kiwicaptcha-verifier >/dev/null 2>&1) || return 1
    fi
    logfile="$RT_RUN_DIR/sidecar.log"
    mkdir -p "$RT_RUN_DIR/sidecar"
    env KIWI_SECRET="$SECRET_DEFAULT" \
        "$bin" --listen "http://127.0.0.1:$port" --scopes login,signup \
        >"$logfile" 2>&1 &
    echo $! >"$RT_RUN_DIR/sidecar/sidecar.pid"
}

up_profile() {
    profile=$1
    case "$profile" in
        redis)
            start_redis redis
            sleep 0.4
            port=$(start_reference_php redis "redis://127.0.0.1:$(redis_port redis)")
            ;;
        sentinel)
            start_sentinel_trio
            sleep 0.8
            port=$(start_reference_php sentinel "redis://127.0.0.1:$((KIWI_RT_BASE_PORT + 1))")
            ;;
        sqlite)
            port=$(start_storage_php sqlite)
            ;;
        files)
            port=$(start_storage_php files)
            ;;
        sidecar)
            start_sidecar
            port=$(profile_port sidecar)
            ;;
        *) log "unknown profile: $profile"; return 2 ;;
    esac
    wait_php_port "$port" || { log "profile $profile never opened port $port"; return 1; }
    base="http://127.0.0.1:$port"
    healthy=''
    i=0
    while [ "$i" -lt 100 ]; do
        probe=$(curl -s --max-time 5 "$base/healthz" 2>/dev/null)
        case "$probe" in
            *'"ok":true'* | ok*)
                healthy=1
                break
                ;;
        esac
        i=$((i + 1))
        sleep 0.2
    done
    if [ -z "$healthy" ]; then
        log "profile $profile failed its health probe; see $RT_RUN_DIR/$profile.log"
        return 1
    fi
    state=$(rt_state_path "$profile")
    {
        echo "PROFILE=$profile"
        echo "BASE_URL=$base"
        echo "PORT=$port"
        case "$profile" in
            redis) echo "REDIS_URL=redis://127.0.0.1:$(redis_port redis)" ;;
            sentinel)
                echo "REDIS_URL=redis://127.0.0.1:$((KIWI_RT_BASE_PORT + 1))"
                echo "MASTER_PORT=$((KIWI_RT_BASE_PORT + 1))"
                echo "REPLICA_PORT=$((KIWI_RT_BASE_PORT + 2))"
                echo "SENTINEL_PORT=$((KIWI_RT_BASE_PORT + 3))"
                ;;
            sqlite) echo "SQLITE_PATH=$RT_RUN_DIR/sqlite/kiwi.db" ;;
        esac
    } >"$state"
    log "up $profile at $base"
}

rt_state_path() {
    printf '%s/%s.env' "$RT_RUN_DIR" "$1"
}

down_profile() {
    profile=$1
    state=$(rt_state_path "$profile")
    runprof="$RT_RUN_DIR/$profile"
    port=$(profile_port "$profile" 2>/dev/null) || port=''
    [ -n "$port" ] && kill_php_port "$port"
    for pidfile in "$runprof"/*.pid; do
        [ -e "$pidfile" ] || continue
        pid=$(cat "$pidfile" 2>/dev/null)
        [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null
        rm -f "$pidfile"
    done
    case "$profile" in
        redis)
            redis-cli -p "$(redis_port redis)" shutdown nosave >/dev/null 2>&1
            ;;
        sentinel)
            for p in $((KIWI_RT_BASE_PORT + 3)) $((KIWI_RT_BASE_PORT + 2)) $((KIWI_RT_BASE_PORT + 1)); do
                redis-cli -p "$p" shutdown nosave >/dev/null 2>&1
            done
            ;;
    esac
    rm -f "$state"
    log "down $profile"
}

rebind_profile() {
    profile=$1
    url=$2
    runprof="$RT_RUN_DIR/$profile"
    [ -f "$runprof/php.pid" ] || { log "profile $profile is not up"; return 1; }
    port=$(profile_port "$profile")
    kill_php_port "$port"
    env KC_REDIS_URL="$url" \
        KIWI_SECRET_KEY="$SECRET_DEFAULT" \
        KIWI_SHA_TARGET_BITS="${KIWI_RT_SHA_BITS:-16}" \
        KIWI_MIN_DURATION_MS=0 \
        KIWI_TTL_SECS="${KIWI_RT_TTL_SECS:-120}" \
        KIWI_ISSUANCE_PER_MINUTE_PER_IP="${KIWI_RT_ISSUANCE_LIMIT:-0}" \
        PHP_CLI_SERVER_WORKERS=8 \
        php -S "127.0.0.1:$port" -t "$REPO_ROOT/deploy/app" \
            "$REPO_ROOT/deploy/app/router.php" >>"$RT_RUN_DIR/$profile.log" 2>&1 &
    echo $! >"$runprof/php.pid"
    wait_php_port "$port" || { log "rebind never reopened port $port"; return 1; }
    sed "s|^REDIS_URL=.*|REDIS_URL=$url|" "$(rt_state_path "$profile")" >"$(rt_state_path "$profile").tmp"
    mv "$(rt_state_path "$profile").tmp" "$(rt_state_path "$profile")"
    log "rebound $profile to $url"
}

status_all() {
    for profile in redis sentinel sqlite files sidecar; do
        state=$(rt_state_path "$profile")
        if [ -f "$state" ]; then
            printf '%-9s up   %s\n' "$profile" "$(sed -n 's/^BASE_URL=//p' "$state")"
        else
            printf '%-9s down\n' "$profile"
        fi
    done
}

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case "$cmd" in
    up)
        [ $# -ge 1 ] || usage
        case "$1" in
            all)
                rc=0
                for p in redis sentinel sqlite files sidecar; do
                    up_profile "$p" || rc=1
                done
                exit $rc
                ;;
            *) up_profile "$1" ;;
        esac
        ;;
    down)
        [ $# -ge 1 ] || usage
        if [ "$1" = all ]; then
            for p in sidecar files sqlite sentinel redis; do
                down_profile "$p"
            done
        else
            down_profile "$1"
        fi
        ;;
    rebind)
        [ $# -ge 2 ] || usage
        rebind_profile "$1" "$2"
        ;;
    status)
        status_all
        ;;
    matrix)
        [ $# -ge 1 ] || usage
        campaign=$1
        shift
        profiles="$*"
        [ -n "$profiles" ] || profiles='redis sentinel sqlite files'
        rc=0
        for p in $profiles; do
            up_profile "$p" || { rc=1; continue; }
            RT_PROFILE=$p KIWI_RT_PROFILE=$p sh "$campaign" || rc=1
            down_profile "$p"
        done
        exit $rc
        ;;
    --help | -h | help) usage ;;
    *) usage ;;
esac
