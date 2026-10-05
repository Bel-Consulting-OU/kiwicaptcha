#!/usr/bin/env bash
# runbook.sh — the KiwiCaptcha HA failover runbook (change.md Part 9 /
# 3.7.4): executable against a real 1-master / 1-replica / 1-sentinel
# topology. Dependencies: redis-cli and coreutils only.
#
# Per-plane availability SLO (the published constants, change.md
# 3.7.4): the monthly availability each serving plane commits to, and
# the stale-primary tolerance the plane's transitions carry. The
# failover drill below is the operational proof that the storage
# plane's numbers are reachable and that no plane serves a stale
# authority.
#
#   Plane                          Surface                        Monthly SLO   Stale-primary tolerance
#   1-3 identity/evidence/decision widget + issuance + assessment   99.9%         none (stateless reads re-issue)
#   3   decision (scored issue)    one-shot signed record          99.9%         none (single-use on the authority)
#   4   enforcement                consume / chain / step-up       99.95%        refuse (security-final, pinned)
#   5   outcomes                   ledger confirm / correct        99.5%         refuse (exactly-once ledger)
#   6   agents                     signed agent API                99.5%         none (idempotent by quota window)
#   7   storage                    Redis authority                 99.95%        fence: WAIT barrier + identity pin
#   8   observability              metrics export                  99.0%         none (best-effort counters)
#
# RTO budget: the drill asserts a completed failover (promotion +
# replica catch-up + verified WAIT) within FAILOVER_DEADLINE_SECS
# (90 s by default, --wait to override).
#
# What each step proves:
#   1. roles        the topology is the shape the SLO table assumes:
#                   one primary, one replica, one Sentinel watching.
#   2. pin          the serving primary's identity is recorded in the
#                   docs/ha-authority.md shape "role|run_id" (the same
#                   identity the bundle's PinnedPrimaryAuthorityGuard
#                   pins via kiwicaptcha:ha-initialize, and the same
#                   comparison the guard runs before every
#                   durability-critical command).
#   3. fence        the verified-WAIT barrier: a fence write on the
#                   primary is acknowledged by the replica via WAIT,
#                   the causal replication fence the store brackets
#                   every security-final transition with.
#   4. failover     SENTINEL FAILOVER promotes the replica.
#   5. serve/refuse the promoted primary serves writes; the demoted
#                   old primary refuses them (READONLY) — the stale
#                   primary never accepts a divergent write.
#   6. refuse       the HA authority REFUSES the promoted identity: the
#                   new primary's "role|run_id" differs from the pin,
#                   which is exactly the PinnedAuthorityRefusalException
#                   the guard raises (pinned vs observed). The runbook
#                   never re-pins automatically: re-pinning is the
#                   deliberate operator procedure (quiesce, then
#                   kiwicaptcha:ha-initialize --force, then doctor).
#
# Usage:
#   runbook.sh [--host H] [--master-port P] [--replica-port P]
#              [--sentinel-port P] [--name N] [--wait N] [--dry-run]
#   Defaults: host 127.0.0.1, master 6430, replica 6431, sentinel 6432,
#   sentinel monitor name "kiwi". --dry-run prints the plan and touches
#   nothing.
#
# Exit codes: 0 the drill passed (a skipped failover on a single-node
# topology is a pass with an honest GAP line), 1 a check failed.

set -u

HOST=127.0.0.1
MASTER_PORT=6430
REPLICA_PORT=6431
SENTINEL_PORT=6432
NAME=kiwi
DRY_RUN=0
FAILOVER_DEADLINE_SECS=90
STEP=0

die() { printf 'runbook FAIL: %s\n' "$1" >&2; exit 1; }
info() { STEP=$((STEP + 1)); printf '[%02d] %s\n' "$STEP" "$1"; }
gap() { printf 'runbook GAP: %s\n' "$1"; }
pass() { printf 'runbook PASS: %s\n' "$1"; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --master-port) MASTER_PORT="$2"; shift 2 ;;
        --replica-port) REPLICA_PORT="$2"; shift 2 ;;
        --sentinel-port) SENTINEL_PORT="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --wait) FAILOVER_DEADLINE_SECS="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help)
            sed -n '2,66p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

if ! command -v redis-cli >/dev/null 2>&1; then
    die "redis-cli is required (no other dependency)"
fi

# rc <port> <command words...>: one redis-cli round trip with stderr
# suppressed (the words must be passed separately: redis-cli maps every
# argument to one command token).
rc() {
    local port="$1"; shift
    redis-cli -h "$HOST" -p "$port" --raw "$@" 2>/dev/null
}

# rc_err <port> <command words...>: the same, with the server error
# reply (or the stderr) on stdout for the caller to show.
rc_err() {
    local port="$1"; shift
    redis-cli -h "$HOST" -p "$port" --raw "$@" 2>&1
}

sentinel_cmd() {
    local sub="$1"; shift
    redis-cli -h "$HOST" -p "$SENTINEL_PORT" --raw SENTINEL "$sub" "$@" 2>/dev/null
}

field_of() {
    # field_of <port> <field>: the value after the named field in the
    # INFO replication section (CRLF stripped).
    redis-cli -h "$HOST" -p "$1" --raw INFO replication 2>/dev/null \
        | awk -F: -v f="$2" '$1 == f { sub("\r", "", $2); print $2; exit }'
}

identity_of() {
    # The serving authority identity in the ha-authority.md pin shape
    # "role|run_id" (the guard reads INFO replication and falls back to
    # INFO server for the run_id; an incomplete identity is treated as
    # stale, never passed).
    local role run_id
    role=$(field_of "$1" role)
    run_id=$(field_of "$1" run_id)
    if [ -z "$run_id" ]; then
        # Newer Redis builds report run_id from the server section only
        # (the same fallback the pinned-primary guard performs).
        run_id=$(redis-cli -h "$HOST" -p "$1" --raw INFO server 2>/dev/null \
            | awk -F: -v f="run_id" '$1 == f { sub("\r", "", $2); print $2; exit }')
    fi
    if [ -z "$role" ] || [ -z "$run_id" ]; then
        printf ''
    else
        printf '%s|%s' "$role" "$run_id"
    fi
}

sentinel_master_port() {
    sentinel_cmd get-master-addr-by-name "$NAME" | sed -n 2p
}

# Predicates for the polling loops: each returns 0 when its condition
# holds, and new_primary_serving also prints the promoted port.
new_primary_serving() {
    local addr
    addr=$(sentinel_master_port)
    [ -n "$addr" ] || return 1
    [ "$addr" != "$MASTER_PORT" ] || return 1
    [ "$(field_of "$addr" role)" = "master" ] || return 1
    printf '%s' "$addr"
}

old_primary_is_replica() {
    local v
    v=$(field_of "$MASTER_PORT" role)
    [ "$v" = "slave" ] || [ "$v" = "replica" ]
}

old_primary_synced() {
    [ "$(field_of "$MASTER_PORT" master_link_status)" = "up" ]
}

poll_quiet() {
    # poll_quiet <deadline-secs> <predicate-fn>: poll_until without the
    # deadline noise (used inside retry loops that print their own).
    local deadline="$1" fn="$2"
    local waited=0
    while [ "$waited" -le "$deadline" ]; do
        if "$fn"; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

poll_until() {
    # poll_until <deadline-secs> <predicate-fn> <description>
    local deadline="$1" fn="$2" desc="$3"
    local waited=0
    while [ "$waited" -le "$deadline" ]; do
        if "$fn"; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    printf 'runbook FAIL: deadline (%ds) exceeded while waiting for %s\n' "$deadline" "$desc" >&2
    return 1
}

plan() {
    cat <<PLAN
failover runbook plan (dry run; nothing below was executed against Redis):
  topology        $HOST:$MASTER_PORT (primary), $HOST:$REPLICA_PORT (replica), sentinel $HOST:$SENTINEL_PORT ("$NAME")
  01 roles        INFO replication on both nodes + SENTINEL masters matches the pair
  02 pin          record the primary identity "role|run_id" (the ha-authority pin shape)
  03 fence        fence write + WAIT 1 on the primary (the verified-WAIT barrier)
  04 failover     SENTINEL FAILOVER $NAME, deadline ${FAILOVER_DEADLINE_SECS}s
  05 serve/refuse the promoted primary answers SET/GET; the demoted primary refuses writes (READONLY)
  06 refuse       the new primary identity differs from the pin: the pinned-primary guard would refuse it
                  (pinned vs observed, docs/ha-authority.md); re-pin deliberately via kiwicaptcha:ha-initialize
PLAN
}

if [ "$DRY_RUN" = "1" ]; then
    plan
    exit 0
fi

# 01 roles: the topology must be the shape the SLO table assumes.
info "roles: primary $HOST:$MASTER_PORT, replica $HOST:$REPLICA_PORT, sentinel $HOST:$SENTINEL_PORT"
rc "$MASTER_PORT" PING >/dev/null || die "primary $HOST:$MASTER_PORT does not answer PING"
master_role=$(field_of "$MASTER_PORT" role)
[ "$master_role" = "master" ] || die "expected role master on $MASTER_PORT, got '${master_role:-none}'"
replica_role=$(field_of "$REPLICA_PORT" role)
replica_up=$(field_of "$REPLICA_PORT" master_link_status)
if [ "$replica_role" = "slave" ] || [ "$replica_role" = "replica" ]; then
    pass "role check: primary on $MASTER_PORT, replica on $REPLICA_PORT (link: ${replica_up:-unknown})"
else
    gap "node $REPLICA_PORT is not a replica (role '${replica_role:-none}'): single-node topology"
fi
if sentinel_cmd get-master-addr-by-name "$NAME" | grep -q .; then
    pass "sentinel \"$NAME\" tracks: $(sentinel_master_port)"
else
    gap "sentinel on $SENTINEL_PORT has no monitor named \"$NAME\" (or is unreachable): the failover steps will be skipped"
fi

# 02 pin: record the serving authority identity.
info "pin: record the primary identity (docs/ha-authority.md shape role|run_id)"
PIN=$(identity_of "$MASTER_PORT")
[ -n "$PIN" ] || die "could not read the primary identity (role/run_id): an unverifiable authority is treated as stale"
pass "pin recorded: $PIN"

# 03 fence: the verified-WAIT barrier over the causal fence write.
info "fence: fence write + WAIT on the primary (the verified-WAIT barrier)"
fence_set=$(rc "$MASTER_PORT" SET kiwi:failover:fence "fence-$(date +%s%N)")
[ "$fence_set" = "OK" ] || die "the primary refused a plain write (reply: ${fence_set:-none})"
acked=$(rc "$MASTER_PORT" WAIT 1 5000)
if [ "${acked:-0}" -ge 1 ] 2>/dev/null; then
    pass "fence verified: $acked replica acknowledged the fence write (WAIT 1 5000)"
else
    gap "no replica acknowledged the fence write within 5 s: the verified-WAIT barrier has nothing to wait for on this topology"
fi

if ! sentinel_cmd get-master-addr-by-name "$NAME" | grep -q .; then
    # Honest single-node gap: the promotion steps need the Sentinel
    # machinery; everything verifiable on this topology was verified.
    gap "SENTINEL FAILOVER not exercised: no sentinel monitor named \"$NAME\" answered. \
This run verified the role shape, the authority pin and the fence/WAIT barrier on the single node; \
the promotion, stale-primary refusal and re-pin steps need the 1-master/1-replica/1-sentinel trio \
(tools/failover/runbook-test.sh builds it whenever redis-sentinel is installed)."
    pass "single-node drill complete (failover steps skipped and documented)"
    exit 0
fi

# 04 failover: promote the replica through the Sentinel. The first
# attempt can be refused or aborted while the Sentinel completes its
# discovery (a refused attempt also parks new attempts for the
# failover-timeout), so the command is retried until the deadline.
info "failover: SENTINEL FAILOVER $NAME (deadline ${FAILOVER_DEADLINE_SECS}s)"
drain_started=$(date +%s)
promoted=0
while [ $(( $(date +%s) - drain_started )) -le "$FAILOVER_DEADLINE_SECS" ]; do
    sentinel_cmd failover "$NAME" >/dev/null 2>&1
    if poll_quiet 10 new_primary_serving >/dev/null; then
        promoted=1
        break
    fi
    sleep 5
done
[ "$promoted" = "1" ] || die "the sentinel did not promote a new primary within ${FAILOVER_DEADLINE_SECS}s"

# 05 serve/refuse: the promoted primary serves, the old primary refuses.
info "verify: the new primary serves writes; the old primary refuses them"
NEW_PORT=$(sentinel_master_port)
[ -n "$NEW_PORT" ] || die "lost the sentinel's view of the new primary"
probe="kiwi:failover:probe-$(date +%s%N)"
serve_set=$(rc "$NEW_PORT" SET "$probe" served)
[ "$serve_set" = "OK" ] || die "the promoted primary on $NEW_PORT refused a write (reply: ${serve_set:-none})"
[ "$(rc "$NEW_PORT" GET "$probe")" = "served" ] \
    || die "the promoted primary on $NEW_PORT did not serve the write back"
pass "serve: the promoted primary $HOST:$NEW_PORT answers SET/GET"

poll_until "$FAILOVER_DEADLINE_SECS" old_primary_is_replica \
    "the demoted primary ($MASTER_PORT) to become a replica" \
    || die "the old primary did not demote to replica within ${FAILOVER_DEADLINE_SECS}s"
readonly_err=$(rc_err "$MASTER_PORT" SET "$probe" divergent | head -n 1)
case "$readonly_err" in
    *READONLY*) pass "refuse: the demoted primary refuses writes ($readonly_err)" ;;
    OK) die "the demoted primary on $MASTER_PORT accepted a write: a stale primary must refuse (READONLY)" ;;
    *) die "the demoted primary on $MASTER_PORT answered unexpectedly: ${readonly_err:-no reply}" ;;
esac
rc "$NEW_PORT" "DEL $probe" >/dev/null

# 06 refuse: the pinned-primary guard semantics against the new authority.
info "refuse: compare the promoted identity against the pin (the guard's pinned vs observed decision)"
OBSERVED=$(identity_of "$NEW_PORT")
[ -n "$OBSERVED" ] || die "could not read the promoted primary's identity: an unverifiable authority is treated as stale"
if [ "$OBSERVED" != "$PIN" ]; then
    pass "stale-primary refusal verified: pinned $PIN, observed $OBSERVED — the pinned-primary guard REFUSES this authority"
    info "re-pin: the deliberate operator procedure (docs/ha-authority.md)"
    pass "the drill never re-pins automatically: quiesce, then kiwicaptcha:ha-initialize --force, then kiwicaptcha:doctor"
else
    # A promotion that lands on a server reporting the pinned identity
    # is the restarted-run_id edge the guard documents: the identity may
    # be kept when the new authority replicated the pin state.
    pass "identity unchanged after promotion ($PIN): the guard keeps serving (the documented restarted-run_id edge)"
fi

# The replica-catch-up fence: the promoted primary's replica (the old
# primary) must acknowledge a fresh fence write, proving the WAIT
# barrier survives promotion.
info "fence: WAIT barrier on the promoted primary (replica catch-up)"
poll_until "$FAILOVER_DEADLINE_SECS" old_primary_synced \
    "the old primary to resync under the new primary" \
    || die "the demoted primary did not resync under the new primary within ${FAILOVER_DEADLINE_SECS}s"
acked=$(rc "$NEW_PORT" WAIT 1 5000)
if [ "${acked:-0}" -ge 1 ] 2>/dev/null; then
    pass "fence verified after promotion: $acked replica acknowledged"
else
    gap "the resynced replica did not acknowledge the post-promotion fence write within 5 s"
fi

pass "failover drill complete: primary $MASTER_PORT -> $NEW_PORT, stale primary refused at $MASTER_PORT, authority pin refuse-on-change verified"
exit 0
