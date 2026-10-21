# d310-backends.sh — the D3.10 multi-backend runner.
#
# The infrastructure campaign's spec matrix is EVERY storage backend
# (the same set `target.sh matrix` defaults to): redis, the sentinel
# trio, sqlite and the filesystem fallback. One battery invocation
# normally exercises only its own profile, so a single-backend run can
# never back a composite "every backend" claim. This runner closes
# that gap: it drives the campaign against each required backend the
# current battery profile has not already covered and writes ONE
# profile-bound run document per backend — the per-backend ledger
# rows ledger.mjs grades the multi-backend contract against.
#
# Contract (precondition on the caller):
#   - $RT_DIR is the tools/redteam directory (both orchestrators set it);
#   - the battery's own target profile stays up (the caller boots it);
#   - KIWI_RT_KEEP_TARGET=1 semantics: nested profiles are torn down
#     HERE, never by the campaign's trap.
#
# Usage: rt_d310_run_backends <campaign> <class> <current-profile> \
#           <seed> <method> <log-dir> <runs-dir>
# Sets:  RT_D310_COVERED  space-separated backends that just ran GREEN
#        RT_D310_MISSING  space-separated backends that did not
# Returns 0 iff every required backend (minus the current profile,
# whose row the caller's own slot already wrote) produced a GREEN
# verdict AND a persisted profile-bound run document.

# The required set is the target.sh matrix default — the campaign
# header's documented matrix, not a static claim in a metric line.
D310_REQUIRED_BACKENDS="redis sentinel sqlite files"

rt_d310_topology_of() {
    case "$1" in
        sentinel) echo sentinel ;;
        cluster) echo cluster ;;
        *) echo single-primary ;;
    esac
}

rt_d310_run_backends() {
    campaign=$1
    class=$2
    current=$3
    seed=$4
    method=$5
    log_dir=$6
    runs_dir=$7

    # The shared row contract: the nested run must satisfy exactly the
    # GREEN record contract the battery's own rows are graded by.
    # shellcheck source=lib/verdict.sh
    . "$RT_DIR/lib/verdict.sh"

    RT_D310_COVERED=""
    RT_D310_MISSING=""
    for p in $D310_REQUIRED_BACKENDS; do
        if [ "$p" = "$current" ]; then
            # The caller's own d3.10 slot already ran and documented
            # this backend under the battery profile.
            continue
        fi
        log="$log_dir/$campaign-$p.log"
        echo "d310-backends: $campaign against backend $p" >&2
        started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        t0=$(date +%s)
        KIWI_RT_PROFILE="$p" KIWI_RT_KEEP_TARGET=1 \
            bash "$RT_DIR/campaigns/$campaign.sh" >"$log" 2>&1
        rc=$?
        duration=$(( $(date +%s) - t0 ))
        verdict_line=$(campaign_log_verdict "$campaign" "$p" "$log" "$rc")
        verdict=${verdict_line%% *}
        detail=${verdict_line#* }
        metric_line=$(grep '^METRIC:' "$log" | tail -n 1 | cut -d' ' -f4-)
        economic_line=$(grep '^ECONOMIC:' "$log" | tail -n 1 | cut -d' ' -f4-)
        sha_us=$(grep -o 'sha16_solve_us=[0-9]*' "$log" | head -n 1 | cut -d= -f2)
        doc_verdict=FAIL
        if [ "$verdict" = "GREEN" ]; then
            doc_verdict=PASS
        fi
        # The profile rides the filename as well as the body: two
        # nested backends can finish inside the same second, and the
        # document is one row PER BACKEND, never one shared file.
        doc="$runs_dir/$(date -u +%Y%m%dT%H%M%SZ)-$campaign-$p-seed-$seed.json"
        wrote=1
        if ! node "$RT_DIR/engine/write-run.mjs" \
            "$doc" "$campaign" "$class" "$seed" "$started" "$duration" "$rc" \
            "$doc_verdict" "$detail" "$metric_line" "$economic_line" "$sha_us" \
            "$method" "" "" "$p" "$(rt_d310_topology_of "$p")"; then
            wrote=0
            echo "d310-backends: the writer refused the $p run document" >&2
        elif [ ! -f "$doc" ]; then
            wrote=0
            echo "d310-backends: the writer reported success but $doc is missing" >&2
        fi
        if [ "$verdict" = "GREEN" ] && [ "$wrote" = "1" ]; then
            RT_D310_COVERED="$RT_D310_COVERED $p"
        else
            RT_D310_MISSING="$RT_D310_MISSING $p"
            echo "d310-backends: $p -> $verdict ($detail)" >&2
        fi
        # Always tear the nested profile down: the campaign keeps the
        # battery's own target through KIWI_RT_KEEP_TARGET=1, and the
        # next backend boots its own ports.
        sh "$RT_DIR/target.sh" down "$p" >/dev/null 2>&1 || true
    done
    RT_D310_COVERED=${RT_D310_COVERED# }
    RT_D310_MISSING=${RT_D310_MISSING# }
    [ -z "$RT_D310_MISSING" ]
}
