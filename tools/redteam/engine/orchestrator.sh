#!/bin/bash
# orchestrator.sh — the red-team engine's controller.
#
# Schedules the campaigns against the target environment, budgets the
# run, collects every result into the runs ledger, consults the
# synthesis agent, and generates THREATS.md and docs/cost-to-abuse.md.
#
# Guardrails, enforced here in code:
#   - the hard allowlist: the orchestrator REFUSES to start unless
#     every configured target host is a loopback or private-range
#     address. There is no override flag.
#   - the deterministic offline default: no local model is consulted
#     unless the operator explicitly exports KIWI_RT_LOCAL_LLM_URL;
#     the adapter then still refuses any non-private host.
#   - generated attacks are committed under tools/redteam/findings/
#     only after the triage gate reproduced them deterministically.
#
# Budget knobs:
#   KIWI_RT_SEED              the run seed (ledger + synthesis pin)
#   KIWI_RT_BUDGET_MINUTES    wall-clock budget (default 120)
#   KIWI_RT_CAMPAIGN_TIMEOUT  per-campaign seconds (default 900)
#   KIWI_RT_CAMPAIGNS         subset list (default the full battery)
#   KIWI_RT_SCALE             environment downscale passed through
#   KIWI_RT_LOCAL_LLM_URL     optional local runtime (see
#                             engine/model-adapter.mjs for the exact
#                             request and response contract)
#
# Usage:
#   tools/redteam/engine/orchestrator.sh [--profile redis]
#                                        [--synth] [--regression]

set -u

RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
REPO_ROOT=$(cd "$RT_DIR/../.." && pwd)
RUNS_DIR="$RT_DIR/engine/runs"
mkdir -p "$RUNS_DIR"

# ---------- the hard allowlist ----------
target_host() {
    printf '%s' "${KIWI_RT_TARGET_HOST:-127.0.0.1}"
}

is_private() {
    case "$1" in
        127.* | 10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[0-1].* | ::1 | localhost | fc* | fd*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

TARGET=$(target_host)
if ! is_private "$TARGET"; then
    printf 'orchestrator: REFUSING to start: target host %s is outside the loopback and private allowlist\n' "$TARGET" >&2
    exit 4
fi
if [ -n "${KIWI_RT_LOCAL_LLM_URL:-}" ]; then
    LLM_HOST=$(printf '%s' "$KIWI_RT_LOCAL_LLM_URL" | sed -E 's#^https?://([^/:]+).*#\1#')
    if ! is_private "$LLM_HOST"; then
        printf 'orchestrator: REFUSING the local model url: host %s is outside the private allowlist\n' "$LLM_HOST" >&2
        exit 4
    fi
fi

: "${KIWI_RT_SEED:=0x6b776d74}"
: "${KIWI_RT_BUDGET_MINUTES:=120}"
: "${KIWI_RT_CAMPAIGN_TIMEOUT:=900}"
PROFILE=${KIWI_RT_PROFILE:-redis}
export KIWI_RT_SEED KIWI_RT_PROFILE

BUDGET_DEADLINE=$(( $(date +%s) + KIWI_RT_BUDGET_MINUTES * 60 ))
RESULT=0

log() { printf 'orchestrator: %s\n' "$*" >&2; }

# ---------- the recon and synthesis agents ----------
log "recon agent: enumerating the attack surface"
node "$RT_DIR/engine/recon.mjs" >&2 || RESULT=1

if [ "${1:-}" = "--synth" ] || [ "${KIWI_RT_SYNTH:-0}" = "1" ]; then
    log "synthesis agent: generating the candidate corpus"
    node "$RT_DIR/engine/synth.mjs" >&2 || log "synthesis agent failed; continuing with the campaign battery"
fi

# ---------- the campaign battery ----------
CAMPAIGNS=${KIWI_RT_CAMPAIGNS:-"d3.1-commodity-nojs d3.5-credential-stuffing d3.10-infrastructure d3.12-protocol-parser d3.14-privacy d3.17-cross-sdk-parity"}

# The campaign name maps to its spec class for the ledger.
class_of() {
    case "$1" in
        d3.10*) echo "D3.10 infrastructure attacker" ;;
        d3.12*) echo "D3.12 protocol and parser" ;;
        d3.14*) echo "D3.14 privacy adversary" ;;
        d3.16*) echo "D3.16 accessibility and compatibility" ;;
        d3.17*) echo "D3.17 cross-SDK parity attack" ;;
        d3.5*) echo "D3.5 credential stuffing" ;;
        d3.1*) echo "D3.1 commodity no-JS bots" ;;
        *) echo "unclassified" ;;
    esac
}

for campaign in $CAMPAIGNS; do
    now=$(date +%s)
    if [ "$now" -ge "$BUDGET_DEADLINE" ]; then
        log "budget exhausted before $campaign; the ledger keeps what ran"
        RESULT=1
        break
    fi
    log "campaign $campaign against profile $PROFILE"
    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    t0=$(date +%s)
    OUT=$(timeout "$KIWI_RT_CAMPAIGN_TIMEOUT" \
        env KIWI_RT_KEEP_TARGET=1 KIWI_RT_PROFILE="$PROFILE" KIWI_RT_SEED="$KIWI_RT_SEED" \
        bash "$RT_DIR/campaigns/$campaign.sh" 2>&1)
    rc=$?
    duration=$(( $(date +%s) - t0 ))

    # The campaign's own lines are the human-readable record; the run
    # document is the ledger entry the aggregator reads.
    printf '%s\n' "$OUT"
    metric_line=$(printf '%s\n' "$OUT" | grep '^METRIC:' | tail -n 1 | cut -d' ' -f4-)
    economic_line=$(printf '%s\n' "$OUT" | grep '^ECONOMIC:' | tail -n 1 | cut -d' ' -f4-)
    if [ "$rc" -eq 0 ]; then
        verdict=PASS
        detail=$(printf '%s\n' "$OUT" | grep '^RESULT: PASS' | head -n 1 | cut -d' ' -f5-)
    else
        verdict=FAIL
        detail=$(printf '%s\n' "$OUT" | grep '^RESULT: FAIL' | tail -n 1 | cut -d' ' -f5-)
        RESULT=1
    fi
    sha_us=$(printf '%s\n' "$OUT" | grep -o 'sha16_solve_us=[0-9]*' | head -n 1 | cut -d= -f2)
    run_doc=$(printf '%s\n' "$OUT" | grep '^RESULT' | head -n 1 | sed 's/ //g' | head -c 40)
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    doc="$RUNS_DIR/${timestamp}-${campaign}-seed-${KIWI_RT_SEED}.json"
    node -e '
const fs = require("fs");
const [campaign, cls, seed, started, duration, rc, verdict, detail, metric, economic, shaUs] = process.argv.slice(2);
fs.writeFileSync(process.argv[process.argv.length - 1], JSON.stringify({
    schema: "kiwicaptcha.redteam.run/1",
    campaign, attackClass: cls, seed, started, duration_s: Number(duration),
    exit: Number(rc), result: verdict, detail,
    metrics: { raw: metric, sha16_solve_us: shaUs ? Number(shaUs) : null },
    economic,
}, null, 2) + "\n");
' - "$campaign" "$(class_of "$campaign")" "$KIWI_RT_SEED" "$started" "$duration" "$rc" "$verdict" "$detail" "$metric_line" "$economic_line" "$sha_us" "$doc"
    log "campaign $campaign -> $verdict in ${duration}s (ledger: $(basename "$doc"))"
done

# ---------- the regression agent (nightly corpus) ----------
if [ "${1:-}" = "--regression" ] || [ "${KIWI_RT_REGRESSION:-0}" = "1" ]; then
    log "regression agent: replaying the committed finding corpus"
    node "$RT_DIR/engine/regression.mjs" --out "$RUNS_DIR/regression-$(date -u +%Y%m%dT%H%M%SZ).json" >&2 || RESULT=1
fi

# ---------- the outputs ----------
node "$RT_DIR/engine/ledger.mjs" --seed "$KIWI_RT_SEED" >&2 || RESULT=1

if [ "$RESULT" -eq 0 ]; then
    log "run green: THREATS.md and docs/cost-to-abuse.md regenerated from the ledger"
else
    log "run had RED campaigns; the outputs reflect it"
fi
exit $RESULT
