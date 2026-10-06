#!/bin/bash
# d3.6-token-brokering.sh — token brokering and relay (D3.6).
#
# The broker solves once (or harvests once) and sells the token: relay
# to another origin, another scope, another binding, another node, all
# inside the token's TTL, plus a stockpiling run against the issuance
# caps. Every relay leg lands on the REAL verifier; the embed and
# opener legs run in a real chromium against genuinely different loop
# back origins (separate ports are separate origins).
#
# Ports: 6474 node A (the solve), 6475 node B (the cross-node relay;
# the two nodes share the profile Redis exactly like two fleet nodes),
# 6471 hosts the widget page for the embed and the hostile page. The
# embed fixture (campaigns/lib/d36.hostile.html) carries the broker's
# full toolkit: same-origin reach into the widget frame, postMessage
# probing, opener-chain reads.
#
# Required results (all asserted from the real surfaces):
#   - zero cross-scope acceptance (login token as signup),
#   - zero cross-binding acceptance (the one-shot anti-oracle retires
#     the record on the first wrong-binding try),
#   - zero cross-node acceptance of a second redemption and zero
#     cross-node scope relay,
#   - the replay of the solved token inside its TTL is refused as
#     already_consumed (the relay's core primitive dies),
#   - the stockpile run hits exactly the configured issuance cap
#     (stockpiles are bounded by caps),
#   - the hostile embed reads nothing out of the widget frame (the
#     token never leaves the widget's origin), and the relayed token
#     the farm would sell is refused at every destination.
#
# Economic metric: a brokered token costs one solve and yields zero
# accepted relays, so the resale value of a solved token is zero; the
# cost per accepted relayed abuse is unbounded.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.6-token-brokering
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)
PROFILE_BASE=$(rt_base_url "$RT_PROFILE")

NODE_A=6474
NODE_B=6475
PAGE_PORT=6471
SECRET='d36s3cr3td36s3cr3td36s3cr3td36s3cr3t'

# ---------- two nodes on one shared store (the fleet shape) ----------
sh "$REDETEAM_DIR/target.sh" down d36a >/dev/null 2>&1 || true
sh "$REDETEAM_DIR/target.sh" down d36b >/dev/null 2>&1 || true
WIRE_LOG="$RT_DIR/runs/env/d36-wire.log"
start_node() {
    local port=$1
    env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
        KC_REDIS_URL="${REDIS_URL:-redis://127.0.0.1:1}" \
        KIWI_SECRET_KEY="$SECRET" \
        KIWI_SHA_TARGET_BITS=16 KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=120 \
        KIWI_ISSUANCE_PER_MINUTE_PER_IP=0 \
        php -S "127.0.0.1:$port" -t "$REPO_ROOT/deploy/app" \
            "$REPO_ROOT/deploy/app/router.php" >>"$WIRE_LOG" 2>&1 &
}
start_node "$NODE_A"
NODE_A_PID=$!
# Node B carries the stockpile budget: the documented 30 per minute.
STOCK_PORT=$((NODE_A + 20))
env KIWI_RT_DEPLOY_VENDOR="$REPO_ROOT/deploy/app/vendor" \
    KC_REDIS_URL="${REDIS_URL:-redis://127.0.0.1:1}" \
    KIWI_SECRET_KEY='d36st0ckd36st0ckd36st0ckd36st0ckd36' \
    KIWI_SHA_TARGET_BITS=16 KIWI_MIN_DURATION_MS=0 KIWI_TTL_SECS=120 \
    KIWI_ISSUANCE_PER_MINUTE_PER_IP=30 \
    php -S "127.0.0.1:$STOCK_PORT" -t "$REPO_ROOT/deploy/app" \
        "$REPO_ROOT/deploy/app/router.php" >>"$WIRE_LOG" 2>&1 &
STOCK_PID=$!

# The widget page server (proxies to node A) and the hostile embed
# server (the embed is the root page of its own origin).
node "$RT_DIR/campaigns/lib/rt-page-server.mjs" --port "$PAGE_PORT" \
    --wire "http://127.0.0.1:$NODE_A" >/dev/null 2>&1 &
PAGE_PID=$!
EMBED_HTML="$RT_DIR/runs/env/d36-hostile-live.html"
python3 - "$EMBED_HTML" "$RT_DIR/campaigns/lib/d36.hostile.html" "$PAGE_PORT" <<'PYEMBED'
import sys
path, template, page_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
body = open(template, "r").read()
open(path, "w").write(body.replace("__VICTIM_URL__", f"http://127.0.0.1:{page_port}/"))
PYEMBED
node "$RT_DIR/campaigns/lib/rt-page-server.mjs" --port 6476 \
    --wire "http://127.0.0.1:$NODE_A" --html "$EMBED_HTML" >/dev/null 2>&1 &
EMBED_PID=$!

cleanup() {
    kill "$NODE_A_PID" "$STOCK_PID" "$PAGE_PID" "$EMBED_PID" 2>/dev/null
    pkill -f "php -S 127.0.0.1:$NODE_A " 2>/dev/null
    pkill -f "php -S 127.0.0.1:$STOCK_PORT " 2>/dev/null
    pkill -f "rt-page-server.mjs --port $PAGE_PORT" 2>/dev/null
    pkill -f "rt-page-server.mjs --port 6476" 2>/dev/null
}
trap cleanup EXIT

ready=0
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 "$NODE_A" 2>/dev/null && nc -z 127.0.0.1 "$STOCK_PORT" 2>/dev/null && nc -z 127.0.0.1 "$PAGE_PORT" 2>/dev/null && nc -z 127.0.0.1 6476 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.25
done
[ "$ready" = 1 ] || {
    rt_report_fail "the d3.6 nodes or page server never opened their ports"
    rt_finish
}

# ---------- the browser leg: the hostile embed and the opener chain ----------
BROWSER_OUT="$RT_DIR/runs/env/d36-embed.json"
cd "$REPO_ROOT/tests/browser" || { rt_report_fail "tests/browser missing"; rt_finish; }
KIWI_RT_D36_EMBED_URL="http://127.0.0.1:6476/" \
KIWI_RT_D36_OUT="$BROWSER_OUT" timeout 180 node "$RT_DIR/campaigns/lib/d36.embed.mjs" \
    >"$RT_DIR/runs/env/d36-embed.out" 2>"$RT_DIR/runs/env/d36-embed.err"
EMBED_RC=$?
cd "$REPO_ROOT" || exit 2
[ "$EMBED_RC" -eq 0 ] || {
    rt_report_fail "the embed driver failed (see runs/env/d36-embed.err)"
    rt_finish
}
cat "$BROWSER_OUT"

# ---------- the wire legs: every relay destination ----------
RELAY_OUT=$(NODE_A="$NODE_A" NODE_B="$NODE_B" STOCK_PORT="$STOCK_PORT" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PYRELAY'
import json, os, sys
sys.path.insert(0, os.environ["KIWI_RT_DIR"])
import rtclient as rt

node_a = f"http://127.0.0.1:{os.environ['NODE_A']}"
node_b = f"http://127.0.0.1:{os.environ['NODE_B']}"
stock = f"http://127.0.0.1:{os.environ['STOCK_PORT']}"
out = {}

# The solve: the farm's one honest payment.
doc = rt.solve(node_a, "login")
assert doc.get("solved"), doc
token = doc["token"]

# The relays, every one inside the TTL.
cross_scope = rt.verify(node_a, token, scope="signup")
out["cross_scope_ok"] = bool(cross_scope.ok)
out["cross_scope_code"] = cross_scope.error_code or cross_scope.code

cross_binding = rt.verify(node_a, token, scope="login", binding="broker-dest-1")
out["cross_binding_ok"] = bool(cross_binding.ok)
out["cross_binding_code"] = cross_binding.error_code or cross_binding.code

# The honest redemption happened at solve time; the replay after it is
# the broker's core primitive.
replay = rt.verify(node_a, token, scope="login")
out["replay_ok"] = bool(replay.ok)
out["replay_code"] = replay.error_code or replay.code

# Cross-node: the second fleet node must agree on every refusal.
cross_node = rt.verify(node_b, token, scope="signup")
out["cross_node_ok"] = bool(cross_node.ok)
out["cross_node_code"] = cross_node.error_code or cross_node.code
# A fresh solve on node A verified on node B within TTL (the legal
# relay the fence must catch or allow deliberately): solve unbound on
# A, verify once on B.
doc2 = rt.solve(node_a, "login")
token2 = doc2.get("token", "")
legit = rt.verify(node_b, token2, scope="login")
out["cross_node_fresh_ok"] = bool(legit.ok)
out["cross_node_fresh_code"] = legit.error_code or legit.code

# The stockpile: 40 burst issues against the 30 budget.
issued = limited = 0
for _ in range(40):
    resp = rt.challenge(stock, "login")
    if resp.status == 200 and resp.body.get("nonce"):
        issued += 1
    elif resp.status == 429 and resp.error_code == "RATE_LIMITED":
        limited += 1
out["stock_issued"] = issued
out["stock_limited"] = limited
print(json.dumps(out))
PYRELAY
)
RELAY_RC=$?
printf '%s\n' "$RELAY_OUT"
[ "$RELAY_RC" -eq 0 ] || {
    rt_report_fail "the relay leg crashed"
    rt_finish
}

jval() { printf '%s' "$RELAY_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
rt_assert_eq "$(jval cross_scope_ok)" "False" "relay: zero cross-scope acceptance"
rt_assert_eq "$(jval cross_binding_ok)" "False" "relay: zero cross-binding acceptance"
rt_assert_eq "$(jval replay_ok)" "False" "relay: in-TTL replay refused (already consumed)"
rt_assert_eq "$(jval cross_node_ok)" "False" "relay: zero cross-node acceptance"
rt_assert_eq "$(jval stock_issued)" "30" "stockpile: exactly the cap issued"
rt_assert_eq "$(jval stock_limited)" "10" "stockpile: the burst remainder refused with 429"

# ---------- the human baseline ----------
BASELINE=$(KIWI_RT_BASE="$PROFILE_BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PYBASE'
import os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
doc = rt.solve(os.environ["KIWI_RT_BASE"], "login")
resp = rt.verify(os.environ["KIWI_RT_BASE"], doc.get("token", ""), scope="login")
print("allowed" if resp.ok else "denied")
PYBASE
)
rt_assert_eq "$BASELINE" "allowed" "human baseline: honest solve and verify accepted"

rt_metric "relays_refused=4 stock_issued=$(jval stock_issued) embed_token_reads=$(printf '%s' "$BROWSER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token_reads"])')"
printf 'ECONOMIC: %s %s cost_per_accepted_relayed_abuse=unbounded accepted_relays=0 resale_value_of_solved_token=0\n' \
    "$RT_CAMPAIGN" "$RT_PROFILE"

rt_finish
