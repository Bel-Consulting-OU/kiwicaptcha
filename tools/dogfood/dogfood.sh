#!/usr/bin/env bash
# dogfood.sh - drive the shipped surfaces against one live deployment.
#
# Boots the reference deployment (php -S) and the hardened verifier
# sidecar, then walks the chain a real integrator follows: solve a
# challenge with the native solver, verify it through the deployment's
# own verifier, refuse tampered and replayed tokens, verify through the
# sidecar's issue and verify pair, gate requests through the compat
# gateway and nginx auth_request, and read the health, metrics and
# doctor surfaces. Every step asserts; any failure exits non-zero.
# Ports 8490-8494 belong to this script and are torn down on exit.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP=$(mktemp -d)
REDIS_PORT=8491
APP_PORT=8490
SIDECAR_PORT=8492
GATE_PORT=8493
NGINX_PORT=8494
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
  nginx -s stop -p "$TMP/nginx" -c "$TMP/nginx/nginx.conf" >/dev/null 2>&1 || true
  redis-cli -p "$REDIS_PORT" shutdown nosave >/dev/null 2>&1 || true
  if [ -n "${DOGFOOD_KEEP_LOGS:-}" ]; then
    mkdir -p "$ROOT/tools/dogfood/last-run"
    cp -f "$TMP"/*.log "$ROOT/tools/dogfood/last-run/" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

step() { printf '\n== %s ==\n' "$1"; }
ok() { printf 'ok  %s\n' "$1"; }
bad() { printf 'fail %s\n' "$1" >&2; exit 1; }

json_field() { python3 -c "import json,sys; v=json.load(sys.stdin).get(sys.argv[1],''); print('true' if v is True else 'false' if v is False else v)" "$1"; }

step "boot redis and the reference deployment"
redis-server --port "$REDIS_PORT" --save '' --appendonly no --daemonize yes
sleep 0.4
SECRET=$(openssl rand -hex 32)
( cd "$ROOT/deploy/app" && \
  exec env KIWI_SECRET_KEY="$SECRET" KC_REDIS_URL="redis://127.0.0.1:$REDIS_PORT" \
  php -d opcache.jit=off -S "127.0.0.1:$APP_PORT" router.php ) >"$TMP/app.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do curl -fsS "http://127.0.0.1:$APP_PORT/healthz" >/dev/null 2>&1 && break; sleep 0.25; done
curl -fsS "http://127.0.0.1:$APP_PORT/healthz" | json_field ok | grep -qx true || bad "deployment healthz (see $TMP/app.log)"
ok "deployment healthy on :$APP_PORT"

step "build the native solver and the hardened sidecar"
cargo build -q -p kiwicaptcha-solver -p kiwicaptcha-verifier
SOLVER="$ROOT/target/debug/kiwicaptcha-solver"
SIDECAR="$ROOT/target/debug/kiwicaptcha-verifier"
[ -x "$SOLVER" ] || bad "solver binary missing"
[ -x "$SIDECAR" ] || bad "sidecar binary missing"
ok "binaries built"

step "deployment challenge, native solve, core verify"
curl -fsS -X POST "http://127.0.0.1:$APP_PORT/challenge" -H 'content-type: application/json' \
  -d '{"scope":"login"}' >/dev/null || bad "challenge endpoint"
TOKEN=$("$SOLVER" solve --endpoint "http://127.0.0.1:$APP_PORT/challenge" --scope login 2>"$TMP/solve.err" | json_field token)
[ -n "$TOKEN" ] || bad "solver produced no token (see $TMP/solve.err)"
R=$(curl -fsS -X POST "http://127.0.0.1:$APP_PORT/verify" -H 'content-type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"scope\":\"login\"}")
printf '%s' "$R" | json_field ok | grep -qx true || bad "fresh token refused: $R"
ok "solver token verified by the deployment"

step "tampered and replayed tokens are refused"
BAD_TOKEN="${TOKEN:0:10}X${TOKEN:11}"
R=$(curl -fsS -X POST "http://127.0.0.1:$APP_PORT/verify" -H 'content-type: application/json' \
  -d "{\"token\":\"$BAD_TOKEN\",\"scope\":\"login\"}")
printf '%s' "$R" | json_field ok | grep -qx false || bad "tampered token accepted: $R"
R=$(curl -fsS -X POST "http://127.0.0.1:$APP_PORT/verify" -H 'content-type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"scope\":\"login\"}")
printf '%s' "$R" | json_field ok | grep -qx false || bad "replayed token accepted: $R"
ok "tampered refused, replay refused"

step "sidecar issue, solve, verify with the file store"
mkdir -p "$TMP/sidecar-store"
KIWI_SECRET="$SECRET" KIWI_STORE="file=$TMP/sidecar-store" KIWI_PROFILE=sha18 \
  KIWI_SCOPES="login=standard" "$SIDECAR" --listen "http://127.0.0.1:$SIDECAR_PORT" --workers 4 \
  >"$TMP/sidecar.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do curl -fsS "http://127.0.0.1:$SIDECAR_PORT/healthz" >/dev/null 2>&1 && break; sleep 0.25; done
curl -fsS "http://127.0.0.1:$SIDECAR_PORT/healthz" >/dev/null || bad "sidecar healthz (see $TMP/sidecar.log)"
STOKEN=$("$SOLVER" solve --endpoint "http://127.0.0.1:$SIDECAR_PORT/issue" --scope login --remoteip 127.0.0.1 2>"$TMP/ssolve.err" | json_field token)
[ -n "$STOKEN" ] || bad "sidecar solve produced no token (see $TMP/ssolve.err)"
SR=$(curl -fsS -X POST "http://127.0.0.1:$SIDECAR_PORT/verify" -H 'content-type: application/json' \
  -d "{\"token\":\"$STOKEN\",\"scope\":\"login\",\"remoteip\":\"127.0.0.1\"}")
printf '%s' "$SR" | json_field success | grep -qix true || bad "sidecar refused a fresh token: $SR"
SR=$(curl -fsS -X POST "http://127.0.0.1:$SIDECAR_PORT/verify" -H 'content-type: application/json' \
  -d "{\"token\":\"$STOKEN\",\"scope\":\"login\",\"remoteip\":\"127.0.0.1\"}")
printf '%s' "$SR" | json_field success | grep -qix false || bad "sidecar accepted a replay: $SR"
curl -fsS "http://127.0.0.1:$SIDECAR_PORT/metrics" | grep -q 'kiwicaptcha_verifier_verifies_total' || bad "sidecar metrics"
curl -fsS "http://127.0.0.1:$SIDECAR_PORT/doctor" | grep -q '"listen"' || bad "sidecar doctor"
ok "sidecar issue, verify, replay refusal, metrics and doctor"

step "compat gateway in front of the deployment"
( cd "$ROOT/integrations-platforms" && \
  exec env KIWI_VERIFY_URL="http://127.0.0.1:$APP_PORT/verify" KIWI_VERIFY_MODE=json KIWI_SCOPE=login \
  php -S "127.0.0.1:$GATE_PORT" -t . ) >"$TMP/gate.log" 2>&1 &
PIDS+=($!)
sleep 0.5
GTOKEN=$("$SOLVER" solve --endpoint "http://127.0.0.1:$APP_PORT/challenge" --scope login 2>/dev/null | json_field token)
G1=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$GATE_PORT/kiwi-verify.php" \
  -H 'content-type: application/json' -d "{\"token\":\"$GTOKEN\"}")
G2=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$GATE_PORT/kiwi-verify.php" \
  -H 'content-type: application/json' -d '{"token":"garbage"}')
[ "$G1" = "204" ] || bad "gate refused a valid token: $G1 (see $TMP/gate.log)"
[ "$G2" = "403" ] || bad "gate answered $G2 for garbage (expected 403)"
ok "gateway allows a valid token (204) and refuses garbage (403)"

step "nginx auth_request in front of the same gate"
mkdir -p "$TMP/nginx/logs"
cat > "$TMP/nginx/nginx.conf" <<CONF
daemon on;
pid $TMP/nginx/nginx.pid;
error_log $TMP/nginx/logs/error.log;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path $TMP/nginx/client_body;
  proxy_temp_path $TMP/nginx/proxy;
  fastcgi_temp_path $TMP/nginx/fastcgi;
  uwsgi_temp_path $TMP/nginx/uwsgi;
  scgi_temp_path $TMP/nginx/scgi;
  server {
    listen 127.0.0.1:$NGINX_PORT;
    location = /protected {
      auth_request /auth;
      proxy_pass http://127.0.0.1:$APP_PORT/healthz;
    }
    location = /auth {
      internal;
      proxy_pass http://127.0.0.1:$GATE_PORT/kiwi-verify.php;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";
      proxy_set_header X-Kiwi-Token \$http_x_kiwi_token;
    }
  }
}
CONF
nginx -p "$TMP/nginx" -c "$TMP/nginx/nginx.conf" -t >/dev/null 2>&1 || bad "nginx config rejected"
nginx -p "$TMP/nginx" -c "$TMP/nginx/nginx.conf" >/dev/null 2>&1
sleep 0.4
NTOKEN=$("$SOLVER" solve --endpoint "http://127.0.0.1:$APP_PORT/challenge" --scope login 2>/dev/null | json_field token)
N1=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$NGINX_PORT/protected" -H "X-Kiwi-Token: $NTOKEN")
N2=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$NGINX_PORT/protected")
[ "$N1" = "200" ] || bad "nginx auth_request refused a valid token: $N1"
[ "$N2" = "403" ] || bad "nginx auth_request allowed a missing token: $N2"
ok "nginx auth_request gates the route (200 with a valid token, 403 without)"

printf '\ndogfood: every step green (deployment, core verify, solver, sidecar, gateway, nginx)\n'
