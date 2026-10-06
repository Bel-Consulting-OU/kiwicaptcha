#!/usr/bin/env bash
# sidecar-spawn.sh — the test harness's sidecar lifecycle for the
# elixir delegation suite: writes the armed evidence into a fresh file
# store, starts the sidecar on a free loopback port, waits for healthz
# and prints the URL. The evidence document lands at $1 (a file), the
# URL on stdout's last line. The pid rides $2 (a file) for the cleanup
# script.
#
# usage: sidecar-spawn.sh BINARY SECRET EVIDENCE_FILE PID_FILE STORE_DIR

set -u
BIN=$1
SECRET=$2
EVIDENCE_FILE=$3
PID_FILE=$4
STORE_DIR=$5

mkdir -p "$STORE_DIR"

"$BIN" exec-evidence --secret "$SECRET" --scope login --action login-action \
    --version 1 --store-dir "$STORE_DIR" >"$EVIDENCE_FILE"

PORT=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)

KIWI_LISTEN="http://127.0.0.1:$PORT" KIWI_SECRET="$SECRET" \
KIWI_STORE="file=$STORE_DIR" KIWI_BINDING=none KIWI_PROFILE=sha16 \
    "$BIN" >"$STORE_DIR/sidecar.log" 2>&1 &
echo $! >"$PID_FILE"

for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
        printf 'http://127.0.0.1:%s\n' "$PORT"
        exit 0
    fi
    sleep 0.15
done
echo "the sidecar never answered /healthz; see $STORE_DIR/sidecar.log" >&2
exit 1
