#!/usr/bin/env bash
# sidecar-stop.sh — the cleanup peer of sidecar-spawn.sh: kills the
# recorded sidecar pid and removes its store directory.
#
# usage: sidecar-stop.sh PID_FILE STORE_DIR

set -u
PID_FILE=$1
STORE_DIR=$2

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" 2>/dev/null || true
    rm -f "$PID_FILE"
fi
rm -rf "$STORE_DIR"
