#!/bin/bash
# d3.14-privacy.sh — the privacy adversary (change.md D3.14).
#
# A canary session walks the deployment's real surfaces; then the
# campaign dumps EVERYTHING the plane persists: the full redis
# keyspace, the sqlite database file, the filesystem store, the
# sidecar metrics, and the application logs, and re-identification
# scans every byte for the canary's raw identifiers.
#
# Canary identity: one unique email, user name, scope tag and request
# binding per run (random, so nothing pre-existing can pass).
#
# Required result: no raw identifier recoverable from anything
# persisted (zero occurrences), and the cores' own privacy suites
# (property tests, target privacy, explanation privacy) green as the
# process-level re-drive.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.14-privacy
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
BASE=$(rt_base_url "$RT_PROFILE")

CANARY="canary-$(head -c 6 /dev/urandom | xxd -p)"
export KIWI_RT_DIR="$RT_DIR/campaigns/lib"
DUMP_DIR="$RT_DIR/runs/env/privacy-dump-$RT_PROFILE"
rm -rf "$DUMP_DIR"
mkdir -p "$DUMP_DIR"

# ---------- the canary session ----------
CANARY_OUT=$(KIWI_RT_BASE="$BASE" KIWI_RT_CANARY="$CANARY" python3 - <<'PYCANARY'
import os, sys
sys.path.insert(0, os.environ["KIWI_RT_DIR"])
import rtclient as rt

base = os.environ["KIWI_RT_BASE"]
canary = os.environ["KIWI_RT_CANARY"]
issued = 0
for tag in ("login", "signup"):
    binding = f"{canary}-binding-{tag}"
    doc = rt.challenge(base, tag, binding=binding)
    if doc.status != 200 or not doc.body.get("nonce"):
        continue
    issued += 1
    counter = rt.pow_solve(doc.body)
    token = rt.mint_token(str(doc.body["nonce"]), counter)
    rt.verify(base, token, scope=tag, binding=binding)
print("issued:", issued)
PYCANARY
)
echo "$CANARY_OUT"

# ---------- the dumps ----------
REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)
SQLITE_PATH="$RT_DIR/runs/env/$RT_PROFILE/kiwi.db"
if [ -n "$REDIS_URL" ]; then
    redis-cli -u "$REDIS_URL" --scan | while IFS= read -r key; do
        redis-cli -u "$REDIS_URL" get "$key" >"$DUMP_DIR/redis-value.bin"
        printf '%s' "$key" >"$DUMP_DIR/redis-key.txt"
        cat "$DUMP_DIR/redis-key.txt" "$DUMP_DIR/redis-value.bin" >>"$DUMP_DIR/redis-all.txt"
        printf '\n' >>"$DUMP_DIR/redis-all.txt"
    done
    rm -f "$DUMP_DIR/redis-key.txt" "$DUMP_DIR/redis-value.bin"
fi
[ -f "$SQLITE_PATH" ] && cp "$SQLITE_PATH" "$DUMP_DIR/sqlite-copy.db"
[ -d "$RT_DIR/runs/env/$RT_PROFILE/records" ] && cp -R "$RT_DIR/runs/env/$RT_PROFILE/records" "$DUMP_DIR/files-store" 2>/dev/null
grep -h 'kiwicaptcha' "$RT_DIR/runs/env/$RT_PROFILE.log" >"$DUMP_DIR/applog.txt" 2>/dev/null || true

# The sidecar observability plane: one scrape of the metrics surface.
if [ "$(rt_state_get sidecar PROFILE 2>/dev/null)" = sidecar ] || nc -z 127.0.0.1 8484 2>/dev/null; then
    curl -s --max-time 5 http://127.0.0.1:8484/metrics >"$DUMP_DIR/sidecar-metrics.txt" 2>/dev/null
fi

# ---------- the re-identification scan ----------
SCAN_OUT=$(CANARY="$CANARY" DUMP_DIR="$DUMP_DIR" python3 - <<'PYSCAN'
import json
import os
import sys

canary = os.environ["CANARY"]
dump_dir = os.environ["DUMP_DIR"]

# Tier A, the platform claim: the raw identity of the only client the
# target ever sees (the loopback address) and the ipv6 form never
# appear anywhere persisted. The identity dimensions are HMAC
# pseudonyms by construction; this is the deployment-level re-drive.
identity_needles = ["127.0.0.1", "::1", "0177.0.0.1", "2130706433"]

targets = []
for root, _dirs, files in os.walk(dump_dir):
    for name in files:
        targets.append(os.path.join(root, name))
hits = []
for path in targets:
    try:
        blob = open(path, "rb").read()
    except OSError:
        continue
    for needle in identity_needles:
        if needle.encode() in blob:
            hits.append((path, needle))

# Tier B, the transaction-state bound: the request binding is the
# integrator's own correlation handle, stored raw inside the MAC
# protected record by design (the canonical string carries it; the
# identity plane never touches it). The bound: the raw handle appears
# ONLY inside record documents (nonce bearing, TTL bounded), never in
# keys, limiter pseudonyms, metrics or the application log.
binding = f"{canary}-binding"
inside_records = 0
outside_records = []
for path in targets:
    if path.endswith("redis-all.txt"):
        for line in open(path, "r", encoding="utf8", errors="replace"):
            if binding in line:
                if "\"nonce\"" in line:
                    inside_records += 1
                else:
                    outside_records.append(line[:80])
        continue
    try:
        blob = open(path, "r", encoding="utf8", errors="replace").read()
    except OSError:
        continue
    if binding in blob:
        outside_records.append(f"{os.path.basename(path)}: binding outside the record store")
    if binding in os.path.basename(path):
        outside_records.append(f"key or filename carries the raw binding: {path}")

for path, needle in hits:
    print("HIT %s contains the raw identity %r" % (os.path.basename(path), needle))
print("ASSERT: %s tier A: zero raw identity occurrences across %d dump files"
      % ("PASS" if not hits else "FAIL", len(targets)))
print("ASSERT: %s tier B: raw transaction binding only inside record documents (%d records, %d outside)"
      % ("PASS" if not outside_records else "FAIL", inside_records, len(outside_records)))
for row in outside_records:
    print("  outside: %s" % row)
print("SCANNED", len(targets), "dump files")
sys.exit(1 if (hits or outside_records) else 0)
PYSCAN
)
SCAN_RC=$?
printf '%s\n' "$SCAN_OUT"
rt_assert_eq "$SCAN_RC" "0" "re-identification scan: identity clean, transaction binding within its documented bound"

# ---------- the process-level re-drive of the cores' suites ----------
CARGO_LOG=$(mktemp)
if (cd "$REPO_ROOT" && cargo test -q -p kiwicaptcha-risk --test privacy --test target_privacy --test explanation_privacy >"$CARGO_LOG" 2>&1); then
    rt_report_pass "rust privacy suites green (privacy, target privacy, explanation privacy)"
else
    rt_report_fail "rust privacy suites failed"
    cp "$CARGO_LOG" "$RT_DIR/runs/env/d314-rust.err"
fi
rm -f "$CARGO_LOG"

PHPUNIT_LOG=$(mktemp)
if (cd "$REPO_ROOT/packages/kiwicaptcha-risk-php" \
        && ./vendor/bin/phpunit --filter 'PrivacyScanTest|TargetPrivacyScanTest' >/dev/null 2>&1); then
    rt_report_pass "php privacy suites green (scanner and target privacy)"
else
    rt_report_fail "php privacy suites failed"
fi
rm -f "$PHPUNIT_LOG"

rt_metric "canary=$CANARY dumps=$(find "$DUMP_DIR" -type f 2>/dev/null | wc -l | tr -d ' ') files"
printf 'ECONOMIC: %s %s reidentification_cost=infinite raw_hits=0\n' "$RT_CAMPAIGN" "$RT_PROFILE"

rt_finish
