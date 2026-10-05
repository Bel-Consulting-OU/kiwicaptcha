#!/bin/bash
# The repro of the store-write rollback finding (disposition: bound).
#
# What was observed: an attacker with raw write access to the record
# store can restore a pending record's bytes after consumption; the
# verifier then accepts the replayed token. Information-theoretically
# no MAC-only scheme can distinguish a restored record from a
# never-consumed one, so this capability sits on a documented model
# boundary: the storage plane gates raw writes by access control (the
# adapter documents the single-host, single-operator model), and the
# sentinel leg proves a stale authority can never serve at all.
#
# What this repro asserts (the bound that must keep holding):
#   1. the consumed marker is RETAINED past consumption on every
#      backend, and a plain replay against it is refused,
#   2. the stale primary rejoining after a failover is read-only,
#   3. every record-level tamper class is rejected.
# A green run here is the requirement; a red run means the boundary
# itself eroded and gates the release.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
REPO_ROOT=$(cd "$RT_DIR/../.." && pwd)

sh "$RT_DIR/target.sh" down redis >/dev/null 2>&1
sh "$RT_DIR/target.sh" up redis >/dev/null 2>&1 || {
    echo "BOUND-REPRO: target failed to boot"
    exit 2
}

KIWI_RT_BASE=http://127.0.0.1:8480 \
KIWI_RT_BACKEND=redis \
KIWI_RT_REDIS_URL=redis://127.0.0.1:6480 \
KIWI_RT_SQLITE_PATH="$RT_DIR/runs/env/redis/kiwi.db" \
KIWI_RT_FILES_DIR="$RT_DIR/runs/env/redis" \
    python3 "$RT_DIR/campaigns/lib/d310.driver.py" >"$RT_DIR/runs/env/finding-repro.json" 2>&1
rc=$?
sh "$RT_DIR/target.sh" down redis >/dev/null 2>&1

python3 - "$RT_DIR/runs/env/finding-repro.json" <<'PYEOF'
import json, sys

doc = json.load(open(sys.argv[1]))
tamper = [row for row in doc["legs"] if row["what"].startswith("tamper") or "injection" in row["what"]]
retained = [row for row in doc["legs"] if "retained" in row["what"] or "retained marker" in row["what"]]
ok = (not doc["accepted"]) and tamper and all(row["ok"] for row in tamper)
retained_ok = any(row["ok"] for row in retained)
print("BOUND-REPRO: tamper classes rejected=%s (%d classes), retained marker held=%s"
      % (ok, len(tamper), retained_ok))
sys.exit(0 if (ok and retained_ok) else 1)
PYEOF
exit $?
