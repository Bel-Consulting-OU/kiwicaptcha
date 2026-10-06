#!/bin/bash
# wire-differential.sh — the repro harness for the "wire-differential"
# candidate class. Two wire spellings of the same semantic document (a
# plain scope and its JSON-unicode-escaped twin) must produce the same
# verdict; a differing verdict is a differential and a finding.
set -u
. "$(cd "$(dirname "$0")" && pwd)/repro-common.sh"
BASE=$(repro_target)
OUT=$(KIWI_RT_BASE="$BASE" KIWI_RT_DIR="$RT_DIR/campaigns/lib" python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ["KIWI_RT_DIR"]))
import rtclient as rt
base = os.environ["KIWI_RT_BASE"]
plain = rt.verify(base, "nonexistent-token", scope="login")
escaped_body = '{"scope":"\\u006Cogin","token":"nonexistent-token"}'
resp = rt.post_json(base + "/verify", None, raw_body=escaped_body.encode())
from rtclient import Response
escaped = Response(resp.status, resp.raw)
same = (plain.ok == escaped.ok) and (plain.error_code or "x") == (escaped.error_code or "x")
print(json.dumps({"code": escaped.error_code or escaped.code or "ok", "differential": 0 if same else 1}))
PY
)
printf "%s" "$OUT" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
print(json.dumps({'harness': 'wire-differential', 'verdict': 'REPRODUCED' if doc['differential'] else 'REFUTED', 'wire_code': doc['code']}))
"
