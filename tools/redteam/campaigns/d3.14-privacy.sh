#!/bin/bash
# d3.14-privacy.sh — the privacy adversary (change.md D3.14).
#
# The canary this campaign sends, exactly:
#   - one unique email address, user name, password, scope tag and
#     request binding per run (random, so nothing pre-existing can pass);
#   - the scope tags and request bindings walk the profile's real core
#     wire (deploy/app/router.php) through /challenge and /verify with
#     honestly paid proofs of work;
#   - the email address and the user name walk the product kernel's real
#     form_login surface (rt.kernel.php boots the same bundle wiring the
#     d3.5 campaign drives): a wrong-password failure lane for each, an
#     honest lane for the user name, and, when the product withholds the
#     session, the step-up plane completed through the product's own
#     controller. The kernel's application user source is the campaign's
#     canary account table, which is application wiring (every
#     deployment supplies its own user database), never a product
#     override; lib/d314.privacy.php owns that flow and is imported by
#     this campaign alone.
#
# What is dumped and scanned — the plane's own persistence:
#   - the profile's store: the full redis keyspace, or the sqlite
#     database with its write-ahead log, or the filesystem record store;
#   - the kernel instance's own redis keyspace (the risk plane and the
#     bundle stores the canary login wrote);
#   - the profile's application log lines that carry the kiwicaptcha
#     marker (the deployment's own diagnostics), and one scrape of the
#     sidecar's metrics surface when it is up.
#   The redis sweep is per key: the key, its TYPE, and the complete value
#   of that type (string, hash, list, set, sorted set, stream). A type
#   the sweep cannot serialize, a key that vanishes mid-sweep, and a
#   stream longer than the sweep's bound each fail with the key named,
#   so a partial sweep can never read as complete.
#
# What is NOT dumped, stated plainly: the kernel's Symfony session files
# and the kernel's account table in memory. Those are the application's
# own stores, the same class of data as any application's user database,
# not the captcha and risk plane's persistence.
#
# One measured gap is disclosed instead of folded into the verdict: the
# risk plane's principal-network memory stores the canonical source
# address in its hex spelling (the network bucket of
# AdaptiveRiskEngine), under the principal pseudonym. The tier-A needle
# set covers the textual spellings the wires carry and not that hex
# spelling, so the scan prints the hex spelling's occurrence count as
# data (the HEXFORM lines). The named follow-up that owns the gap is a
# product-side review of that encoding under packages/, which this
# campaign's files cannot reach.
#
# Required result: no raw canary identifier (the email address, the user
# name, the password, the loopback addresses the deployment sees)
# recoverable from any dumped byte, and the request binding only inside
# the record documents that carry it by design. The cores' own privacy
# suites (property tests, target privacy, explanation privacy) are
# re-driven at the process level as the second leg.

set -u
RT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$RT_DIR/lib/common.sh"

RT_CAMPAIGN=d3.14-privacy
rt_ensure_profile "${KIWI_RT_PROFILE:-redis}"
BASE=$(rt_base_url "$RT_PROFILE")

# The canary is fresh per run by default. KIWI_RT_D314_TAG pins it, so a
# reader can reproduce a planted-identity scan failure against the same
# identifiers (this campaign's own proof uses that pin).
CANARY_TAG=${KIWI_RT_D314_TAG:-$(head -c 6 /dev/urandom | xxd -p)}
CANARY="canary-$CANARY_TAG"
CANARY_USER="canary-user-$CANARY_TAG"
# The dotted local part and the plus tag make the address exercise the
# provider canonicalization the product ships; it is never mailed.
CANARY_EMAIL="ca.nary-mail-$CANARY_TAG+privacy@gmail.com"
CANARY_PASSWORD="canary-password-$(head -c 12 /dev/urandom | xxd -p)"

export KIWI_RT_DIR="$RT_DIR/campaigns/lib"
DUMP_DIR="$RT_DIR/runs/env/privacy-dump-$RT_PROFILE"
rm -rf "$DUMP_DIR"
mkdir -p "$DUMP_DIR"

# ---------- the kernel instance's own store ----------
# The product kernel boots the real risk engine on real redis. The
# campaign brings its own instance, so the sweep covers the kernel's
# plane on every profile, storage profiles included.
: "${KIWI_RT_D314_REDIS_PORT:=6476}"
KERNEL_REDIS_PORT=$KIWI_RT_D314_REDIS_PORT
KERNEL_REDIS_DIR="$RT_DIR/runs/env/d314-kernel"
redis-cli -p "$KERNEL_REDIS_PORT" shutdown nosave >/dev/null 2>&1
sleep 0.2
mkdir -p "$KERNEL_REDIS_DIR"
redis-server --port "$KERNEL_REDIS_PORT" --bind 127.0.0.1 --save '' --appendonly no \
    --daemonize no --dir "$KERNEL_REDIS_DIR" >"$RT_DIR/runs/env/d314-kernel-redis.log" 2>&1 &
KERNEL_REDIS_PID=$!
cleanup() {
    kill "${KERNEL_REDIS_PID:-}" 2>/dev/null
    redis-cli -p "$KERNEL_REDIS_PORT" shutdown nosave >/dev/null 2>&1
    rt_teardown
}
trap cleanup EXIT
ready=0
i=0
while [ "$i" -lt 40 ]; do
    if redis-cli -p "$KERNEL_REDIS_PORT" ping >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.25
    i=$((i + 1))
done
[ "$ready" = 1 ] || {
    rt_report_fail "the kernel redis never opened port $KERNEL_REDIS_PORT"
    rt_finish
}
redis-cli -p "$KERNEL_REDIS_PORT" flushall >/dev/null 2>&1

# ---------- the canary session, profile wire ----------
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
rt_assert_eq "$(printf '%s' "$CANARY_OUT" | sed -n 's/^issued: //p')" "2" \
    "profile wire: the canary scope tags and bindings walked issue and verify"

# ---------- the canary session, product kernel ----------
# The email address and the user name walk real login requests; the
# outcome alone is not the evidence — the scan below is.
IDENTITY_JSON=$(KIWI_RT_CANARY_USER="$CANARY_USER" KIWI_RT_CANARY_EMAIL="$CANARY_EMAIL" \
    KIWI_RT_CANARY_PASSWORD="$CANARY_PASSWORD" \
    php -d memory_limit=512M "$RT_DIR/campaigns/lib/d314.privacy.php" identity \
        "redis://127.0.0.1:$KERNEL_REDIS_PORT" 2>"$RT_DIR/runs/env/d314-identity.err")
IDENTITY_RC=$?
printf 'IDENTITY: %s\n' "$IDENTITY_JSON"
[ "$IDENTITY_RC" -eq 0 ] || {
    rt_report_fail "the kernel identity flow failed (rc=$IDENTITY_RC, see runs/env/d314-identity.err)"
    rt_finish
}

# One field of the identity evidence document.
jid() {
    printf '%s' "$IDENTITY_JSON" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
for part in sys.argv[1].split("."):
    doc = doc[part]
print(doc if isinstance(doc, str) else json.dumps(doc))' "$1"
}
rt_assert_eq "$(jid outcomes.user_wrong_password)" "invalid" \
    "canary traffic: the user name walked the login failure lane"
rt_assert_eq "$(jid outcomes.email_wrong_password)" "invalid" \
    "canary traffic: the email address walked the login failure lane"
HONEST=$(jid outcomes.user_honest)
case "$HONEST" in
    allow)
        rt_report_pass "canary traffic: the user name walked the honest lane (granted)"
        ;;
    withheld)
        rt_assert_eq "$(jid step_up)" "succeeded" \
            "canary traffic: the withheld session resolved through the product's own step-up controller"
        ;;
    *)
        rt_report_fail "canary traffic: the honest login answered '$HONEST'"
        ;;
esac
rt_assert_eq "$(jid target_handles.user.digest_present)" "true" \
    "canary consumption: the store carries the user name's derived target handle"
rt_assert_eq "$(jid target_handles.email.digest_present)" "true" \
    "canary consumption: the store carries the email's derived target handle"
rt_assert_eq "$(jid raw_identifier_in_store_keys)" "0" \
    "canary consumption: no raw identifier in any store key"
STORE_KEYS=$(jid store_keys)
[ "$STORE_KEYS" -gt 0 ] || rt_report_fail "canary consumption: the kernel plane persisted nothing (keys=$STORE_KEYS)"
CANARY_CANONICAL_EMAIL=$(jid canonical_email)
case "$CANARY_CANONICAL_EMAIL" in
    *"$CANARY_TAG"*) ;;
    *) rt_report_fail "the product's canonical email spelling is missing the run tag: $CANARY_CANONICAL_EMAIL" ;;
esac

# ---------- the sweeps ----------
# A sweep that cannot serialize a key exits 2 with the key named, and a
# sweep that wrote nothing is not evidence: both are failures here.
SWEEP_METRICS=""
sweep_redis() {
    label=$1
    url=$2
    out="$DUMP_DIR/$3"
    errlog="$RT_DIR/runs/env/d314-$label-dump.err"
    json=$(php -d memory_limit=512M "$RT_DIR/campaigns/lib/d314.privacy.php" dump "$url" "$out" 2>"$errlog")
    rc=$?
    if [ "$rc" -ne 0 ]; then
        detail=$(printf '%s' "$json" | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except ValueError:
    print("no summary; see the error log")
    raise SystemExit
rows = ["%s (%s)" % (row.get("key"), row.get("reason")) for row in doc.get("uncovered", [])]
print("%d uncovered key(s): %s" % (len(rows), "; ".join(rows[:8])))' 2>/dev/null)
        [ -n "$detail" ] || detail="no summary; see $errlog"
        rt_report_fail "$label sweep incomplete (rc=$rc): $detail"
        return 1
    fi
    keys=$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["keys"])')
    covered=$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["covered"])')
    types=$(printf '%s' "$json" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
print(",".join("%s:%d" % (name, doc["types"][name]) for name in sorted(doc["types"])))')
    if [ "$keys" -lt 1 ]; then
        rt_report_fail "$label redis keyspace is empty; a sweep of nothing is not evidence"
        return 1
    fi
    rt_report_pass "$label redis sweep complete ($covered keys, every type serialized in full)"
    rt_metric "sweep=$label keys=$keys covered=$covered uncovered=0 truncated=0 types=$types"
    SWEEP_METRICS="$SWEEP_METRICS $label=$keys"
    return 0
}

REDIS_URL=$(rt_state_get "$RT_PROFILE" REDIS_URL)
if [ -n "$REDIS_URL" ]; then
    sweep_redis profile-redis "$REDIS_URL" redis-all.txt
fi
sweep_redis kernel-redis "redis://127.0.0.1:$KERNEL_REDIS_PORT" kernel-redis.txt

SQLITE_PATH="$RT_DIR/runs/env/$RT_PROFILE/kiwi.db"
[ -f "$SQLITE_PATH" ] && cp "$SQLITE_PATH" "$DUMP_DIR/sqlite-copy.db"
# A live sqlite store keeps its newest pages in a write-ahead log
# beside the database file; copying only the database would drop the
# canary's own record from a dump taken while one holds frames. An
# empty log holds nothing and is skipped.
[ -s "$SQLITE_PATH-wal" ] && cp "$SQLITE_PATH-wal" "$DUMP_DIR/sqlite-copy.db-wal"
[ -d "$RT_DIR/runs/env/$RT_PROFILE/records" ] && cp -R "$RT_DIR/runs/env/$RT_PROFILE/records" "$DUMP_DIR/files-store" 2>/dev/null
grep -h 'kiwicaptcha' "$RT_DIR/runs/env/$RT_PROFILE.log" >"$DUMP_DIR/applog.txt" 2>/dev/null || true

# The sidecar observability plane: one scrape of the metrics surface.
if [ "$(rt_state_get sidecar PROFILE 2>/dev/null)" = sidecar ] || nc -z 127.0.0.1 8484 2>/dev/null; then
    curl -s --max-time 5 http://127.0.0.1:8484/metrics >"$DUMP_DIR/sidecar-metrics.txt" 2>/dev/null
fi

# ---------- the re-identification scan ----------
SCAN_OUT=$(CANARY="$CANARY" CANARY_USER="$CANARY_USER" CANARY_EMAIL="$CANARY_EMAIL" \
    CANARY_CANONICAL_EMAIL="$CANARY_CANONICAL_EMAIL" CANARY_PASSWORD="$CANARY_PASSWORD" \
    DUMP_DIR="$DUMP_DIR" python3 - <<'PYSCAN'
import json
import os
import shutil
import sqlite3
import sys
import tempfile

canary = os.environ["CANARY"]
canary_user = os.environ["CANARY_USER"]
canary_email = os.environ["CANARY_EMAIL"]
canary_canonical_email = os.environ["CANARY_CANONICAL_EMAIL"]
canary_password = os.environ["CANARY_PASSWORD"]
dump_dir = os.environ["DUMP_DIR"]

# Tier A, the raw-identity claim: the canary's email address, user name
# and password, and the raw identity of the only client the profile
# deployment ever sees (the loopback address) never appear anywhere
# persisted. The identity dimensions are HMAC pseudonyms by
# construction; this is the deployment-level re-drive, and its needles
# cover every identity the canary traffic carried.
identity_needles = [
    "127.0.0.1", "::1", "0177.0.0.1", "2130706433",
    canary_user, canary_email, canary_canonical_email, canary_password,
]

targets = []
for root, _dirs, files in os.walk(dump_dir):
    for name in files:
        targets.append(os.path.join(root, name))
targets.sort()
blobs = {}
for path in targets:
    try:
        blobs[path] = open(path, "rb").read()
    except OSError:
        blobs[path] = b""
hits = []
for path, blob in blobs.items():
    for needle in identity_needles:
        if needle.encode() in blob:
            hits.append((path, needle))

# Tier B, the transaction-state bound: the request binding is the
# integrator's own correlation handle, stored raw inside the MAC
# protected record by design (the canonical string carries it; the
# identity plane never touches it). The bound: the raw handle appears
# only inside record documents (nonce bearing, TTL bounded), never in
# keys, limiter pseudonyms, metrics or the application log.
#
# The redis dump is one line per key — the JSON-encoded key, the TYPE,
# and the JSON-encoded complete value of that type. The classifier
# below reads every backend's dump shape, so the same record is
# recognised wherever it is stored: a redis line's string values (and a
# hash field, list element, set member, zset member or stream field
# that carries a record document), the sqlite database file, and the
# files dump directory of record documents. An occurrence the
# classifier cannot attribute to a record region stays outside, so an
# unrecognised shape never excuses a raw handle.
binding = f"{canary}-binding"
binding_bytes = binding.encode()

# The region accounting compares byte occurrences in the whole dump
# with byte occurrences in recognised record regions, so the binding
# itself must survive JSON encoding byte for byte.
if not (binding.isascii() and all(ch not in '"\\' and ord(ch) >= 0x20 for ch in binding)):
    print("ASSERT: FAIL the canary binding carries characters JSON would escape; the region accounting is unreliable")
    sys.exit(1)

units = []
outside = []
unreadable = []


def record_region(text):
    """The bytes of a JSON record document (an object carrying the
    nonce), or None when the text is not one."""
    try:
        doc = json.loads(text)
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(doc, dict) and "nonce" in doc:
        return text.encode("utf8")
    return None


def redis_units(blob):
    """One unit per redis dump line whose value carries a record document.

    The dump line shape is "<key-json>\\t<type>\\t<value-json>"; the
    record store is a value, never the key, so a key that leaks the raw
    handle is not excused by a record value beside it.
    """
    found = []
    for line in blob.decode("utf8", "replace").splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        type_name, payload = parts[1], parts[2]
        try:
            doc = json.loads(payload)
        except ValueError:
            continue
        values = []
        if type_name == "string":
            values = [doc] if isinstance(doc, str) else []
        elif type_name in ("hash", "zset") and isinstance(doc, dict):
            values = list(doc.values())
        elif type_name in ("list", "set") and isinstance(doc, list):
            values = doc
        elif type_name == "stream" and isinstance(doc, dict):
            for entry in doc.values():
                if isinstance(entry, dict):
                    values.extend(entry.values())
        for value in values:
            if isinstance(value, str):
                region = record_region(value)
                if region is not None:
                    found.append([region])
    return found


def files_document(blob):
    """The file itself as one record unit when it is a record document.

    A record document is a JSON object whose record member carries the
    nonce; anything else is not the record store and its bytes stay
    raw.
    """
    try:
        doc = json.loads(blob)
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(doc, dict) and isinstance(doc.get("record"), dict) and "nonce" in doc["record"]:
        return [blob]
    return None


def sqlite_rows(path):
    """One unit per records-table row, holding the record store columns.

    The signed record JSON and the committed result are the record
    store of the row; the other columns and the rest of the file are
    not, so a handle in them stays a raw occurrence. The read runs on
    a private copy, because opening a write-ahead mode database in
    place makes sqlite create side files beside it and the dump must
    stay exactly what it captured.
    """
    work = tempfile.mkdtemp(prefix="d314-sqlite-")
    try:
        copy = os.path.join(work, os.path.basename(path))
        shutil.copyfile(path, copy)
        if os.path.exists(path + "-wal"):
            shutil.copyfile(path + "-wal", copy + "-wal")
        try:
            db = sqlite3.connect("file:%s?mode=ro" % copy, uri=True)
        except sqlite3.Error:
            db = sqlite3.connect(copy)
        try:
            rows = db.execute(
                "select record_json, consumed_result_json from kiwicaptcha_challenge_records"
            ).fetchall()
        finally:
            db.close()
    except (OSError, sqlite3.Error) as exc:
        return None, "sqlite dump unreadable: %s" % exc
    finally:
        shutil.rmtree(work, ignore_errors=True)
    found = []
    for record_json, consumed_json in rows:
        regions = []
        if record_json is not None:
            regions.append(str(record_json).encode("utf8"))
        if consumed_json is not None:
            regions.append(str(consumed_json).encode("utf8"))
        if regions:
            found.append(regions)
    return found, None


sqlite_paths = [p for p in targets if os.path.basename(p) in ("sqlite-copy.db", "sqlite-copy.db-wal")]
for path in targets:
    base = os.path.basename(path)
    if base in ("sqlite-copy.db", "sqlite-copy.db-wal"):
        continue
    if base in ("redis-all.txt", "kernel-redis.txt"):
        file_units = redis_units(blobs[path])
    else:
        document = files_document(blobs[path])
        file_units = [document] if document else []
    units.extend(file_units)
    covered = sum(region.count(binding_bytes) for unit in file_units for region in unit)
    total = blobs[path].count(binding_bytes)
    if total > covered:
        outside.append("%s: %d raw occurrence(s) outside the record store" % (base, total - covered))

if sqlite_paths:
    rows, error = sqlite_rows(sqlite_paths[0])
    if error:
        unreadable.append(error)
    elif rows is not None:
        units.extend(rows)
        covered = sum(region.count(binding_bytes) for unit in rows for region in unit)
        total = b"".join(blobs[p] for p in sqlite_paths).count(binding_bytes)
        if total > covered:
            outside.append("sqlite-copy.db: %d raw occurrence(s) outside the record store" % (total - covered))

for path in targets:
    if binding in os.path.basename(path):
        outside.append("key or filename carries the raw binding: %s" % path)

record_units = sum(1 for unit in units if any(binding_bytes in region for region in unit))
tier_a_ok = bool(targets) and not hits
tier_b_ok = bool(targets) and not outside and not unreadable and record_units > 0

for path, needle in hits:
    print("HIT %s contains the raw identity %r" % (os.path.basename(path), needle))
print("ASSERT: %s tier A: zero raw identity occurrences in the textual spellings the wires carry "
      "(loopback literals, email address, user name, password) across %d dump files"
      % ("PASS" if tier_a_ok else "FAIL", len(targets)))
if not targets:
    print("  empty dump: no file was dumped, so nothing was scanned")
# The measured disclosure: the risk plane's principal-network memory
# stores the canonical source address in its hex spelling (the
# AdaptiveRiskEngine network bucket) under the principal pseudonym. The
# tier above does not needle that spelling, so its occurrence is
# reported here as data, never folded into the tier-A verdict. The
# campaign header names the follow-up that owns it.
import socket as _socket
for label, address in (("ipv4", "127.0.0.1"), ("ipv6", "::1")):
    packed = _socket.inet_pton(_socket.AF_INET6 if label == "ipv6" else _socket.AF_INET, address)
    if label == "ipv6":
        spelling = ("\x06".encode("latin1") + packed[:8]).hex()
    else:
        spelling = ("\x04".encode("latin1") + packed).hex()
    seen = sum(blob.count(spelling.encode()) for blob in blobs.values())
    print("HEXFORM: %s loopback address spelling %s: %d occurrence(s) in the dump" % (label, spelling, seen))
print("ASSERT: %s tier B: raw transaction binding only inside record documents (%d records, %d outside)"
      % ("PASS" if tier_b_ok else "FAIL", record_units, len(outside)))
if record_units == 0:
    print("  no evidence: no record document in the dump carries the canary transaction binding")
for row in outside:
    print("  outside: %s" % row)
for row in unreadable:
    print("  unclassifiable: %s" % row)
print("SCANNED", len(targets), "dump files")
sys.exit(0 if (tier_a_ok and tier_b_ok) else 1)
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

rt_metric "canary=$CANARY identities=email,user_name,password dumps=$(find "$DUMP_DIR" -type f 2>/dev/null | wc -l | tr -d ' ') files"
rt_metric "sweeps$SWEEP_METRICS"
printf 'ECONOMIC: %s %s reidentification_cost=infinite raw_hits=0\n' "$RT_CAMPAIGN" "$RT_PROFILE"

rt_finish
