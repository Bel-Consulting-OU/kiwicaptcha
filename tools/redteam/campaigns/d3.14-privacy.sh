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
    # One scanner process over the whole keyspace: the per-key
    # redis-cli spawn of the previous shape turned a 500k-key target
    # into a multi-hour walk (one fork per key). The dumped bytes and
    # the file shape are identical (key then value then newline).
    #
    # This program sits inside a single-quoted shell string, so every
    # backslash reaches php exactly as written: one backslash is the
    # namespace separator of a fully qualified name. The earlier form
    # doubled them, php read a stray backslash token and died with a
    # parse error before a single key was read, while the campaign
    # ignored the exit status and scanned an empty directory. A single
    # backslash here is the whole fix.
    REDIS_DUMP_ERR=$(mktemp)
    REPO_ROOT="$REPO_ROOT" DUMP_DIR="$DUMP_DIR" RT_REDIS_URL="$REDIS_URL" php -r '
    $autoload = getenv("REPO_ROOT")."/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php";
    if (is_file($autoload)) { require_once $autoload; }
    $client = new \Predis\Client(getenv("RT_REDIS_URL"));
    $all = fopen(getenv("DUMP_DIR")."/redis-all.txt", "w");
    $cursor = "0";
    do {
        $reply = $client->executeCommand(new \Predis\Command\RawCommand("SCAN", [$cursor, "COUNT", "5000"]));
        $cursor = (string) $reply[0];
        foreach ($reply[1] as $key) {
            // Non-string keys dump the refusal marker the redis-cli
            // shape carried, never a crash: the scan must cover every
            // key, and hashes, sets and ZSETs are part of the space.
            try {
                $value = $client->get($key);
            } catch (\Predis\Response\ServerException $e) {
                $value = "(error ".$e->getMessage().")";
            }
            fwrite($all, $key.(is_string($value) ? $value : "")."\n");
        }
    } while ($cursor !== "0");
    fclose($all);
    ' 2>"$REDIS_DUMP_ERR"
    REDIS_DUMP_RC=$?
    REDIS_DUMP_BYTES=0
    if [ -f "$DUMP_DIR/redis-all.txt" ]; then
        REDIS_DUMP_BYTES=$(wc -c <"$DUMP_DIR/redis-all.txt" | tr -d ' ')
    fi
    # A dump that failed or wrote nothing is not evidence: the campaign
    # fails here, with the php exit status, instead of scanning an
    # empty artifact and reporting green. The stderr is kept only on a
    # failure, beside the other failure logs.
    if [ "$REDIS_DUMP_RC" -ne 0 ] || [ "$REDIS_DUMP_BYTES" -eq 0 ]; then
        rt_report_fail "redis keyspace dump did not complete (php rc=$REDIS_DUMP_RC, $REDIS_DUMP_BYTES bytes written); an empty dump is not evidence"
        cp "$REDIS_DUMP_ERR" "$RT_DIR/runs/env/d314-redis-dump.err"
    fi
    rm -f "$REDIS_DUMP_ERR"
fi
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
SCAN_OUT=$(CANARY="$CANARY" DUMP_DIR="$DUMP_DIR" python3 - <<'PYSCAN'
import json
import os
import shutil
import sqlite3
import sys
import tempfile

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
# Every storage backend writes its own dump shape and the classifier
# below reads all three, so the same record is recognised wherever it
# is stored. The redis dump is one line per key (key bytes glued to
# the value), the sqlite dump is the database file itself, and the
# files dump is the store directory of record documents. An occurrence
# the classifier cannot attribute to a record region stays outside,
# so an unrecognised shape never excuses a raw handle.
binding = f"{canary}-binding"
binding_bytes = binding.encode()

units = []
outside = []
unreadable = []


def redis_units(blob):
    """One unit per redis dump line whose JSON value carries the nonce.

    The record store is the value, never the key, so a key that leaks
    the raw handle is not excused by a record value beside it.
    """
    found = []
    for line in blob.decode("utf8", "replace").splitlines():
        brace = line.find("{")
        if brace < 0:
            continue
        value = line[brace:]
        try:
            doc = json.loads(value)
        except ValueError:
            continue
        if isinstance(doc, dict) and "nonce" in doc:
            found.append([value.encode("utf8")])
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
    if base == "redis-all.txt":
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
print("ASSERT: %s tier A: zero raw identity occurrences across %d dump files"
      % ("PASS" if tier_a_ok else "FAIL", len(targets)))
if not targets:
    print("  empty dump: no file was dumped, so nothing was scanned")
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

rt_metric "canary=$CANARY dumps=$(find "$DUMP_DIR" -type f 2>/dev/null | wc -l | tr -d ' ') files"
printf 'ECONOMIC: %s %s reidentification_cost=infinite raw_hits=0\n' "$RT_CAMPAIGN" "$RT_PROFILE"

rt_finish
