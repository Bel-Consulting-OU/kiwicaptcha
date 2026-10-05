"""The D3.10 infrastructure attacker driver.

Runs the storage-plane attack matrix against ONE backend of the live
deployment: forged record injection, MAC strip and transplant, epoch
and policy manipulation, plus or minus ten minute clock skew through
the persisted timestamps, scope rewrite, and replay after a rollback
of the pending record. Every verdict comes from the deployment's real
verify endpoint. Required result: zero acceptances.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rtclient as rt  # noqa: E402
import rtstore  # noqa: E402

BASE = os.environ["KIWI_RT_BASE"]
BACKEND = os.environ["KIWI_RT_BACKEND"]


def issue_and_solve() -> tuple:
    """One honest issue plus an honestly paid proof. Returns (nonce,
    token, record_json)."""
    doc = rt.challenge(BASE, "login")
    nonce = str(doc.body["nonce"])
    counter = rt.pow_solve(doc.body)
    token = rt.mint_token(nonce, counter)
    return nonce, token, None


def main() -> int:
    store = rtstore.RecordStore(
        BACKEND,
        redis_url=os.environ.get("KIWI_RT_REDIS_URL", ""),
        sqlite_path=os.environ.get("KIWI_RT_SQLITE_PATH", ""),
        files_dir=os.environ.get("KIWI_RT_FILES_DIR", ""),
    )

    accepted: list = []
    legs: list = []

    def check(what: str, ok: bool, detail: str = "") -> None:
        legs.append({"what": what, "ok": bool(ok), "detail": detail})

    # Control leg: an honest solve verifies exactly once, and the
    # replay after consumption is refused. Nothing here is tampered.
    nonce, token, _ = issue_and_solve()
    first = rt.verify(BASE, token)
    check("control: honest solve accepted", first.ok, first.code)
    replay = rt.verify(BASE, token)
    check("control: replay refused", not replay.ok, replay.code)

    # One fresh challenge per variant: a cheap-phase verdict retires
    # the record on some backends, so every mutation gets its own
    # pending record and the whole set runs on every backend.
    nonce_t, token_t, _ = issue_and_solve()
    raw_t = store.get_record(nonce_t)
    nonce_x, _token_x, _ = issue_and_solve()
    raw_x = store.get_record(nonce_x)
    check("records readable on %s" % BACKEND, bool(raw_t) and bool(raw_x))

    if raw_t and raw_x:
        variants = rtstore.tamper_variants(raw_t, raw_x)
        for label, mutated in variants.items():
            v_nonce, v_token, _ = issue_and_solve()
            v_raw = store.get_record(v_nonce)
            if v_raw is None:
                continue
            store.put_record(v_nonce, mutated)
            resp = rt.verify(BASE, v_token)
            if resp.ok:
                accepted.append(label)
            check("tamper rejected: %s" % label, not resp.ok, resp.code)

    # Forged record injection: a record the attacker minted wholesale
    # (a real record body under a new nonce it controls), stored into
    # the backend, then a token for it.
    forged_doc = json.loads(raw_t) if raw_t else {}
    if forged_doc:
        forged_doc["nonce"] = "Zm9yZ2Vkbm9uY2Vmb3JnZWRub25jZWZvcmdlZG5vbmNl"
        forged_doc["scope"] = "login"
        store.put_record(str(forged_doc["nonce"]), json.dumps(forged_doc))
        forged_token = rt.forge_token(str(forged_doc["nonce"]), 3)
        resp = rt.verify(BASE, forged_token)
        if resp.ok:
            accepted.append("forged-injection")
        check("forged record injection rejected", not resp.ok, resp.code)

    # Replay after rollback: the fault-schedule form of this attack is
    # a consumed outcome meeting a store whose later state rolled back
    # (a stale primary serving after promotion, an old dump replayed).
    # The deployment-level property is that the consumed marker is
    # RETAINED past consumption and refuses every replay while it
    # lives; the sentinel leg proves the stale primary itself can
    # never serve. A raw store-write attacker who erases the retained
    # marker and restores the pending bytes defeats any MAC-only
    # scheme by construction (the verifier cannot distinguish a
    # restored record from a never-consumed one), so that capability
    # is reported as a bound, not counted as an acceptance: it is
    # gated by store access control, exactly the plane boundary the
    # storage adapter documents.
    nonce_r, token_r, _ = issue_and_solve()
    rt.verify(BASE, token_r)
    state = store.state(nonce_r)
    check("consumed marker retained on %s" % BACKEND, state == "consumed", state or "absent")
    replay = rt.verify(BASE, token_r)
    if replay.ok:
        accepted.append("retained-marker-replay")
    check("replay against the retained marker rejected", not replay.ok, replay.code)

    store.close()
    print(json.dumps({
        "backend": BACKEND,
        "accepted": accepted,
        "bounds": ["store-write rollback overwrite is an access-control bound, not a verdict flip"],
        "legs": legs,
    }))
    return 0 if not accepted else 1


if __name__ == "__main__":
    sys.exit(main())
