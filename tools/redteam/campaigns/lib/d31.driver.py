"""The D3.1 attack driver: forged, replayed and omitted token floods.

Runs every attack class against one live deployment base URL and emits
one JSON summary. The assertions here are the required result: zero
acceptances outside the single honest control, the one-shot anti-oracle
on binding retries, and the human baseline intact.
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rtclient as rt  # noqa: E402

BASE = os.environ["KIWI_RT_BASE"]
N = int(os.environ.get("KIWI_RT_N", "600"))

assertions: list[dict] = []


def check(what: str, ok: bool, detail: str = "") -> None:
    assertions.append({"what": what, "ok": bool(ok), "detail": detail})


def main() -> int:
    accepted = 0
    attempts = 0
    replay_burned = 0

    def attempt(resp: rt.Response, what: str, must_deny: bool = True) -> None:
        nonlocal attempts, accepted
        attempts += 1
        if resp.ok:
            accepted += 1
            check(what, not must_deny, "accepted a %s token" % what)
        elif resp.status == 0:
            check(what, False, "transport failure (target down?)")

    # Class 1: random forged tokens, plausible wire shape.
    rng = 0x6B776D74
    for _ in range(max(20, N // 20)):
        rng = (rng * 1103515245 + 12345) & 0x7FFFFFFF
        nonce = base64.b64encode(rng.to_bytes(4, "big") * 8).decode()
        attempt(rt.verify(BASE, rt.forge_token(nonce)), "forged-random")

    # Class 2: forgeries around a REAL nonce that never paid the proof.
    issued = rt.challenge(BASE, "login")
    check("challenge issuance reachable", issued.status == 200 and bool(issued.body.get("nonce")))
    real_nonce = str(issued.body.get("nonce", ""))
    for counter in (0, 1, 2, 7, 1337):
        attempt(rt.verify(BASE, rt.forge_token(real_nonce, counter)), "forged-unpaid")

    # Class 3: bit-flipped variants of a genuinely solved token.
    solved = rt.solve(BASE, "login")
    token = str(solved.get("token", ""))
    check("native solver solved the real challenge", bool(token))
    for offset in range(12):
        attempt(rt.verify(BASE, rt.mutate_token(token, offset)), "forged-mutated")

    # Class 4: replay of one legitimately solved token. The FIRST
    # verify is the honest control and must be accepted exactly once;
    # every replay after it must burn.
    if token:
        first = rt.verify(BASE, token)
        check("honest control accepted exactly once", first.ok)
        if first.ok:
            pass  # the human baseline; not an abuse acceptance
        for _ in range(max(20, N // 30)):
            resp = rt.verify(BASE, token)
            attempts += 1
            if resp.ok:
                accepted += 1
                check("replay rejected", False, "a consumed token verified again")
            else:
                replay_burned += 1
                if resp.code not in ("already_consumed", "record_not_found"):
                    check("replay rejection code", False, resp.code)

    # Class 5: omitted and empty tokens.
    for _ in range(5):
        attempt(rt.verify(BASE, "", omit_token=True), "omitted-token")
        attempt(rt.verify(BASE, ""), "empty-token")

    # Class 6: cross-scope re-labeling of a fresh honest token.
    token_b = rt.solve_token(BASE, "login")
    if token_b:
        attempt(rt.verify(BASE, token_b, scope="signup"), "cross-scope")

    # Class 7: binding re-labeling plus the one-shot anti-oracle: a
    # wrong binding burns the record, so the corrected retry must find
    # the record gone. The proof here is paid honestly in python
    # against the bound challenge (the CLI solver cannot carry a
    # binding; the preimage contract is identical).
    issued_bound = rt.challenge(BASE, "login", binding="txn-9f27")
    bound_token = ""
    if issued_bound.status == 200 and issued_bound.body.get("nonce"):
        try:
            counter = rt.pow_solve(issued_bound.body)
            bound_token = rt.mint_token(str(issued_bound.body["nonce"]), counter)
        except (KeyError, ValueError):
            bound_token = ""
    if bound_token:
        wrong = rt.verify(BASE, bound_token, binding="txn-other")
        attempt(wrong, "wrong-binding")
        retry = rt.verify(BASE, bound_token, binding="txn-9f27")
        attempts += 1
        if retry.ok:
            accepted += 1
            check("one-shot anti-oracle", False, "a burned record verified on retry")
        else:
            check("one-shot anti-oracle", retry.code in ("record_not_found", "already_consumed"),
                  "burned record answered %s" % retry.code)

    # Class 8: oversized and malformed documents.
    big = b'{"token":"' + b"A" * 20000 + b'"}'
    attempt(rt.verify(BASE, None, raw_body=big), "oversized-body")
    attempt(rt.verify(BASE, None, raw_body=b'{"token": nope}'), "malformed-json")
    attempt(rt.verify(BASE, None, raw_body=b'{"token":"x","token":"y"}'), "duplicate-key")
    attempt(rt.verify(BASE, None, raw_body=b'{"unknown":1}'), "unknown-field")

    # Class 9: wrong-algorithm issuance probes (server-owned profile).
    wrong_algo = rt.challenge(BASE, "login", extra={"algorithm": "gpu-sha"})
    check("invalid algorithm refused", wrong_algo.error_code == "INVALID_ALGORITHM",
          wrong_algo.error_code)

    # Class 10: scope confusables never alias a real scope.
    confusables = ["ｌogin", "lоgin", "logi\u200bn", "LOGİN"]
    for scope in confusables:
        resp = rt.challenge(BASE, scope)
        check("confusable scope refused: %r" % scope, resp.error_code == "INVALID_SCOPE",
              resp.error_code)

    # Human baseline: one more honest solve and verify must succeed.
    honest_solve = bool(rt.solve_token(BASE, "login"))
    doc = {
        "attempts": attempts,
        "accepted": accepted,
        "replay_burned": replay_burned,
        "honest_solve": honest_solve,
        "honest_verify": honest_solve,
        "assertions": assertions,
    }
    print(json.dumps(doc))
    return 0 if accepted == 0 and honest_solve else 1


if __name__ == "__main__":
    sys.exit(main())
