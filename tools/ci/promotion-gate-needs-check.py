#!/usr/bin/env python3
"""The promotion-gate dependency assertion, as a testable unit.

ci.yml's promotion-gate job runs this exact logic (inline) against
toJSON(needs): it refuses unless every dependency reported success and
the needs map is non-empty. This file is the same ruleset as a module
with a self-test harness over the synthetic result states, so a change
to the inline logic can be proven against: all success, one failure,
one skipped, one cancelled, and an empty map.
"""
import json
import os
import sys


def gate_refuses(needs_json: str) -> bool:
    """True when the gate must fail (refuse), false when it passes.

    An unreadable or malformed needs map is never a pass: a missing,
    empty or garbled input refuses with the same verdict as an empty
    map instead of crashing with a traceback (a gate that throws on
    bad input would still exit non-zero, but with no typed verdict for
    the log or the next reader).
    """
    try:
        needs = json.loads(needs_json)
    except (json.JSONDecodeError, TypeError):
        return True
    if not isinstance(needs, dict) or not needs:
        return True
    return any(
        not isinstance(data, dict) or data.get("result") != "success"
        for data in needs.values()
    )


CASES = [
    ("all success", {"rust": {"result": "success"}, "php": {"result": "success"}}, False),
    ("one failure", {"rust": {"result": "success"}, "php": {"result": "failure"}}, True),
    ("one skipped", {"rust": {"result": "success"}, "php": {"result": "skipped"}}, True),
    ("one cancelled", {"rust": {"result": "success"}, "php": {"result": "cancelled"}}, True),
    ("empty needs map", {}, True),
    ("null needs map", None, True),
    ("unreadable entry", {"rust": "boom"}, True),
]

def assert_live() -> int:
    """The ci.yml entry point: refuse (exit 1) when the live needs map
    carries any non-success result, when it is empty, or when it cannot
    be read at all."""
    needs_json = os.environ.get("NEEDS_JSON", "")
    if gate_refuses(needs_json):
        try:
            needs = json.loads(needs_json)
        except json.JSONDecodeError:
            needs = None
        if not isinstance(needs, dict):
            print("promotion-gate refused: unreadable needs map", file=sys.stderr)
        elif not needs:
            print("promotion-gate refused: empty needs map", file=sys.stderr)
        else:
            bad = {
                k: (v.get("result") if isinstance(v, dict) else "unreadable")
                for k, v in needs.items()
                if not isinstance(v, dict) or v.get("result") != "success"
            }
            print("promotion-gate refused:", bad, file=sys.stderr)
        return 1
    print("promotion-gate: every dependency reported success")
    return 0


if __name__ == "__main__":
    if "--assert" in sys.argv:
        sys.exit(assert_live())
    failed = 0
    for name, needs, expect_refuse in CASES:
        got = gate_refuses(json.dumps(needs))
        ok = got == expect_refuse
        print("%s %s: gate %s" % ("PASS" if ok else "FAIL", name, "refused" if got else "passed"))
        failed += 0 if ok else 1
    sys.exit(1 if failed else 0)
