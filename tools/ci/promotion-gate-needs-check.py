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
    """True when the gate must fail (refuse), false when it passes."""
    needs = json.loads(needs_json)
    if not needs:
        return True
    return any(data.get("result") != "success" for data in needs.values())


CASES = [
    ("all success", {"rust": {"result": "success"}, "php": {"result": "success"}}, False),
    ("one failure", {"rust": {"result": "success"}, "php": {"result": "failure"}}, True),
    ("one skipped", {"rust": {"result": "success"}, "php": {"result": "skipped"}}, True),
    ("one cancelled", {"rust": {"result": "success"}, "php": {"result": "cancelled"}}, True),
    ("empty needs map", {}, True),
]

def assert_live() -> int:
    """The ci.yml entry point: refuse (exit 1) when the live needs map
    carries any non-success result, or when it is empty."""
    needs_json = os.environ.get("NEEDS_JSON", "")
    if gate_refuses(needs_json):
        try:
            needs = json.loads(needs_json) if needs_json else {}
        except json.JSONDecodeError:
            needs = {}
        bad = {k: v.get("result") for k, v in needs.items() if v.get("result") != "success"}
        print("promotion-gate refused:", bad or "empty needs map", file=sys.stderr)
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
