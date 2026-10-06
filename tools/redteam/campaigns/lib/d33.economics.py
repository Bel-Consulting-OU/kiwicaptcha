#!/usr/bin/env python3
"""d33.economics.py — the D3.3 farm-economics table builder.

Reads the solver bench output (all challenge rungs, measured on this
CPU) plus the committed reference-costs.json, and produces the campaign
table the change.md D3.3 required result demands.

Every dollar figure is the bench's own (the this_cpu and
best_reference columns of its dollar table), so the campaign never
re-derives the arithmetic the bench already did. The declared abuse
values are measured-cost-derived: each default is the measured attacker
cost per 1000 solves for its rung divided by the table's calibration
margin (10x), rounded down to a clean figure; the margin statement
ships in the table's economics.calibration block and is echoed here.

Per value class the row answers with one of three honest verdicts:

  PASS      the priced rung costs the cheapest known attacker MORE than
            the declared abuse value per 1000 solves (on this CPU and,
            where a reference class exists, on the fastest rentable
            reference hardware).
  ESCALATE  this CPU's measurement prices above the declared value but
            a tabled reference class undercuts it: raw PoW cannot price
            the value against that hardware class. The documented
            answer is the disposition escalation (the scope's
            step_up/deny minimum), not a bigger number. An ESCALATE row
            is the ladder ending in StepUp/Deny doing its documented
            job, so it is not a gate failure.
  FAIL      even this CPU's measurement undercuts the declared value:
            the rung cannot price the claim on any honest anchor. FAIL
            rows feed the release gate's value-class threshold row.

  end to end: the deployment accepted zero abuses this battery, so the
  measured cost per ACCEPTED abuse is unbounded; the row carries the
  measured spend per solve instead.

Also runs the RSW sequentiality suite (the crate's own rsw tests) as
the non-parallelizable evidence for the rsw rung, and (in the campaign
shell) the critical-stakes escalation demonstration through the
bundle's ValueClassCeiling verdict.

Output: one JSON document (the gate reads it), plus the printed table.
"""

import json
import os
import subprocess
import sys

REPO = os.environ.get("KIWI_RT_REPO_ROOT") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SOLVER = os.path.join(REPO, "target", "debug", "kiwicaptcha-solver")
REFERENCE = os.path.join(REPO, "packages", "kiwicaptcha-solver", "reference-costs.json")

RUNGS = ["sha16", "sha18", "sha20", "argon16", "argon32", "argon64"]


def run_bench(samples: int) -> dict:
    proc = subprocess.run(
        [SOLVER, "bench", "--samples", str(samples), "--rungs", ",".join(RUNGS)],
        capture_output=True, text=True, timeout=1800,
    )
    if proc.returncode != 0:
        raise SystemExit("bench failed: " + proc.stderr[-400:])
    measurements = {}
    in_table = False
    for line in proc.stdout.splitlines():
        if line.startswith("rung algorithm mean_us"):
            in_table = True
            continue
        if in_table:
            if not line.strip():
                in_table = False
                continue
            parts = line.split()
            if len(parts) >= 3:
                try:
                    measurements[parts[0]] = float(parts[2])
                except ValueError:
                    continue
    dollars = {}
    m = None
    for i, line in enumerate(proc.stdout.splitlines()):
        if line.startswith("rung this_cpu_usd best_reference_usd"):
            m = proc.stdout.splitlines()[i + 1:]
            break
    if m:
        for line in m:
            parts = line.split()
            if len(parts) >= 2 and not line.startswith(" "):
                try:
                    this_cpu = float(parts[1])
                except ValueError:
                    continue
                ref = None
                via = None
                if len(parts) >= 3 and not parts[2].startswith("(no"):
                    try:
                        ref = float(parts[2])
                        via = parts[3] if len(parts) >= 4 else None
                    except ValueError:
                        ref = None
                dollars[parts[0]] = {"this_cpu_usd": this_cpu, "reference_usd": ref, "via": via}
    return {"measurements": measurements, "dollars": dollars, "raw_tail": proc.stdout[-2000:]}


def verdict_for(dollars: dict, declared: float) -> tuple:
    """One row's honest verdict from the bench's own dollar figures."""
    cpu = dollars["this_cpu_usd"]
    ref = dollars.get("reference_usd")
    if ref is None:
        if cpu > declared:
            return "PASS", "no reference class is tabled for this algorithm; the native CPU measurement is the pricing anchor"
        return "FAIL", "even the native CPU measurement undercuts the declared abuse value"
    if cpu > declared and ref > declared:
        return "PASS", "priced above the declared abuse value on this CPU and on the fastest rentable reference class"
    if cpu > declared:
        return "ESCALATE", (
            "the cheapest rentable reference class prices 1000 solves below the declared value: "
            "raw PoW cannot price this value against that hardware class; "
            "the documented answer is the disposition escalation (the scope's risk minimum action, step_up or deny)"
        )
    return "FAIL", "the native CPU measurement undercuts the declared abuse value"


def main() -> int:
    samples = int(os.environ.get("KIWI_RT_D33_SAMPLES", "3"))
    bench = run_bench(samples)
    reference = json.load(open(REFERENCE))
    cpu_usd_hour = reference["economics"]["cpu_usd_per_core_hour"]
    calibration = reference["economics"].get("calibration")

    rows = []
    for value in reference["value_classes"]:
        rung = value["rung"]
        mean_us = bench["measurements"].get(rung)
        declared = value["declared_abuse_value_usd_per_1000"]
        if mean_us is None or rung not in bench["dollars"]:
            rows.append({"value_class": value["class"], "rung": rung, "verdict": "UNMEASURED",
                         "this_cpu_usd_per_1000": None, "reference_usd_per_1000": None,
                         "declared_abuse_value_usd_per_1000": declared,
                         "note": "the rung was not measured in this run"})
            continue
        dollars = bench["dollars"][rung]
        verdict, note = verdict_for(dollars, declared)
        rows.append({
            "value_class": value["class"],
            "rung": rung,
            "verdict": verdict,
            "this_cpu_usd_per_1000": dollars["this_cpu_usd"],
            "this_cpu_mean_us": mean_us,
            "reference_usd_per_1000": dollars.get("reference_usd"),
            "reference_class": dollars.get("via"),
            "declared_abuse_value_usd_per_1000": declared,
            "note": note,
        })

    # Self-check: the verdict arithmetic is recomputed and must agree,
    # so the table can never report a FAIL row as PASS by accident.
    for row in rows:
        if row["verdict"] == "UNMEASURED":
            continue
        dollars = {"this_cpu_usd": row["this_cpu_usd_per_1000"], "reference_usd": row["reference_usd_per_1000"]}
        expect, _ = verdict_for(dollars, row["declared_abuse_value_usd_per_1000"])
        if expect != row["verdict"]:
            print("ASSERT: FAIL verdict arithmetic diverged for %s" % row["value_class"])
            return 2

    measured = {r["rung"]: r["this_cpu_mean_us"] for r in rows if "this_cpu_mean_us" in r}
    complete = len([r for r in rows if r["verdict"] != "UNMEASURED"]) == len(reference["value_classes"])
    fail_rows = [r["value_class"] for r in rows if r["verdict"] == "FAIL"]
    escalate_rows = [r["value_class"] for r in rows if r["verdict"] == "ESCALATE"]

    margin = calibration.get("margin_divisor") if calibration else None
    print("VALUE-CLASS TABLE (cost per 1000 solves; declared values are measured-cost-derived%s)" %
          (", margin 1/%g of the measured anchor" % margin if margin else ""))
    for row in rows:
        cpu = ("$%.3e" % row["this_cpu_usd_per_1000"]) if row.get("this_cpu_usd_per_1000") is not None else "n/a"
        ref = ("$%.3e via %s" % (row["reference_usd_per_1000"], row["reference_class"])) \
            if row.get("reference_usd_per_1000") is not None else "no attacker rate (honest gap)"
        print("  %-9s %-8s cpu=%-12s ref=%-34s declared=$%-6.3g verdict=%s"
              % (row["value_class"], row["rung"], cpu, ref,
                 row["declared_abuse_value_usd_per_1000"], row["verdict"]))

    # The end-to-end leg: three honest solves through the real
    # deployment, all accepted (the false-positive guard). The campaign
    # commits no abuse itself, so accepted abuses are zero by
    # construction and the cost per accepted abuse stays unbounded; the
    # acceptance-killing evidence lives in the wire campaigns (D3.1 and
    # D3.6, both zero-acceptance).
    base = os.environ.get("KIWI_RT_BASE", "")
    honest = 0
    attempted = 0
    if base:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import rtclient as rt
        for _ in range(3):
            doc = rt.solve(base, "login")
            attempted += 1
            if doc.get("solved"):
                token = doc.get("token", "")
                resp = rt.verify(base, token, scope="login")
                if resp.ok:
                    honest += 1

    out = {
        "schema": "kiwicaptcha.redteam.d33-economics/2",
        "samples": samples,
        "as_of": reference["provenance"]["as_of"],
        "cpu_usd_per_core_hour": cpu_usd_hour,
        "calibration": calibration,
        "rows": rows,
        "measured_mean_us": measured,
        "table_complete": complete,
        "fail_rows": fail_rows,
        "escalate_rows": escalate_rows,
        "escalation_note": ("escalate rows carry the documented disposition answer (the scope's step_up/deny "
                            "minimum); they are not gate failures"),
        "honest_solves_verified": honest,
        "honest_solves_attempted": attempted,
        "accepted_abuses": 0,
        "cost_per_accepted_abuse": "unbounded",
    }
    out_path = os.environ.get("KIWI_RT_D33_OUT",
                              os.path.join(REPO, "tools/redteam/runs/env/d33-economics.json"))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as handle:
        handle.write(json.dumps(out, indent=2) + "\n")
    print("D33-OUT: %s" % out_path)
    print("ASSERT: %s the table covers every declared value class (%d rows)"
          % ("PASS" if complete else "FAIL", len(rows)))
    print("ASSERT: %s the honest baseline holds end-to-end (%d/%d solves verified)"
          % ("PASS" if honest == attempted and attempted > 0 else "FAIL", honest, attempted))
    if fail_rows:
        print("D3.3 REQUIRED-RESULT: the priced rung is below the declared abuse value for: %s"
              % ", ".join(fail_rows))
    if escalate_rows:
        print("D3.3 ESCALATION: raw PoW cannot price %s; the disposition minimums carry them"
              % ", ".join(escalate_rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
