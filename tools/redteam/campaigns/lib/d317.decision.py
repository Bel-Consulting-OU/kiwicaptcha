#!/usr/bin/env python3
"""d317.decision.py — the decision and token authority rows of D3.17.

The shared register protocol/decision-v1/corpus.json is the authority.
This driver replays every row through two independent SDK
implementations (Python and Node) with their public decision surfaces,
so a drift between the register and either implementation fails the
campaign before any per-SDK suite runs. The per-SDK corpus suites in
the campaign cover the remaining five SDKs.

Output: ASSERT lines on stdout and a process status of 0 only when
both direct drives agree with the register.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(os.environ.get("KIWI_RT_REPO_ROOT", ".")).resolve()
CORPUS = REPO / "protocol" / "decision-v1" / "corpus.json"


def fail(message: str) -> None:
    print(f"ASSERT: FAIL d3.17 decision {message}")


def python_drive(corpus: dict) -> int:
    sys.path.insert(0, str(REPO / "packages" / "kiwicaptcha-python-sdk"))
    from kiwicaptcha.decision import VerifyDecision, _RETRY_CODES
    from kiwicaptcha.errors import VerifyError, VerifyOutcome
    from kiwicaptcha.middleware import _status_for_disposition, resolve_token_values

    failures = 0
    for code, disposition in corpus["codes"].items():
        try:
            decision = VerifyDecision.from_outcome(VerifyOutcome.invalid(VerifyError(code)))
        except ValueError as error:
            fail(f"python does not know {code}: {error}")
            failures += 1
            continue
        if decision.disposition != disposition:
            fail(f"python {code}: {decision.disposition} != {disposition}")
            failures += 1
    if sorted(corpus["retry_codes"]) != sorted(_RETRY_CODES):
        fail(f"python retry table {sorted(_RETRY_CODES)} != {sorted(corpus['retry_codes'])}")
        failures += 1
    if _status_for_disposition("retry") != corpus["http"]["retry_status"]:
        fail("python retry status row diverges")
        failures += 1
    if _status_for_disposition("deny") != corpus["http"]["deny_status"]["python"]:
        fail("python deny status row diverges")
        failures += 1
    for row in corpus["authority"]["matrix"]:
        token, failure = resolve_token_values(row["header"], row["form"], row["query"])
        verdict = "conflict" if failure == "token_source_conflict" else (
            "missing" if failure == "malformed_token" else "verify"
        )
        if verdict != row["verdict"]:
            fail(f"python authority {row['case']}: {verdict} != {row['verdict']}")
            failures += 1
        elif verdict == "verify" and token != row["token"]:
            fail(f"python authority {row['case']}: token {token} != {row['token']}")
            failures += 1
    print(
        "ASSERT: PASS d3.17 decision python direct drive "
        f"({len(corpus['codes'])} codes, {len(corpus['authority']['matrix'])} authority rows)"
    )
    return failures


NODE_DRIVE = r"""
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const repo = process.env.KIWI_RT_REPO_ROOT;
const require_ = createRequire(`${repo}/packages/kiwicaptcha-node/package.json`);
const sdk = require_("@kiwicaptcha/node");
const corpus = JSON.parse(readFileSync(`${repo}/protocol/decision-v1/corpus.json`, "utf8"));
let failures = 0;
for (const [code, want] of Object.entries(corpus.codes)) {
    const got = sdk.dispositionForCode(code);
    if (got !== want) {
        console.log(`ASSERT: FAIL d3.17 decision node ${code}: ${got} != ${want}`);
        failures += 1;
    }
    const result = sdk.invalidResult(code);
    if (result.disposition !== want) {
        console.log(`ASSERT: FAIL d3.17 decision node result ${code}: ${result.disposition} != ${want}`);
        failures += 1;
    }
}
const retry = [...sdk.RETRY_ERROR_CODES].sort();
const registered = [...corpus.retry_codes].sort();
if (JSON.stringify(retry) !== JSON.stringify(registered)) {
    console.log(`ASSERT: FAIL d3.17 decision node retry table ${retry} != ${registered}`);
    failures += 1;
}
for (const row of corpus.authority.matrix) {
    const resolution = sdk.resolveTokenValues({
        header: row.header, form: row.form, query: row.query,
    });
    const verdict = resolution.code === "token_source_conflict" ? "conflict"
        : resolution.code === "malformed_token" ? "missing" : "verify";
    if (verdict !== row.verdict) {
        console.log(`ASSERT: FAIL d3.17 decision node authority ${row.case}: ${verdict} != ${row.verdict}`);
        failures += 1;
    } else if (verdict === "verify" && resolution.token !== row.token) {
        console.log(`ASSERT: FAIL d3.17 decision node authority ${row.case}: token ${resolution.token} != ${row.token}`);
        failures += 1;
    }
}
if (failures === 0) {
    console.log(`ASSERT: PASS d3.17 decision node direct drive (${Object.keys(corpus.codes).length} codes, ${corpus.authority.matrix.length} authority rows)`);
}
process.exit(failures === 0 ? 0 : 1);
"""


def node_drive() -> int:
    node_dir = REPO / "packages" / "kiwicaptcha-node"
    build = subprocess.run(
        ["npm", "run", "build"],
        cwd=node_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if build.returncode != 0:
        print("ASSERT: FAIL d3.17 decision node build")
        if build.stderr:
            print(build.stderr)
        return 1
    env = dict(os.environ, KIWI_RT_REPO_ROOT=str(REPO))
    run = subprocess.run(
        ["node", "--input-type=module", "-e", NODE_DRIVE],
        cwd=node_dir,
        env=env,
        text=True,
    )
    return 0 if run.returncode == 0 else 1


def main() -> int:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    failures = python_drive(corpus)
    failures += node_drive()
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
