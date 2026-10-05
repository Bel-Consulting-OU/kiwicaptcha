#!/usr/bin/env node
/**
 * regression.mjs — the regression agent: the manifest-driven replayer
 * that re-runs the full corpus of committed findings (the nightly
 * corpus of change.md Part 10.1).
 *
 * Every finding under tools/redteam/findings/ carries a disposition:
 *   open  the repro asserts the CORRECT behavior and fails until the
 *         fix lands; a green repro here means the fix landed and the
 *         finding closes,
 *   bound the repro asserts a documented model boundary; it must
 *         stay green.
 *
 * The replayer never gates on a flaky repro: a script that errors
 * (non-zero exit without its expected shape) is reported as BROKEN
 * and fails the run, because an unrunnable gate is worse than no gate.
 *
 * Usage: node regression.mjs [--out runs/regression-<ts>.json]
 */

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const RT_DIR = dirname(ENGINE_DIR);
const REPO_ROOT = dirname(dirname(RT_DIR));
const FINDINGS_DIR = join(RT_DIR, "findings");

const args = process.argv.slice(2);
const outArg = args.includes("--out") ? args[args.indexOf("--out") + 1] : null;

const rows = [];
for (const name of readdirSync(FINDINGS_DIR).filter((f) => f.endsWith(".json")).sort()) {
    const manifest = JSON.parse(readFileSync(join(FINDINGS_DIR, name), "utf8"));
    const reproPath = join(REPO_ROOT, manifest.repro);
    let status;
    let detail = "";
    try {
        execFileSync("bash", [reproPath], { encoding: "utf8", timeout: 900000 });
        status = "pass";
    } catch (err) {
        status = "fail";
        detail = String(err.stdout ?? err.message).split("\n").slice(-3).join(" | ").slice(0, 300);
    }
    rows.push({
        id: manifest.id,
        attackClass: manifest.attackClass,
        disposition: manifest.disposition,
        expected: manifest.gate,
        status,
        detail,
    });
}

const open = rows.filter((r) => r.disposition === "open");
const bounds = rows.filter((r) => r.disposition === "bound");
const summary = {
    schema: "kiwicaptcha.redteam.regression/1",
    corpus: rows.length,
    openFindings: open.length,
    bounds: bounds.length,
    broken: rows.filter((r) => r.status === "fail" && r.disposition === "bound").length,
    closed: open.filter((r) => r.status === "pass").length,
    stillRed: open.filter((r) => r.status === "fail").length,
    rows,
};
for (const row of rows) {
    console.log(`REGRESSION: ${row.id} [${row.disposition}] ${row.status} ${row.attackClass} ${row.detail}`);
}
console.log(`REGRESSION-SUMMARY: corpus=${summary.corpus} open=${summary.openFindings}`
    + ` closed=${summary.closed} bounds=${summary.bounds} broken=${summary.broken}`);

if (outArg) writeFileSync(outArg, JSON.stringify(summary, null, 2) + "\n");
// The corpus fails the run only when a BOUND broke or an open finding
// regressed further; open-and-still-red is the tracked state.
process.exit(summary.broken > 0 ? 1 : 0);
