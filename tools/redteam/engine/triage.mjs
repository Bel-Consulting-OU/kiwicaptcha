#!/usr/bin/env node
/**
 * triage.mjs — the triage agent: reproduce, minimize, and file a
 * finding as a reviewable regression test.
 *
 * Guardrails enforced here (change.md Part 10.3):
 *   - deterministic reproduction: the repro script runs twice and the
 *     sha256 of both transcripts must match; a flaky repro never
 *     files a finding and never gates,
 *   - reviewable artifacts: every finding lands under
 *     tools/redteam/findings/ as a pair (JSON manifest plus an
 *     executable repro script); nothing runs that isn't committed,
 *   - hash pinning: the finding id and the gate decision carry the
 *     transcript hash, so a release gate can re-verify the exact
 *     repro.
 *
 * Usage:
 *   node triage.mjs --repro <script.sh> --class <class> --disposition open|bound \
 *        --summary "text" [--evidence file]...
 *
 * Exit code 0: a finding was filed (open) or a bound was recorded.
 * Exit code 3: reproduction was not deterministic (nothing filed).
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const FINDINGS_DIR = join(dirname(ENGINE_DIR), "findings");

function argOf(name) {
    const args = process.argv.slice(2);
    const index = args.indexOf(name);
    return index >= 0 ? args[index + 1] : undefined;
}

function runRepro(script) {
    return execFileSync("bash", [script], {
        encoding: "utf8",
        timeout: 600000,
        env: { ...process.env, KIWI_RT_TRIAGE: "1" },
    });
}

const repro = argOf("--repro");
const attackClass = argOf("--class") ?? "unclassified";
const disposition = argOf("--disposition") ?? "open";
const summary = argOf("--summary") ?? "";
if (!repro || !existsSync(repro)) {
    console.error("triage: --repro script required and must exist");
    process.exit(2);
}

// Deterministic reproduction: two runs, one transcript hash.
const transcriptA = runRepro(repro);
const transcriptB = runRepro(repro);
const hashA = createHash("sha256").update(transcriptA).digest("hex");
const hashB = createHash("sha256").update(transcriptB).digest("hex");
if (hashA !== hashB) {
    console.error("triage: reproduction is not deterministic; nothing filed");
    console.error(`triage: transcript hashes diverge (${hashA.slice(0, 12)} vs ${hashB.slice(0, 12)})`);
    process.exit(3);
}

const shortHash = hashA.slice(0, 8);
const id = `F-${shortHash}`;
const reproTarget = join(FINDINGS_DIR, `${id}.sh`);

// The committed repro is the finding: reviewable, runnable, and the
// regression replayer's nightly input.
const reproBody = readFileSync(repro, "utf8");
writeFileSync(reproTarget, reproBody);
chmodSync(reproTarget, 0o755);

const manifest = {
    schema: "kiwicaptcha.redteam.finding/1",
    id,
    attackClass,
    disposition,
    summary,
    transcriptSha256: hashA,
    repro: `tools/redteam/findings/${id}.sh`,
    evidence: (process.argv.filter((a) => a === "--evidence").length > 0
        ? process.argv.flatMap((a, i) => (a === "--evidence" ? [process.argv[i + 1]] : []))
        : []),
    filedBy: "engine/triage.mjs",
    // A failing-first gate: disposition open means the repro asserts
    // the CORRECT behavior and currently fails (the weakness is
    // live); disposition bound means the documented model boundary
    // holds and the repro asserts the boundary.
    gate: disposition === "open" ? "red-until-fixed" : "asserts-bound",
};
writeFileSync(join(FINDINGS_DIR, `${id}.json`), JSON.stringify(manifest, null, 2) + "\n");

console.log(`triage: finding ${id} filed (${disposition}); transcript hash ${hashA.slice(0, 12)} pinned`);
console.log(`triage: repro committed as ${manifest.repro}`);
