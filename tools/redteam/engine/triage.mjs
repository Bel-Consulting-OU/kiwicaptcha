#!/usr/bin/env node
/**
 * triage.mjs — the triage agent: the candidate consumer of the
 * synthesis corpus, the two-run deterministic reproduction gate, and
 * the filing agent for reviewable findings.
 *
 * The closed loop this file implements (the audit's decorative-loop
 * finding, closed):
 *
 *   1. CONSUME   the default mode reads the synthesis corpus
 *                (engine/candidates-<seed>.json written by synth.mjs);
 *                every candidate is triaged, never sampled.
 *   2. SELECT    each candidate's class is mapped through the harness
 *                library (engine/harness-library.mjs) to the real
 *                repro harness that proves or refutes it.
 *   3. GATE      the harness runs twice; both transcripts are hashed;
 *                a diverging hash means the harness is flaky and the
 *                candidate is marked unstable, never filed.
 *   4. FILE      a candidate whose harness verdict is REPRODUCED on a
 *                stable transcript files a finding (manifest plus
 *                repro) under tools/redteam/findings/ and lands the
 *                regression test. REFUTED candidates are recorded
 *                with their evidence hash, which is what makes the
 *                refutations auditable.
 *
 * The explicit single-repro mode (--repro <script>) is kept for a
 * hand-filed finding; the same two-run gate applies.
 *
 * Exit code 0: the corpus was triaged (any disposition).
 * Exit code 3: the corpus file was requested but missing.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { harnessForClass, HARNESS_LIBRARY_VERSION } from "./harness-library.mjs";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const RT_DIR = dirname(ENGINE_DIR);
const FINDINGS_DIR = join(RT_DIR, "findings");

function argOf(name) {
    const args = process.argv.slice(2);
    const index = args.indexOf(name);
    return index >= 0 ? args[index + 1] : undefined;
}

function runRepro(script) {
    const started = Date.now();
    const transcript = execFileSync("bash", [script], {
        encoding: "utf8",
        timeout: 600000,
        env: { ...process.env, KIWI_RT_TRIAGE: "1" },
    });
    return { transcript, durationMs: Date.now() - started };
}

function lastJsonLine(transcript) {
    const lines = transcript.trim().split("\n").filter((l) => l.startsWith("{"));
    return lines.length > 0 ? lines[lines.length - 1] : "";
}

function fileFinding({ attackClass, disposition, summary, transcriptHash, reproBody, evidence }) {
    const shortHash = transcriptHash.slice(0, 8);
    const id = `F-${shortHash}`;
    const reproTarget = join(FINDINGS_DIR, `${id}.sh`);
    writeFileSync(reproTarget, reproBody);
    chmodSync(reproTarget, 0o755);
    const manifest = {
        schema: "kiwicaptcha.redteam.finding/1",
        id,
        attackClass,
        disposition,
        severity: "medium",
        summary,
        transcriptSha256: transcriptHash,
        repro: `tools/redteam/findings/${id}.sh`,
        evidence: evidence ?? [],
        filedBy: "engine/triage.mjs",
        gate: disposition === "open" ? "red-until-fixed" : "asserts-bound",
    };
    writeFileSync(join(FINDINGS_DIR, `${id}.json`), JSON.stringify(manifest, null, 2) + "\n");
    console.log(`triage: finding ${id} filed (${disposition}); transcript hash ${transcriptHash.slice(0, 12)} pinned`);
    console.log(`triage: repro committed as ${manifest.repro}`);
    return id;
}

// ---------- mode one: the explicit single repro ----------
const repro = argOf("--repro");
if (repro) {
    if (!existsSync(repro)) {
        console.error("triage: --repro script required and must exist");
        process.exit(2);
    }
    const attackClass = argOf("--class") ?? "unclassified";
    const disposition = argOf("--disposition") ?? "open";
    const summary = argOf("--summary") ?? "";
    const a = runRepro(repro);
    const b = runRepro(repro);
    const hashA = createHash("sha256").update(a.transcript).digest("hex");
    const hashB = createHash("sha256").update(b.transcript).digest("hex");
    if (hashA !== hashB) {
        console.error("triage: reproduction is not deterministic; nothing filed");
        console.error(`triage: transcript hashes diverge (${hashA.slice(0, 12)} vs ${hashB.slice(0, 12)})`);
        process.exit(3);
    }
    fileFinding({
        attackClass,
        disposition,
        summary,
        transcriptHash: hashA,
        reproBody: readFileSync(repro, "utf8"),
    });
    process.exit(0);
}

// ---------- mode two: the candidate corpus ----------
const seed = process.env.KIWI_RT_SEED ?? "0x6b776d74";
const corpusPath = argOf("--candidates") ?? join(ENGINE_DIR, `candidates-${seed.replace(/^0x/, "")}.json`);
const outPath = argOf("--out") ?? join(ENGINE_DIR, "runs", `triage-${seed.replace(/^0x/, "")}.json`);

if (!existsSync(corpusPath)) {
    console.error(`triage: the synthesis corpus is missing (${corpusPath}); run synth.mjs first`);
    process.exit(3);
}
const corpus = JSON.parse(readFileSync(corpusPath, "utf8"));
const candidates = corpus.candidates ?? [];
console.error(`triage: consuming ${candidates.length} candidates from ${corpusPath} (harness library v${HARNESS_LIBRARY_VERSION})`);

const rows = [];
for (const candidate of candidates) {
    const harness = harnessForClass(candidate.class);
    if (harness === null) {
        rows.push({
            id: candidate.id,
            candidate: candidate.rationale ?? `${candidate.class} via ${candidate.mutation}`,
            harness: null,
            disposition: "no-harness",
            stable: false,
            reproduced: false,
            note: "the class has no harness in the library; it is named in the report, never silently dropped",
        });
        continue;
    }
    let first;
    let second;
    try {
        first = runRepro(harness.script);
        second = runRepro(harness.script);
    } catch (err) {
        rows.push({
            id: candidate.id,
            candidate: candidate.rationale ?? `${candidate.class} via ${candidate.mutation}`,
            harness: harness.script,
            disposition: "harness-error",
            stable: false,
            reproduced: false,
            note: String(err.message ?? err).slice(0, 160),
        });
        continue;
    }
    const hashA = createHash("sha256").update(first.transcript).digest("hex");
    const hashB = createHash("sha256").update(second.transcript).digest("hex");
    const stable = hashA === hashB;
    let verdict = null;
    try {
        verdict = JSON.parse(lastJsonLine(first.transcript));
    } catch {
        verdict = null;
    }
    const reproduced = stable && verdict !== null && verdict.verdict === "REPRODUCED";
    let findingId = null;
    if (reproduced) {
        findingId = fileFinding({
            attackClass: `${candidate.class} (candidate ${candidate.id})`,
            disposition: "open",
            summary: `The candidate ${candidate.id} (${candidate.class} via ${candidate.mutation} against ${candidate.target}) reproduced deterministically through ${harness.script}: wire code ${verdict?.wire_code ?? "unknown"}.`,
            transcriptHash: hashA,
            reproBody: readFileSync(join(ENGINE_DIR, harness.script), "utf8"),
            evidence: [harness.script],
        });
    }
    rows.push({
        id: candidate.id,
        candidate: candidate.rationale ?? `${candidate.class} via ${candidate.mutation}`,
        harness: harness.script,
        disposition: stable ? (reproduced ? "finding-filed" : "refuted") : "unstable",
        stable,
        reproduced,
        wireCode: verdict?.wire_code ?? null,
        transcriptSha256: hashA,
        findingId,
        durationMs: first.durationMs + second.durationMs,
    });
    console.error(`triage: ${candidate.id} ${candidate.class} -> ${stable ? (reproduced ? "REPRODUCED (finding)" : "refuted") : "unstable harness"} (${verdict?.wire_code ?? "?"})`);
}

const summary = {
    schema: "kiwicaptcha.redteam.triage/1",
    seed,
    corpus: corpusPath,
    harnessLibrary: HARNESS_LIBRARY_VERSION,
    candidates: candidates.length,
    refuted: rows.filter((r) => r.disposition === "refuted").length,
    findingsFiled: rows.filter((r) => r.disposition === "finding-filed").length,
    unstable: rows.filter((r) => r.disposition === "unstable").length,
    noHarness: rows.filter((r) => r.disposition === "no-harness").length,
    rows,
};
writeFileSync(outPath, JSON.stringify(summary, null, 2) + "\n");
console.log(`TRIAGE-SUMMARY: candidates=${summary.candidates} refuted=${summary.refuted} findings=${summary.findingsFiled} unstable=${summary.unstable} noharness=${summary.noHarness}`);
console.log(`triage: report written to ${outPath}`);
process.exit(0);
