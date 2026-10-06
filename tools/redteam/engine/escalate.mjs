#!/usr/bin/env node
/**
 * escalate.mjs — the self-escalation mandate of the engine (change.md
 * 10.2), implemented and provable from the runs ledger.
 *
 * When a run's battery and triage produced no new finding, the next
 * run's synthesis MUST escalate: two prior technique labels are
 * combined (seeded, reproducible) and the synthesis budget knob is
 * raised. This module reads the ledger, decides, and writes the
 * escalation document the orchestrator and synth.mjs consume; the
 * document carries the run number, the combined labels and the raised
 * knob, so "the loop escalates" is a fact a reader can check in
 * engine/runs/escalations.json.
 */

import { readdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HARNESS_LIBRARY } from "./harness-library.mjs";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const RUNS_DIR = join(ENGINE_DIR, "runs");
const LEDGER_PATH = join(RUNS_DIR, "escalations.json");

const seedText = process.env.KIWI_RT_SEED ?? "0x6b776d74";
const seed = Number(seedText) >>> 0 || 1;

function lcg(state) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return [state, state];
}

const labels = Object.keys(HARNESS_LIBRARY);

// The prior run history: latest run per campaign from the ledger docs.
const byCampaign = new Map();
if (existsSync(RUNS_DIR)) {
    for (const name of readdirSync(RUNS_DIR).filter((f) => f.endsWith(".json")).sort()) {
        if (name.startsWith("triage") || name.startsWith("escalation")) continue;
        try {
            const run = JSON.parse(readFileSync(join(RUNS_DIR, name), "utf8"));
            if (run.campaign) byCampaign.set(run.campaign, run);
        } catch {}
    }
}
const latest = [...byCampaign.values()];
const greenRuns = latest.filter((r) => r.result === "PASS").length;
const redRuns = latest.filter((r) => r.result === "FAIL").length;
const triageDoc = existsSync(join(RUNS_DIR, `triage-${seedText.replace(/^0x/, "")}.json`))
    ? JSON.parse(readFileSync(join(RUNS_DIR, `triage-${seedText.replace(/^0x/, "")}.json`), "utf8"))
    : null;
const findingsThisRun = triageDoc?.findingsFiled ?? 0;

let ledger = { schema: "kiwicaptcha.redteam.escalations/1", escalations: [] };
if (existsSync(LEDGER_PATH)) {
    try { ledger = JSON.parse(readFileSync(LEDGER_PATH, "utf8")); } catch {}
}

const runNumber = (ledger.escalations.at(-1)?.run ?? 0) + 1;
let state = (seed ^ runNumber) >>> 0 || 1;
[state, state] = lcg(state);
const labelA = labels[state % labels.length];
[state, state] = lcg(state);
const labelB = labels[(state + runNumber) % labels.length];

const priorKnob = ledger.escalations.at(-1)?.raisedSynthCount ?? 24;
const raisedSynthCount = Math.min(512, Math.round(priorKnob * 1.25));
const escalated = findingsThisRun === 0;

const entry = {
    run: runNumber,
    decidedAt: new Date().toISOString().slice(0, 19) + "Z",
    trigger: escalated
        ? "no new finding this run: the synthesis escalates"
        : `a finding was filed this run (${findingsThisRun}); the corpus holds and no escalation is due`,
    combinedLabels: escalated ? [labelA, labelB] : null,
    priorSynthCount: priorKnob,
    raisedSynthCount: escalated ? raisedSynthCount : priorKnob,
    ledgerFacts: { greenRuns, redRuns, campaignsInLedger: latest.length },
};
if (escalated) {
    ledger.escalations.push(entry);
} else {
    ledger.escalations.push(entry);
}
writeFileSync(LEDGER_PATH, JSON.stringify(ledger, null, 2) + "\n");

console.log(`ESCALATION: run=${entry.run} escalated=${escalated ? "yes" : "no"} labels=${entry.combinedLabels ? entry.combinedLabels.join("+") : "-"} synth_count=${entry.raisedSynthCount}`);
if (escalated) {
    process.env.KIWI_RT_SYNTH_COMBINE = entry.combinedLabels.join("+");
    process.env.KIWI_RT_SYNTH_COUNT = String(entry.raisedSynthCount);
    console.log(`escalation: exporting KIWI_RT_SYNTH_COMBINE=${process.env.KIWI_RT_SYNTH_COMBINE} KIWI_RT_SYNTH_COUNT=${process.env.KIWI_RT_SYNTH_COUNT}`);
    console.log(`escalation: ledger updated at ${LEDGER_PATH}`);
}
process.exit(0);
