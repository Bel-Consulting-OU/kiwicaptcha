#!/usr/bin/env node
/**
 * ledger.mjs — the runs ledger aggregator and the output generator.
 *
 * Reads every run document the orchestrator wrote under
 * engine/runs/<ts>-<campaign>-seed<seed>.json, selects ONE run per
 * campaign slot under the strict evidence contract, and generates the
 * two Part 10.4 outputs:
 *
 *   THREATS.md            the living table at the repo root: attack
 *                         class, current economic result, status,
 *   docs/cost-to-abuse.md the public per-value-class cost table from
 *                         the bench reference costs and the fresh
 *                         measurement the campaigns recorded.
 *
 * The selection invariant per campaign slot: the newest run document
 * satisfying ALL of —
 *
 *   - campaign name exact (the document's campaign field, not the
 *     filename),
 *   - seed exact (the seed this ledger invocation runs under),
 *   - exit status present and 0,
 *   - verdict/result PASS,
 *   - the document parses and carries the required schema fields
 *     (including all three evidence digests), and
 *   - product_fingerprint, harness_fingerprint and
 *     campaign_fingerprint each equal the CURRENT tree's digests
 *     (engine/fingerprint.mjs, computed now),
 *
 * is that slot's evidence. A document missing any of the three digests
 * (pre-upgrade evidence) never satisfies: the slot reads stale/RED with
 * the reason, and the ledger never falls back to an older passing run
 * of a different seed or shape. A malformed or unreadable document is
 * skipped with a stderr note naming the file, is reported against its
 * slot (filename convention, best effort), and never lets selection
 * fall through to an older successful run silently: when a newer
 * refused document sits above the selected run, the row names it.
 *
 * Both files are generated: the header marks them as engine output,
 * the engine version is the seed, and regeneration is idempotent.
 */

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const RT_DIR = dirname(ENGINE_DIR);
const REPO = dirname(dirname(RT_DIR));
const RUNS_DIR = join(ENGINE_DIR, "runs");

const seedArg = process.argv.includes("--seed")
    ? process.argv[process.argv.indexOf("--seed") + 1]
    : (process.env.KIWI_RT_SEED ?? "0x6b776d74");

// ---------- the evidence digests, computed against the current tree ----------
import { productFingerprint, harnessFingerprint, campaignFingerprint } from "./fingerprint.mjs";

let currentProduct = null;
let currentHarness = null;
let digestError = null;
try {
    currentProduct = productFingerprint();
    currentHarness = harnessFingerprint();
} catch (err) {
    // Fail closed: without the current digests nothing can be fresh.
    digestError = err.message;
}
const campaignDigestCache = new Map();
function campaignDigest(campaign) {
    if (!campaignDigestCache.has(campaign)) {
        try {
            campaignDigestCache.set(campaign, { digest: campaignFingerprint(campaign) });
        } catch (err) {
            campaignDigestCache.set(campaign, { error: err.message });
        }
    }
    return campaignDigestCache.get(campaign);
}

// ---------- the runs ledger ----------
// The filename convention (write-run callers): <ts>-<campaign>-seed<seed>.json.
const RUN_DOC_NAME_RE = /^\d{8}T\d{6}Z-(.+)-seed-.+\.json$/;
// Engine bookkeeping that lives beside the run documents but is never
// one: the escalation record, the LLM-consult evidence, the triage
// reports. They are not run documents and are not named as malformed.
const BOOKKEEPING_RE = /^(escalations\.json|agent-loop-evidence\.json|triage-.*\.json)$/;

// Chronological (filename-sorted) event list per campaign slot. Parsed
// documents are attributed by their campaign field; an unreadable file
// cannot name a campaign, so its filename decides the slot it is
// reported against (best effort — the stderr note names it regardless).
const slotEvents = new Map();

for (const name of readdirSync(RUNS_DIR).filter((f) => f.endsWith(".json")).sort()) {
    if (BOOKKEEPING_RE.test(name)) continue;
    let run = null;
    try {
        run = JSON.parse(readFileSync(join(RUNS_DIR, name), "utf8"));
    } catch (err) {
        console.error(`ledger: skipping unreadable run document ${name}: ${err.message}`);
        const m = RUN_DOC_NAME_RE.exec(name);
        if (m) {
            const events = slotEvents.get(m[1]) ?? [];
            events.push({ kind: "unreadable", file: name, reason: `parse error: ${err.message}` });
            slotEvents.set(m[1], events);
        }
        continue;
    }
    if (!run || typeof run.campaign !== "string" || run.campaign === "") {
        console.error(`ledger: skipping unreadable run document ${name}: no campaign field`);
        const m = RUN_DOC_NAME_RE.exec(name);
        if (m) {
            const events = slotEvents.get(m[1]) ?? [];
            events.push({ kind: "unreadable", file: name, reason: "no campaign field" });
            slotEvents.set(m[1], events);
        }
        continue;
    }
    const events = slotEvents.get(run.campaign) ?? [];
    events.push({ kind: "doc", file: name, run });
    slotEvents.set(run.campaign, events);
}

// Every documented campaign slot (the 9.3 list). A slot without a
// recorded run is listed as NOT RUN with the reason — never omitted,
// never green.
const EXPECTED_CAMPAIGNS = [
    { campaign: "d3.1-commodity-nojs", attackClass: "D3.1 commodity no-JS bots" },
    { campaign: "d3.2-stealth-headless", attackClass: "D3.2 stealth headless" },
    { campaign: "d3.3-pow-economics", attackClass: "D3.3 PoW farm economics" },
    { campaign: "d3.4-proxy-pools", attackClass: "D3.4 proxy pools" },
    { campaign: "d3.5-credential-stuffing", attackClass: "D3.5 credential stuffing" },
    { campaign: "d3.6-token-brokering", attackClass: "D3.6 token brokering" },
    { campaign: "d3.7-solver-farms", attackClass: "D3.7 human solver farms" },
    { campaign: "d3.8-ai-agents", attackClass: "D3.8 AI agents" },
    { campaign: "d3.9-risk-gaming", attackClass: "D3.9 risk-engine gaming" },
    { campaign: "d3.10-infrastructure", attackClass: "D3.10 infrastructure attacker" },
    { campaign: "d3.11-dos", attackClass: "D3.11 denial of service" },
    { campaign: "d3.12-protocol-parser", attackClass: "D3.12 protocol and parser" },
    { campaign: "d3.13-supply-chain", attackClass: "D3.13 supply chain" },
    { campaign: "d3.14-privacy", attackClass: "D3.14 privacy adversary" },
    { campaign: "d3.15-multi-tenant", attackClass: "D3.15 multi-tenant" },
    { campaign: "d3.16-accessibility", attackClass: "D3.16 accessibility and compatibility" },
    { campaign: "d3.17-cross-sdk-parity", attackClass: "D3.17 cross-SDK parity attack" },
];

/**
 * The honest scale note: what this run actually measured, not what the
 * spec volume would have been. A hash count is never restated as a
 * solve count.
 */
function scaleNote(run) {
    const raw = run.metrics?.raw ?? "";
    const bits = [];
    if (raw) bits.push(`measured: ${raw}`);
    // The dishonest label "solves=N hashes" names a hash budget as if
    // it were solves. Call that out and restate it as hashes.
    const mislabeled = /\bsolves=(\d+)\s+hashes\b/.exec(raw);
    if (mislabeled) {
        bits.push(
            `actual scale: the figure ${mislabeled[1]} is a hash budget, not a solve count`
            + " (restated honestly; see the campaign's wire sample for the true solve n)",
        );
    }
    // Explicitly defuse the hash/solve confusion when the raw metric
    // carries both a hash budget and a solve sample.
    const hashBudget = /(?:pow_hashes|hashes)=(\d+)/.exec(raw)
        ?? (mislabeled ? null : /(\d+)\s*hashes/.exec(raw));
    const solves = /(?:wire_sample|sample|accepted)=(\d+)/.exec(raw)
        ?? (mislabeled ? null : /\bsolves=(\d+)/.exec(raw));
    if (hashBudget && solves && Number(hashBudget[1]) > Number(solves[1]) * 100) {
        bits.push(
            `actual scale: ${solves[1]} solve(s) against a hash budget of ${hashBudget[1]}`
            + " (hash count is not a solve count)",
        );
    }
    // A downscale factor is part of the evidence, not a footnote.
    const downscale = /downscale=([^\s]+)/.exec(raw);
    if (downscale) bits.push(`downscale stated: ${downscale[1]}`);
    if (run.duration_s !== undefined) bits.push(`wall ${run.duration_s}s`);
    return bits.join("; ") || "no scale metric recorded in the run document";
}

/**
 * The schema fields a run document must carry before it can be
 * evidence at all. A document missing any of the three digests is
 * pre-upgrade evidence and never satisfies — it is never backfilled.
 */
const REQUIRED_FIELDS = [
    "schema",
    "campaign",
    "seed",
    "exit",
    "result",
    "product_fingerprint",
    "harness_fingerprint",
    "campaign_fingerprint",
];

/**
 * Why the digests of this run no longer match the current tree, or
 * null when all three bind. The mismatch is named field by field so a
 * stale row says exactly which surface moved.
 */
function digestRefusal(run, campaign) {
    if (digestError !== null) {
        return `the current digests could not be computed (${digestError})`;
    }
    const missing = ["product_fingerprint", "harness_fingerprint", "campaign_fingerprint"]
        .filter((f) => typeof run[f] !== "string" || run[f] === "");
    if (missing.length > 0) {
        return `the document carries no ${missing.join(", ")} — pre-upgrade evidence predating the digest binding`;
    }
    const cd = campaignDigest(campaign);
    const mismatches = [];
    if (run.product_fingerprint !== currentProduct) {
        mismatches.push(`product_fingerprint ${run.product_fingerprint} != current ${currentProduct}`);
    }
    if (run.harness_fingerprint !== currentHarness) {
        mismatches.push(`harness_fingerprint ${run.harness_fingerprint} != current ${currentHarness}`);
    }
    if (cd.error) {
        mismatches.push(`campaign_fingerprint could not be computed: ${cd.error}`);
    } else if (run.campaign_fingerprint !== cd.digest) {
        mismatches.push(`campaign_fingerprint ${run.campaign_fingerprint} != current ${cd.digest}`);
    }
    if (mismatches.length > 0) return mismatches.join("; ");
    return null;
}

/**
 * Why this document can never be selected for the slot regardless of
 * digests: wrong campaign name, wrong seed, missing or non-zero exit,
 * non-PASS verdict, or a missing schema field.
 */
function shapeRefusal(run, campaign) {
    if (run.campaign !== campaign) return "campaign name mismatch";
    if (run.seed !== seedArg) {
        return `seed ${JSON.stringify(run.seed)} != the ledger seed ${JSON.stringify(seedArg)}`;
    }
    if (typeof run.exit !== "number" || !Number.isFinite(run.exit)) {
        return "no exit status recorded";
    }
    if (run.exit !== 0) return `exit status ${run.exit}`;
    if (run.result !== "PASS") return `result ${JSON.stringify(run.result)}`;
    const missing = REQUIRED_FIELDS.filter((f) => run[f] === undefined || run[f] === null || run[f] === "");
    if (missing.length > 0) return `missing required field(s): ${missing.join(", ")}`;
    return null;
}

function qualifies(run, campaign) {
    // Digest first: stale evidence is refused with its mismatch even
    // when the shape is also wrong.
    return digestRefusal(run, campaign) === null && shapeRefusal(run, campaign) === null;
}

/**
 * The row note when an event refuses to be evidence. Digest failures
 * read STALE with the mismatch named; shape failures read REFUSED and
 * say the ledger never falls back to an older passing run of a
 * different seed or shape.
 */
function refusalNoteOf(ev, campaign) {
    if (ev.kind === "unreadable") {
        return {
            status: "RED",
            verdict: `unreadable run document (${ev.file})`,
            evidence: `STALE: the newest run document for this slot is unreadable (${ev.file}: ${ev.reason}); it is never evidence. Re-run the campaign.`,
        };
    }
    const digest = digestRefusal(ev.run, campaign);
    if (digest !== null) {
        return {
            status: "RED",
            verdict: `stale run: ${digest}`,
            evidence: `STALE: ${digest}. Re-run the campaign against the current tree; a leftover run is never a pass.`,
        };
    }
    const shape = shapeRefusal(ev.run, campaign);
    if (shape !== null) {
        return {
            status: "RED",
            verdict: `refused run document: ${shape}`,
            evidence: `REFUSED: the newest run document does not satisfy the selection contract (${shape}); the ledger never falls back to an older passing run of a different seed or shape. Re-run the campaign.`,
        };
    }
    return null;
}

/**
 * Strict per-slot selection: the newest document satisfying the whole
 * contract (campaign, seed, exit 0, PASS, schema, all three digests
 * current). No qualifying document means the slot is not fresh; the
 * note carries the newest document's refusal (or NOT RUN). When a
 * newer refused document sits above the selected run, the refusal is
 * carried so a fall-through to the older qualifying run is never
 * silent.
 */
function selectRun(campaign) {
    const events = slotEvents.get(campaign) ?? [];
    let selected = null;
    for (const ev of events) {
        if (ev.kind === "doc" && qualifies(ev.run, campaign)) selected = ev;
    }
    const newest = events.length > 0 ? events[events.length - 1] : null;
    if (selected !== null) {
        return {
            run: selected.run,
            file: selected.file,
            note: null,
            newerRefusal: newest !== selected ? refusalNoteOf(newest, campaign) : null,
        };
    }
    const note = newest !== null
        ? refusalNoteOf(newest, campaign)
        : {
            status: "NOT RUN",
            verdict: "no recorded run under tools/redteam/engine/runs/",
            evidence: "NOT RUN: this environment has no run document for this campaign; it is not a pass",
        };
    return { run: null, file: null, note, newerRefusal: null };
}

const selections = new Map();
for (const { campaign } of EXPECTED_CAMPAIGNS) {
    selections.set(campaign, selectRun(campaign));
}

/**
 * The campaigns whose measured result claims to be the product
 * itself (method: product). For these the run document must carry
 * the product-method provenance: a `driver` naming a Kernel subclass
 * and a `container_overrides` count that is present and zero. A run
 * whose harness booted no kernel, or booted one with overrides, is a
 * fixture measurement and can never be GREEN here — the audit that
 * found the D3.5 "kernel" driver booting no kernel is the reason
 * this refusal exists.
 */
const PRODUCT_METHOD_CAMPAIGNS = new Set([
    "d3.5-credential-stuffing",
    "d3.3-pow-economics",
]);

function productMethodGap(run) {
    if (!PRODUCT_METHOD_CAMPAIGNS.has(run.campaign)) {
        return null;
    }
    const driver = run.driver ?? run.driver_class ?? null;
    const overrides = run.container_overrides;
    if (typeof driver !== "string" || driver === "" || !driver.endsWith("Kernel")) {
        return `driver is ${driver === null ? "missing" : `"${driver}"`} — not a Kernel subclass`;
    }
    if (overrides === undefined || overrides === null) {
        return "container_overrides is missing";
    }
    if (Number(overrides) !== 0) {
        return `container_overrides is ${overrides} (the product contract is 0)`;
    }

    return null;
}

function statusOf(run, campaign) {
    // Defensive fail-closed re-check: a selected run already passed
    // every check, but the tree is hashed again here so a digest that
    // changed mid-generation can never ride through as GREEN.
    const digest = digestRefusal(run, campaign);
    if (digest !== null) {
        return {
            status: "RED",
            verdict: `stale run: ${digest}`,
            evidence: `STALE: ${digest}. Re-run the campaign against the current tree; a leftover run is never a pass.`,
        };
    }
    const gap = productMethodGap(run);
    if (gap !== null) {
        return {
            status: "RED",
            verdict: `product-method provenance refused: ${gap}`,
            evidence: "METHOD: the run claims the product itself (method: product) but does not carry a Kernel-subclass driver with container_overrides=0. Re-run through the real product kernel; a fixture measurement is never a pass.",
        };
    }
    if (run.result === "PASS") {
        return { status: "GREEN", verdict: run.economic ?? "attacker uneconomic", evidence: scaleNote(run) };
    }
    return { status: "RED", verdict: run.detail ?? "see run document", evidence: scaleNote(run) };
}

/**
 * The honest footnote when the selected run is NOT the slot's newest
 * document: a newer document was refused, and the fall-through to the
 * older qualifying run is stated in the row instead of hiding.
 */
function evidenceSuffix(selection) {
    if (!selection.newerRefusal) return "";
    return ` (a newer run document was refused: ${selection.newerRefusal.verdict})`;
}

/**
 * D3.5 is one row: step-up prevention volume and compromise economics
 * are measurements of the same run, so they share one status. The row
 * is RED whenever the measured verdict is FAIL (real compromises never
 * ride into a green cell) or the run itself did not pass — a single run
 * is never reported as both GREEN and RED.
 */
function d35Row(run, suffix = "") {
    const evidence = scaleNote(run) + suffix;
    if (!run) {
        return "| D3.5 credential stuffing | no measured economics | NOT RUN | NOT RUN: no run document; not a pass |";
    }
    const gap = productMethodGap(run);
    if (gap !== null) {
        return `| D3.5 credential stuffing | product-method provenance refused: ${gap} | RED | METHOD: the run claims the product itself but carries no Kernel-subclass driver with container_overrides=0. Re-run through the real product kernel. |`;
    }
    const text = `${run.economic ?? ""} ${run.metrics?.raw ?? ""}`;
    const rate = /compromised_valid_rate=([0-9.]+)/.exec(text);
    const cost = /cost_per_compromised_account=([0-9.]+|unbounded)/.exec(text);
    const verdict = /\bverdict=(PASS|FAIL)\b/.exec(text);
    const threshold = /critical_threshold=([0-9.]+)/.exec(text);
    const rateThreshold = /rate_threshold=([0-9.]+)/.exec(text);
    const prevented = /blocked_valid_prevented=(\d+)/.exec(text);
    const numbers = `compromised_valid_rate=${rate?.[1] ?? "?"} (threshold ${rateThreshold?.[1] ?? "0.0"})`
        + ` cost_per_compromised_account=${cost?.[1] ?? "?"} (critical threshold ${threshold?.[1] ?? "?"} usd)`
        + (prevented ? ` blocked_valid_prevented=${prevented[1]}` : "");
    const green = run.result === "PASS" && verdict?.[1] === "PASS";
    return `| D3.5 credential stuffing | ${numbers} | ${green ? "GREEN" : "RED"} | ${evidence} |`;
}

const threatRows = EXPECTED_CAMPAIGNS.map(({ campaign, attackClass }) => {
    const sel = selections.get(campaign);
    if (campaign === "d3.5-credential-stuffing") {
        if (!sel.run) {
            return `| D3.5 credential stuffing | ${sel.note.verdict} | ${sel.note.status} | ${sel.note.evidence} |`;
        }
        return d35Row(sel.run, evidenceSuffix(sel));
    }
    if (!sel.run) {
        return `| ${attackClass} | ${sel.note.verdict} | ${sel.note.status} | ${sel.note.evidence} |`;
    }
    const { status, verdict, evidence } = statusOf(sel.run, campaign);
    return `| ${attackClass} | ${verdict} | ${status} | ${evidence}${evidenceSuffix(sel)} |`;
}).flat();

// The method note and the engine-loop facts (escalations and triage),
// read from the engine's own ledger documents.
// The method note is generated from the run documents themselves:
// each run records how the engine produced it (offline grammar or a
// consulted model). Nothing is hard-coded here. Only the SELECTED run
// per slot speaks: a refused document's method is not the engine's
// method.
const methodNotes = EXPECTED_CAMPAIGNS
    .map(({ campaign }) => selections.get(campaign)?.run?.method)
    .filter(Boolean);
let methodNote = methodNotes.length > 0
    ? "the engine method is recorded per run: " + [...new Set(methodNotes)].join("; ")
    : "the engine method is recorded per run (see the run documents)";
let escalationNote = "no escalation record yet";
let triageNote = "no triage report yet";
try {
    const escalations = JSON.parse(readFileSync(join(RUNS_DIR, "escalations.json"), "utf8"));
    const last = escalations.escalations.at(-1);
    if (last) {
        escalationNote = `run ${last.run}: ${last.trigger}${last.combinedLabels ? ` (combined ${last.combinedLabels.join(" + ")}, synthesis budget raised to ${last.raisedSynthCount})` : ""}`;
    }
} catch {}
try {
    const triageSeed = String(seedArg).replace(/^0x/, "");
    const triage = JSON.parse(readFileSync(join(RUNS_DIR, `triage-${triageSeed}.json`), "utf8"));
    const inconclusive = triage.inconclusive ?? 0;
    const harnessError = triage.harnessError ?? 0;
    triageNote = `the synthesis corpus was consumed end to end: ${triage.candidates} candidates triaged, ${triage.refuted} refuted deterministically (two-run hash gate), ${triage.findingsFiled} findings filed, ${triage.unstable} unstable harnesses, ${inconclusive} inconclusive, ${harnessError} harness errors, ${triage.noHarness} classes without a harness`;
} catch {}

const slotsWithDocs = EXPECTED_CAMPAIGNS.filter(({ campaign }) =>
    (slotEvents.get(campaign) ?? []).some((ev) => ev.kind === "doc")).length;
const slotsSelected = EXPECTED_CAMPAIGNS.filter(({ campaign }) => selections.get(campaign)?.run).length;

const threats = `# THREATS

The living output of the automated red-team engine (change.md Part 10).
Generated from the runs ledger by \`tools/redteam/engine/ledger.mjs\`;
regenerate with the orchestrator. Status GREEN means a real recorded
run of the campaign's required result held while binding the CURRENT
product, harness and campaign digests (engine/fingerprint.mjs), RED
means it did not, NOT RUN means this environment has no run document
for the campaign (that is not a pass and is never omitted from this
table).

Seed: \`${seedArg}\` · Campaign slots: ${EXPECTED_CAMPAIGNS.length} ·
Recorded runs: ${slotsWithDocs} · Satisfying the current seed and
digest contract: ${slotsSelected}

## Method note

${methodNote}

The self-escalation mandate: ${escalationNote}

The closed synthesis loop: ${triageNote}

| Attack class | Current economic result | Status | Evidence (actual measured scale) |
| --- | --- | --- | --- |
${threatRows.join("\n")}

## The bounds the engine holds itself to

- Every campaign states its environment downscale openly; the evidence
  column records the scale that actually ran, and a hash budget is
  never restated as a solve count.
- A campaign without a recorded run is listed NOT RUN with its reason.
  Green is never claimed without a run document.
- Evidence is bound to three digests recorded at run time (product,
  harness, campaign). A run whose digests do not match the current
  tree is STALE, never a pass — a campaign or harness edit invalidates
  old PASS evidence exactly as a product edit does — and the ledger
  never falls back to an older passing run of a different seed or
  shape. A document that predates the digest binding never satisfies.
- Known tiny-scale facts from the recorded evidence, stated honestly
  (transcribed from the run documents and runs/env/gate logs, not
  invented): the D3.5 wire sample paid 13,215,184 proof-of-work hashes
  for 200 wire solves (that figure is a hash budget, not a solve
  count) while the engine loop decided 100,000 leaked-list rows; D3.2
  solved 25 challenges (a 4000x downscale of one farm-day); D3.4
  walked 10,000 pool addresses over 66 wire requests (100x downscale).
  The specification volumes are not claimed to have been replayed.
- Every finding is reproduced deterministically before it gates.
- Every committed repro is a reviewable test under tools/redteam/findings/.
- The engine targets loopback and private addresses only.
`;

writeFileSync(join(REPO, "THREATS.md"), threats);

// ---------- the cost-to-abuse table ----------
// The expanded hand-maintained cost-to-abuse.md (value-class table,
// rental provenance, the rsw measurement gap) is preserved: the
// generator only writes this file when it is missing or still in the
// narrow generated shape. A rich document is never clobbered.
const costPath = join(REPO, "docs/cost-to-abuse.md");
let existingCost = "";
try {
    existingCost = readFileSync(costPath, "utf8");
} catch {}
const costIsRich = existingCost.includes("## The value-class table");
if (costIsRich) {
    console.log("ledger: docs/cost-to-abuse.md is hand-expanded; leaving it untouched");
} else {
    let reference = {};
    try {
        const raw = JSON.parse(readFileSync(
            join(REPO, "packages/kiwicaptcha-solver/reference-costs.json"), "utf8"));
        reference = raw;
    } catch {
        // without the reference table the doc degrades to the measured row
    }
    const asOf = reference.provenance?.as_of ?? "unrecorded";
    const rateRows = (reference.attacker_rates ?? [])
        .map((rate) => `| ${rate.hardware_class} | ${rate.hashes_per_second.toExponential(1)} hashes/s | sha256 | ${rate.id} |`);

    const measured = EXPECTED_CAMPAIGNS
        .map(({ campaign }) => selections.get(campaign)?.run)
        .filter(Boolean)
        .map((run) => run.metrics?.sha16_solve_us)
        .filter((v) => typeof v === "number" && v > 0);
    const sha16Us = measured.at(-1);

    const solveCostRows = [];
    if (sha16Us) {
        solveCostRows.push(
            `| sha16 (browser rung) | ${Math.round(sha16Us).toLocaleString("en-US")} us per solve (measured on the campaign bench) | native sha256, single core |`,
        );
    }
    solveCostRows.push(
        "| sha18 | 4x the sha16 row (2^18 / 2^16 = 4) | native sha256, single core |",
        "| sha20 | ~16x the sha16 row | native sha256, single core |",
        "| argon16..64 | memory-hard; see the bench's own table | native argon2id, single core |",
        "| rsw | inherently sequential; no hardware class buys a parallel speedup | time-lock squaring |",
    );

    const costDoc = `# Cost to abuse

The public per-value-class table (change.md Part 10.4): what an
attacker pays per successful abuse per value class, measured and
published rather than asserted. Generated by the red-team engine's
ledger from the bench reference costs and the campaigns' fresh
measurements on the release machine.

Reference class provenance: ${reference.provenance?.statement ?? "see reference-costs.json"}
(as of ${asOf}; refreshed by hand, stale entries replaced).

## Hardware classes the attacker rents

| Hardware class | Advertised rate | Algorithm | Class id |
| --- | --- | --- | --- |
${rateRows.join("\n")}

## What one solve costs an attacker here

| Ladder rung | Measured cost | Note |
| --- | --- | --- |
${solveCostRows.join("\n")}

## Reading the table

The campaigns report cost per ACCEPTED abuse. A green campaign in
THREATS.md means the recorded run's required result held at the
scale its evidence column states — not that every volume of the
specification was replayed. Where the recorded run accepted zero
abuses the attacker's cost per successful abuse is unbounded there:
the spend is real (the bench prices every solve) and the yield is
zero. Where a run measured a non-zero yield (for example a
documented residual), the economic line carries that count and the
scale honestly. The engine's economic lines carry the measured spend
per honest solve; the bench's own verdict per value class
(packages/kiwicaptcha-solver bench) prices each scope's abuse value
against these rates.

${reference.provenance?.honesty ?? ""}
`;

    writeFileSync(costPath, costDoc);
}

console.log(`ledger: ${EXPECTED_CAMPAIGNS.length} campaign slots aggregated`
    + ` (${slotsWithDocs} with recorded runs, ${slotsSelected} satisfying the current seed and digest contract);`
    + " THREATS.md generated");
