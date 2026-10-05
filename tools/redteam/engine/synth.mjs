#!/usr/bin/env node
/**
 * synth.mjs — the exploit-synthesis agent, deterministic offline
 * implementation with the local-model adapter behind an interface.
 *
 * The grammar: an attack class (from the recon surface map) crossed
 * with a mutation operator and a target endpoint. A seeded LCG walks
 * the cross product exactly as the php and rust fuzz corpora do, so
 * a run with seed S always produces the same candidate list; the
 * candidates are written to engine/candidates-<seed>.json for the
 * triage gate.
 *
 * Offline determinism: without KIWI_RT_LOCAL_LLM_URL no model is
 * consulted and the candidate list is a pure function of the seed.
 * With it (operator-provided, private-range only, temperature 0,
 * pinned prompt), the adapter's completion may ADD candidates; its
 * text is never executed, it is parsed as candidate descriptions and
 * everything still passes through triage before it can gate.
 *
 * Budget knobs: KIWI_RT_SYNTH_COUNT (default 24 candidates),
 * KIWI_RT_SEED (default 0x6b776d74).
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { optionalCompletion } from "./model-adapter.mjs";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));

/** The 31-bit LCG discipline the php fuzz corpus pins. */
class Lcg {
    constructor(seed) {
        this.state = seed >>> 0 || 1;
    }

    next() {
        this.state = (this.state * 1103515245 + 12345) & 0x7fffffff;
        return this.state;
    }

    pick(list) {
        return list[this.next() % list.length];
    }
}

const CLASSES = [
    "forged-token",
    "replay",
    "framing-ambiguity",
    "duplicate-key",
    "scope-confusable",
    "binding-relabel",
    "record-tamper",
    "epoch-manipulation",
    "clock-skew",
    "issuance-burst",
    "wire-differential",
    "privacy-canary",
];

const MUTATIONS = [
    "byte-flip",
    "mac-strip",
    "mac-transplant",
    "truncation",
    "overlong-encoding",
    "field-swap",
    "duplicate-field",
    "length-confusion",
    "case-fold-probe",
    "separation-injection",
];

const SOURCES = [
    "engine/surface-map.json",
    "protocol/limits.json",
    "protocol/solution-token-v1/fixtures.json",
    "protocol/risk-v1/target-vectors.json",
];

const seed = Number(process.env.KIWI_RT_SEED ?? "0x6b776d74");
const count = Number(process.env.KIWI_RT_SYNTH_COUNT ?? "24");

const surface = JSON.parse(readFileSync(join(ENGINE_DIR, "surface-map.json"), "utf8"));
const targets = surface.endpoints.map((e) => `${e.surface}${e.route}`);
if (targets.length === 0) {
    console.error("synth: surface map has no endpoints; run recon.mjs first");
    process.exit(2);
}

const rng = new Lcg(seed);
const candidates = [];
for (let i = 0; i < count; i++) {
    const attackClass = rng.pick(CLASSES);
    const mutation = rng.pick(MUTATIONS);
    const target = rng.pick(targets);
    const source = rng.pick(SOURCES);
    candidates.push({
        id: `C-${(i + 1).toString().padStart(3, "0")}`,
        seed: rng.next(),
        class: attackClass,
        mutation,
        target,
        corpus: source,
        rationale: `${attackClass} via ${mutation} against ${target}, corpus ${source}`,
        source: "deterministic-grammar",
        expected: "rejected-or-refused",
    });
}

// The local-model adapter: consulted only when an operator points the
// engine at their own runtime; candidates parsed from its text are
// marked with their source and still go through triage.
let modelNote = "offline mode: no local model consulted";
try {
    const completion = await optionalCompletion({ seed });
    if (completion.consulted) {
        const lines = completion.text.split("\n").filter((line) => line.startsWith("CANDIDATE:"));
        for (const [index, line] of lines.entries()) {
            const [cls, mut, target] = line.slice("CANDIDATE:".length).trim().split("|");
            if (cls && mut && target) {
                candidates.push({
                    id: `M-${(index + 1).toString().padStart(3, "0")}`,
                    class: cls.trim(),
                    mutation: mut.trim(),
                    target: target.trim(),
                    source: "local-model",
                    expected: "rejected-or-refused",
                });
            }
        }
        modelNote = `local model consulted: ${lines.length} candidates parsed from completion`;
    }
} catch (err) {
    modelNote = `local model refused: ${err.message}`;
}

const out = {
    schema: "kiwicaptcha.redteam.candidates/1",
    seed,
    count: candidates.length,
    modelNote,
    candidates,
};
const outPath = join(ENGINE_DIR, `candidates-${seed.toString(16)}.json`);
writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
console.log(`synth: ${candidates.length} candidates (seed ${seed.toString(16)}); ${modelNote}`);
console.log(`synth: candidates written to ${outPath}`);
