/**
 * harness-library.mjs — the candidate-class to repro-harness mapping
 * of the triage gate. Every attack class the synthesis grammar emits
 * maps to the real, committed harness under engine/repros/ that proves
 * or refutes it against the live deployment. A class without a harness
 * maps to null and is NAMED in the triage report (never silently
 * dropped); adding a class to the grammar without adding a harness row
 * is therefore visible in every triage report.
 */

import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPROS = join(dirname(fileURLToPath(import.meta.url)), "repros");

export const HARNESS_LIBRARY_VERSION = 1;

export const HARNESS_LIBRARY = {
    "forged-token": { script: join(REPROS, "forged-token.sh"), proves: "a structurally valid token that never paid the proof of work is refused" },
    "replay": { script: join(REPROS, "replay.sh"), proves: "the one-shot consume refuses the in-TTL replay" },
    "framing-ambiguity": { script: join(REPROS, "framing-ambiguity.sh"), proves: "the framing contract refuses contradictory length framing" },
    "duplicate-key": { script: join(REPROS, "duplicate-key.sh"), proves: "duplicate JSON keys are refused on the raw document" },
    "scope-confusable": { script: join(REPROS, "scope-confusable.sh"), proves: "a case-variant scope is not the configured scope" },
    "binding-relabel": { script: join(REPROS, "binding-relabel.sh"), proves: "the binding anti-oracle burns the record on a wrong binding" },
    "record-tamper": { script: join(REPROS, "record-tamper.sh"), proves: "a flipped byte breaks the MAC and the record" },
    "epoch-manipulation": { script: join(REPROS, "epoch-manipulation.sh"), proves: "an expired record is refused after its TTL" },
    "clock-skew": { script: join(REPROS, "clock-skew.sh"), proves: "a fabricated below-floor solve duration is refused" },
    "issuance-burst": { script: join(REPROS, "issuance-burst.sh"), proves: "the burst shape yields no acceptance (the cap plane is d3.11's)" },
    "wire-differential": { script: join(REPROS, "wire-differential.sh"), proves: "two wire spellings of one document decide identically" },
    "privacy-canary": { script: join(REPROS, "privacy-canary.sh"), proves: "the canary identity is recoverable from nothing persisted" },
};

export function harnessForClass(attackClass) {
    const entry = HARNESS_LIBRARY[attackClass];
    if (!entry) return null;
    return { script: entry.script, proves: entry.proves };
}
