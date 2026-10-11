/**
 * synth.test.mjs — the synthesis corpus contract. Offline the corpus
 * is a pure function of the seed: the same seed twice writes the same
 * bytes, and every grammar candidate carries its honest source mark.
 *
 * Run: node --test tools/redteam/engine/test/
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const SYNTH = join(ENGINE_DIR, "..", "synth.mjs");
const SCRATCH_SEED = "0x73796e74";
const corpusOf = (seed) => join(ENGINE_DIR, "..", `candidates-${seed.replace(/^0x/, "")}.json`);

describe("synth corpus", () => {
    test("offline the corpus is a pure function of the seed", () => {
        const env = { ...process.env, KIWI_RT_SEED: SCRATCH_SEED, KIWI_RT_SYNTH_COUNT: "6" };
        delete env.KIWI_RT_LOCAL_LLM_URL;
        try {
            execFileSync("node", [SYNTH], { env, encoding: "utf8" });
            const corpus = corpusOf(SCRATCH_SEED);
            assert.ok(existsSync(corpus), "synth wrote the corpus file");
            const first = readFileSync(corpus, "utf8");
            const doc = JSON.parse(first);
            assert.equal(doc.count, 6);
            for (const candidate of doc.candidates) {
                assert.equal(candidate.source, "deterministic-grammar");
            }
            execFileSync("node", [SYNTH], { env, encoding: "utf8" });
            assert.equal(readFileSync(corpus, "utf8"), first, "the corpus bytes repeat exactly");
        } finally {
            rmSync(corpusOf(SCRATCH_SEED), { force: true });
        }
    });
});
