/**
 * orchestrator.test.mjs — the hybrid-mode contract of the Part 10
 * controller: the argument parser refuses bad modes before anything
 * runs, hybrid implies the up-front synthesis cycle, and every
 * campaign is followed by a synth-then-triage cycle whose findings
 * are filed by triage itself. The battery is not run here;
 * exit-criteria.sh owns that measurement.
 *
 * Run: node --test tools/redteam/engine/test/
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const ORCHESTRATOR = join(ENGINE_DIR, "..", "orchestrator.sh");

function runOrchestrator(args) {
    try {
        execFileSync("bash", [ORCHESTRATOR, ...args], { encoding: "utf8", timeout: 30000 });
        return 0;
    } catch (err) {
        return err.status ?? 1;
    }
}

describe("orchestrator modes", () => {
    const src = readFileSync(ORCHESTRATOR, "utf8");

    test("bad modes and unknown arguments are refused before anything runs", () => {
        assert.equal(runOrchestrator(["--mode", "bogus"]), 2);
        assert.equal(runOrchestrator(["--mode=bogus"]), 2);
        assert.equal(runOrchestrator(["--mode"]), 2);
        assert.equal(runOrchestrator(["--nonsense"]), 2);
    });

    test("hybrid mode implies the up-front synthesis cycle", () => {
        assert.match(src, /if \[ "\$MODE" = hybrid \]; then\n    SYNTH_REQUESTED=1/);
    });

    test("hybrid runs a synthesis cycle after each campaign through the triage gate", () => {
        assert.match(src, /hybrid cycle for \$campaign/);
        assert.match(src, /KIWI_RT_HYBRID_SYNTH_COUNT/);
        const cycleStart = src.indexOf("the hybrid cycle");
        const cycleEnd = src.indexOf("hybrid summary");
        assert.ok(cycleStart > 0 && cycleEnd > cycleStart, "the hybrid cycle block exists");
        const cycle = src.slice(cycleStart, cycleEnd);
        const synthAt = cycle.indexOf("engine/synth.mjs");
        const triageAt = cycle.indexOf("engine/triage.mjs");
        assert.ok(synthAt > 0, "the cycle synthesizes");
        assert.ok(triageAt > synthAt, "triage consumes the corpus after synthesis");
    });

    test("the cycle seed is derived from the run seed and the campaign name", () => {
        assert.match(src, /seed \^ label/);
    });

    test("hybrid findings are counted and triage files them under findings/", () => {
        assert.match(src, /HYBRID_FINDINGS/);
        assert.match(src, /tools\/redteam\/findings\//);
    });
});
