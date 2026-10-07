/**
 * gate.test.mjs — the exit-criteria gate honesty contract, asserted
 * against the script source and a lightweight skip-mode run. The heavy
 * campaign battery is not executed here; the skip-mode run proves
 * SKIP rows never print as green and KIWI_EC_ALLOW_SKIP is consulted.
 *
 * Run: node --test tools/redteam/engine/test/
 * (the skip-mode run needs the redis target profile booted)
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const RT_DIR = join(ENGINE_DIR, "..", "..");
const REPO = join(RT_DIR, "..", "..");
const GATE = join(RT_DIR, "exit-criteria.sh");

const ALL_SKIPS = {
    KIWI_EC_SKIP_CAMPAIGNS: "1",
    KIWI_EC_SKIP_BASELINE: "1",
    KIWI_EC_SKIP_CLIENTPERF: "1",
    KIWI_EC_SKIP_TLC: "1",
    KIWI_EC_SKIP_FUZZ: "1",
    KIWI_EC_SKIP_COVERAGE_FUZZ: "1",
    KIWI_EC_SKIP_CLUSTER: "1",
    KIWI_EC_SKIP_PARITY: "1",
    KIWI_EC_SKIP_LINT: "1",
    KIWI_EC_SKIP_BUDGET: "1",
    KIWI_EC_SKIP_CONTRACT: "1",
    KIWI_EC_SKIP_REGRESSION: "1",
};

function runGate(extraEnv = {}) {
    const env = { ...process.env, ...ALL_SKIPS, ...extraEnv, KIWI_RT_PROFILE: "redis" };
    try {
        const stdout = execFileSync("bash", [GATE], {
            cwd: REPO,
            env,
            encoding: "utf8",
            timeout: 120000,
        });
        return { code: 0, stdout };
    } catch (err) {
        return { code: err.status ?? 1, stdout: `${err.stdout ?? ""}${err.stderr ?? ""}` };
    }
}

function targetUp() {
    try {
        execSync("sh tools/redteam/target.sh up redis >/dev/null 2>&1", { cwd: REPO, timeout: 60000 });
        return true;
    } catch {
        return false;
    }
}

describe("exit-criteria source contract", () => {
    const src = readFileSync(GATE, "utf8");

    test("SKIP rows remain non-green", () => {
        assert.match(src, /those rows remain non-green/);
    });

    test("record() treats every non-GREEN verdict as failing", () => {
        assert.match(src, /if \[ "\$3" != "GREEN" \]/);
    });

    test("docs-lint failure is RED and gates", () => {
        assert.match(src, /record docs-lint prose RED "docs-lint failed/);
        assert.match(src, /without enforcing the baseline/);
    });

    test("perf-budget failure is RED and gates (no downgrade label)", () => {
        assert.match(src, /record perf-budget budget RED "the perf budget FAILED/);
    });

    test("the default battery names all 17 campaigns plus coverage-fuzz, TLC and Cluster", () => {
        const expected = [
            "d3.1-commodity-nojs", "d3.2-stealth-headless", "d3.3-pow-economics",
            "d3.4-proxy-pools", "d3.5-credential-stuffing", "d3.6-token-brokering",
            "d3.7-solver-farms", "d3.8-ai-agents", "d3.9-risk-gaming",
            "d3.10-infrastructure", "d3.11-dos", "d3.12-protocol-parser",
            "d3.13-supply-chain", "d3.14-privacy", "d3.15-multi-tenant",
            "d3.16-accessibility", "d3.17-cross-sdk-parity",
        ];
        for (const name of expected) {
            assert.ok(src.includes(name), `battery missing ${name}`);
        }
        assert.match(src, /record coverage-fuzz fuzz/);
        assert.match(src, /record model-checking tla\+/);
        assert.match(src, /record b7\.2-cluster scale/);
    });

    test("missing slots print RED / MISSING, never omitted", () => {
        assert.match(src, /MISSING: not in the configured battery/);
        assert.match(src, /MISSING: no campaign script/);
    });

    test("a 9.5 clause refuses a stale artifact when its campaign did not run", () => {
        assert.match(src, /did_run_this_invocation/);
        assert.match(src, /a stale log cannot prove the 9\.5 clause/);
        assert.match(src, /a leftover economics table is not evidence/);
    });
});

describe("exit-criteria skip-mode run (needs the redis target)", () => {
    test("SKIP rows never print as green and the gate closes without ALLOW_SKIP", (t) => {
        if (!targetUp()) {
            t.skip("redis target profile could not boot");
            return;
        }
        const { code, stdout } = runGate();
        assert.equal(code, 1, "a skipped row must fail the run unless explicitly allowed");
        assert.ok(!/^\s+\S+\s+GREEN\s+skipped/m.test(stdout), "a skipped row must never print as green");
        assert.match(stdout, /skip=\d+/);
        assert.ok(!/ALL GREEN/.test(stdout), "a skip-heavy run must never print ALL GREEN");
        assert.match(stdout, /the release gate is closed/);
    });

    test("KIWI_EC_ALLOW_SKIP=1 opens the gate but the message stays honest", (t) => {
        if (!targetUp()) {
            t.skip("redis target profile could not boot");
            return;
        }
        const { code, stdout } = runGate({ KIWI_EC_ALLOW_SKIP: "1" });
        assert.equal(code, 0);
        assert.match(stdout, /gate open ONLY because KIWI_EC_ALLOW_SKIP=1/);
        assert.match(stdout, /remain non-green/);
        assert.ok(!/ALL GREEN/.test(stdout), "accepted skips must not print ALL GREEN");
    });

    test("every campaign slot has a row in the table", (t) => {
        if (!targetUp()) {
            t.skip("redis target profile could not boot");
            return;
        }
        const { stdout } = runGate({ KIWI_EC_ALLOW_SKIP: "1" });
        for (const name of [
            "d3.1-commodity-nojs", "d3.2-stealth-headless", "d3.3-pow-economics",
            "d3.4-proxy-pools", "d3.5-credential-stuffing", "d3.6-token-brokering",
            "d3.7-solver-farms", "d3.8-ai-agents", "d3.9-risk-gaming",
            "d3.10-infrastructure", "d3.11-dos", "d3.12-protocol-parser",
            "d3.13-supply-chain", "d3.14-privacy", "d3.15-multi-tenant",
            "d3.16-accessibility", "d3.17-cross-sdk-parity",
            "coverage-fuzz", "model-checking", "b7.2-cluster",
        ]) {
            assert.ok(stdout.includes(name), `missing table row for ${name}`);
        }
    });
});
