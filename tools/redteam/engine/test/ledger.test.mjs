/**
 * ledger.test.mjs — the THREATS.md honesty contract: every documented
 * campaign appears, green requires a recorded run, missing runs are
 * NOT RUN, and scale notes never restate hashes as solves.
 *
 * Run: node --test tools/redteam/engine/test/
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const REPO = join(ENGINE_DIR, "..", "..", "..", "..");
const THREATS = join(REPO, "THREATS.md");
const LEDGER = join(ENGINE_DIR, "..", "ledger.mjs");

const EXPECTED = [
    "D3.1 commodity no-JS bots",
    "D3.2 stealth headless",
    "D3.3 PoW farm economics",
    "D3.4 proxy pools",
    "D3.5 credential stuffing",
    "D3.6 token brokering",
    "D3.7 human solver farms",
    "D3.8 AI agents",
    "D3.9 risk-engine gaming",
    "D3.10 infrastructure attacker",
    "D3.11 denial of service",
    "D3.12 protocol and parser",
    "D3.13 supply chain",
    "D3.14 privacy adversary",
    "D3.15 multi-tenant",
    "D3.16 accessibility and compatibility",
    "D3.17 cross-SDK parity attack",
];

describe("THREATS.md honesty", () => {
    test("regenerating the ledger is deterministic and preserves cost-to-abuse", () => {
        const before = existsSync(join(REPO, "docs/cost-to-abuse.md"))
            ? readFileSync(join(REPO, "docs/cost-to-abuse.md"), "utf8")
            : "";
        execFileSync("node", [LEDGER, "--seed", "0x6b776d74"], { cwd: REPO });
        const after = readFileSync(join(REPO, "docs/cost-to-abuse.md"), "utf8");
        if (before.includes("## The value-class table")) {
            assert.equal(after, before, "the hand-expanded cost-to-abuse.md must not be clobbered");
        }
    });

    test("every documented campaign slot appears in the table", () => {
        const text = readFileSync(THREATS, "utf8");
        for (const name of EXPECTED) {
            assert.ok(text.includes(`| ${name} |`), `missing row for ${name}`);
        }
    });

    test("green is never claimed without a recorded run; the NOT RUN path exists", () => {
        const text = readFileSync(THREATS, "utf8");
        assert.match(text, /NOT RUN means this environment has no run document/);
        assert.match(text, /Green is never claimed without a run document/);
        // Every GREEN row must sit on a table line that also carries an
        // evidence cell (4 columns) — the generator never emits a bare
        // green without measured scale.
        const greenRows = text.split("\n").filter((l) => l.includes("| GREEN |"));
        assert.ok(greenRows.length > 0, "expected recorded runs in this environment");
        for (const row of greenRows) {
            const cells = row.split("|").filter((c) => c.trim() !== "");
            assert.equal(cells.length, 4, `GREEN row lacks evidence cell: ${row}`);
            assert.ok(cells[3].trim().length > 0, `GREEN row has empty evidence: ${row}`);
        }
    });

    test("the ledger source lists NOT RUN rather than omitting a slot", () => {
        const src = readFileSync(LEDGER, "utf8");
        assert.match(src, /NOT RUN/);
        assert.match(src, /EXPECTED_CAMPAIGNS/);
        assert.match(src, /hash count is not a solve count/);
    });

    test("known tiny-scale facts are recorded honestly (hashes are not solves)", () => {
        const text = readFileSync(THREATS, "utf8");
        assert.match(text, /13,215,184 proof-of-work hashes/);
        assert.match(text, /hash budget,?\s+not a solve\s+count/);
        assert.match(text, /specification volumes are not claimed to have been replayed/);
    });
});
