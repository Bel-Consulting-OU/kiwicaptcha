/**
 * ledger-chronology.test.mjs — the selection post-scan walks the
 * chronological event list in the right direction: only run documents
 * NEWER than the selected PASS may bury it (a same-seed current-digest
 * FAIL above the selection makes the row RED) or be disclosed in the
 * refused-documents footnote, and the selection's own history below it
 * is never mistaken for newer evidence. A FAIL behind an older PASS
 * must not bury a green run, and a FAIL above one must never be
 * silently dropped.
 *
 * Every scenario drives the real ledger end to end: the fixture
 * mirrors the layout the ledger and the fingerprint module derive from
 * their own location (engine/ at <root>/tools/redteam/engine, the repo
 * root above it), so the copies read and write only a throwaway tree —
 * ledger.mjs, fingerprint.mjs and the run writer are copied in, the
 * fixture campaign script is committed to a scratch git repo so the
 * three evidence digests can be computed, and the documents are
 * written by write-run.mjs, the same writer the orchestrator invokes.
 * The ledger's public API is the runs directory in, THREATS.md out:
 * the assertions read the generated table row.
 *
 * Run: node --test tools/redteam/engine/test/
 */
import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const REAL_ENGINE = dirname(TEST_DIR);
const LEDGER = join(REAL_ENGINE, "ledger.mjs");
const FINGERPRINT = join(REAL_ENGINE, "fingerprint.mjs");
const WRITER = join(REAL_ENGINE, "write-run.mjs");

const SEED = "0x6b776d74";
const CAMPAIGN = "d3.1-commodity-nojs";
const CLASS = "D3.1 commodity no-JS bots";
// The disclosed-refusal footnote the evidence suffix opens with; a
// scenario without newer refused documents must not carry it.
const FOOTNOTE = "(refused or failed run documents sit above the selected run:";
// The ledger's profile resolution (KIWI_RT_PROFILE or redis) pinned so
// the synthetic documents and the ledger agree on the deployment shape.
const ENV = { ...process.env, KIWI_RT_PROFILE: "redis" };

/**
 * The throwaway evidence tree. The copies resolve their runs dir and
 * repo root from their own location, so they bind to the temp tree and
 * never touch the real engine's runs or THREATS.md. The digests hash
 * the git-tracked state only, so the fixture tree is committed once
 * and the documents written afterwards (untracked) never change them.
 */
function buildFixture() {
    // realpathSync: on macOS tmpdir() is a symlinked path (/var/folders
    // -> /private/var/folders) while Node realpaths the copied writer's
    // module URL, and the writer refuses a document path whose resolved
    // prefix disagrees with its own runs dir.
    const root = mkdtempSync(join(realpathSync(tmpdir()), "kiwi-ledger-chronology-"));
    const engine = join(root, "tools", "redteam", "engine");
    const campaigns = join(root, "tools", "redteam", "campaigns");
    const runs = join(engine, "runs");
    mkdirSync(runs, { recursive: true });
    mkdirSync(campaigns, { recursive: true });
    // The ledger writes docs/cost-to-abuse.md under its repo root when
    // the file is not hand-expanded; mirror the real layout so the
    // write lands.
    mkdirSync(join(root, "docs"), { recursive: true });
    // The campaign digest fails closed without a script at
    // tools/redteam/campaigns/<name>.sh; a minimal one is enough.
    writeFileSync(join(campaigns, `${CAMPAIGN}.sh`), `# ${CLASS} — ledger chronology fixture\nexit 0\n`);
    copyFileSync(LEDGER, join(engine, "ledger.mjs"));
    copyFileSync(FINGERPRINT, join(engine, "fingerprint.mjs"));
    copyFileSync(WRITER, join(engine, "write-run.mjs"));
    execFileSync("git", ["init", "-q"], { cwd: root, stdio: "pipe" });
    execFileSync("git", ["add", "-A"], { cwd: root, stdio: "pipe" });
    execFileSync("git", [
        "-c", "user.email=fixture@example.invalid", "-c", "user.name=fixture",
        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture tree",
    ], { cwd: root, stdio: "pipe" });
    return { root, runs, writer: join(engine, "write-run.mjs"), ledger: join(engine, "ledger.mjs") };
}

/**
 * A fresh runs dir per scenario: the chronological order under test is
 * exactly the documents the scenario wrote, nothing else.
 */
function resetRuns(fixture) {
    for (const name of readdirSync(fixture.runs)) {
        rmSync(join(fixture.runs, name), { force: true });
    }
}

/**
 * One synthetic run document, written by the orchestrator's writer,
 * argv for argv: document path first, then campaign, class, seed,
 * started, duration, rc, verdict, detail, metric, economic, shaUs,
 * method, and the deployment binding the ledger grades under. The
 * filename timestamp is the chronological position in the scenario.
 */
function writeDoc(fixture, position, { seed = SEED, verdict = "PASS" } = {}) {
    const name = `20261019T${String(position).padStart(6, "0")}Z-${CAMPAIGN}-seed-${seed}.json`;
    execFileSync("node", [
        fixture.writer,
        join(fixture.runs, name),
        CAMPAIGN, CLASS, seed, "2026-10-19T00:00:00Z", "1", "0",
        verdict, "fixture run", "wire_sample=1", "attacker uneconomic", "0", "offline-grammar",
        "", "", "redis", "single-primary",
    ], { cwd: fixture.root, env: ENV, stdio: "pipe" });
    return name;
}

/**
 * Run the ledger over the documents written so far and return the
 * slot's THREATS.md table row.
 */
function ledgerRow(fixture) {
    execFileSync("node", [fixture.ledger, "--seed", SEED], { cwd: fixture.root, env: ENV, stdio: "pipe" });
    const text = readFileSync(join(fixture.root, "THREATS.md"), "utf8");
    const row = text.split("\n").find((l) => l.startsWith(`| ${CLASS} |`));
    assert.ok(row, "the fixture slot has a THREATS.md row");
    return row;
}

describe("ledger selection chronology", () => {
    const fixture = buildFixture();
    after(() => rmSync(fixture.root, { recursive: true, force: true }));

    test("FAIL then PASS: the newest battery is green and its own history is not newer evidence", () => {
        resetRuns(fixture);
        writeDoc(fixture, 0, { verdict: "FAIL" });
        writeDoc(fixture, 1);
        const row = ledgerRow(fixture);
        assert.ok(row.includes("| GREEN |"), `the newest PASS must be green: ${row}`);
        assert.ok(!row.includes(FOOTNOTE), `history below the selection is never disclosed: ${row}`);
        assert.ok(!row.includes("recorded FAIL under the current tree"), `the older FAIL must not bury the green run: ${row}`);
    });

    test("PASS then FAIL: the newer FAIL buries the older PASS (RED)", () => {
        resetRuns(fixture);
        writeDoc(fixture, 0);
        writeDoc(fixture, 1, { verdict: "FAIL" });
        const row = ledgerRow(fixture);
        assert.ok(row.includes("| RED |"), `a newer FAIL must bury the older PASS: ${row}`);
        assert.match(row, /recorded FAIL under the current tree and seed/);
    });

    test("PASS then FAIL then PASS: the newest PASS is green and the middle FAIL is its history", () => {
        resetRuns(fixture);
        writeDoc(fixture, 0);
        writeDoc(fixture, 1, { verdict: "FAIL" });
        writeDoc(fixture, 2);
        const row = ledgerRow(fixture);
        assert.ok(row.includes("| GREEN |"), `the newest PASS wins: ${row}`);
        assert.ok(!row.includes(FOOTNOTE), `the FAIL below the newest PASS is not newer evidence: ${row}`);
        assert.ok(!row.includes("recorded FAIL under the current tree"), `the middle FAIL must not bury the green run: ${row}`);
    });

    test("PASS then refused then FAIL: RED, and the refusal is disclosed beside the buried FAIL", () => {
        resetRuns(fixture);
        writeDoc(fixture, 0);
        writeDoc(fixture, 1, { seed: "0xdeadbeef" });
        writeDoc(fixture, 2, { verdict: "FAIL" });
        const row = ledgerRow(fixture);
        assert.ok(row.includes("| RED |"), `the FAIL above the PASS must bury it: ${row}`);
        assert.match(row, /recorded FAIL under the current tree and seed/);
        assert.match(row, /refused run document: seed "0xdeadbeef" != the ledger seed "0x6b776d74"/);
    });

    test("PASS then refused: green, with the newer refusal disclosed in the footnote", () => {
        resetRuns(fixture);
        writeDoc(fixture, 0);
        writeDoc(fixture, 1, { seed: "0xdeadbeef" });
        const row = ledgerRow(fixture);
        assert.ok(row.includes("| GREEN |"), `the selected PASS stays green: ${row}`);
        assert.ok(row.includes(FOOTNOTE), `the newer refusal must be disclosed: ${row}`);
        assert.match(row, /refused run document: seed "0xdeadbeef" != the ledger seed "0x6b776d74"/);
    });

    test("FAIL then two PASSes: the newest PASS wins and nothing behind it is buried", () => {
        resetRuns(fixture);
        writeDoc(fixture, 0, { verdict: "FAIL" });
        writeDoc(fixture, 1);
        writeDoc(fixture, 2);
        const row = ledgerRow(fixture);
        assert.ok(row.includes("| GREEN |"), `the newest of the qualifying PASSes wins: ${row}`);
        assert.ok(!row.includes(FOOTNOTE), `nothing sits above the newest PASS: ${row}`);
        assert.ok(!row.includes("recorded FAIL under the current tree"), `the FAIL behind the older PASS must not bury it: ${row}`);
    });
});
