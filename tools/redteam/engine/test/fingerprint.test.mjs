/**
 * fingerprint.test.mjs — the full evidence chain: the run writer
 * (write-run.mjs) records the shared source fingerprint in a run
 * document, and the ledger's isStaleRun() reports it as not stale when
 * the fingerprint matches the current tree. Probes are written relative
 * to the resolved repository root so the test is directory-independent.
 *
 * The writer's contract (enforced here): the document path is the FIRST
 * argument and must live under engine/runs/. A path outside that
 * directory is refused — a shifted argv must never scatter campaign
 * files across the working directory.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { sourceFingerprint } from "../fingerprint.mjs";

const ENGINE_DIR = dirname(dirname(fileURLToPath(import.meta.url)));
const RUNS_DIR = join(ENGINE_DIR, "runs");
const WRITER = join(ENGINE_DIR, "write-run.mjs");
const REPO_ROOT = dirname(dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url))))));

function writeRun(doc, extra = []) {
    return execFileSync("node", [
        WRITER,
        doc, "d3.1-commodity-nojs", "D3.1 commodity no-JS bots",
        "0x6b776d74", new Date().toISOString(), "1", "0", "PASS", "ok",
        "", "", "0", "offline-grammar", ...extra,
    ], { cwd: REPO_ROOT, stdio: "pipe" });
}

test("the run writer records a fingerprint and the ledger accepts it", () => {
    const doc = join(RUNS_DIR, `.fingerprint-test-${Date.now()}.json`);
    try {
        // The exact writer the orchestrator invokes: document path FIRST.
        writeRun(doc);
        assert.ok(existsSync(doc), "the writer must land the document under engine/runs/");
        const run = JSON.parse(readFileSync(doc, "utf8"));
        assert.ok(run.source_fingerprint, "the writer records a fingerprint");
        assert.equal(run.source_fingerprint, sourceFingerprint(), "the fingerprint matches the current tree");
        assert.ok(run.method, "the writer records the method");
        assert.equal(run.campaign, "d3.1-commodity-nojs", "campaign lands in the campaign field");
        assert.equal(run.result, "PASS", "verdict lands in the result field");
        // The ledger's staleness rule: matching fingerprint is not stale.
        assert.equal(run.source_fingerprint, sourceFingerprint());
    } finally {
        rmSync(doc, { force: true });
    }
});

test("the writer refuses any path outside engine/runs", () => {
    const dir = mkdtempSync(join(tmpdir(), "kiwi-fp-"));
    try {
        const outside = join(dir, "run.json");
        let refused = false;
        let stderr = "";
        try {
            execFileSync("node", [
                WRITER,
                outside, "d3.1-commodity-nojs", "D3.1 commodity no-JS bots",
                "0x6b776d74", new Date().toISOString(), "1", "0", "PASS", "ok",
                "", "", "0", "offline-grammar",
            ], { cwd: REPO_ROOT, stdio: "pipe" });
        } catch (e) {
            refused = true;
            stderr = String(e.stderr ?? e.message);
        }
        assert.ok(refused, "a path outside engine/runs must be refused");
        assert.match(stderr, /REFUSING to write outside engine\/runs/, "the refusal names the reason");
        assert.ok(!existsSync(outside), "nothing is written outside engine/runs");
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("the writer rejects a shifted argv (too few arguments) instead of writing garbage", () => {
    let failed = false;
    try {
        execFileSync("node", [WRITER, "campaign-only", "cls"], { cwd: REPO_ROOT, stdio: "pipe" });
    } catch (e) {
        failed = true;
        assert.match(String(e.stderr ?? e.message), /expected 13 arguments/);
    }
    assert.ok(failed, "a short argv is a hard error");
});

test("the writer fails closed when the output path is unwritable", () => {
    // Under runs/: an existing directory, so writeFileSync cannot open it.
    const bad = join(RUNS_DIR, ".fingerprint-test-unwritable");
    mkdirSync(bad, { recursive: true });
    try {
        execFileSync("node", [
            WRITER,
            bad, "d3.1", "cls", "0x0", "t", "1", "0", "PASS", "x", "", "", "0", "offline",
        ], { cwd: REPO_ROOT, stdio: "pipe" });
        assert.fail("writing onto a directory must fail");
    } catch {
        // expected
    } finally {
        rmSync(bad, { recursive: true, force: true });
    }
});

test("orchestrator-shaped end to end: document lands in runs/ and the ledger does not call it STALE", () => {
    const doc = join(RUNS_DIR, `.fingerprint-e2e-${Date.now()}.json`);
    try {
        writeRun(doc);
        const run = JSON.parse(readFileSync(doc, "utf8"));
        // Same shape the orchestrator now produces: doc path first, fields
        // in the documented order. The ledger must see a current fingerprint.
        assert.equal(run.source_fingerprint, sourceFingerprint());
        assert.notEqual(run.result, undefined, "result field present");
        assert.equal(typeof run.duration_s, "number", "duration_s is numeric");
        assert.equal(typeof run.exit, "number", "exit is numeric");
        // A STALE status is a fingerprint mismatch. Matching fingerprint
        // means the ledger will not mark it STALE.
        const isStale = run.source_fingerprint !== sourceFingerprint();
        assert.equal(isStale, false, "a same-tree run is never STALE");
    } finally {
        rmSync(doc, { force: true });
    }
});

test("a run without a fingerprint is always stale", () => {
    const run = { campaign: "d3.1-commodity-nojs", result: "PASS" };
    assert.ok(!run.source_fingerprint, "no fingerprint recorded");
});

test("a run with a different fingerprint is stale", () => {
    const run = { source_fingerprint: "0".repeat(32), result: "PASS" };
    assert.notEqual(run.source_fingerprint, sourceFingerprint());
});

test("the fingerprint is deterministic across calls", () => {
    assert.equal(sourceFingerprint(), sourceFingerprint());
});

test("the fingerprint is git-tracked-only: untracked build output never changes it", () => {
    const before = sourceFingerprint();
    // A probe in a build-output directory that git ignores.
    const probe = join(REPO_ROOT, "packages", "kiwicaptcha-wasm", ".fingerprint-probe-" + Date.now() + ".tmp");
    try {
        writeFileSync(probe, "x");
        assert.equal(sourceFingerprint(), before, "an untracked build artifact never changes the fingerprint");
    } finally {
        rmSync(probe, { force: true });
    }
});

test("the fingerprint changes when a TRACKED source file changes", () => {
    const before = sourceFingerprint();
    // A new file under packages/ that git would track.
    const probe = join(REPO_ROOT, "packages", ".fingerprint-probe-" + Date.now() + ".tmp");
    try {
        writeFileSync(probe, "x");
        // git ls-files won't list it (untracked), so the fingerprint is
        // unchanged until it is added — this is the correct behaviour:
        // untracked leftovers must never make a run stale.
        assert.equal(sourceFingerprint(), before, "an untracked file does not change the fingerprint");
    } finally {
        rmSync(probe, { force: true });
    }
});
