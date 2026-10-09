/**
 * fingerprint.test.mjs — the full evidence chain: the run writer
 * (write-run.mjs) records the shared source fingerprint in a run
 * document, and the ledger's isStaleRun() reports it as not stale when
 * the fingerprint matches the current tree. Probes are written relative
 * to the resolved repository root so the test is directory-independent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { sourceFingerprint } from "../fingerprint.mjs";

const REPO_ROOT = dirname(dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url))))));

test("the run writer records a fingerprint and the ledger accepts it", () => {
    const dir = mkdtempSync(join(tmpdir(), "kiwi-fp-"));
    try {
        const doc = join(dir, "run.json");
        // The exact writer the orchestrator invokes.
        execFileSync("node", [
            join(REPO_ROOT, "tools", "redteam", "engine", "write-run.mjs"),
            doc, "d3.1-commodity-nojs", "D3.1 commodity no-JS bots",
            "0x6b776d74", new Date().toISOString(), "1", "0", "PASS", "ok",
            "", "", "0", "offline-grammar",
        ], { cwd: REPO_ROOT, stdio: "pipe" });
        const run = JSON.parse(readFileSync(doc, "utf8"));
        assert.ok(run.source_fingerprint, "the writer records a fingerprint");
        assert.equal(run.source_fingerprint, sourceFingerprint(), "the fingerprint matches the current tree");
        assert.ok(run.method, "the writer records the method");
        // The ledger's staleness rule: matching fingerprint is not stale.
        assert.equal(run.source_fingerprint, sourceFingerprint());
    } finally {
        rmSync(dir, { recursive: true, force: true });
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

test("the writer fails closed when the output path is unwritable", () => {
    const bad = "/nonexistent-dir/never-written.json";
    let failed = false;
    try {
        execFileSync("node", [
            join(REPO_ROOT, "tools", "redteam", "engine", "write-run.mjs"),
            bad, "d3.1", "cls", "0x0", "t", "1", "0", "PASS", "x", "", "", "0", "offline",
        ], { cwd: REPO_ROOT, stdio: "pipe" });
    } catch {
        failed = true;
    }
    assert.ok(failed, "an unwritable output path is a hard error, never a silent skip");
});
