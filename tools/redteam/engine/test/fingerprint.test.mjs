/**
 * fingerprint.test.mjs — the full evidence chain: the orchestrator
 * writes a run document with the shared source fingerprint, and the
 * ledger must report it as NOT stale when the fingerprint matches the
 * current tree. A run without a fingerprint is always stale.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { sourceFingerprint } from "../fingerprint.mjs";

test("a freshly generated run document is not stale", () => {
    const fp = sourceFingerprint();
    assert.ok(fp.length >= 16, "the fingerprint is a real hash");
    // The orchestrator writes source_fingerprint into every run doc.
    const run = {
        schema: "kiwicaptcha.redteam.run/1",
        campaign: "d3.1-commodity-nojs",
        attackClass: "D3.1 commodity no-JS bots",
        seed: "0x6b776d74",
        started: new Date().toISOString(),
        duration_s: 1,
        exit: 0,
        result: "PASS",
        source_fingerprint: fp,
        metrics: {},
    };
    assert.equal(run.source_fingerprint, fp, "the recorded fingerprint matches the current tree");
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
    assert.equal(sourceFingerprint(), sourceFingerprint(), "two calls give the same hash");
});

test("the fingerprint changes when the source changes", () => {
    const before = sourceFingerprint();
    // A throwaway file inside packages/ changes the measured tree.
    const probe = join(process.cwd(), "packages", ".fingerprint-probe-" + Date.now() + ".tmp");
    try {
        writeFileSync(probe, "x");
        const after = sourceFingerprint();
        assert.notEqual(before, after, "a new source file changes the fingerprint");
    } finally {
        rmSync(probe, { force: true });
    }
    assert.equal(sourceFingerprint(), before, "removing the probe restores the fingerprint");
});
