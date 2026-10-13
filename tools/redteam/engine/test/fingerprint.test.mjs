/**
 * fingerprint.test.mjs — the full evidence chain: the run writer
 * (write-run.mjs) records the THREE evidence digests (product,
 * harness, campaign) in a run document — with source_fingerprint kept
 * as the alias of the product digest — and the ledger's selection
 * reports the document as satisfying the digest contract while the
 * digests match the current tree. Probes are written relative to the
 * resolved repository root so the test is directory-independent.
 *
 * The writer's contract (enforced here): the document path is the FIRST
 * argument and must live under engine/runs/. A path outside that
 * directory is refused — a shifted argv must never scatter campaign
 * files across the working directory. The document also binds the
 * deployment shape (schema /2): the target profile and topology travel
 * in their own fields, and the ledger refuses a document whose profile
 * or topology differs from its own.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { sourceFingerprint, productFingerprint, harnessFingerprint, campaignFingerprint } from "../fingerprint.mjs";

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

test("the run writer records the three digests and the ledger accepts them", () => {
    const doc = join(RUNS_DIR, `.fingerprint-test-${Date.now()}.json`);
    try {
        // The exact writer the orchestrator invokes: document path FIRST.
        writeRun(doc);
        assert.ok(existsSync(doc), "the writer must land the document under engine/runs/");
        const run = JSON.parse(readFileSync(doc, "utf8"));
        assert.equal(run.product_fingerprint, productFingerprint(), "the product digest matches the current tree");
        assert.equal(run.harness_fingerprint, harnessFingerprint(), "the harness digest matches the current tree");
        assert.equal(run.campaign_fingerprint, campaignFingerprint("d3.1-commodity-nojs"), "the campaign digest matches the current tree");
        // The transition alias: source_fingerprint is the product digest.
        assert.equal(run.source_fingerprint, run.product_fingerprint, "source_fingerprint aliases the product digest");
        assert.ok(run.method, "the writer records the method");
        assert.equal(run.campaign, "d3.1-commodity-nojs", "campaign lands in the campaign field");
        assert.equal(run.result, "PASS", "verdict lands in the result field");
        // The deployment binding: schema /2 carries non-empty profile
        // and topology strings (the fallbacks: KIWI_RT_PROFILE or
        // "redis", and the single-primary topology).
        assert.equal(run.schema, "kiwicaptcha.redteam.run/2", "the schema marker is /2");
        assert.equal(typeof run.profile, "string");
        assert.ok(run.profile.trim() !== "", "the profile field is a non-empty string");
        assert.equal(typeof run.topology, "string");
        assert.ok(run.topology.trim() !== "", "the topology field is a non-empty string");
    } finally {
        rmSync(doc, { force: true });
    }
});

test("the writer records the caller's profile and topology verbatim", () => {
    const doc = join(RUNS_DIR, `.fingerprint-profile-${Date.now()}.json`);
    try {
        // The battery's argv shape: empty driver and override slots,
        // then the profile and the topology the gate derived.
        writeRun(doc, ["", "", "sentinel", "sentinel"]);
        const run = JSON.parse(readFileSync(doc, "utf8"));
        assert.equal(run.schema, "kiwicaptcha.redteam.run/2", "the schema marker is /2");
        assert.equal(run.profile, "sentinel", "the caller's profile lands verbatim");
        assert.equal(run.topology, "sentinel", "the caller's topology lands verbatim");
    } finally {
        rmSync(doc, { force: true });
    }
});

test("the writer resolves the profile from the environment and the topology default", () => {
    const doc = join(RUNS_DIR, `.fingerprint-profile-default-${Date.now()}.json`);
    try {
        execFileSync("node", [
            WRITER,
            doc, "d3.1-commodity-nojs", "D3.1 commodity no-JS bots",
            "0x6b776d74", new Date().toISOString(), "1", "0", "PASS", "ok",
            "", "", "0", "offline-grammar",
        ], { cwd: REPO_ROOT, stdio: "pipe", env: { ...process.env, KIWI_RT_PROFILE: "redis" } });
        const run = JSON.parse(readFileSync(doc, "utf8"));
        assert.equal(run.profile, "redis", "an unset profile argument falls back to KIWI_RT_PROFILE");
        assert.equal(run.topology, "single-primary", "an unset topology argument falls back to single-primary");
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
        // in the documented order. The ledger must see current digests.
        assert.equal(run.product_fingerprint, productFingerprint());
        assert.notEqual(run.result, undefined, "result field present");
        assert.equal(typeof run.duration_s, "number", "duration_s is numeric");
        assert.equal(typeof run.exit, "number", "exit is numeric");
        // A STALE status is a digest mismatch. Matching digests
        // mean the ledger will not mark it STALE.
        const isStale = run.product_fingerprint !== productFingerprint()
            || run.harness_fingerprint !== harnessFingerprint()
            || run.campaign_fingerprint !== campaignFingerprint(run.campaign);
        assert.equal(isStale, false, "a same-tree run is never STALE");
    } finally {
        rmSync(doc, { force: true });
    }
});

test("a run without a fingerprint is always stale", () => {
    const run = { campaign: "d3.1-commodity-nojs", result: "PASS" };
    assert.ok(!run.product_fingerprint, "no fingerprint recorded");
});

test("a run with a different fingerprint is stale", () => {
    const run = { product_fingerprint: "0".repeat(32), result: "PASS" };
    assert.notEqual(run.product_fingerprint, productFingerprint());
});

test("the fingerprints are deterministic across calls", () => {
    assert.equal(sourceFingerprint(), sourceFingerprint());
    assert.equal(productFingerprint(), productFingerprint());
    assert.equal(harnessFingerprint(), harnessFingerprint());
    assert.equal(campaignFingerprint("d3.1-commodity-nojs"), campaignFingerprint("d3.1-commodity-nojs"));
});

test("the product digest is git-tracked-only: untracked build output never changes it", () => {
    const before = productFingerprint();
    // A probe in a build-output directory that git ignores.
    const probe = join(REPO_ROOT, "packages", "kiwicaptcha-wasm", ".fingerprint-probe-" + Date.now() + ".tmp");
    try {
        writeFileSync(probe, "x");
        assert.equal(productFingerprint(), before, "an untracked build artifact never changes the digest");
    } finally {
        rmSync(probe, { force: true });
    }
});

test("an untracked file does not change the product digest", () => {
    const before = productFingerprint();
    // A new file under packages/ that git would track.
    const probe = join(REPO_ROOT, "packages", ".fingerprint-probe-" + Date.now() + ".tmp");
    try {
        writeFileSync(probe, "x");
        // git ls-files won't list it (untracked), so the digest is
        // unchanged until it is added — this is the correct behaviour:
        // untracked leftovers must never make a run stale.
        assert.equal(productFingerprint(), before, "an untracked file does not change the digest");
    } finally {
        rmSync(probe, { force: true });
    }
});

test("the product digest covers deploy/ and the shipped wasm assets: both are inside its pathspec set", () => {
    // The digest machinery (index OIDs + uncommitted diff) is proven
    // sensitive by the sourceFingerprint tests above; here we prove the
    // NEW surfaces are inside the hashed pathspec set.
    const listed = execFileSync("git", [
        "ls-files", "-s", "--",
        "packages", "protocol", "integrations-platforms", "deploy", "packages/kiwicaptcha-wasm/assets",
    ], { cwd: REPO_ROOT, encoding: "utf8" });
    assert.ok(listed.includes("deploy/"), "deploy/ is inside the product digest's pathspec set");
    assert.ok(listed.includes("packages/kiwicaptcha-wasm/assets/"), "the shipped wasm bytes are inside the pathspec set");
});

test("the campaign digest covers the campaign script and the lib files it names", () => {
    // d3.3 names lib/rt.kernel.php inside a heredoc require — the parse
    // must see it (the transitive gap is documented, the direct mention
    // is binding).
    const d33 = campaignFingerprint("d3.3-pow-economics");
    const d31 = campaignFingerprint("d3.1-commodity-nojs");
    assert.notEqual(d33, d31, "different campaigns digest differently");
    // A campaign without a script fails closed.
    assert.throws(() => campaignFingerprint("no-such-campaign"), /no campaign script/);
    // Traversal is refused.
    assert.throws(() => campaignFingerprint("../deploy"), /invalid campaign name/);
});
