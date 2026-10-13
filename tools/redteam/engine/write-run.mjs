/**
 * write-run.mjs — the ES-module run-document writer. The orchestrator
 * invokes this instead of an inline node -e that require()s an ESM
 * fingerprint module (require() of an ES module only works on recent
 * Node and throws ERR_REQUIRE_ESM on older ones). The writer computes
 * the THREE evidence digests (product, harness, campaign) once and
 * records the engine method so the ledger's method note is never a
 * hard-coded fallback.
 *
 * The evidence identity: a run document is evidence only while all
 * three digests still match the current tree (fingerprint.mjs). The
 * product digest covers the code the campaigns attack (packages/,
 * protocol/, integrations-platforms/, deploy/, the shipped wasm
 * assets); the harness digest covers the machinery that produced the
 * evidence (tools/redteam/engine, lib, target.sh, cluster.sh, the
 * shared campaigns/lib); the campaign digest covers the campaign's own
 * script and the lib files it names. source_fingerprint is still
 * written as the alias of the product digest so pre-upgrade checks
 * keep working during the transition; the ledger binds on the three
 * new fields and treats their absence as stale evidence.
 *
 * Usage: node write-run.mjs <doc-path> <campaign> <class> <seed> <started> <duration> <rc> <verdict> <detail> <metric> <economic> <shaUs> <method> [driver] [containerOverrides] [profile] [topology]
 *
 * The optional `driver` and `containerOverrides` arguments carry the
 * product-method provenance the ledger checks: for a method:product
 * campaign the driver must name a Kernel subclass and the override
 * count must be present and zero, or the ledger refuses GREEN.
 *
 * The optional `profile` and `topology` arguments bind the document to
 * the deployment shape the battery measured (schema /2): the target
 * profile name and the replication topology that profile boots. The
 * profile falls back to the KIWI_RT_PROFILE environment variable (the
 * battery's own knob, default "redis") and the topology falls back to
 * "single-primary". The ledger selects only documents whose profile
 * and topology equal its own, so a pass under one deployment shape can
 * never be quoted as a pass under another.
 *
 * The document path MUST be the first argument and MUST live under
 * engine/runs/. A path outside that directory is refused: a shifted
 * argv must never scatter campaign-named files across the working
 * directory, and a mis-ordered call must fail loudly instead of
 * writing a document the ledger will later read as a real run. The
 * writer also refuses to write when the campaign digest cannot be
 * computed (no campaign script at tools/redteam/campaigns/<name>.sh):
 * a document without its evidence identity must never land where the
 * ledger will read it.
 */
import { mkdirSync, writeFileSync, existsSync, realpathSync } from "node:fs";
import { join, resolve, sep, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { productFingerprint, harnessFingerprint, campaignFingerprint } from "./fingerprint.mjs";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const RUNS_DIR = join(ENGINE_DIR, "runs");

const args = process.argv.slice(2);
if (args.length < 13) {
    console.error(
        `write-run.mjs: expected 13 arguments (doc-path first), got ${args.length}. `
        + "Usage: node write-run.mjs <doc-path> <campaign> <class> <seed> <started> "
        + "<duration> <rc> <verdict> <detail> <metric> <economic> <shaUs> <method>",
    );
    process.exit(2);
}

const docPath = args[0];
const [campaign, cls, seed, started, duration, rc, verdict, detail, metric, economic, shaUs, method] = args.slice(1);

// The document path must land under engine/runs/. Anything else is a
// shifted argv or a caller bug and is refused before a byte is written.
const resolvedDoc = resolve(docPath);
const resolvedRuns = resolve(RUNS_DIR);
if (resolvedDoc !== resolvedRuns && !resolvedDoc.startsWith(resolvedRuns + sep)) {
    console.error(
        `write-run.mjs: REFUSING to write outside engine/runs: ${docPath}\n`
        + `  resolved: ${resolvedDoc}\n`
        + `  allowed:  ${resolvedRuns}${sep}*`,
    );
    process.exit(3);
}

// The evidence identity is computed before anything is written: a
// failure here (no campaign script, no git tree) refuses the write
// with a named reason instead of landing a document the ledger would
// have to refuse later.
let product;
let harness;
let campaignDigest;
try {
    product = productFingerprint();
    harness = harnessFingerprint();
    campaignDigest = campaignFingerprint(campaign);
} catch (err) {
    console.error(
        `write-run.mjs: REFUSING to write ${docPath}: the evidence digests could not be computed: ${err.message}`,
    );
    process.exit(5);
}

const methodField = method && method !== "" ? method : "offline-grammar (no local model consulted)";
// The product-method provenance (optional 14th/15th arguments): the
// booted driver class and its container override count.
const driverField = args[13] && args[13] !== "" ? args[13] : null;
const overridesField = args[14] !== undefined && args[14] !== "" ? Number(args[14]) : null;
// The deployment binding (optional 16th/17th arguments): the target
// profile the battery ran under and the replication topology that
// profile boots. The fallbacks mirror the battery's own resolution:
// KIWI_RT_PROFILE or "redis" (exit-criteria.sh's default), and the
// single-primary reference topology.
const profileField = args[15] && args[15] !== "" ? args[15] : (process.env.KIWI_RT_PROFILE || "redis");
const topologyField = args[16] && args[16] !== "" ? args[16] : "single-primary";

mkdirSync(RUNS_DIR, { recursive: true });
writeFileSync(
    docPath,
    JSON.stringify(
        {
            schema: "kiwicaptcha.redteam.run/2",
            campaign,
            attackClass: cls,
            seed,
            profile: profileField,
            topology: topologyField,
            started,
            duration_s: Number(duration),
            exit: Number(rc),
            result: verdict,
            detail,
            product_fingerprint: product,
            harness_fingerprint: harness,
            campaign_fingerprint: campaignDigest,
            // Transition alias: the product digest under the legacy
            // name, so existing source_fingerprint checks keep working
            // while readers move to the three-field binding.
            source_fingerprint: product,
            method: methodField,
            driver: driverField,
            container_overrides: overridesField,
            metrics: { raw: metric, sha16_solve_us: shaUs ? Number(shaUs) : null },
            economic,
        },
        null,
        2,
    ) + "\n",
);

// The caller needs a positive signal that the document landed where
// the ledger will look for it.
if (!existsSync(docPath)) {
    console.error(`write-run.mjs: the document did not land at ${docPath}`);
    process.exit(4);
}
// Touch realpathSync so a symlink escape is surfaced at write time.
realpathSync(docPath);
