/**
 * write-run.mjs — the ES-module run-document writer. The orchestrator
 * invokes this instead of an inline node -e that require()s an ESM
 * fingerprint module (require() of an ES module only works on recent
 * Node and throws ERR_REQUIRE_ESM on older ones). The writer computes
 * the source fingerprint once and records the engine method so the
 * ledger's method note is never a hard-coded fallback.
 *
 * Usage: node write-run.mjs <doc-path> <campaign> <class> <seed> <started> <duration> <rc> <verdict> <detail> <metric> <economic> <shaUs> <method>
 *
 * The document path MUST be the first argument and MUST live under
 * engine/runs/. A path outside that directory is refused: a shifted
 * argv must never scatter campaign-named files across the working
 * directory, and a mis-ordered call must fail loudly instead of
 * writing a document the ledger will later read as a real run.
 */
import { mkdirSync, writeFileSync, existsSync, realpathSync } from "node:fs";
import { join, resolve, sep, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { sourceFingerprint } from "./fingerprint.mjs";

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

const fingerprint = sourceFingerprint();
const methodField = method && method !== "" ? method : "offline-grammar (no local model consulted)";

mkdirSync(RUNS_DIR, { recursive: true });
writeFileSync(
    docPath,
    JSON.stringify(
        {
            schema: "kiwicaptcha.redteam.run/1",
            campaign,
            attackClass: cls,
            seed,
            started,
            duration_s: Number(duration),
            exit: Number(rc),
            result: verdict,
            detail,
            source_fingerprint: fingerprint,
            method: methodField,
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
