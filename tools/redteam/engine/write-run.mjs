/**
 * write-run.mjs — the ES-module run-document writer. The orchestrator
 * invokes this instead of an inline node -e that require()s an ESM
 * fingerprint module (require() of an ES module only works on recent
 * Node and throws ERR_REQUIRE_ESM on older ones). The writer computes
 * the source fingerprint once and records the engine method so the
 * ledger's method note is never a hard-coded fallback.
 *
 * Usage: node write-run.mjs <doc-path> <campaign> <class> <seed> <started> <duration> <rc> <verdict> <detail> <metric> <economic> <shaUs> <method>
 */
import { writeFileSync } from "node:fs";
import { sourceFingerprint } from "./fingerprint.mjs";

const args = process.argv.slice(2);
const docPath = args[0];
const [campaign, cls, seed, started, duration, rc, verdict, detail, metric, economic, shaUs, method] = args.slice(1);

const fingerprint = sourceFingerprint();
const methodField = method && method !== "" ? method : "offline-grammar (no local model consulted)";

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
