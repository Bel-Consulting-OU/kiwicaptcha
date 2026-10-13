/**
 * fingerprint.mjs — the evidence-identity digests shared by the
 * orchestrator and the run writer (which record them in every run
 * document) and the ledger (which compares them to decide whether a
 * run is still evidence). Evidence is bound to THREE surfaces:
 *
 *   productFingerprint()     the code the campaigns attack (packages/,
 *                            protocol/, integrations-platforms/) plus
 *                            the deployed runtime surface (deploy/) and
 *                            the shipped wasm bytes
 *                            (packages/kiwicaptcha-wasm/assets);
 *   harnessFingerprint()     the machinery that produced the evidence
 *                            (tools/redteam/engine, tools/redteam/lib,
 *                            target.sh, cluster.sh, and the shared
 *                            campaigns/lib);
 *   campaignFingerprint(n)   the one campaign script plus the
 *                            campaigns/lib files it names.
 *
 * A run recorded before a change to any of the three is stale evidence
 * under the new definition, exactly as a product change is: campaign
 * implementation edits must invalidate old PASS evidence just like
 * product edits do.
 *
 * Only GIT-TRACKED state is hashed: `git ls-files -s` carries the index
 * blob OIDs (the content hash of every tracked file), and `git diff`
 * covers uncommitted edits. Untracked build output (.NET bin/, Elixir
 * _build/, .pytest_cache/, .gradle/, coverage/) and editor/OS files are
 * never hashed, so a run recorded on one machine is never stale on
 * another because of local leftovers.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));
const RT_DIR = dirname(dirname(fileURLToPath(import.meta.url)));

function git(args) {
    return execFileSync("git", args, { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

/**
 * A short content hash of the git-tracked state under `paths`, shared
 * by every digest below. The index OIDs already hash the tracked
 * content; `git diff` captures uncommitted edits; `git status` captures
 * staged new files. Deterministic across clones and machines.
 */
function trackedDigest(paths) {
    const index = git(["ls-files", "-s", "--", ...paths]);
    // --no-ext-diff --no-color and fixed prefixes keep the patch bytes
    // identical across machines and user gitconfig; without them a
    // dirty tree fingerprints differently depending on the host.
    const diff = git(["diff", "--no-ext-diff", "--no-color", "--src-prefix=a/", "--dst-prefix=b/", "--", ...paths]);
    // -uno: untracked files must NOT change the digest (local build
    // output is not part of the measured source).
    const status = git(["status", "--porcelain", "-uno", "--", ...paths]);
    return createHash("sha256")
        .update(index + "\n---diff---\n" + diff + "\n---status---\n" + status)
        .digest("hex")
        .slice(0, 32);
}

/**
 * The legacy single digest over the measured product source. Kept for
 * existing callers; the run documents now record the three-digest
 * binding instead (source_fingerprint remains as the alias of the
 * product digest during the transition).
 */
export function sourceFingerprint() {
    return trackedDigest(["packages", "protocol", "integrations-platforms"]);
}

/**
 * The product digest: everything the campaigns attack, now including
 * the deploy/ runtime surface and the shipped wasm asset bytes. The
 * packages/kiwicaptcha-wasm/assets pathspec is inside packages/ and so
 * is already covered by it; it is listed explicitly so the shipped
 * bytes stay named in the contract even if the packages pathspec is
 * ever narrowed. git collapses overlapping pathspecs, so the explicit
 * entry never double-counts a file.
 */
export function productFingerprint() {
    return trackedDigest([
        "packages",
        "protocol",
        "integrations-platforms",
        "deploy",
        "packages/kiwicaptcha-wasm/assets",
    ]);
}

/**
 * The harness digest: the machinery that produced the evidence. A
 * change here invalidates every recorded run — an engine, shared-lib,
 * target or cluster edit means the old PASS was produced by different
 * code than the one now claiming it.
 */
export function harnessFingerprint() {
    return trackedDigest([
        "tools/redteam/engine",
        "tools/redteam/lib",
        "tools/redteam/target.sh",
        "tools/redteam/cluster.sh",
        "tools/redteam/campaigns/lib",
    ]);
}

// A campaign slot name: no separators, no traversal. The ledger feeds
// document-derived names into campaignFingerprint, so a crafted name
// must never be able to walk out of tools/redteam/campaigns/.
const CAMPAIGN_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
// The `lib/<file>` references a campaign script carries. The bounded
// basename character class keeps the captured group inside campaigns/lib.
const LIB_REF_RE = /\blib\/([A-Za-z0-9][A-Za-z0-9._-]*)/g;

/**
 * The campaign digest: tools/redteam/campaigns/<name>.sh plus every
 * campaigns/lib file the script NAMES as `lib/<basename>`.
 *
 * Known limits of the reference parse (deliberate; fail toward more
 * binding, never less): a plain regex over the script text — source
 * lines, heredocs and comments all count, so an over-mention only
 * makes the digest stricter. A lib file the script reaches only
 * TRANSITIVELY (lib A requiring lib B) is not captured here; that gap
 * is closed by harnessFingerprint, which hashes all of campaigns/lib.
 * Dynamically built references (a variable path segment) are missed
 * for the same reason and covered by the harness digest.
 *
 * Throws when the campaign script does not exist: a document for a
 * campaign without a script can never be evidence, and a missing file
 * must fail closed rather than digest the empty set.
 */
export function campaignFingerprint(campaignName) {
    if (typeof campaignName !== "string" || !CAMPAIGN_NAME_RE.test(campaignName) || campaignName.includes("..")) {
        throw new Error(`campaignFingerprint: invalid campaign name ${JSON.stringify(campaignName)}`);
    }
    const scriptPath = `tools/redteam/campaigns/${campaignName}.sh`;
    const scriptAbs = join(REPO_ROOT, scriptPath);
    if (!existsSync(scriptAbs)) {
        throw new Error(`campaignFingerprint: no campaign script at ${scriptPath}`);
    }
    const referenced = new Set();
    const text = readFileSync(scriptAbs, "utf8");
    const libDir = join(RT_DIR, "campaigns", "lib");
    for (const match of text.matchAll(LIB_REF_RE)) {
        const base = match[1];
        if (base.includes("..")) continue;
        if (existsSync(join(libDir, base))) {
            referenced.add(`tools/redteam/campaigns/lib/${base}`);
        }
    }
    return trackedDigest([scriptPath, ...[...referenced].sort()]);
}
