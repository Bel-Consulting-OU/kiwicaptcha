/**
 * fingerprint.mjs — the source-tree fingerprint shared by the
 * orchestrator (which records it in every run document) and the ledger
 * (which compares it to decide whether a run is stale).
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
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));

function git(args) {
    return execFileSync("git", args, { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

/**
 * A short content hash of the git-tracked source tree (packages/,
 * protocol/, integrations-platforms/). The index OIDs already hash the
 * tracked content; `git diff` captures uncommitted edits; `git status`
 * captures staged new files. Deterministic across clones and machines.
 */
export function sourceFingerprint() {
    const paths = ["packages", "protocol", "integrations-platforms"];
    const index = git(["ls-files", "-s", "--", ...paths]);
    const diff = git(["diff", "--", ...paths]);
    // -uno: untracked files must NOT change the fingerprint (local
    // build output is not part of the measured source).
    const status = git(["status", "--porcelain", "-uno", "--", ...paths]);
    return createHash("sha256")
        .update(index + "\n---diff---\n" + diff + "\n---status---\n" + status)
        .digest("hex")
        .slice(0, 32);
}
