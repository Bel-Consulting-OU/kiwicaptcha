/**
 * fingerprint.mjs — the source-tree fingerprint shared by the
 * orchestrator (which records it in every run document) and the ledger
 * (which compares it to decide whether a run is stale). File mtimes
 * are not usable: git does not preserve them, so a fresh clone or CI
 * checkout gives every file roughly the same time and nothing ever
 * looks stale. A content hash of the measured source tree is stable
 * across clones and changes only when the source actually changes.
 */
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolveRepoRoot();

function resolveRepoRoot() {
    // engine/fingerprint.mjs -> engine -> redteam -> tools -> repo root
    return dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));
}

/**
 * A short content hash of the measured source tree (packages/,
 * protocol/, integrations-platforms/). Directory listings are sorted
 * so the hash is deterministic across filesystems.
 */
export function sourceFingerprint() {
    const roots = ["packages", "protocol", "integrations-platforms"].map((r) => join(REPO_ROOT, r));
    const parts = [];
    const walk = (dir) => {
        for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
            if (["node_modules", "vendor", "target", ".git", "deps", "build", "dist", "__pycache__"].includes(e.name)) continue;
            const full = join(dir, e.name);
            if (e.isDirectory()) walk(full);
            else if (e.isFile()) {
                try {
                    parts.push(e.name + ":" + createHash("sha256").update(readFileSync(full)).digest("hex"));
                } catch {
                    parts.push(e.name + ":unreadable");
                }
            }
        }
    };
    for (const r of roots) {
        if (existsSync(r)) walk(r);
    }
    return createHash("sha256").update(parts.join("\n")).digest("hex").slice(0, 32);
}
