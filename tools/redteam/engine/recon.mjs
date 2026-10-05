#!/usr/bin/env node
/**
 * recon.mjs — the recon agent, deterministic offline implementation.
 *
 * The role per change.md Part 10.1 reads the repo's public surface and
 * the spec, and emits an attack-surface map. This implementation is a
 * manifest-driven enumeration: every endpoint, store, wire asset and
 * campaign class is read from the repo's own files (the deployment
 * routers, the sidecar, the protocol register, the SDK tree), sorted,
 * and written as engine/surface-map.json. No model is consulted; the
 * local-model adapter (see model-adapter.mjs) may refine the map's
 * hypotheses when an operator explicitly points it at a runtime.
 *
 * Determinism contract: same repo state, same map. Ordering is sorted
 * everywhere; no timestamps enter the file.
 */

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const RT_DIR = dirname(ENGINE_DIR);
const REPO = dirname(dirname(RT_DIR));

function readIfExists(path) {
    try {
        return readFileSync(path, "utf8");
    } catch {
        return "";
    }
}

/** Endpoints of one php router file: path literal plus method guard. */
function routesOfPhp(source) {
    const routes = [];
    for (const match of source.matchAll(/'(\/[a-z0-9_.-]*)'/g)) {
        const path = match[1];
        if (path.startsWith("/healthz") || path.startsWith("/challenge")
            || path.startsWith("/verify") || path.startsWith("/issue")
            || path.startsWith("/metrics") || path.startsWith("/doctor")) {
            routes.push(path);
        }
    }
    return [...new Set(routes)].sort();
}

function endpoints() {
    const list = [];
    const reference = readIfExists(join(REPO, "deploy/app/router.php"));
    for (const route of routesOfPhp(reference)) {
        list.push({
            surface: "reference-deployment",
            route,
            methods: route === "/healthz" ? ["GET"] : ["POST"],
            notes: route === "/verify"
                ? "strict framing contract; one-shot consume; independent binding"
                : "real core issuer",
        });
    }
    const storage = readIfExists(join(RT_DIR, "target/router-storage.php"));
    for (const route of routesOfPhp(storage)) {
        list.push({
            surface: "storage-matrix-deployment",
            route,
            methods: route === "/healthz" ? ["GET"] : ["POST"],
            notes: "sqlite and filesystem adapter paths of the 9.2 matrix",
        });
    }
    const sidecar = readIfExists(join(REPO, "packages/kiwicaptcha-verifier/src/lib.rs"));
    for (const match of sidecar.matchAll(/"\/(verify|issue|metrics|doctor|healthz)"/g)) {
        list.push({
            surface: "rust-sidecar",
            route: "/" + match[1],
            methods: match[1] === "verify" || match[1] === "issue" ? ["POST"] : ["GET"],
            notes: "in-process store; loopback only",
        });
    }
    return list;
}

function stores() {
    const dir = join(REPO, "packages/kiwicaptcha-php/src/Storage");
    const adapters = readdirSync(dir).filter((f) => f.endsWith(".php")).sort();
    return {
        phpAdapters: adapters,
        topologies: ["redis-single", "redis-sentinel-trio", "sqlite", "filesystem", "in-process-sidecar"],
        limits: JSON.parse(readIfExists(join(REPO, "protocol/limits.json"))),
    };
}

function corpora() {
    const root = join(REPO, "protocol");
    const files = [];
    const walk = (dir) => {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
            const full = join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith(".json")) files.push(full.slice(REPO.length + 1));
        }
    };
    walk(root);
    return files.sort();
}

function sdks() {
    return readdirSync(join(REPO, "packages"))
        .filter((name) => name.startsWith("kiwicaptcha-"))
        .sort();
}

function campaignClasses() {
    const spec = readIfExists(join(REPO, "change.md"));
    const classes = [];
    for (const match of spec.matchAll(/^D3\.(\d+) ([^—]+)—/gm)) {
        classes.push({ id: `D3.${match[1]}`, name: match[2].trim() });
    }
    return classes;
}

/** Attack hypotheses the surface implies; the synthesis grammar seeds. */
function hypotheses(map) {
    const h = [];
    const has = (route) => map.endpoints.some((e) => e.route === route);
    if (has("/verify")) {
        h.push("forged and replayed tokens against the verify one-shot model",
            "binding re-labeling and the burned-record anti-oracle",
            "framing ambiguity between two readings of one body");
    }
    if (has("/challenge")) {
        h.push("issuance budget exhaustion and outstanding-record pressure",
            "confusable scope strings at the identifier pattern boundary");
    }
    if (map.stores.topologies.length > 1) {
        h.push("record tampering, MAC strip and transplant on each store",
            "epoch and policy manipulation in the persisted record",
            "clock skew through the persisted timestamps",
            "failover and stale-primary resurrection on the sentinel trio");
    }
    if (map.sdks.length > 0) {
        h.push("wire differentials across every sdk on the shared corpus");
    }
    return h;
}

const map = {
    schema: "kiwicaptcha.redteam.surface/1",
    endpoints: endpoints(),
    stores: stores(),
    corpora: corpora(),
    sdks: sdks(),
    campaigns: campaignClasses(),
};

map.hypotheses = hypotheses(map);

const outPath = join(ENGINE_DIR, "surface-map.json");
writeFileSync(outPath, JSON.stringify(map, null, 2) + "\n");
console.log(`recon: ${map.endpoints.length} endpoints, ${map.corpora.length} wire assets,`
    + ` ${map.sdks.length} sdk packages, ${map.campaigns.length} spec campaign classes`);
console.log(`recon: surface map written to ${outPath}`);
