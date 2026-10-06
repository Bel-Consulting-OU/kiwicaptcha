#!/usr/bin/env node
/**
 * rt-page-server.mjs — the red-team campaigns' loopback page and asset
 * server (node stdlib only, no dependency).
 *
 * What it serves on one loopback port:
 *   GET  /                        the widget page (the real driver
 *                                 plus the real lazy modules, wired
 *                                 with real SRI integrity attributes)
 *   GET  /kiwi-captcha/assets/*   the repo's real widget assets,
 *                                 content-addressed by name prefix
 *                                 (driver.* -> widget-driver.js and so
 *                                 on), bytes read from disk per request
 *   POST /challenge, POST /verify proxied verbatim to the wire target
 *                                 (--wire base url), so the page stays
 *                                 same-origin while the REAL issuer and
 *                                 verifier answer every request
 *   GET  /__page-source           the exact page bytes (the decoy
 *                                 secrecy and provenance assertions
 *                                 read this, never a re-serialization)
 *
 * CLI:
 *   --port N        listen port (the campaign reserves its own)
 *   --wire URL      the challenge/verify passthrough target
 *   --html FILE     page template override (otherwise the built-in
 *                   widget page)
 *   --quiet         no per-request logging
 *
 * The server binds 127.0.0.1 only and refuses to start on any other
 * host, the same allowlist rule the engine's orchestrator enforces.
 */

import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const ASSETS_DIR = join(REPO, "packages/kiwicaptcha-wasm/assets");

function argOf(name, fallback) {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : fallback;
}

const port = Number(argOf("--port", "6471"));
const wire = argOf("--wire", "http://127.0.0.1:6470");
const htmlFile = argOf("--html", "");
const swFile = argOf("--sw-file", "");
const quiet = process.argv.includes("--quiet");

const host = "127.0.0.1";
if (!wire.startsWith("http://127.0.0.1") && !wire.startsWith("http://[::1]")) {
    console.error(`rt-page-server: refusing non-loopback wire target ${wire}`);
    process.exit(2);
}

const ASSET_FILES = {
    driver: "widget-driver.js",
    risk: "widget-risk.js",
    worker: "kiwi-worker.js",
    runtime: "kiwicaptcha-wasm.js",
    telemetry: "widget-telemetry.js",
    compat: "widget-compat.js",
    locales: "widget-locales.js",
    execution: "execution-interpreter.js",
};

function assetUrl(kind, file) {
    const bytes = readFileSync(join(ASSETS_DIR, file));
    const hash = createHash("sha256").update(bytes).digest("hex");
    return { url: `/kiwi-captcha/assets/${kind}.${hash}.js`, sri: "sha256-" + createHash("sha256").update(bytes).digest("base64") };
}

function widgetPage() {
    const driver = assetUrl("driver", "widget-driver.js");
    const runtime = assetUrl("runtime", "kiwicaptcha-wasm.js");
    const worker = assetUrl("worker", "kiwi-worker.js");
    const risk = assetUrl("risk", "widget-risk.js");
    const telemetry = assetUrl("telemetry", "widget-telemetry.js");
    const execution = assetUrl("execution", "execution-interpreter.js");
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>red-team widget page</title>
<script src="${runtime.url}" integrity="${runtime.sri}" crossorigin="anonymous"></script>
<script src="${driver.url}" integrity="${driver.sri}" crossorigin="anonymous"></script>
</head>
<body>
<div id="host">
<form id="the-form" action="/form-submit" method="post">
<div class="kiwi-container"
     data-kiwi-scope="login"
     data-kiwi-endpoint="/challenge"
     data-kiwi-runtime-src="${runtime.url}" data-kiwi-runtime-integrity="${runtime.sri}"
     data-kiwi-worker-src="${worker.url}" data-kiwi-worker-integrity="${worker.sri}"
     data-kiwi-risk-src="${risk.url}" data-kiwi-risk-integrity="${risk.sri}"
     data-kiwi-telemetry-src="${telemetry.url}" data-kiwi-telemetry-integrity="${telemetry.sri}"
     data-kiwi-execution-src="${execution.url}" data-kiwi-execution-integrity="${execution.sri}"
     data-kiwi-telemetry="1">
<input type="hidden" name="kiwi__token" data-kiwi-token value="">
<div class="kiwi-widget" data-kiwi-widget data-state="idle" role="status" aria-live="polite">
<div class="kiwi-icon-wrapper"><svg></svg><div class="kiwi-glow"></div></div>
<div class="kiwi-main">
<div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span data-kiwi-badge class="kiwi-badge">Idle</span></div>
<div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>
<div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
</div></div></div></form>
</div>
<p id="out"></p>
</body>
</html>
`;
}

let pageBytes;
if (htmlFile !== "" && existsSync(htmlFile)) {
    pageBytes = readFileSync(htmlFile);
} else {
    pageBytes = Buffer.from(widgetPage(), "utf8");
}

function proxyPost(req, res, incoming) {
    const chunks = [];
    incoming.on("data", (chunk) => chunks.push(chunk));
    incoming.on("end", () => {
        const body = Buffer.concat(chunks);
        const target = new URL(req.url, wire);
        const upstream = http.request(target, {
            method: "POST",
            headers: {
                "content-type": req.headers["content-type"] ?? "application/json",
                "content-length": body.length,
                "x-forwarded-for": req.headers["x-forwarded-for"] ?? "203.0.113.9",
            },
            timeout: 30000,
        }, (up) => {
            res.writeHead(up.statusCode ?? 502, { "content-type": up.headers["content-type"] ?? "application/json" });
            up.pipe(res);
        });
        upstream.on("error", (err) => {
            res.writeHead(502, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: { code: "upstream_failed", message: String(err) } }));
        });
        upstream.end(body);
    });
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${host}:${port}`);
    if ((url.pathname === "/challenge" || url.pathname === "/verify") && req.method === "POST") {
        proxyPost(req, res, req);
        return;
    }
    if (url.pathname === "/__page-source") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(pageBytes);
        return;
    }
    const asset = url.pathname.match(/^\/kiwi-captcha\/assets\/([a-z]+)\.[0-9a-f]{64}\.js$/);
    if (req.method === "GET" && asset) {
        const file = ASSET_FILES[asset[1]];
        if (!file) {
            res.writeHead(404);
            res.end("no such asset kind");
            return;
        }
        try {
            const bytes = readFileSync(join(ASSETS_DIR, file));
            res.writeHead(200, {
                "content-type": "text/javascript; charset=utf-8",
                "cache-control": "public, max-age=31536000, immutable",
            });
            res.end(bytes);
        } catch {
            res.writeHead(404);
            res.end("asset missing");
        }
        return;
    }
    if (req.method === "GET" && url.pathname === "/sw.js" && swFile !== "") {
        try {
            const bytes = readFileSync(resolve(swFile));
            res.writeHead(200, {
                "content-type": "text/javascript; charset=utf-8",
                "service-worker-allowed": "/",
                "cache-control": "no-store",
            });
            res.end(bytes);
        } catch {
            res.writeHead(404);
            res.end("sw missing");
        }
        return;
    }
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(pageBytes);
        return;
    }
    res.writeHead(404);
    res.end("not found");
});

server.listen(port, host, () => {
    if (!quiet) console.log(`rt-page-server: listening on http://${host}:${port} (wire ${wire})`);
});
