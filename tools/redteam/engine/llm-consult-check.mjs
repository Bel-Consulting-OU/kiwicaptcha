#!/usr/bin/env node
/**
 * llm-consult-check.mjs — prove the Part 10 agent loop really
 * consults a model. The release gate's llm-red-team row runs this.
 *
 * Two modes, both honest in the evidence document:
 *   configured  KIWI_RT_LOCAL_LLM_URL points at the operator's local
 *               runtime; the agent loop consults it for real.
 *   stub        no model URL is configured: an in-process node http
 *               server stands in for the model (the CI substitute) and
 *               a local stub target accepts the planned actions. The
 *               loop still runs end to end and must report
 *               consulted:true — offline mode (consulted:false) is
 *               never a pass.
 *
 * Writes tools/redteam/engine/runs/agent-loop-evidence.json and prints
 * one machine line:
 *   LLM-CONSULT: consulted=<true|false> model_kind=<configured|stub> ...
 *
 * Exit codes: 0 consulted:true, 3 the consulted run did not happen.
 */
import http from "node:http";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const RUNS_DIR = join(ENGINE_DIR, "runs");
const EVIDENCE_PATH = join(RUNS_DIR, "agent-loop-evidence.json");
const { runAgentLoop } = await import("./model-adapter.mjs");

function listen(server) {
    return new Promise((resolve) => {
        server.listen(0, "127.0.0.1", () => resolve(server.address().port));
    });
}

function close(server) {
    return new Promise((resolve) => server.close(resolve));
}

function stubModelServer() {
    return http.createServer((req, res) => {
        let body = "";
        req.on("data", (c) => { body += c; });
        req.on("end", () => {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({
                choices: [{
                    message: {
                        content: [
                            "ACTION: GET|/healthz|",
                            'ACTION: POST|/verify|{"scope":"login","token":"stub"}',
                        ].join("\n"),
                    },
                }],
            }));
        });
    });
}

function stubTargetServer() {
    return http.createServer((req, res) => {
        if (req.url === "/healthz") {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: true }));
            return;
        }
        if (req.url === "/verify") {
            res.writeHead(403, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: false, error: { code: "invalid_token" } }));
            return;
        }
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: { code: "not_found" } }));
    });
}

const configured = Boolean(process.env.KIWI_RT_LOCAL_LLM_URL);
let modelKind = configured ? "configured" : "stub";
let report;
let modelServer = null;
let targetServer = null;

try {
    let targetBaseUrl;
    if (configured) {
        // The real target the orchestrator configured; the adapter
        // reads it from KIWI_RT_TARGET_BASE_URL / the profile env.
        targetBaseUrl = process.env.KIWI_RT_TARGET_BASE_URL || undefined;
    } else {
        modelServer = stubModelServer();
        targetServer = stubTargetServer();
        const modelPort = await listen(modelServer);
        const targetPort = await listen(targetServer);
        process.env.KIWI_RT_LOCAL_LLM_URL = `http://127.0.0.1:${modelPort}`;
        process.env.KIWI_RT_LOCAL_LLM_KIND = process.env.KIWI_RT_LOCAL_LLM_KIND ?? "openai";
        targetBaseUrl = `http://127.0.0.1:${targetPort}`;
    }
    report = await runAgentLoop({
        seed: Number(process.env.KIWI_RT_SEED ?? "0x6b776d74"),
        targetBaseUrl,
    });
} catch (err) {
    report = { consulted: false, reason: String(err.message ?? err).slice(0, 200) };
} finally {
    if (modelServer) await close(modelServer);
    if (targetServer) await close(targetServer);
    if (!configured) delete process.env.KIWI_RT_LOCAL_LLM_URL;
}

const consulted = report.consulted === true;
const evidence = {
    schema: "kiwicaptcha.redteam.llm-consult/1",
    consulted,
    model_kind: modelKind,
    reason: report.reason ?? null,
    summary: report.summary ?? null,
    actions: Array.isArray(report.actions) ? report.actions.length : 0,
    triage: (report.triage ?? []).map((t) => ({ verdict: t.verdict, path: t.action?.rawPath ?? null })),
    recorded_at: new Date().toISOString(),
};
mkdirSync(RUNS_DIR, { recursive: true });
writeFileSync(EVIDENCE_PATH, JSON.stringify(evidence, null, 2) + "\n");

console.log(
    `LLM-CONSULT: consulted=${consulted ? "true" : "false"} model_kind=${modelKind}`
    + ` actions=${evidence.actions}`
    + ` reproduced=${report.summary?.reproduced ?? 0}`
    + ` refuted=${report.summary?.refuted ?? 0}`
    + ` evidence=tools/redteam/engine/runs/agent-loop-evidence.json`
    + (consulted ? "" : ` reason=${evidence.reason ?? "unknown"}`),
);
process.exit(consulted ? 0 : 3);
