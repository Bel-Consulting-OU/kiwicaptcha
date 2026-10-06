#!/usr/bin/env node
/**
 * model-adapter.mjs — the local-model adapter of the exploit
 * synthesis agent, the constrained agent loop that drives the harness
 * when a model is configured, and the exact request and response
 * contract for the three documented self-hosted runtimes.
 *
 * Contract (change.md Part 10.1): open-weight models served by a
 * local runtime on the operator's own hardware; no external API is
 * ever called. The adapter is NEVER invoked unless the operator
 * exports KIWI_RT_LOCAL_LLM_URL; CI never sets it, so the engine's
 * default mode is fully deterministic and offline.
 *
 * Supported runtimes, selected with KIWI_RT_LOCAL_LLM_KIND:
 *
 *   llamacpp  llama.cpp server (llama-server):
 *             POST {url}/completion
 *             {"prompt": STR, "n_predict": 512, "temperature": 0,
 *              "seed": INT, "cache_prompt": true}
 *             -> {"content": STR, "stop_reason": ...}
 *
 *   vllm      vLLM OpenAI-compatible server:
 *             POST {url}/v1/completions
 *             {"model": STR (KIWI_RT_LOCAL_LLM_MODEL), "prompt": STR,
 *              "max_tokens": 512, "temperature": 0, "seed": INT}
 *             -> {"choices": [{"text": STR}]}
 *
 *   ollama    Ollama generate:
 *             POST {url}/api/generate
 *             {"model": STR, "prompt": STR, "stream": false,
 *              "options": {"temperature": 0, "seed": INT,
 *                          "num_predict": 512}}
 *             -> {"response": STR}
 *
 *   openai    any OpenAI-compatible chat endpoint already bound to
 *             the operator's own host:
 *             POST {url}/v1/chat/completions
 *             {"model": STR, "messages": [{"role": "user",
 *              "content": STR}], "temperature": 0, "seed": INT}
 *             -> {"choices": [{"message": {"content": STR}}]}
 *
 * Guardrails, enforced in code:
 *   - the URL host must resolve ONLY to loopback or private-range
 *     addresses (EVERY resolved address is checked, not any one);
 *   - the address is resolved once and pinned: the connection goes to
 *     that IP with the original Host header (and SNI when TLS), so a
 *     DNS-rebinding answer after the check cannot redirect the socket;
 *   - temperature is pinned to 0 and the seed is the run seed, so a
 *     model run is reproducible;
 *   - the prompt is the pinned file under engine/prompts/, never
 *     inline text;
 *   - model output is parsed into a constrained action list (HTTP
 *     method + allowlisted path + JSON body) and executed ONLY against
 *     the configured staging/local target base URL. No arbitrary
 *     command execution exists in this path. Off-host redirects are
 *     rejected. Timeouts and a max-action cap bound the loop.
 *
 * Offline/deterministic mode: with no KIWI_RT_LOCAL_LLM_URL the
 * adapter never opens a socket and the engine stays a pure function of
 * its seed.
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import http from "node:http";
import { createHash } from "node:crypto";
import dns from "node:dns";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
export const PROMPTS_DIR = join(ENGINE_DIR, "prompts");

/** The only HTTP surfaces the agent loop may touch. */
export const ALLOWED_ROUTES = new Set(["/healthz", "/challenge", "/verify"]);
const ALLOWED_METHODS = new Set(["GET", "POST"]);
const MAX_BODY_BYTES = 2048;
const DEFAULT_MAX_ACTIONS = 24;
const DEFAULT_TIMEOUT_MS = 15000;

export function isPrivateHost(host) {
    if (!host) return false;
    const name = host.replace(/^\[|\]$/g, "");
    if (name === "localhost" || name.endsWith(".localhost")) return true;
    if (net.isIPv4(name)) {
        const [a, b] = name.split(".").map(Number);
        return a === 127 || a === 10 || (a === 192 && b === 168)
            || (a === 172 && b >= 16 && b <= 31)
            || (a === 169 && b === 254);
    }
    if (net.isIPv6(name)) {
        const lower = name.toLowerCase();
        return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd")
            || lower.startsWith("fe80");
    }
    return false;
}

/**
 * Resolve `hostname` once and require EVERY returned address to be
 * private. Returns the single pinned address the caller must connect
 * to. The injectable `lookup` exists for tests; production uses dns.
 */
export async function resolvePinnedAddress(hostname, lookup = dns.promises.lookup) {
    if (isPrivateHost(hostname)) {
        // Literal private address: pin to itself, no DNS involved.
        return hostname.replace(/^\[|\]$/g, "");
    }
    let addresses;
    try {
        addresses = await lookup(hostname, { all: true });
    } catch {
        throw new Error(`guardrail: host does not resolve: ${hostname}`);
    }
    if (!Array.isArray(addresses) || addresses.length === 0) {
        throw new Error(`guardrail: host does not resolve: ${hostname}`);
    }
    for (const entry of addresses) {
        const addr = typeof entry === "string" ? entry : entry.address;
        if (!isPrivateHost(addr)) {
            throw new Error(
                `guardrail: host ${hostname} resolves to non-private address ${addr};`
                + " every resolved address must be private",
            );
        }
    }
    const first = typeof addresses[0] === "string" ? addresses[0] : addresses[0].address;
    return first.replace(/^\[|\]$/g, "");
}

function parseHttpUrl(url) {
    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        throw new Error(`local-model url is not a url: ${url}`);
    }
    if (parsed.protocol !== "http:") {
        throw new Error(`local-model url must be plain http on the operator's own host: ${url}`);
    }
    return parsed;
}

/**
 * Guard + pin a base URL. Returns { url, hostname, port, pinnedAddress }.
 * `lookup` is injectable for tests.
 */
export async function guardAndPin(url, lookup = dns.promises.lookup) {
    const parsed = parseHttpUrl(url);
    const pinnedAddress = await resolvePinnedAddress(parsed.hostname, lookup);
    return {
        url: parsed.toString(),
        hostname: parsed.hostname,
        port: parsed.port ? Number(parsed.port) : 80,
        pinnedAddress,
        pathPrefix: parsed.pathname.replace(/\/$/, ""),
    };
}

/**
 * One HTTP round trip to `pinned` (from guardAndPin). Connects to the
 * pinned IP with the original Host header so a later DNS answer cannot
 * rebind the socket. Never follows redirects: a 3xx is returned as-is
 * and the caller rejects off-host Location values.
 */
export function pinnedRequest(pinned, { method = "GET", path = "/", headers = {}, body = null, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            host: pinned.pinnedAddress,
            port: pinned.port,
            method,
            path,
            headers: {
                host: pinned.hostname + (pinned.port === 80 ? "" : `:${pinned.port}`),
                ...headers,
            },
            // Never follow redirects automatically.
            setHost: false,
        }, (res) => {
            const chunks = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
                resolve({
                    status: res.statusCode ?? 0,
                    headers: res.headers,
                    raw: Buffer.concat(chunks).toString("utf8"),
                });
            });
        });
        req.setTimeout(timeoutMs, () => {
            req.destroy(new Error(`request timed out after ${timeoutMs}ms`));
        });
        req.on("error", reject);
        if (body !== null && body !== undefined) req.write(body);
        req.end();
    });
}

function assertNoRedirectOffHost(res, pinned) {
    const location = res.headers?.location;
    if (res.status < 300 || res.status >= 400 || !location) return;
    let target;
    try {
        target = new URL(location, `http://${pinned.hostname}${pinned.pathPrefix || ""}/`);
    } catch {
        throw new Error(`guardrail: unparsable redirect location: ${location}`);
    }
    if (target.hostname !== pinned.hostname) {
        throw new Error(
            `guardrail: refusing off-host redirect to ${target.hostname} (allowlisted host is ${pinned.hostname})`,
        );
    }
}

async function postJsonPinned(pinned, path, body, timeoutMs = 120000) {
    const payload = JSON.stringify(body);
    const res = await pinnedRequest(pinned, {
        method: "POST",
        path,
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
        body: payload,
        timeoutMs,
    });
    assertNoRedirectOffHost(res, pinned);
    if (res.status < 200 || res.status >= 300) {
        throw new Error(`local model answered http ${res.status}`);
    }
    try {
        return JSON.parse(res.raw);
    } catch {
        throw new Error("local model answered non-json body");
    }
}

export function pinnedPrompt(name, substitutions = {}) {
    let text = readFileSync(join(PROMPTS_DIR, name), "utf8");
    for (const [key, value] of Object.entries(substitutions)) {
        text = text.replaceAll(`{{${key}}}`, String(value));
    }
    return text;
}

/**
 * One completion against the configured local runtime. Returns the
 * raw text; never evaluated, never executed here.
 */
export async function complete({ url, kind, model, prompt, seed, lookup, timeoutMs }) {
    if (!url) throw new Error("no local model url configured");
    const pinned = await guardAndPin(url, lookup);
    const kind_ = kind ?? "openai";
    let path;
    let body;
    // Endpoint paths are the documented root-relative routes; the
    // original URL's path is a prefix only for the agent-loop target.
    if (kind_ === "llamacpp") {
        path = "/completion";
        body = { prompt, n_predict: 512, temperature: 0, seed, cache_prompt: true };
    } else if (kind_ === "vllm") {
        path = "/v1/completions";
        body = { model, prompt, max_tokens: 512, temperature: 0, seed };
    } else if (kind_ === "ollama") {
        path = "/api/generate";
        body = { model, prompt, stream: false, options: { temperature: 0, seed, num_predict: 512 } };
    } else {
        path = "/v1/chat/completions";
        body = {
            model,
            messages: [{ role: "user", content: prompt }],
            temperature: 0,
            seed,
        };
    }
    const doc = await postJsonPinned(pinned, path, body, timeoutMs);
    if (kind_ === "llamacpp") return String(doc.content ?? "");
    if (kind_ === "ollama") return String(doc.response ?? "");
    return String(doc.choices?.[0]?.text ?? doc.choices?.[0]?.message?.content ?? "");
}

/**
 * The offline gate the orchestrator uses: without an explicitly
 * configured local runtime the adapter is a no-op that reports why.
 */
export async function optionalCompletion({ seed }) {
    const url = process.env.KIWI_RT_LOCAL_LLM_URL;
    if (!url) return { consulted: false, reason: "offline mode: KIWI_RT_LOCAL_LLM_URL not set" };
    const kind = process.env.KIWI_RT_LOCAL_LLM_KIND ?? "openai";
    const model = process.env.KIWI_RT_LOCAL_LLM_MODEL ?? "local";
    const promptName = process.env.KIWI_RT_LOCAL_LLM_PROMPT ?? "synth.prompt.md";
    const prompt = pinnedPrompt(promptName, { seed: seed.toString(16) });
    const text = await complete({ url, kind, model, prompt, seed });
    return { consulted: true, text };
}

// ---------------------------------------------------------------------------
// The constrained agent loop (Task B): plan -> actions -> execute -> triage.
// ---------------------------------------------------------------------------

/**
 * Parse a model plan into a constrained action list. Unknown shapes are
 * rejected into `rejected` and never executed.
 *
 * Line shape: ACTION: <METHOD>|<path>|<json-body-or-empty>
 */
export function parsePlan(text, { allowedRoutes = ALLOWED_ROUTES, maxActions = DEFAULT_MAX_ACTIONS } = {}) {
    const actions = [];
    const rejected = [];
    const lines = String(text ?? "").split("\n");
    for (const raw of lines) {
        const line = raw.trim();
        if (!line.startsWith("ACTION:")) continue;
        const spec = line.slice("ACTION:".length).trim();
        const parts = spec.split("|");
        if (parts.length < 2 || parts.length > 3) {
            rejected.push({ line: line.slice(0, 160), reason: "expected METHOD|path|body" });
            continue;
        }
        const method = parts[0].trim().toUpperCase();
        const path = parts[1].trim();
        const bodyText = (parts[2] ?? "").trim();
        if (!ALLOWED_METHODS.has(method)) {
            rejected.push({ line: line.slice(0, 160), reason: `method ${method} not allowed` });
            continue;
        }
        if (!path.startsWith("/") || path.includes("://") || path.includes("@") || path.includes("\\")) {
            rejected.push({ line: line.slice(0, 160), reason: "path must be origin-relative and contain no scheme/userinfo" });
            continue;
        }
        if (path.includes("..")) {
            rejected.push({ line: line.slice(0, 160), reason: "path traversal refused" });
            continue;
        }
        const route = path.split("?")[0];
        if (!allowedRoutes.has(route)) {
            rejected.push({ line: line.slice(0, 160), reason: `route ${route} is not on the allowlist` });
            continue;
        }
        if (method === "GET" && bodyText !== "") {
            rejected.push({ line: line.slice(0, 160), reason: "GET must carry an empty body" });
            continue;
        }
        let body = null;
        if (method === "POST") {
            if (!bodyText) {
                rejected.push({ line: line.slice(0, 160), reason: "POST requires a JSON body" });
                continue;
            }
            if (Buffer.byteLength(bodyText, "utf8") > MAX_BODY_BYTES) {
                rejected.push({ line: line.slice(0, 160), reason: `body exceeds ${MAX_BODY_BYTES} bytes` });
                continue;
            }
            try {
                body = JSON.parse(bodyText);
            } catch {
                rejected.push({ line: line.slice(0, 160), reason: "body is not valid JSON" });
                continue;
            }
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                rejected.push({ line: line.slice(0, 160), reason: "body must be a JSON object" });
                continue;
            }
        }
        if (actions.length >= maxActions) {
            rejected.push({ line: line.slice(0, 160), reason: `max action cap ${maxActions} reached` });
            continue;
        }
        actions.push({ method, path: route, rawPath: path, body });
    }
    return { actions, rejected };
}

/**
 * Deterministic triage of one action result. Same (action, result)
 * always yields the same verdict — this is a pure function.
 *
 * Verdicts:
 *   REPRODUCED    the target accepted an action that should have been
 *                 refused (a finding candidate)
 *   REFUTED       the target refused the action (the expected behavior)
 *   OBSERVED      informational surface (healthz / challenge issue)
 *   INCONCLUSIVE  the transport failed or the answer is unparsable
 */
export function triageActionResult(action, result) {
    const { method, path } = action;
    const status = result.status ?? 0;
    let body = null;
    if (result.raw) {
        try { body = JSON.parse(result.raw); } catch { body = null; }
    }
    if (!status) {
        return { verdict: "INCONCLUSIVE", reason: "transport failure or timeout", status };
    }
    if (status >= 500) {
        return { verdict: "INCONCLUSIVE", reason: `server error ${status}`, status };
    }
    if (path === "/healthz") {
        return { verdict: "OBSERVED", reason: `healthz http ${status}`, status };
    }
    if (path === "/challenge") {
        // Issuing a challenge is expected; a hard refusal is also fine.
        return { verdict: "OBSERVED", reason: `challenge issue http ${status}`, status };
    }
    if (path === "/verify") {
        // The agent loop never pays a proof of work, so a 2xx with
        // ok:true on /verify is an unpaid acceptance — a finding.
        if (status >= 200 && status < 300 && body && body.ok === true) {
            return { verdict: "REPRODUCED", reason: "verify accepted without a paid solve", status, code: body.error?.code ?? body.code ?? "accepted" };
        }
        return { verdict: "REFUTED", reason: `verify refused http ${status}`, status, code: body?.error?.code ?? body?.code ?? `http_${status}` };
    }
    return { verdict: "REFUTED", reason: `unexpected route ${path} answered http ${status}`, status };
}

function readTargetBaseUrl() {
    if (process.env.KIWI_RT_TARGET_BASE_URL) return process.env.KIWI_RT_TARGET_BASE_URL;
    const profile = process.env.KIWI_RT_PROFILE ?? "redis";
    const state = join(ENGINE_DIR, "..", "runs", "env", `${profile}.env`);
    if (existsSync(state)) {
        for (const line of readFileSync(state, "utf8").split("\n")) {
            if (line.startsWith("BASE_URL=")) return line.slice("BASE_URL=".length).trim();
        }
    }
    return "";
}

/**
 * The agent loop. When no model URL is configured this returns
 * { consulted: false } and opens no socket (offline determinism).
 * When configured it: requests a plan, parses a constrained action
 * list, executes those actions ONLY against the configured staging/
 * local target base URL, and triages the results deterministically.
 */
export async function runAgentLoop({
    seed = 0,
    targetBaseUrl,
    lookup,
    timeoutMs = Number(process.env.KIWI_RT_AGENT_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS),
    maxActions = Number(process.env.KIWI_RT_AGENT_MAX_ACTIONS ?? DEFAULT_MAX_ACTIONS),
} = {}) {
    const url = process.env.KIWI_RT_LOCAL_LLM_URL;
    if (!url) {
        return {
            consulted: false,
            reason: "offline mode: KIWI_RT_LOCAL_LLM_URL not set; agent loop not entered",
            actions: [],
            results: [],
            triage: [],
        };
    }

    const baseUrl = targetBaseUrl ?? readTargetBaseUrl();
    if (!baseUrl) {
        throw new Error("agent loop: no staging/local target base URL (set KIWI_RT_TARGET_BASE_URL)");
    }
    const target = await guardAndPin(baseUrl, lookup);

    const kind = process.env.KIWI_RT_LOCAL_LLM_KIND ?? "openai";
    const model = process.env.KIWI_RT_LOCAL_LLM_MODEL ?? "local";
    const promptName = process.env.KIWI_RT_LOCAL_LLM_PROMPT ?? "agent.prompt.md";
    const prompt = pinnedPrompt(promptName, { seed: Number(seed).toString(16) });
    const planText = await complete({ url, kind, model, prompt, seed, lookup, timeoutMs });

    const { actions, rejected } = parsePlan(planText, { maxActions });

    const results = [];
    const triage = [];
    for (const action of actions) {
        let result;
        try {
            const payload = action.body === null
                ? null
                : JSON.stringify(action.body);
            result = await pinnedRequest(target, {
                method: action.method,
                path: action.rawPath,
                headers: payload === null
                    ? {}
                    : {
                        "content-type": "application/json",
                        "content-length": Buffer.byteLength(payload),
                    },
                body: payload,
                timeoutMs,
            });
            assertNoRedirectOffHost(result, target);
        } catch (err) {
            result = { status: 0, headers: {}, raw: "" };
            triage.push({
                action,
                verdict: "INCONCLUSIVE",
                reason: String(err.message ?? err).slice(0, 160),
                status: 0,
            });
            results.push({ action, result });
            continue;
        }
        results.push({ action, result });
        triage.push(triageActionResult(action, result));
    }

    return {
        consulted: true,
        planText,
        actions,
        rejected,
        results: results.map(({ action, result }) => ({
            action,
            status: result.status,
            // Body is summarized, never executed.
            bodyPreview: String(result.raw ?? "").slice(0, 200),
        })),
        triage,
        summary: {
            actions: actions.length,
            rejected: rejected.length,
            reproduced: triage.filter((t) => t.verdict === "REPRODUCED").length,
            refuted: triage.filter((t) => t.verdict === "REFUTED").length,
            observed: triage.filter((t) => t.verdict === "OBSERVED").length,
            inconclusive: triage.filter((t) => t.verdict === "INCONCLUSIVE").length,
        },
        target: { hostname: target.hostname, pinnedAddress: target.pinnedAddress },
    };
}

/**
 * The novelty scorer of the aggressiveness mandate (change.md 10.2).
 *
 * With a configured model, the model's completion would rank the
 * candidate lineages. In CI mode (KIWI_RT_LOCAL_LLM_URL unset) this is
 * the documented no-op adapter: a deterministic hash of the candidate
 * class against the surface map and the run history, so a candidate
 * aimed at a surface the ledger has never recorded scores highest and
 * the allocation stays reproducible. The score is honest about what it
 * is: a stable ordering function, not a model judgment.
 */
export function scoreNovelty({ candidate, surface, runHistory }) {
    const digest = createHash("sha256")
        .update(`${candidate.class}|${candidate.mutation}|${candidate.target}`)
        .digest();
    const seen = runHistory.filter(
        (run) => run.campaign && candidate.target && run.campaign.includes(candidate.class),
    ).length;
    // 0..999: the hash gives the stable base, unseen surfaces bump up.
    const base = digest.readUInt16BE(0) % 1000;
    return { score: Math.min(999, base + (seen === 0 ? 100 : 0)), seenInHistory: seen };
}

/** The honest method note the outputs carry in CI mode. */
export function methodNote() {
    if (process.env.KIWI_RT_LOCAL_LLM_URL) {
        const kind = process.env.KIWI_RT_LOCAL_LLM_KIND ?? "openai";
        return `local model configured (kind=${kind}); the agent loop parses a constrained action list and executes it only against the allowlisted staging target; candidates and actions pass the deterministic triage gate`;
    }
    return "no local model is configured (KIWI_RT_LOCAL_LLM_URL unset); the synthesis corpus is the deterministic seeded grammar and the novelty ordering is the documented no-op scorer";
}

// CLI: run the agent loop once and print its deterministic triage
// report. Offline mode prints the honest no-op line and exits 0 so CI
// keeps working with no model configured.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    const seed = Number(process.env.KIWI_RT_SEED ?? "0x6b776d74");
    try {
        const report = await runAgentLoop({ seed });
        console.log(JSON.stringify(report, null, 2));
        if (!report.consulted) {
            console.log(`agent-loop: ${report.reason}`);
            process.exit(0);
        }
        // A reproduced unpaid acceptance is a finding candidate: the
        // caller (triage / the orchestrator) decides what to file.
        process.exit(report.summary.reproduced > 0 ? 1 : 0);
    } catch (err) {
        console.error(`agent-loop: ${err.message ?? err}`);
        process.exit(2);
    }
}
