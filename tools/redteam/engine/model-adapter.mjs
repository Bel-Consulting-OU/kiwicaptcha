#!/usr/bin/env node
/**
 * model-adapter.mjs — the local-model adapter of the exploit
 * synthesis agent, and the exact request and response contract for
 * the three documented self-hosted runtimes.
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
 * Guardrails, enforced in code: the URL host must be a loopback or
 * private-range address (refused otherwise); temperature is pinned to
 * 0 and the seed is the run seed, so a model run is reproducible; the
 * prompt is the pinned file under engine/prompts/, never inline text;
 * the adapter never executes model output, it only returns candidate
 * text for the deterministic triage gate.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import dns from "node:dns";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
export const PROMPTS_DIR = join(ENGINE_DIR, "prompts");

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

function assertPrivateUrl(url) {
    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        throw new Error(`local-model url is not a url: ${url}`);
    }
    if (parsed.protocol !== "http:") {
        throw new Error(`local-model url must be plain http on the operator's own host: ${url}`);
    }
    const go = (addresses) => {
        if (!addresses.some((address) => isPrivateHost(address))) {
            throw new Error(`guardrail: local-model host ${parsed.host} is outside the private range allowlist`);
        }
    };
    if (isPrivateHost(parsed.hostname)) return;
    // Hostnames resolve before the guardrail answers; a name that
    // resolves public is refused.
    return new Promise((resolve, reject) => {
        dns.lookup(parsed.hostname, { all: true }, (err, addresses) => {
            if (err) reject(new Error(`local-model host does not resolve: ${parsed.hostname}`));
            else {
                try {
                    go(addresses.map((entry) => entry.address));
                    resolve();
                } catch (guardError) {
                    reject(guardError);
                }
            }
        });
    });
}

export function pinnedPrompt(name, substitutions = {}) {
    let text = readFileSync(join(PROMPTS_DIR, name), "utf8");
    for (const [key, value] of Object.entries(substitutions)) {
        text = text.replaceAll(`{{${key}}}`, String(value));
    }
    return text;
}

async function postJson(url, body, timeoutMs = 120000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
            signal: controller.signal,
        });
        if (!response.ok) throw new Error(`local model answered http ${response.status}`);
        return await response.json();
    } finally {
        clearTimeout(timer);
    }
}

/**
 * One completion against the configured local runtime. Returns the
 * raw text; never evaluated, never executed here.
 */
export async function complete({ url, kind, model, prompt, seed }) {
    if (!url) throw new Error("no local model url configured");
    await assertPrivateUrl(url);
    const kind_ = kind ?? "openai";
    let endpoint;
    let body;
    if (kind_ === "llamacpp") {
        endpoint = new URL("/completion", url).toString();
        body = { prompt, n_predict: 512, temperature: 0, seed, cache_prompt: true };
    } else if (kind_ === "vllm") {
        endpoint = new URL("/v1/completions", url).toString();
        body = { model, prompt, max_tokens: 512, temperature: 0, seed };
    } else if (kind_ === "ollama") {
        endpoint = new URL("/api/generate", url).toString();
        body = { model, prompt, stream: false, options: { temperature: 0, seed, num_predict: 512 } };
    } else {
        endpoint = new URL("/v1/chat/completions", url).toString();
        body = {
            model,
            messages: [{ role: "user", content: prompt }],
            temperature: 0,
            seed,
        };
    }
    const doc = await postJson(endpoint, body);
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
