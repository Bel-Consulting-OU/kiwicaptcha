/**
 * model-adapter.test.mjs — offline tests for the local-model adapter
 * and the constrained agent loop. No live model is required: the LLM
 * and the staging target are local http servers started in-process,
 * and the DNS lookup is injected.
 *
 * Run: node --test tools/redteam/engine/test/
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
    isPrivateHost,
    resolvePinnedAddress,
    guardAndPin,
    parsePlan,
    triageActionResult,
    runAgentLoop,
    complete,
    optionalCompletion,
    methodNote,
    ALLOWED_ROUTES,
} from "../model-adapter.mjs";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const REPROS = join(ENGINE_DIR, "..", "repros");

function listen(server) {
    return new Promise((resolve) => {
        server.listen(0, "127.0.0.1", () => resolve(server.address().port));
    });
}

function close(server) {
    return new Promise((resolve) => server.close(resolve));
}

describe("isPrivateHost", () => {
    test("loopback and RFC1918 and link-local are private", () => {
        for (const host of [
            "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "172.31.255.255",
            "169.254.1.1", "localhost", "app.localhost", "::1", "fc00::1", "fd12::1", "fe80::1",
        ]) {
            assert.equal(isPrivateHost(host), true, host);
        }
    });

    test("public addresses are not private", () => {
        for (const host of [
            "8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.0.1", "example.com",
            "2001:4860:4860::8888", "", null,
        ]) {
            assert.equal(isPrivateHost(host), false, String(host));
        }
    });
});

describe("resolvePinnedAddress — every resolved address must be private", () => {
    test("accepts when every address is private and pins the first", async () => {
        const lookup = async () => [
            { address: "127.0.0.1", family: 4 },
            { address: "10.1.2.3", family: 4 },
        ];
        assert.equal(await resolvePinnedAddress("target.internal", lookup), "127.0.0.1");
    });

    test("rejects when ANY resolved address is public (the old some() bug)", async () => {
        const lookup = async () => [
            { address: "127.0.0.1", family: 4 },
            { address: "8.8.8.8", family: 4 },
        ];
        await assert.rejects(
            () => resolvePinnedAddress("rebind.example", lookup),
            /every resolved address must be private/,
        );
    });

    test("rejects when the only address is public", async () => {
        const lookup = async () => [{ address: "93.184.216.34", family: 4 }];
        await assert.rejects(
            () => resolvePinnedAddress("evil.example", lookup),
            /non-private address/,
        );
    });

    test("literal private address pins to itself without DNS", async () => {
        let called = 0;
        const lookup = async () => { called += 1; return []; };
        assert.equal(await resolvePinnedAddress("192.168.0.10", lookup), "192.168.0.10");
        assert.equal(called, 0);
    });

    test("resolve failure is a guardrail refusal", async () => {
        const lookup = async () => { throw new Error("ENOTFOUND"); };
        await assert.rejects(
            () => resolvePinnedAddress("nowhere.internal", lookup),
            /does not resolve/,
        );
    });
});

describe("parsePlan — constrained action list", () => {
    test("accepts allowlisted GET/POST actions", () => {
        const plan = [
            "ACTION: GET|/healthz|",
            'ACTION: POST|/challenge|{"scope":"login"}',
            'ACTION: POST|/verify|{"scope":"login","token":"x"}',
        ].join("\n");
        const { actions, rejected } = parsePlan(plan);
        assert.equal(actions.length, 3);
        assert.equal(rejected.length, 0);
        assert.equal(actions[0].method, "GET");
        assert.equal(actions[1].path, "/challenge");
        assert.deepEqual(actions[1].body, { scope: "login" });
    });

    test("rejects off-allowlist routes, schemes, userinfo and traversal", () => {
        const plan = [
            "ACTION: POST|/admin|{}",
            "ACTION: GET|http://evil.example/healthz|",
            "ACTION: GET|/../etc/passwd|",
            "ACTION: GET|//evil.example/healthz|",
            "ACTION: DELETE|/verify|",
            'ACTION: POST|/verify|[1,2]',
            "ACTION: POST|/verify|not-json",
            "ACTION: GET|/verify|{}",
        ].join("\n");
        const { actions, rejected } = parsePlan(plan);
        assert.equal(actions.length, 0);
        assert.equal(rejected.length, 8);
    });

    test("caps the number of actions", () => {
        const plan = Array.from({ length: 5 }, () => "ACTION: GET|/healthz|").join("\n");
        const { actions, rejected } = parsePlan(plan, { maxActions: 2 });
        assert.equal(actions.length, 2);
        assert.equal(rejected.length, 3);
        assert.match(rejected[0].reason, /max action cap/);
    });

    test("only the allowlisted routes may appear in an action", () => {
        const { actions } = parsePlan("ACTION: GET|/healthz|");
        assert.ok(ALLOWED_ROUTES.has(actions[0].path));
    });
});

describe("triageActionResult — deterministic verdicts", () => {
    const verify = { method: "POST", path: "/verify", rawPath: "/verify", body: {} };

    test("same inputs always produce the same verdict", () => {
        const result = { status: 200, raw: '{"ok":true}' };
        const a = triageActionResult(verify, result);
        const b = triageActionResult(verify, result);
        assert.deepEqual(a, b);
    });

    test("unpaid verify acceptance is REPRODUCED", () => {
        const t = triageActionResult(verify, { status: 200, raw: '{"ok":true}' });
        assert.equal(t.verdict, "REPRODUCED");
    });

    test("verify refusal is REFUTED", () => {
        const t = triageActionResult(verify, {
            status: 403,
            raw: '{"ok":false,"error":{"code":"invalid_token"}}',
        });
        assert.equal(t.verdict, "REFUTED");
        assert.equal(t.code, "invalid_token");
    });

    test("challenge and healthz are OBSERVED", () => {
        assert.equal(
            triageActionResult({ method: "POST", path: "/challenge" }, { status: 200, raw: "{}" }).verdict,
            "OBSERVED",
        );
        assert.equal(
            triageActionResult({ method: "GET", path: "/healthz" }, { status: 200, raw: "{}" }).verdict,
            "OBSERVED",
        );
    });

    test("transport failure is INCONCLUSIVE, never a quiet pass", () => {
        assert.equal(
            triageActionResult(verify, { status: 0, raw: "" }).verdict,
            "INCONCLUSIVE",
        );
    });
});

describe("agent loop — sandbox and offline mode", () => {
    test("offline mode consults nothing and stays deterministic", async () => {
        delete process.env.KIWI_RT_LOCAL_LLM_URL;
        const a = await runAgentLoop({ seed: 0x1 });
        const b = await runAgentLoop({ seed: 0x1 });
        assert.equal(a.consulted, false);
        assert.match(a.reason, /offline mode/);
        assert.deepEqual(a.triage, []);
        assert.deepEqual(a, b);
    });

    test("optionalCompletion offline reports why and does not throw", async () => {
        delete process.env.KIWI_RT_LOCAL_LLM_URL;
        const res = await optionalCompletion({ seed: 1 });
        assert.equal(res.consulted, false);
        assert.match(res.reason, /KIWI_RT_LOCAL_LLM_URL not set/);
    });

    test("method note is honest in both modes", () => {
        delete process.env.KIWI_RT_LOCAL_LLM_URL;
        assert.match(methodNote(), /no local model is configured/);
        process.env.KIWI_RT_LOCAL_LLM_URL = "http://127.0.0.1:9/";
        assert.match(methodNote(), /local model configured/);
        delete process.env.KIWI_RT_LOCAL_LLM_URL;
    });

    test("rejects a model URL whose host is public", async () => {
        process.env.KIWI_RT_LOCAL_LLM_URL = "http://example.com/";
        try {
            await assert.rejects(
                () => complete({ url: process.env.KIWI_RT_LOCAL_LLM_URL, prompt: "x", seed: 1 }),
                /guardrail|private|resolve/,
            );
        } finally {
            delete process.env.KIWI_RT_LOCAL_LLM_URL;
        }
    });
});

describe("agent loop end to end against a local model and local target", () => {
    let modelServer;
    let targetServer;
    let modelPort;
    let targetPort;
    let targetHits;

    before(async () => {
        targetHits = [];
        modelServer = http.createServer((req, res) => {
            let body = "";
            req.on("data", (c) => { body += c; });
            req.on("end", () => {
                // The plan: one accepted-looking verify (finding), one
                // refused verify, one healthz, plus a rejected action.
                res.writeHead(200, { "content-type": "application/json" });
                res.end(JSON.stringify({
                    choices: [{
                        message: {
                            content: [
                                'ACTION: GET|/healthz|',
                                'ACTION: POST|/verify|{"scope":"login","token":"unpaid"}',
                                'ACTION: POST|/verify|{"scope":"login","token":"also-unpaid"}',
                                "ACTION: POST|/admin|{}",
                            ].join("\n"),
                        },
                    }],
                }));
            });
        });
        targetServer = http.createServer((req, res) => {
            targetHits.push(`${req.method} ${req.url}`);
            if (req.url === "/healthz") {
                res.writeHead(200, { "content-type": "application/json" });
                res.end(JSON.stringify({ ok: true }));
                return;
            }
            if (req.url === "/verify") {
                let body = "";
                req.on("data", (c) => { body += c; });
                req.on("end", () => {
                    let token = "";
                    try { token = JSON.parse(body).token ?? ""; } catch { /* ignore */ }
                    if (token === "unpaid") {
                        // The stub target accepts the first unpaid token
                        // so the agent loop must classify it as a finding.
                        res.writeHead(200, { "content-type": "application/json" });
                        res.end(JSON.stringify({ ok: true }));
                    } else {
                        res.writeHead(403, { "content-type": "application/json" });
                        res.end(JSON.stringify({ ok: false, error: { code: "invalid_token" } }));
                    }
                });
                return;
            }
            res.writeHead(404, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: false, error: { code: "not_found" } }));
        });
        modelPort = await listen(modelServer);
        targetPort = await listen(targetServer);
    });

    after(async () => {
        await close(modelServer);
        await close(targetServer);
        delete process.env.KIWI_RT_LOCAL_LLM_URL;
    });

    test("plans, executes only allowlisted actions against the target, triages deterministically", async () => {
        process.env.KIWI_RT_LOCAL_LLM_URL = `http://127.0.0.1:${modelPort}`;
        process.env.KIWI_RT_LOCAL_LLM_KIND = "openai";
        const report = await runAgentLoop({
            seed: 0x6b776d74,
            targetBaseUrl: `http://127.0.0.1:${targetPort}`,
        });
        assert.equal(report.consulted, true);
        assert.equal(report.actions.length, 3);
        assert.equal(report.rejected.length, 1);
        assert.equal(report.summary.reproduced, 1);
        assert.equal(report.summary.refuted, 1);
        assert.equal(report.summary.observed, 1);
        // The rejected /admin action never reached the target.
        assert.ok(!targetHits.some((h) => h.includes("/admin")));
        // Deterministic: a second identical run yields the same triage.
        const again = await runAgentLoop({
            seed: 0x6b776d74,
            targetBaseUrl: `http://127.0.0.1:${targetPort}`,
        });
        assert.deepEqual(again.triage, report.triage);
    });

    test("complete() pins to loopback and reads the documented response shape", async () => {
        const text = await complete({
            url: `http://127.0.0.1:${modelPort}`,
            kind: "openai",
            model: "local",
            prompt: "P",
            seed: 1,
        });
        assert.match(text, /ACTION:/);
    });

    test("off-host redirects are rejected", async () => {
        // A tiny model that answers 302 to a public host.
        const redirector = http.createServer((req, res) => {
            res.writeHead(302, { location: "http://8.8.8.8/steal" });
            res.end();
        });
        const port = await listen(redirector);
        try {
            await assert.rejects(
                () => complete({
                    url: `http://127.0.0.1:${port}`,
                    kind: "openai",
                    model: "local",
                    prompt: "P",
                    seed: 1,
                }),
                /off-host redirect|http 302/,
            );
        } finally {
            await close(redirector);
        }
    });

    test("guardAndPin refuses a URL that resolves to a mixed public/private set", async () => {
        const lookup = async () => [
            { address: "10.0.0.1", family: 4 },
            { address: "1.2.3.4", family: 4 },
        ];
        await assert.rejects(
            () => guardAndPin("http://mixed.internal:8080/", lookup),
            /every resolved address must be private/,
        );
    });
});

describe("harness stubs are honest", () => {
    test("framing-ambiguity computes its verdict, it is not hardcoded", () => {
        const src = readFileSync(join(REPROS, "framing-ambiguity.sh"), "utf8");
        assert.ok(!/verdict\\":\\"REFUTED\\"/.test(src) && !src.includes('"verdict": "REFUTED"'),
            "framing-ambiguity.sh must not hardcode REFUTED");
        assert.match(src, /VERDICT=REPRODUCED/);
        assert.match(src, /VERDICT=INCONCLUSIVE/);
    });

    test("issuance-burst computes its verdict from the observed count", () => {
        const src = readFileSync(join(REPROS, "issuance-burst.sh"), "utf8");
        assert.ok(!src.includes('verdict": \\"REFUTED\\"') && !src.includes('\'verdict\': \'REFUTED\''),
            "issuance-burst.sh must not hardcode REFUTED");
        assert.match(src, /accepted.*>.*45/);
    });

    test("target_unavailable is INCONCLUSIVE, never a quiet REFUTED", () => {
        for (const name of ["clock-skew.sh", "epoch-manipulation.sh", "framing-ambiguity.sh", "issuance-burst.sh"]) {
            const src = readFileSync(join(REPROS, name), "utf8");
            if (src.includes("target_unavailable")) {
                assert.match(src, /INCONCLUSIVE[^]*target_unavailable|target_unavailable[^]*INCONCLUSIVE/,
                    `${name} must report INCONCLUSIVE when the target is unavailable`);
            }
        }
    });
});
