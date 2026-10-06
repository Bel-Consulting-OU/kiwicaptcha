#!/usr/bin/env node
/**
 * d313.supply.mjs — the D3.13 browser legs: supply chain, integrity
 * and host-page hostility, all in real chromium.
 *
 *   control      the clean page: the widget solves end to end (the
 *                baseline the tamper legs are measured against)
 *   sri tamper   the driver asset's response bytes are flipped
 *                mid-flight (the MITM shape of a compromised CDN or
 *                proxy): the integrity attributes must refuse the
 *                payload, the widget must fail closed, and nothing
 *                tampered may execute or solve
 *   sw mitm      a service worker rewrites every asset response with
 *                tampered bytes: the same refusal and fail-closed
 *                verdict, from a different interception layer
 *   pollution    the hostile host page pollutes Object.prototype and
 *                clobbers the driver's name spaces before and during
 *                the solve: the driver must survive and complete the
 *                solve; any observable breakage is reported as facts
 *                for a finding
 *
 * Output: one JSON document on stdout. The exit code covers the two
 * required results only (driver integrity and fail-closed loading);
 * the pollution facts are advisory data for the wrapper.
 */

import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TESTS_BROWSER = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../tests/browser");
const { chromium } = createRequire(join(TESTS_BROWSER, "package.json"))("@playwright/test");

const CLEAN = process.env.KIWI_RT_D313_CLEAN ?? "http://127.0.0.1:6471/";
const SW_PAGE = process.env.KIWI_RT_D313_SW ?? "http://127.0.0.1:6473/";
const POLLUTION = process.env.KIWI_RT_D313_POLLUTION ?? "http://127.0.0.1:6474/";
const OUT = process.env.KIWI_RT_D313_OUT ?? "";

const results = { control: {}, sri_tamper: {}, sw_mitm: {}, pollution: {} };

async function waitForSolve(page, timeoutMs = 90000) {
    await page.waitForFunction(() => {
        const input = document.querySelector("input[data-kiwi-token]");
        const badge = document.querySelector("[data-kiwi-badge]");
        const state = badge ? badge.getAttribute("data-state") ?? badge.textContent : "";
        return input && input.value && input.value.length > 0
            && !/fail|error|expired|unavailable/i.test(String(state));
    }, null, { timeout: timeoutMs, polling: 250 });
    return page.inputValue("input[data-kiwi-token]");
}

const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });

// ---------- control ----------
{
    const context = await browser.newContext();
    const page = await context.newPage();
    const consoleErrors = [];
    page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text().slice(0, 160)); });
    await page.goto(CLEAN, { waitUntil: "domcontentloaded" });
    try {
        const token = await waitForSolve(page);
        results.control = { solved: true, token_len: token.length, console_errors: consoleErrors.slice(0, 4) };
    } catch (err) {
        const badge = await page.evaluate(() => document.querySelector("[data-kiwi-badge]")?.getAttribute("data-state"));
        results.control = { solved: false, badge: badge, err: String(err).slice(0, 200) };
    }
    await context.close();
}

// ---------- the SRI tamper (the mid-flight byte flip) ----------
{
    const context = await browser.newContext();
    const page = await context.newPage();
    const blocked = [];
    page.on("console", (m) => {
        const text = m.text();
        if (/Failed to find a valid digest|integrity|error parsing/i.test(text)) {
            blocked.push(text.slice(0, 160));
        }
    });
    let tamperedAssets = 0;
    await page.route("**/kiwi-captcha/assets/driver.*.js", async (route) => {
        const response = await route.fetch();
        let body = (await response.text()).toString();
        // The one-byte flip, mid-flight: a tampered payload a naive
        // proxy would happily deliver.
        const cut = Math.floor(body.length / 2);
        body = body.slice(0, cut) + ";" + body.slice(cut + 1);
        tamperedAssets++;
        await route.fulfill({ status: response.status(), contentType: response.headers()["content-type"] ?? "text/javascript", body });
    });
    await page.goto(CLEAN, { waitUntil: "domcontentloaded" });
    let solved = false;
    try {
        await waitForSolve(page, 20000);
        solved = true;
    } catch {}
    const badge = await page.evaluate(() => document.querySelector("[data-kiwi-badge]")?.getAttribute("data-state"));
    const token = await page.evaluate(() => document.querySelector("input[data-kiwi-token]")?.value ?? "");
    results.sri_tamper = {
        tampered_responses: tamperedAssets,
        solved_despite_tamper: solved,
        widget_state: badge,
        token_len: token.length,
        console_blocked: blocked.slice(0, 4),
    };
    await context.close();
}

// ---------- the service worker MITM ----------
{
    const context = await browser.newContext();
    const page = await context.newPage();
    const blocked = [];
    page.on("console", (m) => {
        const text = m.text();
        if (/Failed to find a valid digest|integrity|error parsing/i.test(text)) {
            blocked.push(text.slice(0, 160));
        }
    });
    await page.goto(SW_PAGE, { waitUntil: "domcontentloaded" });
    // Wait out the SW registration and its activation.
    try {
        await page.waitForFunction(() => document.title.startsWith("sw-"), null, { timeout: 10000 });
    } catch {}
    await page.reload({ waitUntil: "domcontentloaded" });
    let solved = false;
    try {
        await waitForSolve(page, 20000);
        solved = true;
    } catch {}
    const badge = await page.evaluate(() => document.querySelector("[data-kiwi-badge]")?.getAttribute("data-state"));
    const swState = await page.evaluate(async () => {
        const reg = await navigator.serviceWorker.getRegistration();
        return reg ? (reg.active ? "active" : reg.installing ? "installing" : "waiting") : "none";
    });
    results.sw_mitm = {
        service_worker: swState,
        solved_despite_mitm: solved,
        widget_state: badge,
        console_blocked: blocked.slice(0, 4),
    };
    await context.close();
}

// ---------- the hostile host page (pollution + clobbering) ----------
{
    const context = await browser.newContext();
    const page = await context.newPage();
    const pageErrors = [];
    page.on("pageerror", (err) => pageErrors.push(String(err).slice(0, 160)));
    await page.goto(POLLUTION, { waitUntil: "domcontentloaded" });
    let solved = false;
    let tokenLen = 0;
    try {
        const token = await waitForSolve(page);
        solved = true;
        tokenLen = token.length;
    } catch {}
    const facts = await page.evaluate(() => ({
        polluted: ({}).kiwiMode === "attacker",
        clobbered: Boolean(document.getElementById("kiwiWidgets")),
        badge: document.querySelector("[data-kiwi-badge]")?.getAttribute("data-state"),
    }));
    results.pollution = {
        solved_under_pollution: solved,
        token_len: tokenLen,
        page_errors: pageErrors.slice(0, 4),
        facts,
    };
    await context.close();
}

await browser.close();
const doc = JSON.stringify(results, null, 1);
if (OUT !== "") {
    (await import("node:fs")).writeFileSync(OUT, doc + "\n");
}
console.log(doc);
const ok = results.control.solved === true
    && results.sri_tamper.solved_despite_tamper === false
    && results.sw_mitm.solved_despite_mitm === false;
process.exit(ok ? 0 : 3);
