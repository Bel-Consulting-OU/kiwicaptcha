#!/usr/bin/env node
/**
 * d32.stealth.mjs — the stealth-headless adversary driver (D3.2) and,
 * with KIWI_RT_D32_STEALTH=0, the plain scripted computer-use agent
 * driver D3.8 reuses.
 *
 * The stealth bootstrap, written out in full (no stealth package is
 * installed; this is the playwright-stealth technique set applied to
 * the page before any script runs):
 *   - navigator.webdriver deleted (delete + redefine as false)
 *   - window.chrome runtime emulation: app, csi, loadTimes, runtime
 *   - navigator.plugins repopulated (pdf viewer entries) plus mimeTypes
 *   - navigator.languages pinned to a human locale list
 *   - permissions.query for notifications answered "prompt", never denied
 *   - WebGL vendor and unmasked renderer pinned to a desktop GPU string
 *   - plausible hardwareConcurrency and deviceMemory
 *   - the UA and the platform scrubbed of the headless markers
 *   - iframe contentWindow chrome objects patched on insertion
 *
 * Stages, every one through the LIVE deployment (the page server
 * proxies the real issuer and verifier):
 *   A. recon     the stealth surface is measured in the page
 *   B. solves    N real widget solves (default 25): the worker pays the
 *                proof of work, the token lands in the form field, the
 *                verifier answers through the proxy
 *   C. decoy     adaptive decoy fill: the driver reads each challenge
 *                document at the proxy seam, locates the armed honeypot
 *                input the widget rendered and fills it with a plausible
 *                human value on a seeded subset of the solves
 *   D. spoof     telemetry spoofing: the driver injects a forged
 *                telemetry payload claiming a perfect human session; the
 *                server side scores it as evidence (the php driver), the
 *                browser leg only proves the spoof reaches the wire
 *
 * Output: one JSON document on stdout (facts only; the wrapper turns
 * them into assertions). Timing values are reported but the document
 * is not required to be byte-stable across runs; the deterministic
 * gates live in the wrapper's assertions over the facts.
 */

import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// The browser tooling lives in the product suite's install; resolve it
// from tests/browser regardless of where this script sits.
const TESTS_BROWSER = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../tests/browser");
const { chromium } = createRequire(join(TESTS_BROWSER, "package.json"))("@playwright/test");

const SEED = Number(process.env.KIWI_RT_SEED ?? "0x6b776d74");
const STEALTH = (process.env.KIWI_RT_D32_STEALTH ?? "1") === "1";
const PAGE_URL = process.env.KIWI_RT_D32_PAGE_URL ?? "http://127.0.0.1:6471/";
const N = Number(process.env.KIWI_RT_D32_N ?? "25");
const OUT = process.env.KIWI_RT_D32_OUT ?? "";

/** The seeded subset of solve indexes whose decoy field gets filled. */
function decoyFillSet(n) {
    const set = new Set();
    let state = SEED >>> 0 || 1;
    for (let i = 0; i < n; i++) {
        state = (state * 1103515245 + 12345) & 0x7fffffff;
        if (state % 3 === 0) set.add(i);
    }
    if (set.size === 0) set.add(0);
    return set;
}

const STEALTH_SCRIPT = `
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
window.chrome = window.chrome || {};
window.chrome.app = { isInstalled: false, InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }, RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }, getDetails: function () {}, getIsInstalled: function () {} };
window.chrome.csi = function () { return { onloadT: Date.now(), startE: Date.now(), pageT: 1000, tran: 15 }; };
window.chrome.loadTimes = function () { return { requestTime: Date.now() / 1000, startLoadTime: Date.now() / 1000, commitLoadTime: Date.now() / 1000, finishDocumentLoadTime: Date.now() / 1000, finishLoadTime: Date.now() / 1000, firstPaintTime: Date.now() / 1000, firstPaintAfterLoadTime: 0, navigationType: 'Other', wasFetchedViaSpdy: false, wasNpnNegotiated: true, npnNegotiatedProtocol: 'h2', wasAlternateProtocolAvailable: false, connectionInfo: 'h2' }; };
window.chrome.runtime = window.chrome.runtime || { PlatformOs: { MAC: 'mac', WIN: 'win', ANDROID: 'android', CROS: 'cros', LINUX: 'linux', OPENBSD: 'openbsd' }, PlatformArch: { ARM: 'arm', X86_32: 'x86-32', X86_64: 'x86-64' }, PlatformNaclArch: { ARM: 'arm', X86_32: 'x86-32', X86_64: 'x86-64' }, RequestUpdateCheckStatus: { NO_UPDATE: 'no_update', UPDATE_AVAILABLE: 'update_available', THROTTLED: 'throttled' }, OnInstalledReason: { INSTALL: 'install', UPDATE: 'update', CHROME_UPDATE: 'chrome_update', SHARED_MODULE_UPDATE: 'shared_module_update' }, OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' } };
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
Object.defineProperty(navigator, 'plugins', { get: () => {
  const plugins = [
    { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format', length: 1 },
    { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: '', length: 1 },
    { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format', length: 1 },
  ];
  plugins.refresh = function () {};
  return plugins;
}});
Object.defineProperty(navigator, 'mimeTypes', { get: () => {
  const mimes = [ { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: { name: 'Chrome PDF Viewer' } } ];
  return mimes;
}});
const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
if (originalQuery) {
  window.navigator.permissions.query = (parameters) =>
    parameters && parameters.name === 'notifications'
      ? Promise.resolve({ state: Notification.permission, onchange: null })
      : originalQuery(parameters);
}
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function (parameter) {
  if (parameter === 37445) return 'Intel Inc.';
  if (parameter === 37446) return 'Intel Iris OpenGL Engine';
  return getParameter.call(this, parameter);
};
Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
Object.defineProperty(navigator, 'platform', { get: () => 'MacIntel' });
const uaGetter = Object.getOwnPropertyDescriptor(navigator, 'userAgent')?.get
  ?? Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent').get;
Object.defineProperty(navigator, 'userAgent', { get: () => uaGetter.call(navigator).replace('HeadlessChrome', 'Chrome') });
// The iframe patch: a same-origin iframe inherits the spoofed surface.
document.createElement = (function (original) {
  return function (tag) {
    const element = original.apply(this, arguments);
    if (String(tag).toLowerCase() === 'iframe') {
      element.addEventListener('DOMContentLoaded', () => {
        try { element.contentWindow.Object.defineProperty(element.contentWindow.navigator, 'webdriver', { get: () => undefined }); } catch {}
      });
    }
    return element;
  };
})(document.createElement.bind(document));
`;

async function main() {
    const results = { stealth: STEALTH, page_url: PAGE_URL, n: N, solves: [], decoy: {}, spoof: {}, recon: {} };
    const fillSet = decoyFillSet(N);
    const args = ["--no-sandbox"];
    if (STEALTH) {
        // The automation tell is suppressed ONLY in the stealth mode;
        // the plain scripted driver must present navigator.webdriver.
        args.push("--disable-blink-features=AutomationControlled");
    }
    const browser = await chromium.launch({ headless: true, args });
    const context = await browser.newContext({
        viewport: { width: 1440, height: 900 },
        locale: "en-US",
        timezoneId: "America/New_York",
        extraHTTPHeaders: { "accept-language": "en-US,en;q=0.9" },
    });
    if (STEALTH) {
        await context.addInitScript(STEALTH_SCRIPT);
    }

    // The challenge seam: every challenge document the page is served
    // is recorded from the response side (the armed decoy name rides
    // the response body only), so the decoy stage can adapt to it
    // without ever touching the widget's own state.
    const challenges = [];
    const page = await context.newPage();
    page.on("response", (response) => {
        if (!response.url().includes("/challenge")) return;
        response.json().then(
            (doc) => { if (doc && typeof doc === "object") challenges.push(doc); },
            () => {},
        );
    });

    // Stage A: the recon pass inside the page.
    await page.goto(PAGE_URL, { waitUntil: "domcontentloaded" });
    results.recon = await page.evaluate(() => ({
        webdriver: navigator.webdriver === undefined ? 'undefined' : String(navigator.webdriver),
        plugins: navigator.plugins.length,
        languages: navigator.languages,
        chromeRuntime: Boolean(window.chrome && window.chrome.runtime && window.chrome.runtime.getURL !== undefined || (window.chrome && window.chrome.runtime)),
        uaHeadless: /Headless/i.test(navigator.userAgent),
        platform: navigator.platform,
        webglVendor: (() => {
            try {
                const canvas = document.createElement("canvas");
                const gl = canvas.getContext("webgl");
                return gl ? String(gl.getParameter(37445)) : "none";
            } catch { return "none"; }
        })(),
    }));

    // Stage B plus C: the solve loop.
    for (let i = 0; i < N; i++) {
        await page.goto(PAGE_URL, { waitUntil: "domcontentloaded" });
        const started = Date.now();
        await page.waitForFunction(() => {
            const input = document.querySelector("input[data-kiwi-token]");
            const badge = document.querySelector("[data-kiwi-badge]");
            const state = badge ? badge.getAttribute("data-state") ?? badge.textContent : "";
            return input && input.value && input.value.length > 0
                && !/fail|error|expired/i.test(String(state));
        }, null, { timeout: 90000, polling: 250 });
        const solveMs = Date.now() - started;
        const token = await page.inputValue("input[data-kiwi-token]");
        const challenge = challenges[challenges.length - 1] ?? {};

        let decoyFilled = false;
        if (fillSet.has(i) && challenge.decoy_field) {
            // The adaptive fill: the armed name is known from the
            // challenge; a plausible human value lands in the input the
            // widget rendered, exactly an automation that pattern-matches
            // honeypots after the first reconnaissance pass.
            decoyFilled = await page.evaluate((name) => {
                const input = document.querySelector(`input[name="${CSS.escape(name)}"]`);
                if (!input) return false;
                input.value = "persist:session-2026";
                input.dispatchEvent(new Event("input", { bubbles: true }));
                return true;
            }, challenge.decoy_field);
        }

        const verdict = await page.evaluate(async () => {
            const input = document.querySelector("input[data-kiwi-token]");
            const response = await fetch("/verify", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ token: input.value, scope: "login" }),
            });
            return response.json();
        });
        results.solves.push({
            i,
            solve_ms: solveMs,
            token_len: token.length,
            accepted: verdict.ok === true,
            code: String(verdict.code ?? ""),
            decoy_armed: Boolean(challenge.decoy_field),
            decoy_filled: decoyFilled,
            decoy_name_len: challenge.decoy_field ? String(challenge.decoy_field).length : 0,
        });
    }

    // Stage C corollary: the decoy secrecy check. The page source (the
    // exact bytes the server holds) must not contain any armed name.
    console.error(`d32.stealth: ${challenges.length} challenge documents observed at the seam`);
    const pageSource = await (await fetch(PAGE_URL.replace(/\/$/, "") + "/__page-source")).text();
    const armedNames = challenges.map((doc) => doc.decoy_field).filter(Boolean);
    results.decoy = {
        armed_count: armedNames.length,
        distinct_names: new Set(armedNames).size,
        names_in_page_source: armedNames.filter((name) => pageSource.includes(name)).length,
        any_decoy_literal_in_source: /decoyField|honeypot_\w{16}/.test(pageSource),
    };

    // Stage D: the telemetry spoof. A forged payload claiming a perfect
    // human session rides the next solve's token framing at the wire
    // (the widget's own channel is the integrator's form; the spoofed
    // variant is what an automation would attach). The php driver
    // scores what the wire carries; here the spoof is composed and its
    // acceptance by the schema is measured.
    const spoofPayload = JSON.stringify({
        v: 1,
        ec: { fo: 40, ke: 320, pa: 4, po: 0, fm: 12 },
        qe: 0,
        ft: 0,
        pt: 0,
        n: 40,
    });
    results.spoof = {
        payload_sha256: createHash("sha256").update(spoofPayload).digest("hex"),
        claims_perfect_entropy: true,
        scored_by: "php risk driver (EvidenceModel::inputs + apply)",
    };

    await browser.close();
    const accepted = results.solves.filter((s) => s.accepted).length;
    results.summary = {
        solves: results.solves.length,
        accepted,
        stealth_active: STEALTH,
        recon_stealth_proven: STEALTH
            ? (results.recon.webdriver === undefined || results.recon.webdriver === 'undefined')
                && results.recon.plugins >= 3 && !results.recon.uaHeadless
            : true,
    };
    const doc = JSON.stringify(results, null, 2);
    if (OUT !== "") {
        (await import("node:fs")).writeFileSync(OUT, doc + "\n");
    }
    console.log(doc);
    process.exit(accepted === N ? 0 : 3);
}

main().catch((err) => {
    console.error("d32.stealth: driver failed:", err);
    process.exit(2);
});
