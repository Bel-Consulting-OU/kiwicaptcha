#!/usr/bin/env node
/**
 * d36.embed.mjs — the D3.6 browser leg: the hostile embed page loaded
 * in real chromium against a genuinely different loopback origin (the
 * widget page lives on another port, which is another origin).
 *
 * The broker's toolkit is all in the fixture page (same-origin reach
 * into the widget frame, postMessage probing, the opener chain). The
 * driver measures what the toolkit actually got: whether any token
 * bytes left the widget's origin, and it solves one widget for real in
 * the frame so a token exists to steal. The wire relays of whatever
 * the broker does harvest are refused by the campaign's wire legs.
 *
 * Output: one JSON document on stdout.
 */

import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TESTS_BROWSER = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../tests/browser");
const { chromium } = createRequire(join(TESTS_BROWSER, "package.json"))("@playwright/test");

const embedUrl = process.env.KIWI_RT_D36_EMBED_URL ?? "http://127.0.0.1:6471/d36-hostile-live.html";
const outPath = process.env.KIWI_RT_D36_OUT ?? "";

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();

// The widget frame solves for real, so a live token exists to steal.
await page.goto(embedUrl, { waitUntil: "domcontentloaded" });
const victimFrame = page.frameLocator("#victim");
await victimFrame.locator("input[data-kiwi-token]").waitFor({ state: "attached", timeout: 30000 });
try {
    await victimFrame.locator("input[data-kiwi-token]").waitFor({ state: "attached", timeout: 30000 });
} catch {}

let frameTokenRead = null;
try {
    frameTokenRead = await victimFrame.locator("input[data-kiwi-token]").inputValue({ timeout: 5000 });
} catch {
    frameTokenRead = null;
}
let brokerLoot = "";
try {
    await page.waitForFunction(() => (window.__brokerLoot ?? "").length > 0, null, { timeout: 8000 });
    brokerLoot = await page.evaluate(() => window.__brokerLoot);
} catch {
    brokerLoot = "";
}

const summary = {
    embed_url: embedUrl,
    token_reads: 0,
    token_bytes_leaked: 0,
    blocked_reads: 0,
    broker_loot: brokerLoot.split("|").filter(Boolean),
};
for (const entry of summary.broker_loot) {
    if (entry.startsWith("token:") && entry !== "token:none") {
        summary.token_reads += 1;
        summary.token_bytes_leaked += entry.length - "token:".length;
    }
    if (entry.startsWith("blocked:")) {
        summary.blocked_reads += 1;
    }
}
await browser.close();
const doc = JSON.stringify(summary, null, 2);
if (outPath !== "") {
    (await import("node:fs")).writeFileSync(outPath, doc + "\n");
}
console.log(doc);
process.exit(summary.token_bytes_leaked === 0 ? 0 : 3);
