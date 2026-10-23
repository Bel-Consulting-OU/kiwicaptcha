// website-pixel-shots.mjs — render the edition-6 specimens through the
// production renderers in headless Chromium and screenshot each element at
// 2x, for pixel comparison against the design PDF's own specimen pages.

import { createRequire } from "node:module";
import { mkdirSync, writeFileSync, readFileSync, copyFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const { chromium } = require(
  join(dirname(fileURLToPath(import.meta.url)), "..", "..", "tests", "browser", "node_modules", "playwright"),
);

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const kit = join(repo, "packages", "kiwicaptcha-widget-system");
const fonts = join(repo, "packages", "kiwicaptcha", "design", "fonts");

const { renderWidget, STATUS_STATES } = await import(pathToFileURL(join(kit, "widget-view.js")).href);
const { renderFactor } = await import(pathToFileURL(join(kit, "factor-view.js")).href);
const statesDoc = JSON.parse(readFileSync(join(kit, "widget-states.json"), "utf8"));
const copyDoc = JSON.parse(readFileSync(join(kit, "widget-copy-v5.json"), "utf8"));
const en = copyDoc.packs.en;

const outDir = join(repo, "target", "website-pixel");
mkdirSync(join(outDir, "fonts"), { recursive: true });
copyFileSync(join(kit, "widget-system.css"), join(outDir, "widget-system.css"));
for (const f of ["alegreyasans-400-latin.woff2", "alegreyasans-500-latin.woff2", "alegreyasans-700-latin.woff2"]) {
  copyFileSync(join(fonts, f), join(outDir, "fonts", f));
}

// (name, markup) pairs matching the design PDF specimen pages 05-12.
const shots = [];
for (const state of STATUS_STATES) {
  shots.push([`status-${state}`, renderWidget({
    state, copy: en.states[state], icon: statesDoc.states[state].icon,
  })]);
}
shots.push(["factor-address", renderFactor({ view: "address", copy: en })]);
shots.push(["factor-requested", renderFactor({ view: "requested", copy: en })]);
shots.push(["factor-code", renderFactor({ view: "code", copy: en })]);
shots.push(["status-solving-dark", renderWidget({
  state: "solving", copy: en.states.solving, icon: "none", theme: "dark",
})]);
shots.push(["status-failed-dark", renderWidget({
  state: "failed", copy: en.states.failed, icon: "warning", theme: "dark",
})]);
shots.push(["factor-code-dark", renderFactor({ view: "code", copy: en, code: "", theme: "dark" })]);

let widths = {};
try {
  widths = JSON.parse(readFileSync(join(outDir, "widths.json"), "utf8"));
} catch { /* canonical widths on first run */ }

// rebuild each specimen at its measured container width (the PDF draws
// instances at natural container sizes; the anatomy stays constant)
for (let i = 0; i < shots.length; i++) {
  const w = widths[shots[i][0]];
  if (!w) continue;
  const isFactor = shots[i][0].startsWith("factor");
  shots[i][1] = isFactor
    ? renderFactor(viewOf(shots[i][0]), { width: w })
    : renderWidget(statusViewOf(shots[i][0], w));
}

function viewOf(name) {
  const kind = name.replace("factor-", "").replace("-dark", "");
  return {
    view: kind === "code" ? "code" : kind,
    copy: en, email: "you@example.com",
    code: kind === "code" ? "123456" : "",
    theme: name.endsWith("-dark") ? "dark" : "light",
  };
}
function statusViewOf(name, width) {
  const state = name.replace("status-", "").replace("-dark", "");
  return {
    state,
    copy: en.states[state],
    icon: statesDoc.states[state].icon,
    width,
    theme: name.endsWith("-dark") ? "dark" : "light",
  };
}

const body = shots.map(([name], i) => `<div class="shot" id="s${i}">${shots[i][1]}</div>`).join("\n");
const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<style>
@font-face { font-family: "Alegreya Sans"; src: url("fonts/alegreyasans-400-latin.woff2") format("woff2"); font-weight: 400; font-display: block; }
@font-face { font-family: "Alegreya Sans"; src: url("fonts/alegreyasans-500-latin.woff2") format("woff2"); font-weight: 500; font-display: block; }
@font-face { font-family: "Alegreya Sans"; src: url("fonts/alegreyasans-700-latin.woff2") format("woff2"); font-weight: 700; font-display: block; }
html, body { margin: 0; background: #ffffff; }
body { padding: 40px; display: flex; flex-direction: column; gap: 40px; align-items: flex-start; }
</style>
<link rel="stylesheet" href="widget-system.css">
</head><body>${body}</body></html>`;
const htmlPath = join(outDir, "shots.html");
writeFileSync(htmlPath, html);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 900, height: 800 }, deviceScaleFactor: 3 });
await page.goto(pathToFileURL(htmlPath).href);
await page.evaluate(() => document.fonts.ready);

for (let i = 0; i < shots.length; i++) {
  const el = page.locator(`#s${i} > *`);
  await el.screenshot({ path: join(outDir, `${shots[i][0]}.png`) });
}
await browser.close();
console.log(`pixel shots: ${shots.length} specimens rendered to ${outDir}`);
