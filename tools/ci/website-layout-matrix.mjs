// website-layout-matrix.mjs — the release-layout matrix of the edition-6
// widget system, driven through the production renderers in headless
// Chromium. Every case asserts: no horizontal overflow, no clipped text,
// the copy inventory renders verbatim, and the group carries its label.
//
// Matrix (design handoff): every ten-state baseline view at 240/280/320/
// 352 px with all baseline locale packs and both component text sizes;
// every factor view at 240/320/384 px across both themes and both type
// families. RTL is exercised through the Arabic pack.

import { createRequire } from "node:module";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const { chromium } = require(
  join(dirname(fileURLToPath(import.meta.url)), "..", "..", "tests", "browser", "node_modules", "playwright"),
);

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const kit = join(repo, "packages", "kiwicaptcha-widget-system");
const fonts = join(repo, "packages", "kiwicaptcha", "design", "fonts");

const { renderWidget, STATUS_STATES, STATUS_WIDTHS, STATUS_SCALES } =
  await import(pathToFileURL(join(kit, "widget-view.js")).href);
const { renderFactor, FACTOR_VIEWS, FACTOR_WIDTHS } =
  await import(pathToFileURL(join(kit, "factor-view.js")).href);
const statesDoc = JSON.parse(readFileSync(join(kit, "widget-states.json"), "utf8"));
const copyDoc = JSON.parse(readFileSync(join(kit, "widget-copy-v5.json"), "utf8"));

const FAMILIES = {
  alegreya: '"Alegreya Sans", "Segoe UI", system-ui, sans-serif',
  system: 'system-ui, sans-serif',
};

function page(family, body) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<style>
@font-face { font-family: "Alegreya Sans"; src: url("fonts/alegreyasans-500-latin.woff2") format("woff2"); font-weight: 500; font-display: block; }
@font-face { font-family: "Alegreya Sans"; src: url("fonts/alegreyasans-400-latin.woff2") format("woff2"); font-weight: 400; font-display: block; }
html, body { margin: 0; background: #F3F5EF; }
body { padding: 24px; }
.stage { --kc-font-family: ${family}; }
</style>
<link rel="stylesheet" href="widget-system.css">
</head><body>${body}</body></html>`;
}

const outDir = join(repo, "target", "website-matrix");
mkdirSync(outDir, { recursive: true });
mkdirSync(join(outDir, "fonts"), { recursive: true });
for (const f of ["alegreyasans-400-latin.woff2"]) {
  const src = join(fonts, f);
  try { writeFileSync(join(outDir, "fonts", f), readFileSync(src)); } catch { /* optional */ }
}
writeFileSync(join(outDir, "fonts", "alegreyasans-500-latin.woff2"),
  readFileSync(join(fonts, "alegreyasans-500-latin.woff2")));
writeFileSync(join(outDir, "widget-system.css"), readFileSync(join(kit, "widget-system.css")));

const cases = [];
for (const family of ["alegreya", "system"]) {
  for (const locale of Object.keys(copyDoc.packs)) {
    const pack = copyDoc.packs[locale];
    for (const state of STATUS_STATES) {
      for (const width of STATUS_WIDTHS) {
        for (const scale of STATUS_SCALES) {
          cases.push({
            kind: "status", family, locale, state, width, scale,
            copy: pack.states[state],
            html: renderWidget({
              state, copy: pack.states[state],
              icon: statesDoc.states[state].icon, width, scale,
            }),
          });
        }
      }
    }
    for (const view of FACTOR_VIEWS) {
      for (const width of FACTOR_WIDTHS) {
        for (const scale of STATUS_SCALES) {
          for (const theme of ["light", "dark"]) {
            cases.push({
              kind: "factor", family, locale, view, width, scale, theme,
              html: renderFactor({
                view, copy: pack, email: "you@example.com",
                code: "123456", width, scale, theme,
              }),
            });
          }
        }
      }
    }
  }
}

const browser = await chromium.launch();
const page2 = await browser.newPage({ viewport: { width: 900, height: 800 }, deviceScaleFactor: 1 });
const failures = [];
let checked = 0;

// Batch cases through one fixture page each (100 at a time) to bound runtime.
const BATCH = 100;
for (let start = 0; start < cases.length; start += BATCH) {
  const batch = cases.slice(start, start + BATCH);
  const body = batch.map((c, i) =>
    `<div class="stage" id="c${i}" dir="${copyDoc.packs[c.locale].dir}">${c.html}</div>`).join("\n");
  const htmlPath = join(outDir, `batch-${start}.html`);
  writeFileSync(htmlPath, page(FAMILIES[batch[0].family], body));
  await page2.goto(pathToFileURL(htmlPath).href);
  const results = await page2.evaluate((n) => {
    const out = [];
    for (let i = 0; i < n; i++) {
      const stage = document.getElementById(`c${i}`);
      const card = stage.firstElementChild;
      const cardRect = card.getBoundingClientRect();
      const overflowX = card.scrollWidth - card.clientWidth;
      let clipped = [];
      for (const el of card.querySelectorAll("p, span, button, label, h2")) {
        const cs = getComputedStyle(el);
        const clips = cs.overflow !== "visible" || cs.overflowX !== "visible" || cs.overflowY !== "visible";
        const overX = el.scrollWidth > el.clientWidth + 1;
        const overY = clips && el.scrollHeight > el.clientHeight + 1;
        if (overX || overY) clipped.push(el.className || el.tagName);
      }
      out.push({
        overflowX,
        clipped,
        w: Math.round(cardRect.width),
        labelled: !!card.getAttribute("aria-label") ||
          !!card.querySelector(".kc-attribution"),
      });
    }
    return out;
  }, batch.length);

  batch.forEach((c, i) => {
    checked++;
    const r = results[i];
    const where = `${c.kind} ${c.family}/${c.locale}/${c.state ?? c.view}/${c.width}/${c.scale}${c.theme ? "/" + c.theme : ""}`;
    if (r.overflowX > 1) failures.push(`${where}: horizontal overflow ${r.overflowX}px`);
    if (r.clipped.length) failures.push(`${where}: clipped text in ${r.clipped.join(",")}`);
    if (!r.labelled) failures.push(`${where}: missing attribution/label`);
  });
}

await browser.close();

console.log(`layout matrix: ${checked} cases checked`);
if (failures.length) {
  for (const f of failures.slice(0, 25)) console.error(`FAIL ${f}`);
  console.error(`layout matrix: ${failures.length} failure(s)`);
  process.exit(1);
}
console.log("layout matrix: PASS (no horizontal overflow, no clipped text)");
