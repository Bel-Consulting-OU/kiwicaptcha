// widget-copy-v5.js — proposed concise baseline translations for the ten
// locale packs, as an ES module. widget-copy-v5.json is the same data; this
// accessor keeps one source. Every pack is PROPOSED copy: native-language
// review is a release task before release. Original runtime packs remain
// unchanged in demo-locales.js, locales.js and the original kit.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const path = join(dirname(fileURLToPath(import.meta.url)), "widget-copy-v5.json");
export const widgetCopyV5 = JSON.parse(readFileSync(path, "utf8"));
export const packs = widgetCopyV5.packs;
export default widgetCopyV5;
