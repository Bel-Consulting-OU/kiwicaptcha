// widget-states.js — the English state content and tone inventory as an
// ES module, for native generation and the live lab. widget-states.json is
// the same data; this accessor keeps one source.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const path = join(dirname(fileURLToPath(import.meta.url)), "widget-states.json");
export const widgetStates = JSON.parse(readFileSync(path, "utf8"));
export const states = widgetStates.states;
export const aliases = widgetStates.aliases;
export const recoveryContract = widgetStates.recoveryContract;
export default widgetStates;
