// widget-view.js — the compact status renderer. Pure view model in, static
// markup out. Edition 6 widget system (KiwiCaptcha_Visual_Identity.pdf
// sections 03-05 and 13). The live lab, static examples and print specimens
// are all generated from this file; hand-drawn HTML lookalikes are not
// authoritative.
//
// view = {
//   state:  'pending'|'idle'|'connecting'|'solving'|'done'|'failed'|
//           'expired'|'worker-unavailable'|'execution-unavailable'|
//           'solver-mismatch',          (source driver states; running and
//                                        mismatch map in at the adapter
//                                        boundary only)
//   copy:   { title, explanation, action }  (resolved locale strings)
//   icon:   'none'|'check'|'warning',
//   theme:  'light'|'dark'   (default 'light')
//   width:  240|280|320|352  (default 352)
//   scale:  1|2              (component text size)
//   interactive: false       (specimens render the action as static text
//                             target markup; the live host wires handlers)
// }
//
// Layout contract (section 03 status anatomy):
//   preferred width 352 px; fit smaller host containers
//   inset and corner: 20 px block / 24 px inline / 12 px radius
//   leading mark 32 px static, exact existing geometry
//   grid: 32 px / flexible copy / 20 px state icon; 14 px gutters
//   title 20/24 host family Medium 500
//   explanation 15/20, 5 px below title
//   attribution 12/16 quiet footer; no divider
//   recovery: 44 px target, text action; capability-driven

import { markSvg, statusIcon, esc } from "./widget-primitives.js";

export const STATUS_STATES = [
  "pending",
  "idle",
  "connecting",
  "solving",
  "done",
  "failed",
  "expired",
  "worker-unavailable",
  "execution-unavailable",
  "solver-mismatch",
];

export const STATUS_WIDTHS = [240, 280, 320, 352];
export const STATUS_SCALES = [1, 2];

const DEFAULTS = {
  theme: "light",
  width: 352,
  scale: 1,
  interactive: false,
};

function classes(view) {
  const theme = view.theme ?? DEFAULTS.theme;
  const width = view.width ?? DEFAULTS.width;
  const scale = view.scale ?? DEFAULTS.scale;
  const parts = ["kc-status", `kc-theme-${theme}`, `kc-w${width}`];
  if (scale !== 1) parts.push("kc-text-2x");
  return parts.join(" ");
}

/**
 * Render the compact status surface as a static HTML string.
 * The action is capability-driven: when copy.action is null the recovery
 * row is absent (the slot stays reserved only where the driver can act).
 */
export function renderWidget(view) {
  if (!view || !view.state || !view.copy) {
    throw new Error("renderWidget: view requires state and copy");
  }
  const { title, explanation, action } = view.copy;
  const icon = view.icon ?? "none";
  const interactive = view.interactive ?? DEFAULTS.interactive;

  const iconSlot = icon === "none"
    ? ""
    : `<span class="kc-state-icon kc-state-icon--${icon}">${statusIcon(icon)}</span>`;

  const actionRow = action
    ? interactive
      ? `<button type="button" class="kc-action">${esc(action)}</button>`
      : `<span class="kc-action" role="img" aria-label="${esc(action)}">${esc(action)}</span>`
    : "";

  return (
    `<div class="${classes(view)}">` +
    `<div class="kc-status-main">` +
    markSvg(32) +
    `<div class="kc-copy">` +
    `<p class="kc-title">${esc(title)}</p>` +
    `<p class="kc-explanation">${esc(explanation)}</p>` +
    `</div>` +
    iconSlot +
    `</div>` +
    `<div class="kc-status-foot">` +
    actionRow +
    `<span class="kc-attribution">KiwiCaptcha</span>` +
    `</div>` +
    `</div>`
  );
}
