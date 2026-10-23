// widget-primitives.js — the exact mark, the status icons and escaping.
// Edition 6 widget system. The mark is the canonical Spiral Lock: the two
// canonical paths of packages/kiwicaptcha/resources/kiwi-mark.svg on the
// 64x64 grid with a 6.6 stroke, round caps and joins. Status icons are
// fixed 20 px geometry; the close cross is a fixed 16 px SVG. Everything
// recolors through currentColor.

const MARK_PATHS =
  '<path d="M32 42 C32 35 43 35 43 42 C43 51 29 54 23 46 C16 36 25 28 35 29 C47 29 54 38 53 46 C52 56 43 60 31 59 C17 58 9 51 10 41 C10 33 16 28 21 28"/>' +
  '<path d="M22 25 V16 A10 10 0 0 1 42 16 V25"/>';

/** The canonical Spiral Lock mark at any size; exact existing geometry. */
export function markSvg(size = 32, className = "kc-mark") {
  return (
    `<svg class="${className}" width="${size}" height="${size}" viewBox="0 0 64 64" ` +
    `fill="none" stroke="currentColor" stroke-width="6.6" stroke-linecap="round" ` +
    `stroke-linejoin="round" aria-hidden="true" focusable="false">${MARK_PATHS}</svg>`
  );
}

// Status icons: one non-colour cue (shape) plus colour. Neutral and active
// views reserve the 20 px slot without displaying redundant activity.
const ICON_CHECK =
  '<svg class="kc-icon" width="20" height="20" viewBox="0 0 20 20" fill="none" ' +
  'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ' +
  'aria-hidden="true" focusable="false"><path d="M3.5 10.5 L8 15 L16.5 5.5"/></svg>';

const ICON_WARNING =
  '<svg class="kc-icon" width="20" height="20" viewBox="0 0 20 20" fill="none" ' +
  'stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" ' +
  'aria-hidden="true" focusable="false"><path d="M10 2.6 L18.6 17.4 H1.4 Z"/>' +
  '<path d="M10 7.6 V11.4"/><path d="M10 14.2 V14.6"/></svg>';

const ICON_CROSS =
  '<svg class="kc-icon kc-icon--cross" width="16" height="16" viewBox="0 0 16 16" fill="none" ' +
  'stroke="currentColor" stroke-width="1.6" stroke-linecap="round" ' +
  'aria-hidden="true" focusable="false"><path d="M3 3 L13 13"/><path d="M13 3 L3 13"/></svg>';

const STATUS_ICONS = { none: "", check: ICON_CHECK, warning: ICON_WARNING };

/** The state icon for a view: "", a completion check or a failure warning. */
export function statusIcon(icon = "none") {
  return STATUS_ICONS[icon] ?? "";
}

/** The 16 px SVG close cross (never a font multiplication glyph). */
export function closeCross() {
  return ICON_CROSS;
}

/** Escape a string for interpolation into markup. */
export function esc(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Wrap interpolated run text (email, operation summaries) in bdi. */
export function bdi(value) {
  return `<bdi>${esc(value)}</bdi>`;
}
