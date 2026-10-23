// factor-view.js — the one pure factor renderer used by the live demo,
// generated gallery and print specimens. Edition 6 widget system
// (KiwiCaptcha_Visual_Identity.pdf sections 06-11). Manual HTML lookalikes
// are not authoritative; everything visible comes from this file.
//
// view = {
//   view:   'requested'|'address'|'sending'|'code'|'verifying'|
//           'delivery-error'|'code-error'|'expired'|'rate-limited'|
//           'service-unavailable'|'response',
//   copy:   resolved locale pack (widget-copy-v5.json shape),
//   email:  'you@example.com'   (code views interpolate it into the copy),
//   code:   retained code value (code-error keeps it; expired clears it),
//   theme:  'light'|'dark',
//   width:  240|320|384,
//   scale:  1|2,
//   interactive: false
// }
//
// Layout contract (section 06 factor anatomy):
//   preferred width 384 px; natural height; 12 px radius
//   insets 24 px top / 28 px inline / 20 px bottom
//   caption 13/16; 26 px static mark; close 44 px target, 16 px SVG cross
//   heading and copy: 28/30 Medium 500; 16/22 explanation
//   field: 14/20 label; 8 px gap; 48 px input (16/24; code face 18/24)
//   primary action: full width; 48 px; 17/24 centered label
//   utilities: 44 px text targets; no competing outline
//
// The security boundary is unchanged: this renderer performs no delivery,
// proof computation, token issuance or grant verification. Close cancels
// and the host dismisses its surface and returns focus to the invoker.

import { markSvg, closeCross, esc, bdi } from "./widget-primitives.js";

export const FACTOR_VIEWS = [
  "requested",
  "address",
  "sending",
  "code",
  "verifying",
  "delivery-error",
  "code-error",
  "expired",
  "rate-limited",
  "service-unavailable",
  "response",
];

export const FACTOR_WIDTHS = [240, 320, 384];

const DEFAULTS = { theme: "light", width: 384, scale: 1, interactive: false };

const EMAIL_VIEWS = new Set(["address", "sending", "delivery-error"]);
const CODE_VIEWS = new Set(["code", "verifying", "code-error", "expired", "rate-limited"]);

function header(copy, { withClose }) {
  const close = withClose
    ? `<button type="button" class="kc-close" aria-label="${esc(copy.factor.close)}">${closeCross()}</button>`
    : "";
  return (
    `<div class="kc-factor-head">` +
    markSvg(26, "kc-mark kc-mark--task") +
    `<span class="kc-caption">${esc(copy.factor.caption)}</span>` +
    close +
    `</div>`
  );
}

function field({ id, label, placeholder, value, codeFace, error, disabled }) {
  const errorLine = error
    ? `<p class="kc-field-error" role="alert" id="${id}-error">${esc(error)}</p>`
    : "";
  const described = error ? ` aria-describedby="${id}-error"` : "";
  const invalid = error ? ` aria-invalid="true"` : "";
  return (
    `<div class="kc-field">` +
    `<label class="kc-label" for="${id}">${esc(label)}</label>` +
    `<input class="kc-input${codeFace ? " kc-input--code" : ""}" id="${id}" ` +
    `type="text" value="${esc(value ?? "")}"${placeholder ? ` placeholder="${esc(placeholder)}"` : ""}` +
    `${invalid}${described}${disabled ? " disabled" : ""}>` +
    errorLine +
    `</div>`
  );
}

function primary(label, { disabled }) {
  return (
    `<button type="button" class="kc-primary"${disabled ? " disabled" : ""}>${esc(label)}</button>`
  );
}

function utilities(copy, { resend, resendDisabled }) {
  const items = [];
  items.push(`<button type="button" class="kc-utility">${esc(copy.factor.utility_change_email)}</button>`);
  if (resend) {
    items.push(
      `<button type="button" class="kc-utility"${resendDisabled ? " disabled" : ""}>` +
      `${esc(copy.factor.utility_resend)}</button>`
    );
  }
  return `<div class="kc-utilities">${items.join("")}</div>`;
}

function shell(view, copy, inner) {
  const theme = view.theme ?? DEFAULTS.theme;
  const width = view.width ?? DEFAULTS.width;
  const scale = view.scale ?? DEFAULTS.scale;
  const parts = ["kc-factor", `kc-theme-${theme}`, `kc-fw${width}`];
  if (scale !== 1) parts.push("kc-text-2x");
  return (
    `<section class="${parts.join(" ")}" role="group" ` +
    `aria-label="${esc(copy.factor.caption)}">${inner}</section>`
  );
}

/**
 * Render the factor task surface as a static HTML string.
 * One clear task per view: a single full-width primary action, quiet
 * utilities, no divider bar, no badges and no competing outlined button.
 */
export function renderFactor(view) {
  if (!view || !view.view || !view.copy) {
    throw new Error("renderFactor: view requires view and copy");
  }
  const kind = view.view;
  const copy = view.copy;
  const f = copy.factor;
  const email = view.email ?? f.address.placeholder;
  const codeValue = view.code ?? "";
  // Static specimens render each control in its designed appearance;
  // only the phases the design shows pending (sending, verifying,
  // rate-limited) carry the disabled state.
  const input = (args) => field({ ...args });
  const btn = (label, args) => primary(label, { ...args });

  switch (kind) {
    case "requested":
      return shell(view, copy,
        header(copy, { withClose: true }) +
        `<h2 class="kc-heading">${esc(f.requested.title)}</h2>` +
        `<p class="kc-explanation">${esc(f.requested.copy)}</p>` +
        btn(f.requested.primary, {}) +
        `<p class="kc-attribution">KiwiCaptcha</p>`);

    case "address":
    case "sending":
    case "delivery-error": {
      const sending = kind === "sending";
      const failed = kind === "delivery-error";
      return shell(view, copy,
        header(copy, { withClose: true }) +
        `<h2 class="kc-heading">${esc(f.address.title)}</h2>` +
        `<p class="kc-explanation">${esc(f.address.copy)}</p>` +
        input({
          id: "kc-email",
          label: f.address.label,
          placeholder: f.address.placeholder,
          value: failed ? f.address.placeholder : "",
          error: failed ? f.delivery_error.message : null,
        }) +
        btn(sending ? f.sending.primary : failed ? f.delivery_error.primary : f.address.primary,
          { disabled: sending }) +
        `<p class="kc-attribution">KiwiCaptcha</p>`);
    }

    case "code":
    case "verifying":
    case "code-error":
    case "expired":
    case "rate-limited": {
      const verifying = kind === "verifying";
      const codeError = kind === "code-error";
      const expired = kind === "expired";
      const limited = kind === "rate-limited";
      const error = codeError ? f.code_error.message
        : expired ? f.expired.message
        : limited ? f.rate_limited.message
        : null;
      const primaryLabel = codeError || verifying ? f.code.primary
        : expired ? f.expired.primary
        : limited ? f.rate_limited.primary
        : f.code.primary;
      return shell(view, copy,
        header(copy, { withClose: true }) +
        `<h2 class="kc-heading">${esc(f.code.title)}</h2>` +
        `<p class="kc-explanation">${f.code.copy.replace("{email}", bdi(email))}</p>` +
        input({
          id: "kc-code",
          label: f.code.label,
          value: expired || limited || verifying ? "" : codeValue,
          codeFace: true,
          error,
        }) +
        btn(primaryLabel, { disabled: verifying || limited }) +
        utilities(copy, {
          resend: !expired,
          resendDisabled: limited,
        }) +
        `<p class="kc-attribution">KiwiCaptcha</p>`);
    }

    case "service-unavailable":
      return shell(view, copy,
        header(copy, { withClose: true }) +
        `<h2 class="kc-heading">${esc(f.service_unavailable.title)}</h2>` +
        `<p class="kc-explanation">${esc(f.service_unavailable.copy)}</p>` +
        btn(f.service_unavailable.primary, {}) +
        `<p class="kc-attribution">KiwiCaptcha</p>`);

    case "response":
      return shell(view, copy,
        header(copy, { withClose: false }) +
        `<h2 class="kc-heading">${esc(f.response.title)}</h2>` +
        `<p class="kc-explanation">${esc(f.response.copy)}</p>` +
        btn(f.response.primary, {}) +
        `<p class="kc-attribution">KiwiCaptcha</p>`);

    default:
      throw new Error(`renderFactor: unknown view ${kind}`);
  }
}
