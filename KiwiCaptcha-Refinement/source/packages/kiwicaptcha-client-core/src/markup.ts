import type { KiwiRenderOptions } from "./types.js";
import { KIWI_TOKEN_FIELD_NAME } from "./types.js";
import { KIWI_MARK_PATHS } from "./brand.js";

/**
 * The canonical widget markup, built by the client and completed by the
 * driver. The structure mirrors the reference deployment's container: a
 * hidden token input beside a labelled, announced status widget. The
 * driver fills or replaces text content at init and owns every state
 * transition from there, so this markup only has to exist once.
 */

/** Container attributes the driver reads through its config gate. */
function containerAttributes(options: KiwiRenderOptions): Array<[string, string]> {
  const attrs: Array<[string, string]> = [];
  if (options.endpoint) attrs.push(["data-kiwi-endpoint", options.endpoint]);
  if (options.scope) attrs.push(["data-kiwi-scope", options.scope]);
  if (options.algorithm) attrs.push(["data-kiwi-algorithm", options.algorithm]);
  if (options.lang) attrs.push(["data-kiwi-lang", options.lang]);
  if (options.requestBinding) attrs.push(["data-kiwi-request-binding", options.requestBinding]);
  if (options.chainTicket) attrs.push(["data-kiwi-chain-ticket", options.chainTicket]);
  if (typeof options.fetchTimeoutMs === "number" && options.fetchTimeoutMs > 0) {
    attrs.push(["data-kiwi-fetch-timeout-ms", String(Math.floor(options.fetchTimeoutMs))]);
  }
  return attrs;
}

/** Widget attributes declared at issuance (provider-compatible metadata). */
function widgetAttributes(options: KiwiRenderOptions): Array<[string, string]> {
  const attrs: Array<[string, string]> = [];
  if (options.action) attrs.push(["data-action", options.action]);
  if (options.cData) attrs.push(["data-cdata", options.cData]);
  if (options.execution === "execute") attrs.push(["data-execution", "execute"]);
  return attrs;
}

export interface KiwiMarkup {
  container: HTMLElement;
  widget: HTMLElement;
  tokenInput: HTMLInputElement;
}

/**
 * Build the canonical markup inside (and return) fresh elements from the
 * given document. The container receives the four-setting attributes plus
 * an optional theme class; the widget subtree matches the reference
 * deployment so the driver's stylesheet keys work unchanged.
 */
export function buildKiwiMarkup(doc: Document, options: KiwiRenderOptions): KiwiMarkup {
  const container = doc.createElement("div");
  container.className = "kiwi-container";
  for (const [name, value] of containerAttributes(options)) {
    container.setAttribute(name, value);
  }
  if (options.theme && options.theme !== "auto") {
    container.classList.add(`kiwi-theme-${options.theme}`);
  }

  const tokenInput = doc.createElement("input");
  tokenInput.type = "hidden";
  tokenInput.name = options.tokenFieldName ?? KIWI_TOKEN_FIELD_NAME;
  tokenInput.setAttribute("data-kiwi-token", "");
  tokenInput.value = "";
  container.appendChild(tokenInput);

  const widget = doc.createElement("div");
  widget.className = "kiwi-widget";
  widget.setAttribute("data-kiwi-widget", "");
  widget.setAttribute("data-state", "idle");
  widget.setAttribute("role", "group");
  widget.setAttribute("aria-label", "KiwiCaptcha security check");
  for (const [name, value] of widgetAttributes(options)) {
    widget.setAttribute(name, value);
  }

  const icon = doc.createElement("div");
  icon.className = "kiwi-icon-wrapper";
  icon.setAttribute("aria-hidden", "true");
  const svg = doc.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 64 64");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "6.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  for (const geometry of KIWI_MARK_PATHS) {
    const path = doc.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", geometry);
    svg.appendChild(path);
  }
  icon.appendChild(svg);

  const main = doc.createElement("div");
  main.className = "kiwi-main";

  const top = doc.createElement("div");
  top.className = "kiwi-top";
  const label = doc.createElement("span");
  label.className = "kiwi-label";
  label.setAttribute("data-kiwi-label", "");
  label.textContent = "Security Check";
  const badge = doc.createElement("span");
  badge.className = "kiwi-badge";
  badge.setAttribute("data-kiwi-badge", "");
  badge.textContent = "Idle";
  top.appendChild(label);
  top.appendChild(badge);

  const track = doc.createElement("div");
  track.className = "kiwi-track";
  track.setAttribute("aria-hidden", "true");
  const bar = doc.createElement("div");
  bar.className = "kiwi-bar";
  bar.setAttribute("data-kiwi-bar", "");
  bar.setAttribute("data-progress", "0");
  track.appendChild(bar);

  const bottom = doc.createElement("div");
  bottom.className = "kiwi-bottom";
  const info = doc.createElement("p");
  info.className = "kiwi-info";
  info.setAttribute("data-kiwi-info", "");
  info.textContent = "Protected by KiwiCaptcha";
  const timer = doc.createElement("span");
  timer.className = "kiwi-timer";
  timer.setAttribute("data-kiwi-timer", "");
  bottom.appendChild(info);
  bottom.appendChild(timer);

  main.appendChild(top);
  main.appendChild(track);
  main.appendChild(bottom);

  widget.appendChild(icon);
  widget.appendChild(main);
  const status = doc.createElement("span");
  status.className = "kiwi-sr-only";
  status.setAttribute("data-kiwi-status", "");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  widget.appendChild(status);
  container.appendChild(widget);

  return { container, widget, tokenInput };
}
