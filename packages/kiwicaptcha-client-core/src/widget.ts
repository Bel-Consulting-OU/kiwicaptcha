import { getKiwiCaptcha, loadKiwiCaptcha } from "./loader.js";
import { buildKiwiMarkup, type KiwiMarkup } from "./markup.js";
import type {
  KiwiCaptchaApi,
  KiwiRenderOptions,
  KiwiWidgetHandle,
} from "./types.js";

/**
 * Imperative render and teardown on top of the driver's provider API.
 *
 * Lifecycle rules the frameworks rely on (identical everywhere because
 * they live here):
 * - Each render builds FRESH markup inside the container, so a remount
 *   into a reused node never resurrects a destroyed widget (the driver
 *   permanently refuses data-kiwi-destroyed elements).
 * - Lifecycle callbacks come from the driver's bubbling kiwi:* events,
 *   never from the per-generation callback options, so every generation
 *   of the widget reports through one stable wiring.
 * - destroy() detaches listeners and cancels the driver record while
 *   LEAVING the container node in place: the framework owns that node.
 *   The driver's remove() (which also unlinks the markup) is used only
 *   when the driver predates destroy().
 */

interface EventWiring {
  type: string;
  fn: EventListener;
}

const EVENT_MAP: ReadonlyArray<readonly [string, string]> = [
  ["kiwi:ready", "ready"],
  ["kiwi:verifying", "verifying"],
  ["kiwi:verified", "verified"],
  ["kiwi:error", "error"],
  ["kiwi:expired", "expired"],
  ["kiwi:retrying", "retrying"],
  ["kiwi:worker-unavailable", "worker-unavailable"],
  ["kiwi:execution-unavailable", "execution-unavailable"],
];

function readScope(detail: unknown): string {
  const d = detail as { scope?: unknown } | null;
  return typeof d?.scope === "string" ? d.scope : "";
}

function readString(detail: unknown, key: string): string {
  const d = detail as Record<string, unknown> | null;
  const v = d ? d[key] : undefined;
  return typeof v === "string" ? v : "";
}

/** Options forwarded verbatim to the driver's render(). */
function driverOptions(options: KiwiRenderOptions): Record<string, unknown> {
  const forwarded: Record<string, unknown> = {};
  if (options.scope !== undefined) forwarded.scope = options.scope;
  if (options.sitekey !== undefined) forwarded.sitekey = options.sitekey;
  if (options.lang !== undefined) forwarded.lang = options.lang;
  if (options.action !== undefined) forwarded.action = options.action;
  if (options.cData !== undefined) forwarded.cData = options.cData;
  if (options.chainTicket !== undefined) forwarded.chainTicket = options.chainTicket;
  if (options.responseField !== undefined) forwarded.responseField = options.responseField;
  if (options.execution !== undefined) forwarded.execution = options.execution;
  return forwarded;
}

export interface RenderKiwiOptions extends KiwiRenderOptions {
  /**
   * The document to build markup from; defaults to the container's own
   * ownerDocument.
   */
  doc?: Document;
}

/**
 * Render a widget into the container and return its handle.
 *
 * Throws when the driver is not loaded: the frameworks await
 * loadKiwiCaptcha() before rendering, and a silent no-op would strand a
 * form without a token field.
 */
export function renderKiwiCaptcha(
  container: HTMLElement,
  options: RenderKiwiOptions,
): KiwiWidgetHandle {
  const doc = options.doc ?? container.ownerDocument;
  const api = options.api ?? getKiwiCaptcha(doc);
  if (!api) {
    throw new Error(
      "KiwiCaptcha: the widget driver is not loaded; call loadKiwiCaptcha() before rendering",
    );
  }

  let markup: KiwiMarkup;
  if (options.buildMarkup === false) {
    const widget = container.querySelector<HTMLElement>("[data-kiwi-widget]");
    const tokenInput = container.querySelector<HTMLInputElement>("[data-kiwi-token]");
    if (!widget || !tokenInput) {
      throw new Error(
        "KiwiCaptcha: buildMarkup false requires a [data-kiwi-widget] element and a [data-kiwi-token] input inside the container",
      );
    }
    markup = { container, widget, tokenInput };
  } else {
    // A remount into a reused container starts clean: stale markup of a
    // destroyed generation must never be driven a second time.
    container.replaceChildren();
    markup = buildKiwiMarkup(doc, options);
    container.appendChild(markup.container);
  }

  const id = api.render(markup.widget, driverOptions(options));
  if (!id) {
    throw new Error("KiwiCaptcha: the driver refused the render (target or options invalid)");
  }

  const wirings: EventWiring[] = [];
  const wire = (type: string, fn: EventListener) => {
    markup.widget.addEventListener(type, fn);
    wirings.push({ type, fn });
  };

  const detailOf = (event: Event): unknown => {
    const ev = event as CustomEvent;
    return ev.detail ?? {};
  };

  if (options.onReady) wire("kiwi:ready", (e) => options.onReady!(readScope(detailOf(e))));
  if (options.onVerifying) wire("kiwi:verifying", (e) => options.onVerifying!(readScope(detailOf(e))));
  if (options.onVerify) {
    wire("kiwi:verified", (e) => {
      const d = detailOf(e) as { nonce?: unknown };
      const token = readString(d, "token") || api.getResponse(id);
      options.onVerify!(token, {
        scope: readScope(d),
        nonce: typeof d?.nonce === "string" ? d.nonce : undefined,
        token,
      });
    });
  }
  if (options.onError) {
    wire("kiwi:error", (e) => {
      const d = detailOf(e);
      options.onError!(readString(d, "error") || "challenge-failed", { scope: readScope(d) });
    });
  }
  if (options.onExpire) wire("kiwi:expired", (e) => options.onExpire!(readScope(detailOf(e))));
  if (options.onRetry) {
    wire("kiwi:retrying", (e) => {
      const d = detailOf(e) as { attempt?: unknown };
      options.onRetry!({
        scope: readScope(d),
        error: readString(d, "error"),
        attempt: typeof d?.attempt === "number" ? d.attempt : 0,
      });
    });
  }
  if (options.onWorkerUnavailable) {
    wire("kiwi:worker-unavailable", (e) => {
      const d = detailOf(e);
      options.onWorkerUnavailable!(readString(d, "reason") || "worker-unavailable", readScope(d));
    });
  }
  if (options.onExecutionUnavailable) {
    wire("kiwi:execution-unavailable", (e) => {
      const d = detailOf(e);
      options.onExecutionUnavailable!(
        readString(d, "reason") || "execution-unavailable",
        readScope(d),
      );
    });
  }

  let destroyed = false;
  const handle: KiwiWidgetHandle = {
    id,
    element: markup.widget,
    container: markup.container,
    getResponse: () => (destroyed ? "" : api.getResponse(id)),
    isExpired: () => (destroyed ? false : api.isExpired(id)),
    reset: () => {
      if (!destroyed) api.reset(id);
    },
    execute: () => {
      if (destroyed) return Promise.reject(new Error("kiwicaptcha: widget destroyed"));
      return api.execute(id);
    },
    destroy: () => {
      if (destroyed) return;
      destroyed = true;
      for (const { type, fn } of wirings) {
        markup.widget.removeEventListener(type, fn);
      }
      wirings.length = 0;
      if (typeof api.destroy === "function") {
        // The framework owns the container node: destroy() cancels the
        // run and the record without unlinking the markup.
        api.destroy(markup.widget);
      } else {
        api.remove(id);
      }
    },
  };
  return handle;
}

/**
 * Load the driver (if needed) and render in one step, the shape the
 * framework components use after their container mounts.
 */
export function renderKiwiCaptchaAsync(
  container: HTMLElement,
  options: RenderKiwiOptions,
): Promise<KiwiWidgetHandle> {
  const api = options.api ?? getKiwiCaptcha(container.ownerDocument);
  if (api) return Promise.resolve(renderKiwiCaptcha(container, options));
  return loadKiwiCaptcha({ doc: container.ownerDocument }).then((loaded) =>
    renderKiwiCaptcha(container, { ...options, api: loaded }),
  );
}

export type { KiwiCaptchaApi };
