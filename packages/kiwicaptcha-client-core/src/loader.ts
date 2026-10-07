import type { KiwiCaptchaApi } from "./types.js";
import { KIWI_SCRIPT_SRC_DEFAULT } from "./types.js";

type DriverWindow = Window & { KiwiCaptcha?: KiwiCaptchaApi };

/**
 * Read the loaded driver surface from a document's window, or null when
 * the driver script has not run yet.
 *
 * A DOM-clobbered named property (`<div id="KiwiCaptcha">`) shadows the
 * window slot with an element. Shape-check the API surface before
 * accepting it: a clobbered value must never be handed out as the driver
 * (it would make loadKiwiCaptcha resolve without loading anything, and
 * every later render/execute would throw on a DOM node).
 */
export function getKiwiCaptcha(doc: Document = document): KiwiCaptchaApi | null {
  const w = doc.defaultView as DriverWindow | null;
  const api = w && w.KiwiCaptcha;
  return api && typeof api.render === "function" ? api : null;
}

// One in-flight load per (document, src): a page that mounts five widget
// components at once must inject exactly one driver script.
const registry = new WeakMap<Document, Map<string, Promise<KiwiCaptchaApi>>>();

export interface LoadKiwiOptions {
  /** The driver script URL. Default "/kiwi.js". */
  scriptSrc?: string;
  /** The document to load into. Default the global document. */
  doc?: Document;
  /** Reject when the driver has not appeared within this budget. */
  timeoutMs?: number;
  /** Optional SRI integrity attribute for the script element. */
  integrity?: string;
  /** Optional crossorigin attribute for the script element. */
  crossorigin?: "anonymous" | "use-credentials";
}

/**
 * Load the widget driver once and resolve its provider API.
 *
 * A driver already present on the window resolves immediately without
 * injecting anything (the widget owns the API: the first copy loaded
 * wins). Concurrent callers share one script element per source, a failed
 * load retires its entry so a later call can retry, and an optional
 * timeout bounds a hung request instead of wedging the page.
 */
export function loadKiwiCaptcha(options: LoadKiwiOptions = {}): Promise<KiwiCaptchaApi> {
  const doc = options.doc ?? document;
  const src = options.scriptSrc ?? KIWI_SCRIPT_SRC_DEFAULT;

  const existing = getKiwiCaptcha(doc);
  if (existing) return Promise.resolve(existing);

  let perDoc = registry.get(doc);
  if (!perDoc) {
    perDoc = new Map();
    registry.set(doc, perDoc);
  }
  const inFlight = perDoc.get(src);
  if (inFlight) return inFlight;

  const load = injectDriverScript(doc, src, options);
  perDoc.set(src, load);
  load.catch(() => {
    // A failed load must not be memoized: the next caller retries.
    const current = registry.get(doc);
    if (current && current.get(src) === load) current.delete(src);
  });
  return load;
}

function injectDriverScript(
  doc: Document,
  src: string,
  options: LoadKiwiOptions,
): Promise<KiwiCaptchaApi> {
  return new Promise<KiwiCaptchaApi>((resolve, reject) => {
    const script = doc.createElement("script");
    script.src = src;
    script.async = true;
    if (options.integrity) script.integrity = options.integrity;
    if (options.crossorigin) script.crossOrigin = options.crossorigin;

    let timer: ReturnType<typeof setTimeout> | null = null;
    const settle = (fn: () => void) => {
      if (timer !== null) clearTimeout(timer);
      script.removeEventListener("load", onLoad);
      script.removeEventListener("error", onError);
      fn();
    };

    const onLoad = () => {
      const api = getKiwiCaptcha(doc);
      if (api) {
        settle(() => resolve(api));
      } else {
        settle(() =>
          reject(
            new Error(
              `KiwiCaptcha: ${src} loaded but window.KiwiCaptcha is missing; ` +
                "the asset may be the wrong file or an older driver",
            ),
          ),
        );
      }
    };
    const onError = () => {
      settle(() => reject(new Error(`KiwiCaptcha: the driver script failed to load (${src})`)));
    };

    script.addEventListener("load", onLoad);
    script.addEventListener("error", onError);
    if (options.timeoutMs && options.timeoutMs > 0) {
      timer = setTimeout(() => {
        settle(() => reject(new Error(`KiwiCaptcha: the driver script did not load within ${options.timeoutMs}ms`)));
      }, options.timeoutMs);
    }
    (doc.head || doc.documentElement).appendChild(script);
  });
}
