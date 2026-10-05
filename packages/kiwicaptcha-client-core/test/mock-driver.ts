import type { KiwiCaptchaApi } from "../src/index.js";

/**
 * A faithful mock of the widget driver's provider surface for DOM tests.
 *
 * It mirrors the behavior the core must handle (packages/
 * kiwicaptcha-wasm/assets/widget-driver.js): render returns a stable id
 * and dispatches kiwi:ready; the solve dispatches kiwi:verifying then
 * kiwi:verified (with nonce and token) or kiwi:error; verified tokens
 * land in the [data-kiwi-token] input; reset re-arms without removing
 * nodes; remove unlinks the widget's container; destroy keeps the node
 * but permanently refuses the element.
 */

export interface MockRecord {
  id: string;
  element: HTMLElement;
  options: Record<string, unknown>;
  state: "pending" | "solving" | "verified" | "expired";
  token: string;
  destroyed: boolean;
}

export interface MockDriver extends KiwiCaptchaApi {
  records: Map<string, MockRecord>;
  injectedOptions: Array<Record<string, unknown>>;
  simulateVerifying(id: string): void;
  simulateVerified(id: string, token: string, nonce?: string): void;
  simulateError(id: string, message: string): void;
  simulateExpired(id: string): void;
  simulateRetry(id: string, error: string, attempt: number): void;
  simulateWorkerUnavailable(id: string, reason: string): void;
  simulateExecutionUnavailable(id: string, reason: string): void;
  tokenInput(id: string): HTMLInputElement | null;
}

export function dispatchKiwi(el: HTMLElement, name: string, detail: Record<string, unknown>): void {
  const w = el.ownerDocument.defaultView;
  if (!w) return;
  const CustomEventCtor = w.CustomEvent;
  el.dispatchEvent(
    new CustomEventCtor(`kiwi:${name}`, { bubbles: true, cancelable: false, detail }),
  );
}

export function installMockDriver(doc: Document): MockDriver {
  const w = doc.defaultView as (Window & { KiwiCaptcha?: KiwiCaptchaApi }) | null;
  if (!w) throw new Error("the document has no window");

  const records = new Map<string, MockRecord>();
  const injectedOptions: Array<Record<string, unknown>> = [];
  let counter = 0;

  function record(id: string): MockRecord {
    const rec = records.get(id);
    if (!rec) throw new Error(`mock driver: unknown widget id ${id}`);
    return rec;
  }

  function tokenInput(id: string): HTMLInputElement | null {
    const rec = records.get(id);
    if (!rec) return null;
    const host = rec.element.closest(".kiwi-container") ?? rec.element;
    return host.querySelector<HTMLInputElement>("[data-kiwi-token]");
  }

  const api: MockDriver = {
    records,
    injectedOptions,
    render(target, options = {}) {
      const el =
        typeof target === "string"
          ? (doc.getElementById(target) as HTMLElement | null)
          : (target as HTMLElement | null);
      if (!el || el.dataset.kiwiDestroyed) return "0";
      if (el.dataset.kiwiStarted) return el.dataset.kiwiInstance ?? "0";
      const id = `mock-${++counter}`;
      el.dataset.kiwiInstance = id;
      el.dataset.kiwiStarted = "1";
      const state = options["execution"] === "execute" ? "pending" : "solving";
      records.set(id, { id, element: el, options, state, token: "", destroyed: false });
      injectedOptions.push(options);
      dispatchKiwi(el, "ready", { scope: options["scope"] ?? "login" });
      if (state === "solving") dispatchKiwi(el, "verifying", { scope: options["scope"] ?? "login" });
      return id;
    },
    reset(id) {
      const rec = record(id);
      rec.state = "solving";
      rec.token = "";
      const input = tokenInput(id);
      if (input) input.value = "";
      dispatchKiwi(rec.element, "verifying", { scope: "login" });
    },
    getResponse(id) {
      const rec = records.get(id);
      return rec && rec.state === "verified" ? rec.token : "";
    },
    execute(id) {
      const rec = record(id);
      if (rec.state === "verified") return Promise.resolve(rec.token);
      rec.state = "solving";
      return new Promise<string>((resolve, reject) => {
        const onVerified = (ev: Event) => {
          const detail = (ev as CustomEvent).detail ?? {};
          cleanup();
          resolve(String(detail["token"] ?? ""));
        };
        const onError = (ev: Event) => {
          const detail = (ev as CustomEvent).detail ?? {};
          cleanup();
          reject(new Error(String(detail["error"] ?? "kiwicaptcha: solve failed")));
        };
        const cleanup = () => {
          rec.element.removeEventListener("kiwi:verified", onVerified);
          rec.element.removeEventListener("kiwi:error", onError);
        };
        rec.element.addEventListener("kiwi:verified", onVerified);
        rec.element.addEventListener("kiwi:error", onError);
      });
    },
    remove(id) {
      const rec = records.get(id);
      if (!rec) return;
      records.delete(id);
      const container = rec.element.closest(".kiwi-container") ?? rec.element;
      container.parentNode?.removeChild(container);
    },
    isExpired(id) {
      const rec = records.get(id);
      return !!rec && rec.state === "expired";
    },
    ready(id) {
      record(id);
      return Promise.resolve();
    },
    destroy(target) {
      const el = typeof target === "string"
        ? (doc.querySelector(target) as HTMLElement | null)
        : (target as HTMLElement | null);
      if (!el) return;
      el.dataset.kiwiDestroyed = "1";
      const id = el.dataset.kiwiInstance;
      const rec = id ? records.get(id) : undefined;
      if (rec) {
        rec.destroyed = true;
        const input = tokenInput(rec.id);
        if (input) input.value = "";
        records.delete(rec.id);
      }
    },
    simulateVerifying(id) {
      const rec = record(id);
      rec.state = "solving";
      dispatchKiwi(rec.element, "verifying", { scope: "login" });
    },
    simulateVerified(id, token, nonce) {
      const rec = record(id);
      rec.state = "verified";
      rec.token = token;
      const input = tokenInput(id);
      if (input) input.value = token;
      dispatchKiwi(rec.element, "verified", { scope: "login", nonce, token });
    },
    simulateError(id, message) {
      const rec = record(id);
      rec.state = "solving";
      dispatchKiwi(rec.element, "error", { scope: "login", error: message });
    },
    simulateExpired(id) {
      const rec = record(id);
      rec.state = "expired";
      rec.token = "";
      const input = tokenInput(id);
      if (input) input.value = "";
      dispatchKiwi(rec.element, "expired", { scope: "login" });
    },
    simulateRetry(id, error, attempt) {
      const rec = record(id);
      dispatchKiwi(rec.element, "retrying", { scope: "login", error, attempt });
    },
    simulateWorkerUnavailable(id, reason) {
      const rec = record(id);
      dispatchKiwi(rec.element, "worker-unavailable", { scope: "login", reason });
    },
    simulateExecutionUnavailable(id, reason) {
      const rec = record(id);
      dispatchKiwi(rec.element, "execution-unavailable", { scope: "login", reason });
    },
    tokenInput,
  };

  w.KiwiCaptcha = api;
  return api;
}
