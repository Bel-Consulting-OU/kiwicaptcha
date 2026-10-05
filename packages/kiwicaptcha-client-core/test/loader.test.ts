import { describe, expect, it, vi } from "vitest";
import { Window } from "happy-dom";

import {
  getKiwiCaptcha,
  KIWI_SCRIPT_SRC_DEFAULT,
  loadKiwiCaptcha,
  type KiwiCaptchaApi,
} from "../src/index.js";
import { installMockDriver } from "./mock-driver.js";

function freshWindow(): Window {
  // The window's fetch never settles for the driver request: happy-dom's
  // own script fetch is held off, so the tests drive the load and error
  // events by hand with full control over ordering.
  const w = new Window({ url: "https://app.example.com/login" });
  (w as unknown as { fetch: () => Promise<never> }).fetch = () => new Promise(() => {});
  return w;
}

const stubApi: KiwiCaptchaApi = {
  render: () => "stub",
  reset: () => {},
  getResponse: () => "",
  execute: () => Promise.resolve(""),
  remove: () => {},
  isExpired: () => false,
  ready: () => Promise.resolve(),
};

describe("loadKiwiCaptcha", () => {
  it("resolves the preloaded driver without injecting a script", async () => {
    const w = freshWindow();
    (w as unknown as { KiwiCaptcha: KiwiCaptchaApi }).KiwiCaptcha = stubApi;
    const api = await loadKiwiCaptcha({ doc: w.document });
    expect(api).toBe(stubApi);
    expect(w.document.scripts.length).toBe(0);
  });

  it("injects one async script and resolves when the global appears", async () => {
    const w = freshWindow();
    const pending = loadKiwiCaptcha({ doc: w.document });

    expect(w.document.scripts.length).toBe(1);
    const script = w.document.scripts[0] as HTMLScriptElement;
    expect(script.src).toBe(`https://app.example.com${KIWI_SCRIPT_SRC_DEFAULT}`);
    expect(script.async).toBe(true);

    // The driver appears, then the script's load event fires: the order
    // the real driver produces (the IIFE sets the global before load).
    installMockDriver(w.document);
    script.dispatchEvent(new w.Event("load"));
    const api = await pending;
    expect(api).toBe(getKiwiCaptcha(w.document));
  });

  it("concurrent callers share one script element", async () => {
    // A disabled-loading window auto-fails the script deterministically:
    // both callers must observe exactly one element and one rejection.
    const w = new Window({
      url: "https://app.example.com/login",
      settings: { disableJavaScriptFileLoading: true },
    });
    const first = loadKiwiCaptcha({ doc: w.document });
    const second = loadKiwiCaptcha({ doc: w.document });
    expect(w.document.scripts.length).toBe(1);
    await expect(first).rejects.toThrow();
    await expect(second).rejects.toThrow();
  });

  it("a load error rejects and clears the memo so a retry re-injects", async () => {
    const w = freshWindow();
    const first = loadKiwiCaptcha({ doc: w.document });
    (w.document.scripts[0] as HTMLScriptElement).dispatchEvent(new w.Event("error"));
    await expect(first).rejects.toThrow(/failed to load/);

    const second = loadKiwiCaptcha({ doc: w.document });
    expect(w.document.scripts.length).toBe(2);
    const script = w.document.scripts[1] as HTMLScriptElement;
    installMockDriver(w.document);
    script.dispatchEvent(new w.Event("load"));
    await expect(second).resolves.toBe(getKiwiCaptcha(w.document));
  });

  it("a load event without the global rejects with the shape check", async () => {
    const w = freshWindow();
    const pending = loadKiwiCaptcha({ doc: w.document });
    (w.document.scripts[0] as HTMLScriptElement).dispatchEvent(new w.Event("load"));
    await expect(pending).rejects.toThrow(/window.KiwiCaptcha is missing/);
  });

  it("carries integrity and crossorigin onto the script element", async () => {
    const w = freshWindow();
    const pending = loadKiwiCaptcha({
      doc: w.document,
      scriptSrc: "/vendor/kiwi.js",
      integrity: "sha384-abc",
      crossorigin: "anonymous",
    });
    const script = w.document.scripts[0] as HTMLScriptElement;
    expect(script.integrity).toBe("sha384-abc");
    expect(script.crossOrigin).toBe("anonymous");
    installMockDriver(w.document);
    script.dispatchEvent(new w.Event("load"));
    await pending;
  });

  it("times out when the driver never appears", async () => {
    vi.useFakeTimers();
    try {
      const w = freshWindow();
      const pending = loadKiwiCaptcha({ doc: w.document, timeoutMs: 250 });
      const assertion = expect(pending).rejects.toThrow(/did not load within 250ms/);
      await vi.advanceTimersByTimeAsync(300);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps per-document loads independent", async () => {
    const a = freshWindow();
    const b = freshWindow();
    const pa = loadKiwiCaptcha({ doc: a.document });
    const pb = loadKiwiCaptcha({ doc: b.document });
    expect(a.document.scripts.length).toBe(1);
    expect(b.document.scripts.length).toBe(1);
    installMockDriver(a.document);
    (a.document.scripts[0] as HTMLScriptElement).dispatchEvent(new a.Event("load"));
    installMockDriver(b.document);
    (b.document.scripts[0] as HTMLScriptElement).dispatchEvent(new b.Event("load"));
    const [apiA, apiB] = await Promise.all([pa, pb]);
    expect(apiA).toBe(getKiwiCaptcha(a.document));
    expect(apiB).toBe(getKiwiCaptcha(b.document));
    expect(apiA).not.toBe(apiB);
  });
});
