import { describe, expect, it } from "vitest";
import { Window } from "happy-dom";

import {
  buildKiwiMarkup,
  getKiwiCaptcha,
  KIWI_TOKEN_FIELD_NAME,
  renderKiwiCaptcha,
  renderKiwiCaptchaAsync,
  type KiwiCaptchaApi,
} from "../src/index.js";
import { installMockDriver, dispatchKiwi, type MockDriver } from "./mock-driver.js";

function freshDoc(): Document {
  const w = new Window({ url: "https://login.example.com/signup" });
  return w.document;
}

interface Fixture {
  doc: Document;
  driver: MockDriver;
  container: HTMLElement;
}

function fixture(): Fixture {
  const doc = freshDoc();
  const driver = installMockDriver(doc);
  doc.body.innerHTML = '<div id="mount"></div>';
  const container = doc.getElementById("mount") as HTMLElement;
  return { doc, driver, container };
}

describe("renderKiwiCaptcha", () => {
  it("throws when the driver is not loaded", () => {
    const doc = freshDoc();
    doc.body.innerHTML = '<div id="mount"></div>';
    expect(() =>
      renderKiwiCaptcha(doc.getElementById("mount") as HTMLElement, {}),
    ).toThrow(/driver is not loaded/);
  });

  it("builds the canonical markup and registers with the driver", () => {
    const { doc, driver, container } = fixture();
    const handle = renderKiwiCaptcha(container, {
      scope: "signup",
      endpoint: "/kc/challenge",
      sitekey: "pk-test-1",
    });

    expect(handle.id).toMatch(/^mock-\d+$/);
    const widget = container.querySelector("[data-kiwi-widget]") as HTMLElement;
    expect(widget).not.toBeNull();
    expect(widget.getAttribute("data-state")).toBe("idle");
    expect(widget.getAttribute("role")).toBe("group");
    expect(widget.querySelector("[data-kiwi-label]")?.textContent).toBe("Security Check");
    expect(container.querySelector(".kiwi-bar")?.getAttribute("data-progress")).toBe("0");

    const tokenInput = container.querySelector("input[data-kiwi-token]") as HTMLInputElement;
    expect(tokenInput.name).toBe(KIWI_TOKEN_FIELD_NAME);
    expect(tokenInput.type).toBe("hidden");

    // The four-setting attributes land on the inner container the core
    // builds; the framework's mount node stays untouched.
    const inner = container.querySelector(".kiwi-container") as HTMLElement;
    expect(inner).not.toBeNull();
    expect(inner.getAttribute("data-kiwi-endpoint")).toBe("/kc/challenge");
    expect(inner.getAttribute("data-kiwi-scope")).toBe("signup");

    // The sitekey and scope reach the driver's render options.
    const passed = driver.injectedOptions.at(-1);
    expect(passed?.["scope"]).toBe("signup");
    expect(passed?.["sitekey"]).toBe("pk-test-1");
    expect(doc.defaultView).not.toBeNull();
  });

  it("delivers the verified token through onVerify and getResponse", () => {
    const { container, driver } = fixture();
    const seen: Array<{ token: string; nonce?: string }> = [];
    const handle = renderKiwiCaptcha(container, {
      scope: "login",
      onVerify: (token, detail) => seen.push({ token, nonce: detail.nonce }),
    });

    driver.simulateVerified(handle.id, "tok-abc", "nonce-1");
    expect(seen).toEqual([{ token: "tok-abc", nonce: "nonce-1" }]);
    expect(handle.getResponse()).toBe("tok-abc");
    const input = container.querySelector("input[data-kiwi-token]") as HTMLInputElement;
    expect(input.value).toBe("tok-abc");
  });

  it("maps error, retry, expire and unavailable events", () => {
    const { container, driver } = fixture();
    const events: string[] = [];
    const handle = renderKiwiCaptcha(container, {
      onError: (message) => events.push(`error:${message}`),
      onRetry: (d) => events.push(`retry:${d.error}:${d.attempt}`),
      onExpire: () => events.push("expired"),
      onVerifying: (scope) => events.push(`verifying:${scope}`),
      onWorkerUnavailable: (reason) => events.push(`worker:${reason}`),
      onExecutionUnavailable: (reason) => events.push(`execution:${reason}`),
    });

    driver.simulateRetry(handle.id, "transport", 1);
    driver.simulateError(handle.id, "exhausted");
    driver.simulateExpired(handle.id);
    driver.simulateVerifying(handle.id);
    driver.simulateWorkerUnavailable(handle.id, "csp");
    driver.simulateExecutionUnavailable(handle.id, "timeout");
    expect(events).toEqual([
      "retry:transport:1",
      "error:exhausted",
      "expired",
      "verifying:login",
      "worker:csp",
      "execution:timeout",
    ]);
  });

  it("resolves execute() with the token and rejects on failure", async () => {
    const { container, driver } = fixture();
    const handle = renderKiwiCaptcha(container, { scope: "login", execution: "execute" });
    const pending = handle.execute();
    driver.simulateVerified(handle.id, "tok-exec");
    await expect(pending).resolves.toBe("tok-exec");

    const failing = renderKiwiCaptcha(container, { scope: "login", execution: "execute" });
    const pendingFail = failing.execute();
    driver.simulateError(failing.id, "deadline");
    await expect(pendingFail).rejects.toThrow("deadline");
  });

  it("reset delegates to the driver and clears the token input", () => {
    const { container, driver } = fixture();
    const handle = renderKiwiCaptcha(container, { scope: "login" });
    driver.simulateVerified(handle.id, "tok-1");
    handle.reset();
    expect(handle.getResponse()).toBe("");
    const input = container.querySelector("input[data-kiwi-token]") as HTMLInputElement;
    expect(input.value).toBe("");
  });

  it("destroy keeps the container node, detaches listeners, deletes the record", () => {
    const { doc, container, driver } = fixture();
    const seen: string[] = [];
    const handle = renderKiwiCaptcha(container, { scope: "login", onVerify: () => seen.push("v") });
    const widget = handle.element;
    handle.destroy();

    expect(container.isConnected).toBe(true);
    expect(container.querySelector("[data-kiwi-widget]")).toBe(widget);
    expect(doc.querySelectorAll("[data-kiwi-widget]").length).toBe(1);

    // No listener leakage: a late verified event reaches no callback.
    // The raw dispatch stands in for the driver (the record is deleted,
    // so the mock's simulate helpers refuse the id).
    dispatchKiwi(handle.element, "verified", { scope: "login", token: "late" });
    expect(seen).toEqual([]);

    // The handle is inert after destroy.
    expect(handle.getResponse()).toBe("");
    await_expect_rejects(handle.execute());
  });

  it("re-rendering into the same container replaces stale markup", () => {
    const { doc, container } = fixture();
    const first = renderKiwiCaptcha(container, { scope: "login" });
    const firstWidget = first.element;
    first.destroy();
    expect(firstWidget.dataset.kiwiDestroyed).toBe("1");

    const second = renderKiwiCaptcha(container, { scope: "login" });
    expect(second.element).not.toBe(firstWidget);
    expect(doc.querySelectorAll("[data-kiwi-widget]").length).toBe(1);
    expect(container.contains(firstWidget)).toBe(false);
  });

  it("supports buildMarkup false against pre-existing markup", () => {
    const { container, driver } = fixture();
    container.innerHTML =
      '<input type="hidden" name="custom_token" data-kiwi-token />' +
      '<div class="kiwi-widget" data-kiwi-widget data-state="idle"></div>';
    const seen: string[] = [];
    const handle = renderKiwiCaptcha(container, {
      buildMarkup: false,
      scope: "login",
      onVerify: (t) => seen.push(t),
    });
    driver.simulateVerified(handle.id, "tok-pre");
    expect(seen).toEqual(["tok-pre"]);

    // A container with no widget markup cannot render in passthrough mode.
    const empty = container.ownerDocument.createElement("div");
    container.ownerDocument.body.appendChild(empty);
    expect(() => renderKiwiCaptcha(empty, { buildMarkup: false })).toThrow();
  });

  it("applies the theme class to the container", () => {
    const { container } = fixture();
    renderKiwiCaptcha(container, { scope: "login", theme: "dark" });
    const inner = container.querySelector(".kiwi-container") as HTMLElement;
    expect(inner.classList.contains("kiwi-theme-dark")).toBe(true);
    expect(inner.classList.contains("kiwi-theme-light")).toBe(false);
  });

  it("reports token expiry through isExpired", () => {
    const { container, driver } = fixture();
    const handle = renderKiwiCaptcha(container, { scope: "login" });
    expect(handle.isExpired()).toBe(false);
    driver.simulateVerified(handle.id, "tok-short");
    expect(handle.isExpired()).toBe(false);
    driver.simulateExpired(handle.id);
    expect(handle.isExpired()).toBe(true);
    expect(handle.getResponse()).toBe("");
  });

  it("falls back to the legacy remove() when the driver has no destroy", () => {
    const { container, driver } = fixture();
    // A pre-destroy driver exposes remove only; delete the modern method.
    delete (driver as Partial<KiwiCaptchaApi>).destroy;
    const handle = renderKiwiCaptcha(container, { scope: "login" });
    const inner = container.querySelector(".kiwi-container") as HTMLElement;
    expect(inner.isConnected).toBe(true);

    handle.destroy();
    expect(driver.records.size).toBe(0);
    // remove() unlinks the markup, unlike destroy(); the mount node stays.
    expect(inner.isConnected).toBe(false);
    expect(container.isConnected).toBe(true);
  });

  it("propagates metadata, algorithm, lang and execution attributes", () => {
    const { container } = fixture();
    renderKiwiCaptcha(container, {
      scope: "comment",
      action: "submit",
      cData: "session-9",
      algorithm: "argon2id",
      lang: "de",
      fetchTimeoutMs: 5000,
      execution: "execute",
    });
    const inner = container.querySelector(".kiwi-container") as HTMLElement;
    const widget = container.querySelector("[data-kiwi-widget]") as HTMLElement;
    expect(inner.getAttribute("data-kiwi-algorithm")).toBe("argon2id");
    expect(inner.getAttribute("data-kiwi-lang")).toBe("de");
    expect(inner.getAttribute("data-kiwi-fetch-timeout-ms")).toBe("5000");
    expect(widget.getAttribute("data-action")).toBe("submit");
    expect(widget.getAttribute("data-cdata")).toBe("session-9");
    expect(widget.getAttribute("data-execution")).toBe("execute");
  });
});

describe("markup builder", () => {
  it("builds markup standalone from a document", () => {
    const doc = freshDoc();
    const m = buildKiwiMarkup(doc, { tokenFieldName: "my_token" });
    expect(m.tokenInput.name).toBe("my_token");
    expect(m.widget.querySelector("svg")).not.toBeNull();
    expect(m.widget.querySelector("svg")?.getAttribute("viewBox")).toBe("0 0 64 64");
    expect(m.widget.querySelectorAll("svg path")).toHaveLength(2);
    expect(m.widget.querySelectorAll('[data-kiwi-status][role="status"]')).toHaveLength(1);
    expect(m.widget.querySelector(".kiwi-icon-wrapper")?.getAttribute("aria-hidden")).toBe("true");
    expect(getKiwiCaptcha(doc)).toBeNull();
  });

  it("defaults the token field name and omits optional attributes", () => {
    const doc = freshDoc();
    const m = buildKiwiMarkup(doc, {});
    expect(m.tokenInput.name).toBe(KIWI_TOKEN_FIELD_NAME);
    expect(m.container.className).toBe("kiwi-container");
    expect(m.container.getAttribute("data-kiwi-risk-context")).toBeNull();
    expect(m.container.getAttribute("data-kiwi-endpoint")).toBeNull();
    expect(m.widget.getAttribute("data-action")).toBeNull();
  });

  it("carries the coarse risk context on the container", () => {
    const doc = freshDoc();
    const m = buildKiwiMarkup(doc, { riskContext: "coarse" });
    expect(m.container.getAttribute("data-kiwi-risk-context")).toBe("coarse");
  });

  it("does not add a theme class for auto or an absent theme", () => {
    const doc = freshDoc();
    expect(buildKiwiMarkup(doc, { theme: "auto" }).container.className).toBe("kiwi-container");
    expect(buildKiwiMarkup(doc, { theme: "light" }).container.className).toBe(
      "kiwi-container kiwi-theme-light",
    );
  });
});

describe("getKiwiCaptcha", () => {
  it("returns null until a shaped driver registers", () => {
    const doc = freshDoc();
    expect(getKiwiCaptcha(doc)).toBeNull();
    // DOM clobbering: an element named KiwiCaptcha must never be accepted.
    doc.body.innerHTML = '<div id="KiwiCaptcha"></div>';
    expect(getKiwiCaptcha(doc)).toBeNull();
  });

  it("returns the registered provider API", () => {
    const { doc, driver } = fixture();
    expect(getKiwiCaptcha(doc)).toBe(driver);
  });
});

describe("KiwiCaptchaApi ready and observe", () => {
  it("ready resolves for a live record and observe disconnects cleanly", async () => {
    const { doc, driver, container } = fixture();
    const handle = renderKiwiCaptcha(container, { scope: "login" });
    const api = getKiwiCaptcha(doc) as KiwiCaptchaApi;

    await expect(api.ready(handle.id)).resolves.toBeUndefined();
    expect(() => api.ready("missing")).toThrow(/unknown widget id/);

    const root = container.querySelector("[data-kiwi-widget]") as HTMLElement;
    const observation = api.observe!(root);
    expect(driver.observed).toEqual([root]);
    observation.disconnect();
    observation.disconnect();
    expect(driver.disconnects).toBe(1);
  });
});

describe("renderKiwiCaptchaAsync", () => {
  it("loads the driver on demand and renders", async () => {
    const w = new Window({ url: "https://app.example.com/login" });
    // Hold off happy-dom's own script fetch so the test controls the load.
    (w as unknown as { fetch: () => Promise<never> }).fetch = () => new Promise(() => {});
    const doc = w.document;
    doc.body.innerHTML = '<div id="mount"></div>';
    const container = doc.getElementById("mount") as HTMLElement;

    const pending = renderKiwiCaptchaAsync(container, { scope: "signup" });
    expect(doc.scripts.length).toBe(1);

    installMockDriver(doc);
    (doc.scripts[0] as HTMLScriptElement).dispatchEvent(new w.Event("load"));
    const handle = await pending;
    expect(handle.id).toMatch(/^mock-\d+$/);
    expect(container.querySelector("[data-kiwi-widget]")).not.toBeNull();
    expect(getKiwiCaptcha(doc)?.getResponse(handle.id)).toBe("");
  });

  it("renders immediately against a preloaded api", async () => {
    const { doc, driver, container } = fixture();
    const handle = await renderKiwiCaptchaAsync(container, { scope: "login", api: driver });
    expect(handle.id).toMatch(/^mock-\d+$/);
    expect(doc.scripts.length).toBe(0);
  });
});

describe("preloaded api option", () => {
  it("renders against an injected api without a window driver", () => {
    const doc = freshDoc();
    doc.body.innerHTML = '<div id="mount"></div>';
    const renders: Array<Record<string, unknown>> = [];
    const api: KiwiCaptchaApi = {
      render: (_t, o) => {
        renders.push(o ?? {});
        return "kiwi-x";
      },
      reset: () => {},
      getResponse: () => "z",
      execute: () => Promise.resolve("z"),
      remove: () => {},
      isExpired: () => false,
      ready: () => Promise.resolve(),
    };
    const handle = renderKiwiCaptcha(doc.getElementById("mount") as HTMLElement, {
      api,
      scope: "login",
    });
    expect(handle.id).toBe("kiwi-x");
    expect(handle.getResponse()).toBe("z");
    expect(renders.at(-1)?.["scope"]).toBe("login");
  });
});

async function await_expect_rejects(p: Promise<string>): Promise<void> {
  await expect(p).rejects.toThrow("destroyed");
}
