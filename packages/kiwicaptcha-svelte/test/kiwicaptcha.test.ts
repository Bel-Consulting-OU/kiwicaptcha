import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { flushSync, mount, unmount, type ComponentProps } from "svelte";
import type { KiwiCaptchaApi } from "@kiwicaptcha/client-core";

import { KiwiCaptcha, kiwiCaptcha } from "../src/index.js";
import {
  installMockDriver,
  type MockDriver,
} from "../../kiwicaptcha-client-core/test/mock-driver.js";

let driver: MockDriver;
let host: HTMLElement;
let instance: Record<string, unknown> | null = null;

beforeEach(() => {
  document.body.innerHTML = "";
  driver = installMockDriver(document);
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  if (instance) {
    unmount(instance as never);
    instance = null;
  }
  host.remove();
  expect(driver.records.size).toBe(0);
});

function mountWidget(props: ComponentProps<typeof KiwiCaptcha>): Record<string, unknown> {
  flushSync(() => {
    instance = mount(KiwiCaptcha, { target: host, props }) as unknown as Record<
      string,
      unknown
    >;
  });
  return instance as Record<string, unknown>;
}

function lastRecordId(): string {
  const ids = [...driver.records.keys()];
  return ids[ids.length - 1] as string;
}

describe("KiwiCaptcha component", () => {
  it("renders the widget markup and forwards scope and sitekey", () => {
    mountWidget({ scope: "login", sitekey: "pk-svelte", endpoint: "/kc" });
    expect(host.querySelector("input[data-kiwi-token]")).not.toBeNull();
    expect(host.querySelector("[data-kiwi-widget]")).not.toBeNull();
    const passed = driver.injectedOptions[driver.injectedOptions.length - 1];
    expect(passed?.["scope"]).toBe("login");
    expect(passed?.["sitekey"]).toBe("pk-svelte");
  });

  it("delivers verify callbacks with token and detail", () => {
    const seen: Array<{ token: string; nonce?: string }> = [];
    mountWidget({
      scope: "login",
      onverify: (token, detail) => seen.push({ token, nonce: detail.nonce }),
    });
    const id = lastRecordId();
    driver.simulateVerified(id, "tok-svelte", "nonce-s");
    expect(seen).toEqual([{ token: "tok-svelte", nonce: "nonce-s" }]);
  });

  it("maps error, expire and retry callbacks", () => {
    const events: string[] = [];
    mountWidget({
      scope: "login",
      onerror: (m) => events.push(`error:${m}`),
      onexpire: () => events.push("expire"),
      onretry: (d) => events.push(`retry:${d.attempt}`),
      onverifying: (scope) => events.push(`verifying:${scope}`),
    });
    const id = lastRecordId();
    driver.simulateVerifying(id);
    driver.simulateRetry(id, "net", 1);
    driver.simulateError(id, "boom");
    driver.simulateExpired(id);
    expect(events).toEqual(["verifying:login", "retry:1", "error:boom", "expire"]);
  });

  it("exposes imperative controls on the bound instance", async () => {
    const comp = mountWidget({ scope: "login" });
    const id = lastRecordId();
    const api = comp as unknown as {
      getResponse(): string;
      reset(): void;
      execute(): Promise<string>;
      isExpired(): boolean;
      destroy(): void;
    };
    expect(api.getResponse()).toBe("");
    driver.simulateVerified(id, "tok-imp");
    expect(api.getResponse()).toBe("tok-imp");
    expect(api.isExpired()).toBe(false);
    await expect(api.execute()).resolves.toBe("tok-imp");
    driver.simulateExpired(id);
    expect(api.isExpired()).toBe(true);
    api.reset();
    expect(api.getResponse()).toBe("");
    api.destroy();
    expect(driver.records.size).toBe(0);
  });

  it("forwards theme, lang, action, execution and riskContext", () => {
    mountWidget({
      scope: "comment",
      theme: "dark",
      lang: "es",
      action: "submit",
      cData: "sd-1",
      execution: "execute",
      riskContext: "coarse",
    });
    const container = host.querySelector(".kiwi-container") as HTMLElement;
    const widget = host.querySelector("[data-kiwi-widget]") as HTMLElement;
    expect(container.classList.contains("kiwi-theme-dark")).toBe(true);
    expect(container.getAttribute("data-kiwi-lang")).toBe("es");
    expect(container.getAttribute("data-kiwi-risk-context")).toBe("coarse");
    expect(widget.getAttribute("data-action")).toBe("submit");
    expect(widget.getAttribute("data-cdata")).toBe("sd-1");
    expect(widget.getAttribute("data-execution")).toBe("execute");
  });

  it("forwards the loader controls to the injected script", async () => {
    delete (window as unknown as { KiwiCaptcha?: KiwiCaptchaApi }).KiwiCaptcha;
    document.head.querySelectorAll("script").forEach((s) => s.remove());
    const originalFetch = window.fetch;
    window.fetch = () => new Promise<Response>(() => {});

    mountWidget({
      scope: "login",
      scriptSrc: "/vendor/kiwi-component.js",
      scriptIntegrity: "sha384-svelte",
      scriptCrossorigin: "anonymous",
      scriptTimeoutMs: 5000,
      scriptNonce: "nonce-svelte",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    const script = document.head.querySelector("script") as HTMLScriptElement | null;
    expect(script).not.toBeNull();
    expect(script?.src).toMatch(/\/vendor\/kiwi-component\.js$/);
    expect(script?.integrity).toBe("sha384-svelte");
    expect(script?.crossOrigin).toBe("anonymous");
    expect(script?.nonce).toBe("nonce-svelte");

    driver = installMockDriver(document);
    script?.dispatchEvent(new Event("load"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(driver.records.size).toBe(1);
    expect(host.querySelector("input[data-kiwi-token]")).not.toBeNull();
    window.fetch = originalFetch;
    document.head.querySelectorAll("script").forEach((s) => s.remove());
  });
});

describe("kiwiCaptcha action", () => {
  it("renders into the action element and destroys on removal", () => {
    const target = document.createElement("div");
    host.appendChild(target);
    const action = kiwiCaptcha(target, { scope: "comment" });
    expect(target.querySelector("input[data-kiwi-token]")).not.toBeNull();
    expect(driver.injectedOptions[driver.injectedOptions.length - 1]?.["scope"]).toBe("comment");

    action.destroy();
    expect(driver.records.size).toBe(0);
  });

  it("rebuilds on an options update", () => {
    const target = document.createElement("div");
    host.appendChild(target);
    const action = kiwiCaptcha(target, { scope: "comment" });
    const firstId = lastRecordId();
    action.update({ scope: "login" });
    expect(driver.records.has(firstId)).toBe(false);
    expect(driver.injectedOptions[driver.injectedOptions.length - 1]?.["scope"]).toBe("login");
    action.destroy();
  });

  it("forwards loader controls and render options", async () => {
    delete (window as unknown as { KiwiCaptcha?: KiwiCaptchaApi }).KiwiCaptcha;
    document.head.querySelectorAll("script").forEach((s) => s.remove());
    const originalFetch = window.fetch;
    window.fetch = () => new Promise<Response>(() => {});
    const target = document.createElement("div");
    host.appendChild(target);
    const action = kiwiCaptcha(target, {
      scope: "login",
      theme: "light",
      lang: "it",
      action: "submit",
      execution: "execute",
      riskContext: "coarse",
      scriptSrc: "/vendor/kiwi-action.js",
      scriptIntegrity: "sha384-action",
      scriptCrossorigin: "anonymous",
      scriptTimeoutMs: 5000,
      scriptNonce: "nonce-action",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    const script = document.head.querySelector("script") as HTMLScriptElement | null;
    expect(script).not.toBeNull();
    expect(script?.src).toMatch(/\/vendor\/kiwi-action\.js$/);
    expect(script?.integrity).toBe("sha384-action");
    expect(script?.crossOrigin).toBe("anonymous");
    expect(script?.nonce).toBe("nonce-action");

    driver = installMockDriver(document);
    script?.dispatchEvent(new Event("load"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(driver.records.size).toBe(1);
    expect(target.querySelector(".kiwi-container")?.getAttribute("data-kiwi-risk-context")).toBe(
      "coarse",
    );
    expect(target.querySelector("[data-kiwi-widget]")?.getAttribute("data-execution")).toBe(
      "execute",
    );
    action.destroy();
    window.fetch = originalFetch;
    document.head.querySelectorAll("script").forEach((s) => s.remove());
  });
});
