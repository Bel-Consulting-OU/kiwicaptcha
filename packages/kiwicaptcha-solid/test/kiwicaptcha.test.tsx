import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { render, type Disposer } from "solid-js/web";
import type { KiwiCaptchaApi } from "@kiwicaptcha/client-core";

import { KiwiCaptcha, type KiwiSolidControls } from "../src/index.js";
import {
  installMockDriver,
  type MockDriver,
} from "../../kiwicaptcha-client-core/test/mock-driver.js";

let driver: MockDriver;
let host: HTMLElement;
let disposer: Disposer | null = null;

beforeEach(() => {
  document.body.innerHTML = "";
  driver = installMockDriver(document);
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  if (disposer) {
    disposer();
    disposer = null;
  }
  host.remove();
  expect(driver.records.size).toBe(0);
});

function lastRecordId(): string {
  const ids = [...driver.records.keys()];
  return ids[ids.length - 1] as string;
}

describe("KiwiCaptcha solid component", () => {
  it("renders the widget markup and forwards scope and sitekey", () => {
    disposer = render(() => (
      <KiwiCaptcha scope="login" sitekey="pk-solid" endpoint="/kc" />
    ), host);
    expect(host.querySelector("input[data-kiwi-token]")).not.toBeNull();
    expect(host.querySelector("[data-kiwi-widget]")).not.toBeNull();
    const passed = driver.injectedOptions.at(-1);
    expect(passed?.["scope"]).toBe("login");
    expect(passed?.["sitekey"]).toBe("pk-solid");
  });

  it("delivers verify callbacks with token and detail", () => {
    const seen: Array<{ token: string; nonce?: string }> = [];
    disposer = render(() => (
      <KiwiCaptcha
        scope="login"
        onVerify={(token, detail) => seen.push({ token, nonce: detail.nonce })}
      />
    ), host);
    driver.simulateVerified(lastRecordId(), "tok-solid", "nonce-o");
    expect(seen).toEqual([{ token: "tok-solid", nonce: "nonce-o" }]);
  });

  it("maps error, expire and retry callbacks", () => {
    const events: string[] = [];
    disposer = render(() => (
      <KiwiCaptcha
        scope="login"
        onError={(m) => events.push(`error:${m}`)}
        onExpire={() => events.push("expire")}
        onRetry={(d) => events.push(`retry:${d.attempt}`)}
        onVerifying={(scope) => events.push(`verifying:${scope}`)}
      />
    ), host);
    const id = lastRecordId();
    driver.simulateVerifying(id);
    driver.simulateRetry(id, "net", 2);
    driver.simulateError(id, "boom");
    driver.simulateExpired(id);
    expect(events).toEqual(["verifying:login", "retry:2", "error:boom", "expire"]);
  });

  it("delivers imperative controls through the ref prop", async () => {
    let controls: KiwiSolidControls | null = null;
    disposer = render(() => (
      <KiwiCaptcha scope="login" ref={(c) => (controls = c)} />
    ), host);
    const id = lastRecordId();
    const c = controls as unknown as KiwiSolidControls;
    expect(c.getResponse()).toBe("");
    driver.simulateVerified(id, "tok-ctl");
    expect(c.getResponse()).toBe("tok-ctl");
    await expect(c.execute()).resolves.toBe("tok-ctl");
    expect(c.isExpired()).toBe(false);
    driver.simulateExpired(id);
    expect(c.isExpired()).toBe(true);
    c.reset();
    expect(c.getResponse()).toBe("");
    c.destroy();
    expect(driver.records.size).toBe(0);
    expect(c.getResponse()).toBe("");
  });

  it("forwards theme, lang, action, execution and riskContext", () => {
    disposer = render(() => (
      <KiwiCaptcha
        scope="comment"
        theme="dark"
        lang="pt"
        action="submit"
        cData="s-1"
        execution="execute"
        riskContext="coarse"
      />
    ), host);
    const container = host.querySelector(".kiwi-container") as HTMLElement;
    const widget = host.querySelector("[data-kiwi-widget]") as HTMLElement;
    expect(container.classList.contains("kiwi-theme-dark")).toBe(true);
    expect(container.getAttribute("data-kiwi-lang")).toBe("pt");
    expect(container.getAttribute("data-kiwi-risk-context")).toBe("coarse");
    expect(widget.getAttribute("data-action")).toBe("submit");
    expect(widget.getAttribute("data-cdata")).toBe("s-1");
    expect(widget.getAttribute("data-execution")).toBe("execute");
  });

  it("forwards the loader controls to the injected script", async () => {
    delete (window as unknown as { KiwiCaptcha?: KiwiCaptchaApi }).KiwiCaptcha;
    document.head.querySelectorAll("script").forEach((s) => s.remove());
    const originalFetch = window.fetch;
    window.fetch = () => new Promise<Response>(() => {});

    disposer = render(() => (
      <KiwiCaptcha
        scope="login"
        scriptSrc="/vendor/kiwi-solid.js"
        scriptIntegrity="sha384-solid"
        scriptCrossorigin="anonymous"
        scriptTimeoutMs={5000}
        scriptNonce="nonce-solid"
      />
    ), host);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const script = document.head.querySelector("script") as HTMLScriptElement | null;
    expect(script).not.toBeNull();
    expect(script?.src).toMatch(/\/vendor\/kiwi-solid\.js$/);
    expect(script?.integrity).toBe("sha384-solid");
    expect(script?.crossOrigin).toBe("anonymous");
    expect(script?.nonce).toBe("nonce-solid");

    driver = installMockDriver(document);
    script?.dispatchEvent(new Event("load"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(driver.records.size).toBe(1);
    expect(host.querySelector("input[data-kiwi-token]")).not.toBeNull();
    window.fetch = originalFetch;
    document.head.querySelectorAll("script").forEach((s) => s.remove());
  });

  it("destroys the driver record when disposed", () => {
    disposer = render(() => <KiwiCaptcha scope="login" />, host);
    expect(driver.records.size).toBe(1);
    const d = disposer;
    disposer = null;
    d();
    expect(driver.records.size).toBe(0);
  });

  it("calls the ref prop exactly once per mount", () => {
    let captured = 0;
    disposer = render(() => (
      <KiwiCaptcha scope="login" ref={() => captured++} />
    ), host);
    expect(captured).toBe(1);
  });
});
