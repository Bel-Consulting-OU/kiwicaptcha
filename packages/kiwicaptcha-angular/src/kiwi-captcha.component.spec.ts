import { ComponentFixture, TestBed } from "@angular/core/testing";
import type { KiwiCaptchaApi } from "@kiwicaptcha/client-core";

import { KiwiCaptcha } from "./kiwi-captcha.component";
import { KiwiCaptchaService } from "./kiwi-captcha.service";
import type { MockDriver } from "../../kiwicaptcha-client-core/test/mock-driver";
import {
  dispatchKiwi,
  installMockDriver,
} from "../../kiwicaptcha-client-core/test/mock-driver";

/**
 * TestBed specs, executed by vitest (the jsdom runner) with the Angular
 * AOT transform, and by `ng test` (Karma) in a browser workspace.
 */
describe("KiwiCaptcha", () => {
  let driver: MockDriver;
  let fixture: ComponentFixture<KiwiCaptcha>;

  function installDriver(): void {
    driver = installMockDriver(document);
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    // The component renders outside the Angular zone; give the driver
    // promise chain a macrotask to land before asserting.
    await new Promise((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function lastOptions(): Record<string, unknown> {
    return driver.injectedOptions[driver.injectedOptions.length - 1] ?? {};
  }

  beforeEach(async () => {
    document.body.innerHTML = "";
    document.head.querySelectorAll("script").forEach((script) => script.remove());
    delete (window as unknown as { KiwiCaptcha?: KiwiCaptchaApi }).KiwiCaptcha;
    installDriver();
    await TestBed.configureTestingModule({
      imports: [KiwiCaptcha],
    }).compileComponents();
    fixture = TestBed.createComponent(KiwiCaptcha);
  });

  afterEach(() => {
    fixture.destroy();
    TestBed.resetTestingModule();
  });

  it("renders the widget markup into the host", async () => {
    fixture.componentRef.setInput("scope", "login");
    fixture.componentRef.setInput("sitekey", "pk-ng");
    fixture.detectChanges();
    await settle();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector("input[data-kiwi-token]")).not.toBeNull();
    expect(el.querySelector("[data-kiwi-widget]")).not.toBeNull();
    expect(lastOptions()["scope"]).toBe("login");
    expect(lastOptions()["sitekey"]).toBe("pk-ng");
    expect(fixture.componentInstance.ready()).toBe(true);
  });

  it("emits verified with the token detail", async () => {
    const seen: Array<{ token: string; nonce?: string }> = [];
    fixture.componentInstance.verified.subscribe((d) =>
      seen.push({ token: d.token, nonce: d.nonce }),
    );
    fixture.componentRef.setInput("scope", "login");
    fixture.detectChanges();
    await settle();
    const id = [...driver.records.keys()][0] as string;
    driver.simulateVerified(id, "tok-ng", "nonce-ng");
    expect(seen).toEqual([{ nonce: "nonce-ng", token: "tok-ng" }]);
    expect(fixture.componentInstance.getResponse()).toBe("tok-ng");
    expect(fixture.componentInstance.isExpired()).toBe(false);
  });

  it("emits failed and expired", async () => {
    const events: string[] = [];
    fixture.componentInstance.failed.subscribe((m) => events.push(`failed:${m}`));
    fixture.componentInstance.expired.subscribe(() => events.push("expired"));
    fixture.componentRef.setInput("scope", "login");
    fixture.detectChanges();
    await settle();
    const id = [...driver.records.keys()][0] as string;
    driver.simulateError(id, "boom");
    driver.simulateExpired(id);
    expect(events).toEqual(["failed:boom", "expired"]);
    expect(fixture.componentInstance.isExpired()).toBe(true);
  });

  it("emits verifying with the scope", async () => {
    const scopes: string[] = [];
    fixture.componentInstance.verifying.subscribe((scope) => scopes.push(scope));
    fixture.componentRef.setInput("scope", "signup");
    fixture.detectChanges();
    await settle();
    const widget = fixture.nativeElement.querySelector("[data-kiwi-widget]") as HTMLElement;
    dispatchKiwi(widget, "verifying", { scope: "signup" });
    expect(scopes).toEqual(["signup"]);
  });

  it("destroys the driver record on component destroy", async () => {
    fixture.componentRef.setInput("scope", "login");
    fixture.detectChanges();
    await settle();
    expect(driver.records.size).toBe(1);
    fixture.destroy();
    expect(driver.records.size).toBe(0);
  });

  it("exposes reset and execute through the component", async () => {
    fixture.componentRef.setInput("scope", "login");
    fixture.detectChanges();
    await settle();
    const id = [...driver.records.keys()][0] as string;
    driver.simulateVerified(id, "tok-exec");
    const token = await fixture.componentInstance.execute();
    expect(token).toBe("tok-exec");
    fixture.componentInstance.reset();
    expect(fixture.componentInstance.getResponse()).toBe("");
  });

  it("loads the driver through the injectable service", async () => {
    const service = TestBed.inject(KiwiCaptchaService);
    const api = await service.load();
    expect(api).toBe(driver);
    // Idempotent: a second load reuses the loaded driver.
    expect(await service.load()).toBe(api);
  });

  it("forwards the remaining render inputs", async () => {
    fixture.componentRef.setInput("scope", "comment");
    fixture.componentRef.setInput("theme", "dark");
    fixture.componentRef.setInput("lang", "de");
    fixture.componentRef.setInput("action", "submit");
    fixture.componentRef.setInput("cData", "ctx-7");
    fixture.componentRef.setInput("execution", "execute");
    fixture.componentRef.setInput("riskContext", "coarse");
    fixture.componentRef.setInput("responseField", "captcha_token");
    fixture.componentRef.setInput("tokenFieldName", "custom_token");
    fixture.componentRef.setInput("algorithm", "argon2id");
    fixture.componentRef.setInput("fetchTimeoutMs", 4000);
    fixture.detectChanges();
    await settle();

    const container = fixture.nativeElement.querySelector(".kiwi-container") as HTMLElement;
    const widget = fixture.nativeElement.querySelector("[data-kiwi-widget]") as HTMLElement;
    expect(container.classList.contains("kiwi-theme-dark")).toBe(true);
    expect(container.getAttribute("data-kiwi-lang")).toBe("de");
    expect(container.getAttribute("data-kiwi-risk-context")).toBe("coarse");
    expect(container.getAttribute("data-kiwi-algorithm")).toBe("argon2id");
    expect(container.getAttribute("data-kiwi-fetch-timeout-ms")).toBe("4000");
    expect(widget.getAttribute("data-action")).toBe("submit");
    expect(widget.getAttribute("data-cdata")).toBe("ctx-7");
    expect(widget.getAttribute("data-execution")).toBe("execute");
    const token = fixture.nativeElement.querySelector("input[data-kiwi-token]") as HTMLInputElement;
    expect(token.name).toBe("custom_token");
    expect(lastOptions()["responseField"]).toBe("captcha_token");
  });

  it("forwards the loader controls to the injected script", async () => {
    // No driver: the component's service load path injects the script.
    delete (window as unknown as { KiwiCaptcha?: KiwiCaptchaApi }).KiwiCaptcha;
    fixture.componentRef.setInput("scope", "login");
    fixture.componentRef.setInput("scriptSrc", "/vendor/kiwi-ng.js");
    fixture.componentRef.setInput("scriptIntegrity", "sha384-ng");
    fixture.componentRef.setInput("scriptCrossorigin", "anonymous");
    fixture.componentRef.setInput("scriptTimeoutMs", 5000);
    fixture.componentRef.setInput("scriptNonce", "nonce-ng");
    fixture.detectChanges();
    await fixture.whenStable();

    const script = document.head.querySelector("script") as HTMLScriptElement | null;
    expect(script).not.toBeNull();
    expect(script?.src).toMatch(/\/vendor\/kiwi-ng\.js$/);
    expect(script?.integrity).toBe("sha384-ng");
    expect(script?.crossOrigin).toBe("anonymous");
    expect(script?.nonce).toBe("nonce-ng");

    installDriver();
    script?.dispatchEvent(new Event("load"));
    await settle();
    expect(driver.records.size).toBe(1);
    expect(fixture.nativeElement.querySelector("input[data-kiwi-token]")).not.toBeNull();
  });

  it("renders against the api input without loading the script", async () => {
    delete (window as unknown as { KiwiCaptcha?: KiwiCaptchaApi }).KiwiCaptcha;
    const calls = { render: 0, destroy: 0 };
    const api: KiwiCaptchaApi = {
      render: () => {
        calls.render += 1;
        return `api-${calls.render}`;
      },
      reset: () => {},
      getResponse: () => "",
      execute: () => Promise.resolve(""),
      remove: () => {},
      isExpired: () => false,
      ready: () => Promise.resolve(),
      destroy: () => {
        calls.destroy += 1;
      },
    };
    fixture.componentRef.setInput("scope", "login");
    fixture.componentRef.setInput("api", api);
    fixture.detectChanges();
    await settle();
    expect(calls.render).toBe(1);
    expect(document.head.querySelector("script")).toBeNull();
    expect(fixture.componentInstance.ready()).toBe(true);
    expect(fixture.componentInstance.getResponse()).toBe("");
  });

  it("forwards buildMarkup false and reports the render failure", async () => {
    const failures: string[] = [];
    fixture.componentInstance.failed.subscribe((message) => failures.push(message));
    fixture.componentRef.setInput("scope", "login");
    fixture.componentRef.setInput("buildMarkup", false);
    fixture.detectChanges();
    await settle();
    expect(failures.length).toBe(1);
    expect(failures[0]).toMatch(/buildMarkup false requires/);
    expect(fixture.componentInstance.ready()).toBe(false);
  });

  it("rebuilds when a config input changes", async () => {
    fixture.componentRef.setInput("scope", "login");
    fixture.detectChanges();
    await settle();
    const firstId = [...driver.records.keys()][0] as string;

    fixture.componentRef.setInput("scope", "signup");
    fixture.detectChanges();
    await settle();

    expect(driver.records.has(firstId)).toBe(false);
    expect(driver.records.size).toBe(1);
    expect(lastOptions()["scope"]).toBe("signup");
    expect(fixture.nativeElement.querySelectorAll("[data-kiwi-widget]").length).toBe(1);
  });
});
