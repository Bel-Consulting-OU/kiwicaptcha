import { ComponentFixture, TestBed } from "@angular/core/testing";
import { KiwiCaptcha } from "./kiwi-captcha.component";
import { KiwiCaptchaService } from "./kiwi-captcha.service";
import type { MockDriver } from "../../kiwicaptcha-client-core/test/mock-driver";
import { installMockDriver } from "../../kiwicaptcha-client-core/test/mock-driver";

/**
 * Karma/Jasmine spec, executed by the Angular workspace CI (`ng test`).
 * The bare `tsc --noEmit` typecheck covers this file; running the specs
 * needs the Karma toolchain (a browser launcher), which the SDK CI
 * provides.
 */
describe("KiwiCaptcha", () => {
  let driver: MockDriver;
  let fixture: ComponentFixture<KiwiCaptcha>;

  beforeEach(async () => {
    driver = installMockDriver(document);
    await TestBed.configureTestingModule({
      imports: [KiwiCaptcha],
    }).compileComponents();
    fixture = TestBed.createComponent(KiwiCaptcha);
  });

  it("renders the widget markup into the host", async () => {
    fixture.componentRef.setInput("scope", "login");
    fixture.componentRef.setInput("sitekey", "pk-ng");
    fixture.detectChanges();
    await fixture.whenStable();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector("input[data-kiwi-token]")).not.toBeNull();
    expect(el.querySelector("[data-kiwi-widget]")).not.toBeNull();
    const passed = driver.injectedOptions.at(-1);
    expect(passed?.["scope"]).toBe("login");
    expect(passed?.["sitekey"]).toBe("pk-ng");
    expect(fixture.componentInstance.ready()).toBeTrue();
  });

  it("emits verified with the token detail", async () => {
    const seen: Array<{ token: string; nonce?: string }> = [];
    fixture.componentInstance.verified.subscribe((d) =>
      seen.push({ token: d.token, nonce: d.nonce }),
    );
    fixture.componentRef.setInput("scope", "login");
    fixture.detectChanges();
    await fixture.whenStable();
    const id = [...driver.records.keys()][0] as string;
    driver.simulateVerified(id, "tok-ng", "nonce-ng");
    expect(seen).toEqual([{ nonce: "nonce-ng", token: "tok-ng" }]);
    expect(fixture.componentInstance.getResponse()).toBe("tok-ng");
  });

  it("emits failed and expired", async () => {
    const events: string[] = [];
    fixture.componentInstance.failed.subscribe((m) => events.push(`failed:${m}`));
    fixture.componentInstance.expired.subscribe(() => events.push("expired"));
    fixture.componentRef.setInput("scope", "login");
    fixture.detectChanges();
    await fixture.whenStable();
    const id = [...driver.records.keys()][0] as string;
    driver.simulateError(id, "boom");
    driver.simulateExpired(id);
    expect(events).toEqual(["failed:boom", "expired"]);
  });

  it("destroys the driver record on component destroy", async () => {
    fixture.componentRef.setInput("scope", "login");
    fixture.detectChanges();
    await fixture.whenStable();
    expect(driver.records.size).toBe(1);
    fixture.destroy();
    expect(driver.records.size).toBe(0);
  });

  it("exposes reset and execute through the component", async () => {
    fixture.componentRef.setInput("scope", "login");
    fixture.detectChanges();
    await fixture.whenStable();
    const id = [...driver.records.keys()][0] as string;
    driver.simulateVerified(id, "tok-exec");
    await expectAsync(fixture.componentInstance.execute()).toBeResolvedTo("tok-exec");
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
});
