import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { flushSync, mount, unmount, type ComponentProps } from "svelte";

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
    const passed = driver.injectedOptions.at(-1);
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
    };
    expect(api.getResponse()).toBe("");
    driver.simulateVerified(id, "tok-imp");
    expect(api.getResponse()).toBe("tok-imp");
    await expect(api.execute()).resolves.toBe("tok-imp");
    api.reset();
    expect(api.getResponse()).toBe("");
  });
});

describe("kiwiCaptcha action", () => {
  it("renders into the action element and destroys on removal", () => {
    const target = document.createElement("div");
    host.appendChild(target);
    const action = kiwiCaptcha(target, { scope: "comment" });
    expect(target.querySelector("input[data-kiwi-token]")).not.toBeNull();
    expect(driver.injectedOptions.at(-1)?.["scope"]).toBe("comment");

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
    expect(driver.injectedOptions.at(-1)?.["scope"]).toBe("login");
    action.destroy();
  });
});
