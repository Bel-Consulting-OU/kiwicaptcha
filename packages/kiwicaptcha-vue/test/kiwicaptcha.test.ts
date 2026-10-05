import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mount, type VueWrapper } from "@vue/test-utils";
import { defineComponent, h, nextTick } from "vue";

import { KiwiCaptcha, useKiwiCaptcha } from "../src/index.js";
import {
  installMockDriver,
  type MockDriver,
} from "../../kiwicaptcha-client-core/test/mock-driver.js";

// The happy-dom vitest environment provides the global window/document;
// the driver is installed there so the components resolve it the same
// way a real page does.
let driver: MockDriver;
let host: HTMLElement;
let wrapper: VueWrapper | null = null;

beforeEach(() => {
  document.body.innerHTML = "";
  driver = installMockDriver(document);
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  if (wrapper) {
    wrapper.unmount();
    wrapper = null;
  }
  host.remove();
  expect(driver.records.size).toBe(0);
});

function mountWidget(props: Record<string, unknown> = {}): VueWrapper {
  wrapper = mount(KiwiCaptcha, {
    props,
    attachTo: host,
  });
  return wrapper;
}

function lastRecordId(): string {
  const ids = [...driver.records.keys()];
  return ids[ids.length - 1] as string;
}

describe("KiwiCaptcha SFC", () => {
  it("mounts the widget markup and forwards scope and sitekey", async () => {
    const w = mountWidget({ scope: "signup", sitekey: "pk-vue", endpoint: "/kc" });
    await nextTick();
    expect(w.find("input[data-kiwi-token]").exists()).toBe(true);
    expect(w.find("[data-kiwi-widget]").exists()).toBe(true);
    const passed = driver.injectedOptions.at(-1);
    expect(passed?.["scope"]).toBe("signup");
    expect(passed?.["sitekey"]).toBe("pk-vue");
    expect(w.find(".kiwi-container").attributes("data-kiwi-endpoint")).toBe("/kc");
  });

  it("emits verify with the token", async () => {
    const w = mountWidget({ scope: "login" });
    await nextTick();
    const id = lastRecordId();
    driver.simulateVerified(id, "tok-vue", "nonce-v");
    await nextTick();
    expect(w.emitted("verify")).toEqual([
      ["tok-vue", { scope: "login", nonce: "nonce-v", token: "tok-vue" }],
    ]);
  });

  it("emits error, expire and retry", async () => {
    const w = mountWidget({ scope: "login" });
    await nextTick();
    const id = lastRecordId();
    driver.simulateRetry(id, "net", 1);
    driver.simulateError(id, "exhausted");
    driver.simulateExpired(id);
    await nextTick();
    expect(w.emitted("retry")).toEqual([[{ scope: "login", error: "net", attempt: 1 }]]);
    expect(w.emitted("error")).toEqual([["exhausted", { scope: "login" }]]);
    expect(w.emitted("expire")).toEqual([["login"]]);
  });

  it("exposes the widget controls through the template ref", async () => {
    const w = mountWidget({ scope: "login" });
    await nextTick();
    const id = lastRecordId();
    const exposed = w.vm as unknown as {
      getResponse(): string;
      reset(): void;
      execute(): Promise<string>;
    };
    expect(exposed.getResponse()).toBe("");
    driver.simulateVerified(id, "tok-exp");
    expect(exposed.getResponse()).toBe("tok-exp");
    await expect(exposed.execute()).resolves.toBe("tok-exp");
    exposed.reset();
    expect(exposed.getResponse()).toBe("");
  });

  it("rebuilds when the scope prop changes", async () => {
    const w = mountWidget({ scope: "login" });
    await nextTick();
    const firstId = lastRecordId();
    await w.setProps({ scope: "comment" });
    await nextTick();
    expect(driver.records.has(firstId)).toBe(false);
    expect(driver.injectedOptions.at(-1)?.["scope"]).toBe("comment");
  });
});

describe("useKiwiCaptcha composable", () => {
  it("mounts into the bound element and wires controls", async () => {
    const seen: string[] = [];
    let controls: ReturnType<typeof useKiwiCaptcha> | null = null;
    const Probe = defineComponent({
      setup() {
        controls = useKiwiCaptcha({ scope: "login", onVerify: (t) => seen.push(t) });
        return () =>
          h("div", {
            ref: (controls as unknown as ReturnType<typeof useKiwiCaptcha>).containerRef,
          });
      },
    });
    wrapper = mount(Probe, { attachTo: host });
    await nextTick();
    const c = controls as unknown as ReturnType<typeof useKiwiCaptcha>;
    expect(document.querySelector("input[data-kiwi-token]")).not.toBeNull();

    const id = lastRecordId();
    driver.simulateVerified(id, "tok-comp");
    expect(seen).toEqual(["tok-comp"]);
    expect(c.getResponse()).toBe("tok-comp");
    await expect(c.execute()).resolves.toBe("tok-comp");
    c.reset();
    expect(c.getResponse()).toBe("");
  });

  it("destroys the widget when the component unmounts", async () => {
    let controls: ReturnType<typeof useKiwiCaptcha> | null = null;
    const Probe = defineComponent({
      setup() {
        controls = useKiwiCaptcha({ scope: "login" });
        return () =>
          h("div", {
            ref: (controls as unknown as ReturnType<typeof useKiwiCaptcha>).containerRef,
          });
      },
    });
    wrapper = mount(Probe, { attachTo: host });
    await nextTick();
    expect(driver.records.size).toBe(1);
    wrapper.unmount();
    wrapper = null;
    expect(driver.records.size).toBe(0);
  });
});
