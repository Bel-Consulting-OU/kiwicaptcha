import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { act, StrictMode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { Window } from "happy-dom";

import { KiwiCaptcha, useKiwiCaptcha, type KiwiCaptchaRef } from "../src/index.js";
import {
  installMockDriver,
  dispatchKiwi,
  type MockDriver,
} from "../../kiwicaptcha-client-core/test/mock-driver.js";

declare global {
  // eslint-disable-next-line no-var
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

let window: Window;
let doc: Document;
let driver: MockDriver;
let mount: HTMLElement;
let root: Root;
let host: HTMLElement;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  window = new Window({ url: "https://app.example.com/login" });
  doc = window.document;
  driver = installMockDriver(doc);
  doc.body.innerHTML = '<div id="host"></div>';
  host = doc.getElementById("host") as HTMLElement;
  mount = doc.createElement("div");
  host.appendChild(mount);
  root = createRoot(mount);
});

interface Rendered {
  widgetHost: HTMLElement;
  tokenInput(): HTMLInputElement | null;
}

function renderComponent(
  props: Record<string, unknown>,
): Rendered {
  let widgetHost: HTMLElement | null = null;
  act(() => {
    root.render(<KiwiCaptcha {...(props as never)} />);
  });
  // The component renders its mount div inside our mount node.
  widgetHost = mount.firstElementChild as HTMLElement;
  return {
    widgetHost,
    tokenInput: () =>
      widgetHost?.querySelector<HTMLInputElement>("input[data-kiwi-token]") ?? null,
  };
}

describe("KiwiCaptcha component", () => {
  it("mounts the widget markup and registers scope and sitekey", () => {
    const view = renderComponent({ scope: "login", sitekey: "pk-1", endpoint: "/kc" });
    expect(view.tokenInput()).not.toBeNull();
    expect(view.widgetHost.querySelector("[data-kiwi-widget]")).not.toBeNull();
    const passed = driver.injectedOptions.at(-1);
    expect(passed?.["scope"]).toBe("login");
    expect(passed?.["sitekey"]).toBe("pk-1");
    expect(view.widgetHost.querySelector(".kiwi-container")?.getAttribute("data-kiwi-endpoint")).toBe("/kc");
  });

  it("delivers tokens through onVerify", () => {
    const seen: string[] = [];
    const view = renderComponent({ scope: "login", onVerify: (t: string) => seen.push(t) });
    const id = [...driver.records.keys()][0] as string;
    driver.simulateVerified(id, "tok-r1", "n1");
    expect(seen).toEqual(["tok-r1"]);
    expect(view.tokenInput()?.value).toBe("tok-r1");
  });

  it("maps error and expiry callbacks", () => {
    const events: string[] = [];
    renderComponent({
      scope: "login",
      onError: (m: string) => events.push(`error:${m}`),
      onExpire: () => events.push("expire"),
      onRetry: (d: { attempt: number }) => events.push(`retry:${d.attempt}`),
    });
    const id = [...driver.records.keys()][0] as string;
    driver.simulateRetry(id, "x", 2);
    driver.simulateError(id, "boom");
    driver.simulateExpired(id);
    expect(events).toEqual(["retry:2", "error:boom", "expire"]);
  });

  it("exposes the imperative handle: getResponse, reset, execute", async () => {
    let ref: KiwiCaptchaRef | null = null;
    act(() => {
      root.render(
        <KiwiCaptcha
          scope="login"
          ref={(r: KiwiCaptchaRef | null) => {
            ref = r;
          }}
        />,
      );
    });
    const id = [...driver.records.keys()][0] as string;
    expect(ref).not.toBeNull();
    expect((ref as KiwiCaptchaRef).getResponse()).toBe("");
    driver.simulateVerified(id, "tok-ref");
    expect((ref as KiwiCaptchaRef).getResponse()).toBe("tok-ref");

    let executed = "";
    await act(async () => {
      executed = await (ref as KiwiCaptchaRef).execute();
    });
    expect(executed).toBe("tok-ref");

    act(() => {
      (ref as KiwiCaptchaRef).reset();
    });
    expect((ref as KiwiCaptchaRef).getResponse()).toBe("");
  });

  it("survives StrictMode's double mount with one live widget", () => {
    act(() => {
      root.render(
        <StrictMode>
          <KiwiCaptcha scope="login" />
        </StrictMode>,
      );
    });
    // One live record; the abandoned first generation was destroyed.
    expect(driver.records.size).toBe(1);
    const inputs = mount.querySelectorAll("input[data-kiwi-token]");
    expect(inputs.length).toBe(1);
  });

  it("re-mounts the widget when a config field changes", () => {
    renderComponent({ scope: "login" });
    const firstId = [...driver.records.keys()][0] as string;
    act(() => {
      root.render(<KiwiCaptcha scope="signup" />);
    });
    expect(driver.records.has(firstId)).toBe(false);
    expect(driver.records.size).toBe(1);
    expect(driver.injectedOptions.at(-1)?.["scope"]).toBe("signup");
  });

  it("keeps the widget mounted when only callbacks change", () => {
    renderComponent({ scope: "login", onVerify: () => {} });
    const id = [...driver.records.keys()][0] as string;
    act(() => {
      root.render(<KiwiCaptcha scope="login" onVerify={() => "other"} />);
    });
    expect(driver.records.has(id)).toBe(true);
  });
});

describe("useKiwiCaptcha hook", () => {
  it("mounts into the returned ref and exposes controls", async () => {
    let controls: ReturnType<typeof useKiwiCaptcha> | null = null;
    function Probe(): React.ReactElement {
      controls = useKiwiCaptcha({ scope: "login" });
      return <div ref={controls.containerRef} />;
    }
    act(() => {
      root.render(<Probe />);
    });
    expect(controls).not.toBeNull();
    const c = controls as unknown as ReturnType<typeof useKiwiCaptcha>;
    expect(mount.querySelector("input[data-kiwi-token]")).not.toBeNull();

    const id = [...driver.records.keys()][0] as string;
    driver.simulateVerified(id, "tok-hook");
    expect(c.getResponse()).toBe("tok-hook");

    let executed = "";
    await act(async () => {
      executed = await c.execute();
    });
    expect(executed).toBe("tok-hook");
    act(() => {
      c.reset();
    });
    expect(c.getResponse()).toBe("");
  });

  it("rejects execute() before the widget mounts", async () => {
    let controls: ReturnType<typeof useKiwiCaptcha> | null = null;
    function Probe(): React.ReactElement {
      controls = useKiwiCaptcha({ scope: "login" });
      return <div />;
    }
    act(() => {
      root.render(<Probe />);
    });
    const c = controls as unknown as ReturnType<typeof useKiwiCaptcha>;
    await expect(c.execute()).rejects.toThrow(/not mounted/);
  });
});

// A late driver event after unmount must reach nothing.
describe("unmount hygiene", () => {
  it("detaches listeners on unmount", () => {
    const seen: string[] = [];
    renderComponent({ scope: "login", onVerify: (t: string) => seen.push(t) });
    const widget = mount.querySelector("[data-kiwi-widget]") as HTMLElement;
    // afterEach unmounts the root; capture the (then detached) widget and
    // dispatch a late verified event: no listener survives the unmount.
    queueMicrotask(() => {});
    unmountListeners = { widget, seen };
  });
});

let unmountListeners: { widget: HTMLElement; seen: string[] } | null = null;

afterEach(() => {
  // After the root unmount (below), assert the late event reached nothing.
  const pending = unmountListeners;
  unmountListeners = null;
  act(() => {
    root.unmount();
  });
  if (pending) {
    dispatchKiwi(pending.widget, "verified", { scope: "login", token: "late" });
    expect(pending.seen).toEqual([]);
  }
  expect(driver.records.size).toBe(0);
});
