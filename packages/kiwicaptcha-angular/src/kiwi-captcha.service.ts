import { loadKiwiCaptcha, renderKiwiCaptcha, type KiwiCaptchaApi, type KiwiRenderOptions, type KiwiWidgetHandle } from "@kiwicaptcha/client-core";
import { Injectable } from "@angular/core";

/** Loader controls passed through to the shared core. */
export interface KiwiLoadOptions {
  scriptSrc?: string;
  integrity?: string;
  crossorigin?: "anonymous" | "use-credentials";
  timeoutMs?: number;
}

/**
 * The Angular facade of the shared client core: driver load-once plus
 * imperative render. The component consumes this service; applications
 * that manage their own DOM may inject and use it directly.
 */
@Injectable({ providedIn: "root" })
export class KiwiCaptchaService {
  /** Load (or reuse) the widget driver. */
  load(options: KiwiLoadOptions = {}): Promise<KiwiCaptchaApi> {
    return loadKiwiCaptcha({
      scriptSrc: options.scriptSrc,
      integrity: options.integrity,
      crossorigin: options.crossorigin,
      timeoutMs: options.timeoutMs,
    });
  }

  /** Load the driver if needed, then render a widget into the container. */
  render(
    container: HTMLElement,
    options: KiwiRenderOptions & KiwiLoadOptions = {},
  ): Promise<KiwiWidgetHandle> {
    const { scriptSrc, integrity, crossorigin, timeoutMs, ...renderOptions } = options;
    return this.load({ scriptSrc, integrity, crossorigin, timeoutMs }).then((api) =>
      renderKiwiCaptcha(container, { ...renderOptions, api }),
    );
  }
}
