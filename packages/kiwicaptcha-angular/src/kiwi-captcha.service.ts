import {
  loadKiwiCaptcha,
  renderKiwiCaptcha,
  type KiwiCaptchaApi,
  type KiwiRenderOptions,
  type KiwiWidgetHandle,
} from "@kiwicaptcha/client-core";
import { Injectable } from "@angular/core";

/** Loader controls passed through to the shared core. */
export interface KiwiLoadOptions {
  scriptSrc?: string;
  scriptIntegrity?: string;
  scriptCrossorigin?: "anonymous" | "use-credentials";
  scriptTimeoutMs?: number;
  scriptNonce?: string;
}

/**
 * The Angular facade of the shared client core: driver load-once plus
 * imperative render. The component consumes this service; applications
 * that manage their own DOM may inject and use it directly.
 *
 * `load(options)` takes the same loader controls as the component inputs:
 * `scriptSrc`, `scriptIntegrity`, `scriptCrossorigin`, `scriptTimeoutMs`
 * and `scriptNonce`. `render(container, options)` also accepts a preloaded
 * `api`, which skips the script load entirely.
 */
@Injectable({ providedIn: "root" })
export class KiwiCaptchaService {
  /** Load (or reuse) the widget driver. */
  load(options: KiwiLoadOptions = {}): Promise<KiwiCaptchaApi> {
    return loadKiwiCaptcha({
      scriptSrc: options.scriptSrc,
      integrity: options.scriptIntegrity,
      crossorigin: options.scriptCrossorigin,
      timeoutMs: options.scriptTimeoutMs,
      scriptNonce: options.scriptNonce,
    });
  }

  /** Load the driver if needed, then render a widget into the container. */
  render(
    container: HTMLElement,
    options: KiwiRenderOptions & KiwiLoadOptions = {},
  ): Promise<KiwiWidgetHandle> {
    const {
      scriptSrc,
      scriptIntegrity,
      scriptCrossorigin,
      scriptTimeoutMs,
      scriptNonce,
      api,
      ...renderOptions
    } = options;
    if (api) {
      return Promise.resolve().then(() => renderKiwiCaptcha(container, { ...renderOptions, api }));
    }
    return this.load({
      scriptSrc,
      scriptIntegrity,
      scriptCrossorigin,
      scriptTimeoutMs,
      scriptNonce,
    }).then((loaded) => renderKiwiCaptcha(container, { ...renderOptions, api: loaded }));
  }
}
