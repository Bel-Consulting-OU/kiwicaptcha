import {
  loadKiwiCaptcha,
  renderKiwiCaptcha,
  type KiwiRenderOptions,
  type KiwiWidgetHandle,
} from "@kiwicaptcha/client-core";

export interface KiwiActionOptions extends KiwiRenderOptions {
  /** The driver script URL. Default "/kiwi.js". */
  scriptSrc?: string;
}

/**
 * The Svelte action: `use:kiwiCaptcha={{ scope: "login" }}`.
 *
 * Renders the widget into the element carrying the action (the element
 * becomes the container), loads the driver on demand, and destroys the
 * widget when the element unmounts. An options update rebuilds the
 * widget; the four-setting fields are endpoint, sitekey, scope, lang.
 */
export function kiwiCaptcha(
  node: HTMLElement,
  initial: KiwiActionOptions = {},
): {
  update(next: KiwiActionOptions): void;
  destroy(): void;
} {
  let options = initial;
  let handle: KiwiWidgetHandle | null = null;
  let generation = 0;

  function build(current: KiwiActionOptions): void {
    const ticket = ++generation;
    try {
      handle = renderKiwiCaptcha(node, current);
    } catch {
      void loadKiwiCaptcha({
        scriptSrc: current.scriptSrc,
      }).then((api) => {
        if (ticket !== generation) return;
        handle = renderKiwiCaptcha(node, { ...current, api });
      });
    }
  }

  build(options);

  return {
    update(next: KiwiActionOptions) {
      options = next;
      // A config change re-renders: fresh markup, fresh driver record.
      handle?.destroy();
      handle = null;
      build(options);
    },
    destroy() {
      ++generation;
      handle?.destroy();
      handle = null;
    },
  };
}
