import {
  onMounted,
  onUnmounted,
  ref,
  watch,
  type Ref,
} from "vue";
import {
  loadKiwiCaptcha,
  renderKiwiCaptcha,
  type KiwiRenderOptions,
  type KiwiWidgetHandle,
} from "@kiwicaptcha/client-core";

/**
 * Composable options: core render options plus the loader controls.
 * Pass a plain object for static configuration, or a getter (typically
 * `() => ({ ...props })`) so prop changes rebuild the widget.
 */
export interface UseKiwiCaptchaOptions extends KiwiRenderOptions {
  /** The driver script URL. Default "/kiwi.js". */
  scriptSrc?: string;
  /** Optional SRI integrity for the driver script. */
  scriptIntegrity?: string;
  /** Optional crossorigin for the driver script. */
  scriptCrossorigin?: "anonymous" | "use-credentials";
  /** Reject the load when the driver has not appeared within the budget. */
  scriptTimeoutMs?: number;
}

export type UseKiwiCaptchaSource =
  | UseKiwiCaptchaOptions
  | (() => UseKiwiCaptchaOptions);

/** What the composable hands back: the mount ref and the controls. */
export interface UseKiwiCaptchaReturn {
  containerRef: Ref<HTMLElement | null>;
  /** True once a widget generation is live in the container. */
  ready: Ref<boolean>;
  execute(): Promise<string>;
  reset(): void;
  getResponse(): string;
  isExpired(): boolean;
}

/**
 * Mount one KiwiCaptcha widget into the element bound to containerRef.
 *
 * The composable owns the lifecycle: driver load-once, fresh markup per
 * mount, event mapping, destroy on unmount, and a rebuild when one of
 * the config fields changes through the source getter. Callback
 * properties stay live without a rebuild, so a parent may pass inline
 * arrow functions.
 */
export function useKiwiCaptcha(source: UseKiwiCaptchaSource): UseKiwiCaptchaReturn {
  const read = (): UseKiwiCaptchaOptions =>
    typeof source === "function" ? source() : source;
  const containerRef = ref<HTMLElement | null>(null);
  const ready = ref(false);
  let handle: KiwiWidgetHandle | null = null;
  let buildToken = 0;

  async function mount(): Promise<void> {
    const node = containerRef.value;
    if (!node) return;
    const options = read();
    const ticket = ++buildToken;
    try {
      handle = renderKiwiCaptcha(node, options);
    } catch {
      const api = await loadKiwiCaptcha({
        scriptSrc: options.scriptSrc,
        integrity: options.scriptIntegrity,
        crossorigin: options.scriptCrossorigin,
        timeoutMs: options.scriptTimeoutMs,
      });
      if (ticket !== buildToken || containerRef.value !== node) return;
      handle = renderKiwiCaptcha(node, { ...options, api });
    }
    ready.value = true;
  }

  function unmount(): void {
    ++buildToken;
    handle?.destroy();
    handle = null;
    ready.value = false;
  }

  onMounted(() => {
    void mount();
  });
  onUnmounted(unmount);

  watch(
    () =>
      JSON.stringify([
        read().endpoint,
        read().sitekey,
        read().scope,
        read().lang,
        read().theme,
        read().action,
        read().cData,
        read().chainTicket,
        read().requestBinding,
        read().fetchTimeoutMs,
        read().algorithm,
        read().responseField,
        read().execution,
        read().tokenFieldName,
        read().buildMarkup,
        read().scriptSrc,
      ]),
    () => {
      if (!containerRef.value) return;
      unmount();
      void mount();
    },
  );

  return {
    containerRef,
    ready,
    execute: () =>
      handle
        ? handle.execute()
        : Promise.reject(new Error("kiwicaptcha: widget not mounted")),
    reset: () => handle?.reset(),
    getResponse: () => handle?.getResponse() ?? "",
    isExpired: () => handle?.isExpired() ?? false,
  };
}
