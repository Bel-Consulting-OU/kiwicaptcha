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
  type KiwiCaptchaApi,
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
  /** Optional CSP nonce set on the injected driver script. */
  scriptNonce?: string;
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
  destroy(): void;
}

// Preloaded apis are compared by identity: JSON serialization collapses
// two distinct api objects with methods to the same "{}".
const apiIds = new WeakMap<object, number>();
let nextApiId = 0;

function apiKey(api: KiwiCaptchaApi | undefined): number | undefined {
  if (!api) return undefined;
  let id = apiIds.get(api);
  if (id === undefined) {
    id = ++nextApiId;
    apiIds.set(api, id);
  }
  return id;
}

/** Every declared option that must rebuild the widget when it changes. */
function configKey(options: UseKiwiCaptchaOptions): string {
  return JSON.stringify([
    options.endpoint,
    options.sitekey,
    options.scope,
    options.lang,
    options.theme,
    options.action,
    options.cData,
    options.chainTicket,
    options.requestBinding,
    options.fetchTimeoutMs,
    options.algorithm,
    options.riskContext,
    options.responseField,
    options.execution,
    options.tokenFieldName,
    options.buildMarkup,
    apiKey(options.api),
    options.scriptSrc,
    options.scriptIntegrity,
    options.scriptCrossorigin,
    options.scriptTimeoutMs,
    options.scriptNonce,
  ]);
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
        scriptNonce: options.scriptNonce,
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
    () => configKey(read()),
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
    destroy: unmount,
  };
}
