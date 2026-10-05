<script lang="ts">
  import {
    renderKiwiCaptcha,
    type KiwiErrorDetail,
    type KiwiRenderOptions,
    type KiwiRetryDetail,
    type KiwiVerifiedDetail,
    type KiwiWidgetHandle,
  } from "@kiwicaptcha/client-core";
  import { onMount } from "svelte";

  /**
   * The KiwiCaptcha widget as a Svelte 5 component.
   *
   * Props are the core render options (endpoint, sitekey, scope, lang
   * is the four-setting quickstart) plus the callback props named
   * `onverify`, `onerror`, `onexpire`, `onready`, `onverifying`,
   * `onretry`, `onworkerunavailable` and `onexecutionunavailable`.
   * Bind the component for reset/execute/getResponse/isExpired.
   */
  interface Props extends KiwiRenderOptions {
    class?: string;
    style?: string;
    onready?: (scope: string) => void;
    onverifying?: (scope: string) => void;
    onverify?: (token: string, detail: KiwiVerifiedDetail) => void;
    onerror?: (message: string, detail: KiwiErrorDetail) => void;
    onexpire?: (scope: string) => void;
    onretry?: (detail: KiwiRetryDetail) => void;
    onworkerunavailable?: (reason: string, scope: string) => void;
    onexecutionunavailable?: (reason: string, scope: string) => void;
  }

  let {
    class: className = "",
    style = "",
    onready,
    onverifying,
    onverify,
    onerror,
    onexpire,
    onretry,
    onworkerunavailable,
    onexecutionunavailable,
    ...config
  }: Props = $props();

  let el: HTMLDivElement;
  let handle: KiwiWidgetHandle | null = null;

  /** Cancel the current run and acquire a fresh challenge. */
  export function reset(): void {
    handle?.reset();
  }
  /** The verified token, or "" while unverified or expired. */
  export function getResponse(): string {
    return handle?.getResponse() ?? "";
  }
  /** Whether the last verified token has expired. */
  export function isExpired(): boolean {
    return handle?.isExpired() ?? false;
  }
  /** Start or await the solve; resolves the token. */
  export function execute(): Promise<string> {
    return handle
      ? handle.execute()
      : Promise.reject(new Error("kiwicaptcha: widget not mounted"));
  }

  onMount(() => {
    // Callbacks read the current prop value at event time, so a parent
    // may pass fresh inline functions without rebuilding the widget.
    // The config fields are captured once: a changed config is expressed
    // as a keyed re-mount ({#key}) by the caller.
    const options: KiwiRenderOptions = {
      ...config,
      onReady: (scope) => onready?.(scope),
      onVerifying: (scope) => onverifying?.(scope),
      onVerify: (token, detail) => onverify?.(token, detail),
      onError: (message, detail) => onerror?.(message, detail),
      onExpire: (scope) => onexpire?.(scope),
      onRetry: (detail) => onretry?.(detail),
      onWorkerUnavailable: (reason, scope) => onworkerunavailable?.(reason, scope),
      onExecutionUnavailable: (reason, scope) => onexecutionunavailable?.(reason, scope),
    };
    try {
      handle = renderKiwiCaptcha(el, options);
    } catch {
      void loadAndRender(el, options).then((h) => {
        handle = h;
      });
    }
    return () => {
      handle?.destroy();
      handle = null;
    };
  });

  async function loadAndRender(
    node: HTMLElement,
    options: KiwiRenderOptions,
  ): Promise<KiwiWidgetHandle> {
    const { loadKiwiCaptcha } = await import("@kiwicaptcha/client-core");
    const api = await loadKiwiCaptcha();
    return renderKiwiCaptcha(node, { ...options, api });
  }
</script>

<div bind:this={el} class={className} {style}></div>
