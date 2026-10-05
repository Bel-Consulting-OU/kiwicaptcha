import {
  onCleanup,
  onMount,
  type JSX,
} from "solid-js";
import {
  loadKiwiCaptcha,
  renderKiwiCaptcha,
  type KiwiRenderOptions,
  type KiwiWidgetHandle,
} from "@kiwicaptcha/client-core";

/** Imperative controls delivered through the ref prop. */
export interface KiwiSolidControls {
  getResponse(): string;
  isExpired(): boolean;
  reset(): void;
  execute(): Promise<string>;
}

export interface KiwiCaptchaProps extends KiwiRenderOptions {
  class?: string;
  style?: JSX.CSSProperties | string;
  /** Receives the imperative controls once the widget is mounted. */
  ref?: (controls: KiwiSolidControls) => void;
}

/**
 * The KiwiCaptcha widget as a SolidJS component.
 *
 * Config props (endpoint, sitekey, scope, lang is the four-setting
 * quickstart) are captured when the widget mounts; callback props stay
 * live, so parents may pass fresh inline functions on every render.
 * Cleanup destroys the driver record when the component unmounts.
 */
export function KiwiCaptcha(props: KiwiCaptchaProps): JSX.Element {
  let el: HTMLDivElement | undefined;
  let handle: KiwiWidgetHandle | null = null;

  const controls: KiwiSolidControls = {
    getResponse: () => handle?.getResponse() ?? "",
    isExpired: () => handle?.isExpired() ?? false,
    reset: () => handle?.reset(),
    execute: () =>
      handle
        ? handle.execute()
        : Promise.reject(new Error("kiwicaptcha: widget not mounted")),
  };

  onMount(() => {
    // Config read once at mount; callbacks delegate through the props
    // proxy so the latest values are used at event time.
    const {
      class: _class,
      style: _style,
      ref: _ref,
      onReady,
      onVerifying,
      onVerify,
      onError,
      onExpire,
      onRetry,
      onWorkerUnavailable,
      onExecutionUnavailable,
      ...config
    } = props;
    const options: KiwiRenderOptions = {
      ...config,
      onReady: (scope) => onReady?.(scope),
      onVerifying: (scope) => onVerifying?.(scope),
      onVerify: (token, detail) => onVerify?.(token, detail),
      onError: (message, detail) => onError?.(message, detail),
      onExpire: (scope) => onExpire?.(scope),
      onRetry: (detail) => onRetry?.(detail),
      onWorkerUnavailable: (reason, scope) => onWorkerUnavailable?.(reason, scope),
      onExecutionUnavailable: (reason, scope) => onExecutionUnavailable?.(reason, scope),
    };
    try {
      handle = renderKiwiCaptcha(el as HTMLElement, options);
    } catch {
      void loadKiwiCaptcha().then((api) => {
        handle = renderKiwiCaptcha(el as HTMLElement, { ...options, api });
      });
    }
    props.ref?.(controls);
  });

  onCleanup(() => {
    handle?.destroy();
    handle = null;
  });

  return <div ref={el} class={props.class} style={props.style} />;
}
