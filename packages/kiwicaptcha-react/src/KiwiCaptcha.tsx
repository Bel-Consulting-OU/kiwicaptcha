import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  type RefObject,
} from "react";
import {
  loadKiwiCaptcha,
  renderKiwiCaptcha,
  type KiwiRenderOptions,
  type KiwiWidgetHandle,
} from "@kiwicaptcha/client-core";

/**
 * Props of the KiwiCaptcha component: the core render options plus the
 * loader controls. The four-setting quickstart is endpoint, sitekey,
 * scope and lang; everything else is the driver's documented opt-ins.
 */
export interface KiwiCaptchaProps extends KiwiRenderOptions {
  /** The driver script URL. Default "/kiwi.js". */
  scriptSrc?: string;
  /** Optional SRI integrity for the driver script. */
  scriptIntegrity?: string;
  /** Optional crossorigin for the driver script. */
  scriptCrossorigin?: "anonymous" | "use-credentials";
  /** Reject the load when the driver has not appeared within the budget. */
  scriptTimeoutMs?: number;
  /** ClassName and style pass straight onto the mount node. */
  className?: string;
  style?: React.CSSProperties;
}

/** Imperative handle exposed through the component's ref. */
export interface KiwiCaptchaRef {
  getResponse(): string;
  isExpired(): boolean;
  reset(): void;
  execute(): Promise<string>;
}

function configKey(props: KiwiCaptchaProps): string {
  return JSON.stringify([
    props.endpoint,
    props.sitekey,
    props.scope,
    props.lang,
    props.theme,
    props.action,
    props.cData,
    props.chainTicket,
    props.requestBinding,
    props.fetchTimeoutMs,
    props.algorithm,
    props.responseField,
    props.execution,
    props.tokenFieldName,
    props.buildMarkup,
    props.scriptSrc,
    props.scriptIntegrity,
    props.scriptCrossorigin,
    props.scriptTimeoutMs,
  ]);
}

/**
 * Mount one KiwiCaptcha widget.
 *
 * The component owns the whole lifecycle: it loads the driver once per
 * page, renders fresh markup into its mount node, maps the driver's
 * kiwi:* events onto the props, and tears the widget down on unmount.
 * Callback props may change freely between renders; only the config
 * fields re-render the widget. StrictMode's double mount is safe: the
 * cleanup destroys the first generation and the second mount rebuilds.
 */
export const KiwiCaptcha = forwardRef<KiwiCaptchaRef, KiwiCaptchaProps>(
  function KiwiCaptcha(props, ref) {
    const {
      scriptSrc,
      scriptIntegrity,
      scriptCrossorigin,
      scriptTimeoutMs,
      className,
      style,
      ...renderOptions
    } = props;
    const containerRef = useRef<HTMLDivElement>(null);
    const handleRef = useRef<KiwiWidgetHandle | null>(null);
    const latest = useRef<KiwiRenderOptions>(renderOptions);
    latest.current = renderOptions;

    const config = configKey(props);

    useEffect(() => {
      const node = containerRef.current;
      if (!node) return;
      let cancelled = false;
      let handle: KiwiWidgetHandle | null = null;

      const start = (): void => {
        if (cancelled || !node) return;
        const api = latest.current.api ?? undefined;
        try {
          handle = renderKiwiCaptcha(node, { ...latest.current, api });
          handleRef.current = handle;
        } catch (err) {
          // The driver is missing: load it, then render once more.
          loadKiwiCaptcha({
            scriptSrc,
            integrity: scriptIntegrity,
            crossorigin: scriptCrossorigin,
            timeoutMs: scriptTimeoutMs,
          }).then((loaded) => {
            if (cancelled || !node) return;
            handle = renderKiwiCaptcha(node, { ...latest.current, api: loaded });
            handleRef.current = handle;
          });
        }
      };

      start();

      return () => {
        cancelled = true;
        handleRef.current = null;
        if (handle) handle.destroy();
      };
      // The config key covers every field that must re-render the widget;
      // callback props flow through latest.current without a re-mount.
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [config]);

    useImperativeHandle(
      ref,
      () => ({
        getResponse: () => handleRef.current?.getResponse() ?? "",
        isExpired: () => handleRef.current?.isExpired() ?? false,
        reset: () => handleRef.current?.reset(),
        execute: () =>
          handleRef.current
            ? handleRef.current.execute()
            : Promise.reject(new Error("kiwicaptcha: widget not mounted")),
      }),
      [],
    );

    return <div ref={containerRef} className={className} style={style} />;
  },
);

/**
 * The hook behind the component, for layouts that place the mount node
 * themselves. Returns the ref to spread onto any element plus the
 * imperative controls; the lifecycle rules are the component's.
 */
export interface UseKiwiCaptchaResult {
  containerRef: RefObject<HTMLDivElement>;
  execute(): Promise<string>;
  reset(): void;
  getResponse(): string;
  isExpired(): boolean;
}

export function useKiwiCaptcha(props: KiwiCaptchaProps): UseKiwiCaptchaResult {
  const {
    scriptSrc,
    scriptIntegrity,
    scriptCrossorigin,
    scriptTimeoutMs,
    ...renderOptions
  } = props;
  const containerRef = useRef<HTMLDivElement>(null);
  const handleRef = useRef<KiwiWidgetHandle | null>(null);
  const latest = useRef<KiwiRenderOptions>(renderOptions);
  latest.current = renderOptions;

  const config = configKey(props);

  useEffect(() => {
    const node = containerRef.current;
    if (!node) return;
    let cancelled = false;
    let handle: KiwiWidgetHandle | null = null;
    try {
      handle = renderKiwiCaptcha(node, latest.current);
      handleRef.current = handle;
    } catch {
      loadKiwiCaptcha({
        scriptSrc,
        integrity: scriptIntegrity,
        crossorigin: scriptCrossorigin,
        timeoutMs: scriptTimeoutMs,
      }).then((loaded) => {
        if (cancelled || !node) return;
        handle = renderKiwiCaptcha(node, { ...latest.current, api: loaded });
        handleRef.current = handle;
      });
    }
    return () => {
      cancelled = true;
      handleRef.current = null;
      if (handle) handle.destroy();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config]);

  return {
    containerRef,
    execute: () =>
      handleRef.current
        ? handleRef.current.execute()
        : Promise.reject(new Error("kiwicaptcha: widget not mounted")),
    reset: () => handleRef.current?.reset(),
    getResponse: () => handleRef.current?.getResponse() ?? "",
    isExpired: () => handleRef.current?.isExpired() ?? false,
  };
}
