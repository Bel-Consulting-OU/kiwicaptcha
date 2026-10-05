/**
 * The shared KiwiCaptcha widget client contract, framework-free.
 *
 * Every framework package (React, Vue, Svelte, Solid, Angular) wraps this
 * core so lifecycle semantics cannot drift between them. The core talks to
 * the browser widget driver (the `window.KiwiCaptcha` provider API of
 * packages/kiwicaptcha-wasm/assets/widget-driver.js): render, reset,
 * execute, getResponse, isExpired, remove, destroy, and the bubbling
 * kiwi:* lifecycle events.
 */

/** The token field name the reference deployments submit. */
export const KIWI_TOKEN_FIELD_NAME = "kiwi__token";

/** The default script the driver is served from. */
export const KIWI_SCRIPT_SRC_DEFAULT = "/kiwi.js";

/** A loaded driver surface (the provider API the widget exposes). */
export interface KiwiCaptchaApi {
  render(target: HTMLElement | string, options?: Record<string, unknown>): string;
  reset(id: string): void;
  getResponse(id: string): string;
  execute(id: string): Promise<string>;
  remove(id: string): void;
  isExpired(id: string): boolean;
  ready(id: string): Promise<void>;
  destroy?(target: HTMLElement | string): void;
  observe?(root: HTMLElement): { disconnect(): void };
}

/** Detail payload of the driver's kiwi:verified event. */
export interface KiwiVerifiedDetail {
  scope: string;
  nonce?: string;
  token: string;
}

/** Detail payload of the driver's kiwi:error event; the message rides the callback. */
export interface KiwiErrorDetail {
  scope: string;
}

/** Detail payload of the driver's kiwi:retrying event. */
export interface KiwiRetryDetail {
  scope: string;
  error: string;
  attempt: number;
}

/** The normalized lifecycle callbacks the frameworks surface. */
export interface KiwiEventHandlers {
  /** The widget registered and its run loop is armed. */
  onReady?: (scope: string) => void;
  /** A challenge was fetched and the solve started. */
  onVerifying?: (scope: string) => void;
  /** A solve produced a token (the same value getResponse returns). */
  onVerify?: (token: string, detail: KiwiVerifiedDetail) => void;
  /** Terminal failure after the driver's bounded retries. */
  onError?: (message: string, detail: KiwiErrorDetail) => void;
  /** A verified token aged out; reacquire with reset() or execute(). */
  onExpire?: (scope: string) => void;
  /** A transient failure entered the driver's automatic retry backoff. */
  onRetry?: (detail: KiwiRetryDetail) => void;
  /** The off-main-thread solver could not start (worker or CSP). */
  onWorkerUnavailable?: (reason: string, scope: string) => void;
  /** An execution-armed challenge could not run its program. */
  onExecutionUnavailable?: (reason: string, scope: string) => void;
}

/**
 * The four-setting quickstart shape every client package documents:
 * endpoint, sitekey, scope, lang. The remaining fields are opt-in
 * passthrough of the driver's own options.
 */
export interface KiwiRenderOptions extends KiwiEventHandlers {
  /** The same-origin challenge endpoint. Default "/api/kcaptcha/challenge". */
  endpoint?: string;
  /** The public sitekey; rides the challenge request for scope mapping. */
  sitekey?: string;
  /** The security scope (login, signup, comment, ...). */
  scope?: string;
  /** Widget language tag (BCP 47). Default: the page's own language. */
  lang?: string;
  /** Presentational hook on the container: light, dark or auto. */
  theme?: "light" | "dark" | "auto";
  /** Provider-compatible action metadata declared at issuance. */
  action?: string;
  /** Provider-compatible cData metadata declared at issuance. */
  cData?: string;
  /** A one-shot server-issued chain ticket, cleared after the solve. */
  chainTicket?: string;
  /** A request-binding value carried into the kiwi_request_binding input. */
  requestBinding?: string;
  /** Challenge fetch timeout in milliseconds. */
  fetchTimeoutMs?: number;
  /** Request a non-default proof-of-work profile. */
  algorithm?: "sha256" | "argon2id" | "rsw" | (string & {});
  /** Alias response field name, or false to disable the alias write. */
  responseField?: string | false;
  /** Explicit-execution mode: the solve starts on execute() only. */
  execution?: "execute";
  /** The hidden token input's name. Default "kiwi__token". */
  tokenFieldName?: string;
  /**
   * Build the canonical widget markup inside the container (default true).
   * When false, the container must already hold a [data-kiwi-widget]
   * element and a [data-kiwi-token] input.
   */
  buildMarkup?: boolean;
  /** A pre-loaded driver; defaults to the document's window.KiwiCaptcha. */
  api?: KiwiCaptchaApi;
}

/** One rendered widget instance. */
export interface KiwiWidgetHandle {
  /** The driver-assigned widget id. */
  readonly id: string;
  /** The widget element the driver owns. */
  readonly element: HTMLElement;
  /** The container the client rendered the widget into. */
  readonly container: HTMLElement;
  /** The verified token, or "" while unverified or expired. */
  getResponse(): string;
  /** Whether the last verified token has expired. */
  isExpired(): boolean;
  /** Cancel the current run and acquire a fresh challenge. */
  reset(): void;
  /** Start (explicit mode) or await the current solve; resolves the token. */
  execute(): Promise<string>;
  /** Tear the widget down: listeners detached, driver record deleted. */
  destroy(): void;
}
