import {
  AfterViewInit,
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  NgZone,
  OnChanges,
  SimpleChanges,
  ViewChild,
  inject,
  input,
  output,
  signal,
} from "@angular/core";
import type {
  KiwiCaptchaApi,
  KiwiRenderOptions,
  KiwiRetryDetail,
  KiwiVerifiedDetail,
  KiwiWidgetHandle,
} from "@kiwicaptcha/client-core";
import { KiwiCaptchaService, type KiwiLoadOptions } from "./kiwi-captcha.service";

/**
 * The KiwiCaptcha widget as a standalone Angular component (Ivy, zone
 * safe, OnPush). Inputs cover the four-setting quickstart (endpoint,
 * sitekey, scope, lang), the core's remaining render options, a preloaded
 * driver (`api`) and the loader controls. Outputs map the driver's kiwi:*
 * lifecycle events back inside the Angular zone. Changing any config input
 * destroys the live widget and rebuilds it from the new options.
 *
 * Driver work runs outside the zone; every output emission re-enters it,
 * so OnPush components see the change without extra wiring.
 */
@Component({
  selector: "kiwi-captcha",
  standalone: true,
  template: `<div #host class="kiwi-angular-host"></div>`,
  styles: [`:host { display: block; }`],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class KiwiCaptcha implements AfterViewInit, OnChanges {
  /** The four-setting quickstart. */
  readonly endpoint = input<string | undefined>(undefined);
  readonly sitekey = input<string | undefined>(undefined);
  readonly scope = input<string | undefined>(undefined);
  readonly lang = input<string | undefined>(undefined);

  /** The core's remaining render options. */
  readonly theme = input<"light" | "dark" | "auto" | undefined>(undefined);
  readonly action = input<string | undefined>(undefined);
  readonly cData = input<string | undefined>(undefined);
  readonly chainTicket = input<string | undefined>(undefined);
  readonly requestBinding = input<string | undefined>(undefined);
  readonly fetchTimeoutMs = input<number | undefined>(undefined);
  readonly algorithm = input<string | undefined>(undefined);
  readonly riskContext = input<"coarse" | undefined>(undefined);
  readonly responseField = input<string | false | undefined>(undefined);
  readonly execution = input<"execute" | undefined>(undefined);
  readonly tokenFieldName = input<string | undefined>(undefined);
  readonly buildMarkup = input<boolean | undefined>(undefined);
  /** A preloaded driver; otherwise the service loads the script. */
  readonly api = input<KiwiCaptchaApi | undefined>(undefined);

  /** The loader controls. */
  readonly scriptSrc = input<string | undefined>(undefined);
  readonly scriptIntegrity = input<string | undefined>(undefined);
  readonly scriptCrossorigin = input<"anonymous" | "use-credentials" | undefined>(undefined);
  readonly scriptTimeoutMs = input<number | undefined>(undefined);
  readonly scriptNonce = input<string | undefined>(undefined);

  /** True once a widget generation is live in the host element. */
  readonly ready = signal(false);

  /** A solve produced a token. */
  readonly verified = output<KiwiVerifiedDetail>();
  /** Terminal failure after the driver's bounded retries (or a render/load failure). */
  readonly failed = output<string>();
  /** A verified token aged out. */
  readonly expired = output<void>();
  /** The driver registered the widget. */
  readonly widgetReady = output<string>();
  /** A challenge was fetched and the solve started. */
  readonly verifying = output<string>();
  /** A transient failure entered the retry backoff. */
  readonly retrying = output<KiwiRetryDetail>();
  /** The off-main-thread solver could not start. */
  readonly workerUnavailable = output<string>();
  /** An execution-armed challenge could not run its program. */
  readonly executionUnavailable = output<string>();

  // The decorator query resolves in every Angular view; the injected host
  // element is the fallback for environments where the inner query is not
  // available (the render still has a valid container).
  @ViewChild("host", { static: true }) private hostRef?: ElementRef<HTMLElement>;
  private readonly hostElement = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly zone = inject(NgZone);
  private readonly destroyRef = inject(DestroyRef);
  private readonly service = inject(KiwiCaptchaService);

  private handle: KiwiWidgetHandle | null = null;
  private destroyed = false;
  private viewInitialized = false;
  private generation = 0;

  ngAfterViewInit(): void {
    this.viewInitialized = true;
    this.destroyRef.onDestroy(() => {
      this.destroyed = true;
      ++this.generation;
      this.handle?.destroy();
      this.handle = null;
      this.ready.set(false);
    });
    this.rebuild();
  }

  ngOnChanges(changes: SimpleChanges): void {
    // The initial input bindings arrive before the view exists; the first
    // render happens in ngAfterViewInit. Afterwards any config change
    // rebuilds against fresh options.
    if (!this.viewInitialized || !changes || Object.keys(changes).length === 0) return;
    this.rebuild();
  }

  /** The verified token, or "" while unverified or expired. */
  getResponse(): string {
    return this.handle?.getResponse() ?? "";
  }

  /** Whether the last verified token has expired. */
  isExpired(): boolean {
    return this.handle?.isExpired() ?? false;
  }

  /** Cancel the current run and acquire a fresh challenge. */
  reset(): void {
    this.handle?.reset();
  }

  /** Start or await the solve; resolves the token. */
  execute(): Promise<string> {
    return this.handle
      ? this.handle.execute()
      : Promise.reject(new Error("kiwicaptcha: widget not mounted"));
  }

  private rebuild(): void {
    if (this.destroyed) return;
    const container = this.hostRef?.nativeElement ?? this.hostElement.nativeElement;
    // Destroy the old generation before the fresh markup replaces it.
    this.handle?.destroy();
    this.handle = null;
    const ticket = ++this.generation;
    this.ready.set(false);
    this.zone.runOutsideAngular(() => {
      void this.service
        .render(container, this.readOptions())
        .then((handle) => {
          if (this.destroyed || ticket !== this.generation) {
            // The view died or another rebuild superseded this render.
            handle.destroy();
            return;
          }
          this.handle = handle;
          this.zone.run(() => this.ready.set(true));
        })
        .catch((err: unknown) => {
          if (ticket !== this.generation) return;
          this.zone.run(() => this.failed.emit(String(err)));
        });
    });
  }

  private readOptions(): KiwiRenderOptions & KiwiLoadOptions {
    return {
      endpoint: this.endpoint(),
      sitekey: this.sitekey(),
      scope: this.scope(),
      lang: this.lang(),
      theme: this.theme(),
      action: this.action(),
      cData: this.cData(),
      chainTicket: this.chainTicket(),
      requestBinding: this.requestBinding(),
      fetchTimeoutMs: this.fetchTimeoutMs(),
      algorithm: this.algorithm(),
      riskContext: this.riskContext(),
      responseField: this.responseField(),
      execution: this.execution(),
      tokenFieldName: this.tokenFieldName(),
      buildMarkup: this.buildMarkup(),
      api: this.api(),
      scriptSrc: this.scriptSrc(),
      scriptIntegrity: this.scriptIntegrity(),
      scriptCrossorigin: this.scriptCrossorigin(),
      scriptTimeoutMs: this.scriptTimeoutMs(),
      scriptNonce: this.scriptNonce(),
      onReady: (scope) => this.zone.run(() => this.widgetReady.emit(scope)),
      onVerifying: (scope) => this.zone.run(() => this.verifying.emit(scope)),
      onVerify: (token, detail) => this.zone.run(() => this.verified.emit(detail)),
      onError: (message) => this.zone.run(() => this.failed.emit(message)),
      onExpire: () => this.zone.run(() => this.expired.emit()),
      onRetry: (detail) => this.zone.run(() => this.retrying.emit(detail)),
      onWorkerUnavailable: (reason) =>
        this.zone.run(() => this.workerUnavailable.emit(reason)),
      onExecutionUnavailable: (reason) =>
        this.zone.run(() => this.executionUnavailable.emit(reason)),
    };
  }
}
